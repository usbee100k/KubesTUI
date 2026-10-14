package main

// Longhorn volumes in Files. A volume isn't a folder on any node's disk
// (it's attached to the node running its app), so opening one starts a
// small helper pod that mounts it at /data, on the node it's attached to
// (allowed next to the running app). Files then works in that pod through
// kubectl exec; copies in and out stream through it. Closing the pane
// removes the pod.

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// kubeStreamer runs a script with cluster access ("$K" is kubectl),
// streaming stdin and stdout (for tar in and out of a volume).
type kubeStreamer func(script string, stdin io.Reader, stdout io.Writer) error

// volHelperImage has GNU find/du/tar/stat, which the listing needs.
const volHelperImage = "debian:bookworm-slim"

type volInfo struct {
	ns, pvc, pv string
	size        string
	node        string   // where Longhorn has it attached ("" = detached)
	apps        []string // Deployments/StatefulSets mounting it
}

func (v volInfo) label() string { return "vol " + v.ns + "/" + v.pvc }

// listVolumes lists the cluster's Longhorn volumes (their claims).
func listVolumes(k kubeRunner) ([]volInfo, error) {
	out, err := k(`$K get pvc -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.volumeName}{"\t"}{.spec.storageClassName}{"\t"}{.status.capacity.storage}{"\n"}{end}'`, "")
	if err != nil {
		return nil, err
	}
	attached := map[string]string{}
	if lh, err := k(`$K -n longhorn-system get volumes.longhorn.io -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.status.currentNodeID}{"\n"}{end}' 2>/dev/null`, ""); err == nil {
		for _, l := range strings.Split(lh, "\n") {
			if n, node, ok := strings.Cut(strings.TrimSpace(l), "\t"); ok {
				attached[n] = node
			}
		}
	}
	users := map[string][]string{} // ns/claim -> workloads
	if wl, err := k(`$K get deploy,statefulset -A -o jsonpath='{range .items[*]}{.kind}{"\t"}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.template.spec.volumes[*].persistentVolumeClaim.claimName}{"\n"}{end}'`, ""); err == nil {
		for _, l := range strings.Split(wl, "\n") {
			f := strings.Split(strings.TrimSpace(l), "\t")
			if len(f) < 4 {
				continue
			}
			for _, c := range strings.Fields(f[3]) {
				users[f[1]+"/"+c] = append(users[f[1]+"/"+c], strings.ToLower(f[0])+"/"+f[2])
			}
		}
	}
	var vols []volInfo
	for _, l := range strings.Split(out, "\n") {
		f := strings.Split(strings.TrimSpace(l), "\t")
		if len(f) < 5 || f[2] == "" || f[3] != "longhorn" {
			continue
		}
		vols = append(vols, volInfo{ns: f[0], pvc: f[1], pv: f[2], size: f[4], node: attached[f[2]], apps: users[f[0]+"/"+f[1]]})
	}
	sort.Slice(vols, func(i, j int) bool { return vols[i].label() < vols[j].label() })
	return vols, nil
}

// openVolumeFS starts the helper pod and returns the volume as a fileSys.
func openVolumeFS(k kubeRunner, stream kubeStreamer, v volInfo) (*sshFS, error) {
	idb := make([]byte, 3)
	_, _ = rand.Read(idb)
	pod := "kubestui-vol-" + hex.EncodeToString(idb)
	spec := obj{
		"restartPolicy":                 "Never",
		"activeDeadlineSeconds":         14400, // gone after 4 hours whatever happens
		"terminationGracePeriodSeconds": 0,
		"tolerations":                   []obj{{"operator": "Exists"}},
		"containers": []obj{{
			"name": "files", "image": volHelperImage,
			"command":      []string{"sleep", "14400"},
			"volumeMounts": []obj{{"name": "data", "mountPath": "/data"}},
		}},
		"volumes": []obj{{"name": "data", "persistentVolumeClaim": obj{"claimName": v.pvc}}},
	}
	if v.node != "" {
		spec["nodeName"] = v.node // where it's attached: works next to the app
	}
	manifest, _ := yaml.Marshal(obj{
		"apiVersion": "v1", "kind": "Pod",
		"metadata": obj{"name": pod, "namespace": v.ns,
			"labels": obj{"app.kubernetes.io/managed-by": "kubestui", "kubestui-files": "volume"}},
		"spec": spec,
	})
	if out, err := k("$K apply -f - >/dev/null", string(manifest)); err != nil {
		return nil, fmt.Errorf("starting the volume helper: %v %s", err, out)
	}
	remove := func() {
		go func() { _, _ = k("$K -n "+v.ns+" delete pod "+pod+" --wait=false >/dev/null 2>&1", "") }()
	}
	deadline := time.Now().Add(3 * time.Minute) // the first time pulls the image
	for {
		out, _ := k("$K -n "+v.ns+" get pod "+pod+" -o jsonpath='{.status.phase}'", "")
		if strings.TrimSpace(out) == "Running" {
			break
		}
		if strings.TrimSpace(out) == "Failed" || time.Now().After(deadline) {
			why, _ := k("$K -n "+v.ns+" get events --field-selector involvedObject.name="+pod+" -o jsonpath='{range .items[*]}{.message}{\"\\n\"}{end}' | tail -n 3", "")
			remove()
			return nil, errors.New("the volume helper didn't start: " + strings.TrimSpace(why))
		}
		time.Sleep(time.Second)
	}
	f := &sshFS{label: v.label(), home: "/data", root: "/data", vol: &v, stream: stream, onClose: remove}
	f.exec = func(cmd string) (string, error) {
		return k("$K -n "+v.ns+" exec "+pod+" -- sh -c "+shellQuote(cmd), "")
	}
	f.pod = pod
	return f, nil
}

// volExec is the kubectl exec prefix for a volume's helper pod.
func volExec(f *sshFS) string {
	return "$K -n " + f.vol.ns + " exec -i " + f.pod + " -- "
}

// restartUsers offers to restart the workloads using a volume after files
// were copied into it, so they pick them up.
func restartUsers(d *demoTerm, k kubeRunner, v *volInfo) {
	if v == nil || len(v.apps) == 0 || k == nil {
		return
	}
	d.Printf("\n%s uses this volume. Restart it now so it picks up the files? (y/N): ", strings.Join(v.apps, ", "))
	a, ok := d.ReadLine(true)
	if !ok || !strings.HasPrefix(strings.ToLower(strings.TrimSpace(a)), "y") {
		d.Print("Not restarted. Later: kubectl -n " + v.ns + " rollout restart " + strings.Join(v.apps, " ") + "\n")
		return
	}
	for _, app := range v.apps {
		if out, err := k("$K -n "+v.ns+" rollout restart "+app, ""); err != nil {
			d.Print(cFail + app + ": " + strings.TrimSpace(out) + " " + err.Error() + "\n")
		} else {
			d.Print(cOK + "Restarted " + app + ".\n")
		}
	}
}

// volNote says where a volume is, for the device list.
func volNote(v volInfo) string {
	where := "detached"
	if v.node != "" {
		where = "on " + v.node
	}
	if len(v.apps) > 0 {
		where += ", used by " + strings.Join(v.apps, ", ")
	}
	return v.size + ", " + where
}
