package main

// Opening Files from the workstation and from the node menu: which
// locations a pane can show, and how node-to-node copies reach kubectl.

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rivo/tview"
	"golang.org/x/crypto/ssh"
)

func statusLight(status string) string {
	switch status {
	case "Ready":
		return "[green]●[-]"
	case "":
		return "[gray]●[-]"
	}
	return "[red]●[-]"
}

// openFiles (workstation): this computer and every node; node-to-node
// copies run kubectl on the control plane over SSH.
func (w *workstation) openFiles() { w.openFilesAt("") }

// openFilesAt opens Files with the right pane on a location (e.g. a
// Longhorn volume from the Command Center); "" for the default.
func (w *workstation) openFilesAt(right string) {
	p := w.current
	rows := w.nodeCache
	if len(rows) == 0 && w.activity != nil {
		rows = w.activity.last
	}
	nodes, _, _ := w.nodeChoices()
	status := map[string]string{}
	for _, r := range rows {
		status[r.name] = r.status
	}

	var locations []fmLocation
	if p.demo {
		locations = append(locations, fmLocation{label: "This computer",
			open: func() (fileSys, error) { return demoNodeFS("This computer"), nil }})
	} else {
		locations = append(locations, fmLocation{label: "This computer",
			open: func() (fileSys, error) { return localFS{}, nil }})
	}
	for _, n := range nodes {
		n := n
		locations = append(locations, fmLocation{label: n.Name, light: statusLight(status[n.Name]),
			open: func() (fileSys, error) {
				if p.demo {
					return demoNodeFS(n.Name), nil
				}
				return openSSHFS(n, []string{p.keyPath()})
			}})
	}

	// kubectl on the control plane, over one SSH connection opened when
	// the first node-to-node copy needs it.
	var mu sync.Mutex
	var cp *ssh.Client
	kube := func(script, stdin string) (string, error) {
		mu.Lock()
		if cp == nil {
			c, err := w.dialer(p)()
			if err != nil {
				mu.Unlock()
				return "", err
			}
			cp = c
		}
		c := cp
		mu.Unlock()
		return runRemote(c, sshKubectl+script, stdin)
	}
	// The same, streaming (tar into and out of volumes).
	stream := func(script string, stdin io.Reader, stdout io.Writer) error {
		if _, err := kube("true", ""); err != nil { // connects if needed
			return err
		}
		mu.Lock()
		c := cp
		mu.Unlock()
		session, err := c.NewSession()
		if err != nil {
			return err
		}
		defer session.Close()
		var stderr strings.Builder
		session.Stdin, session.Stdout, session.Stderr = stdin, stdout, &stderr
		if err := session.Run(sshKubectl + script); err != nil {
			return fmt.Errorf("%v %s", err, strings.TrimSpace(stderr.String()))
		}
		return nil
	}
	isNode := func(name string) bool { _, ok := status[name]; return ok }
	more := func() ([]fmLocation, error) { return volumeLocations(kube, stream) }
	if p.demo {
		kube, more = nil, demoVolumeLocations
	}

	openFileManager(w.app, w.pages, w.footer, fmOptions{
		locations: locations, more: more, kube: kube, isNode: isNode,
		start: [2]string{"", right},
		back: func() {
			mu.Lock()
			if cp != nil {
				cp.Close()
			}
			mu.Unlock()
			w.showCluster()
		},
	})
}

// volumeLocations lists the Longhorn volumes as Files locations.
func volumeLocations(kube kubeRunner, stream kubeStreamer) ([]fmLocation, error) {
	vols, err := listVolumes(kube)
	if err != nil {
		return nil, err
	}
	var locs []fmLocation
	for _, v := range vols {
		v := v
		locs = append(locs, fmLocation{label: v.label(), light: "[aqua]▤[-]", note: volNote(v), volume: true,
			open: func() (fileSys, error) { return openVolumeFS(kube, stream, v) }})
	}
	return locs, nil
}

// demoVolumeLocations: the demo's volumes.
func demoVolumeLocations() ([]fmLocation, error) {
	time.Sleep(300 * time.Millisecond)
	var locs []fmLocation
	for _, v := range []volInfo{
		{ns: "jellyfin", pvc: "jellyfin-config", size: "5Gi", node: "w1", apps: []string{"deployment/jellyfin"}},
		{ns: "n8n", pvc: "n8n-data", size: "5Gi", node: "cp3", apps: []string{"deployment/n8n"}},
		{ns: "nextcloud", pvc: "data", size: "100Gi", node: "w1", apps: []string{"deployment/nextcloud"}},
		{ns: "nextcloud", pvc: "db", size: "10Gi", node: "w1", apps: []string{"statefulset/nextcloud-db"}},
		{ns: "argocd", pvc: "redis-data", size: "1Gi", node: "cp1", apps: []string{"deployment/argocd-redis"}},
	} {
		v := v
		locs = append(locs, fmLocation{label: v.label(), light: "[aqua]▤[-]", note: volNote(v), volume: true,
			open: func() (fileSys, error) { return demoVolumeFS(v.label()), nil }})
	}
	return locs, nil
}

// openNodeFiles (node menu): this node and the other nodes, reached with
// this machine's SSH key (the SSH Console's K installs it); node-to-node
// copies run kubectl here.
func openNodeFiles(app *tview.Application, pages *tview.Pages, footer *tview.TextView, rows []nodeRow, right string, back func()) {
	host, _ := os.Hostname()
	host = strings.ToLower(host)
	home, _ := os.UserHomeDir()
	var keys []string
	for _, n := range []string{"id_ed25519", "id_ecdsa", "id_rsa"} {
		keys = append(keys, filepath.Join(home, ".ssh", n))
	}
	store := loadHostStore()

	status := map[string]string{}
	locations := []fmLocation{{label: "This node (" + host + ")",
		open: func() (fileSys, error) { return localFS{name: "This node (" + host + ")"}, nil }}}
	for _, r := range rows {
		r := r
		status[r.name] = r.status
		if r.name == host {
			continue
		}
		user := sshPage.userFor(&r)
		if e := store.find(r.host); e != nil && e.User != "" {
			user = e.User
		}
		e := hostEntry{Name: r.name, Host: r.host, User: user, Port: 22}
		locations = append(locations, fmLocation{label: r.name, light: statusLight(r.status),
			open: func() (fileSys, error) {
				if e.Host == "" {
					return nil, errors.New("no address for " + e.Name)
				}
				return openSSHFS(e, keys)
			}})
	}
	kube := func(script, stdin string) (string, error) {
		cmd := exec.Command("sh", "-c", sshKubectl+script)
		cmd.Stdin = strings.NewReader(stdin)
		var stderr strings.Builder
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			return string(out), fmt.Errorf("%v: %s", err, strings.TrimSpace(stderr.String()))
		}
		return string(out), nil
	}
	stream := func(script string, stdin io.Reader, stdout io.Writer) error {
		cmd := exec.Command("sh", "-c", sshKubectl+script)
		var stderr strings.Builder
		cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, &stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("%v %s", err, strings.TrimSpace(stderr.String()))
		}
		return nil
	}
	isNode := func(name string) bool { _, ok := status[name]; return ok }
	openFileManager(app, pages, footer, fmOptions{
		locations: locations, kube: kube, isNode: isNode, back: back,
		more:  func() ([]fmLocation, error) { return volumeLocations(kube, stream) },
		start: [2]string{"", right},
	})
}
