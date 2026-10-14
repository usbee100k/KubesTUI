package main

// "Change App Storage": choose where an app's folders live, either a
// Longhorn volume (replicated across nodes) or a folder on one node's own
// disk, without editing manifests by hand.
//
// Runs on a control plane (install.sh --run app-storage), like the Compose
// import: install.sh prepares the GitOps checkout before and commits,
// pushes and watches Argo CD after. Environment: GITOPS_DIR,
// KUBESTUI_RESULT_FILE.
//
// The choices are written to storage-patch.yaml next to the app's
// kustomization.yaml (a Kustomize patch on top of the app's own files),
// plus storage-pvcs.yaml for new Longhorn volumes. The app's files are not
// touched, so homelabCD template updates never conflict with them, and
// removing an entry from storage-patch.yaml puts the original back.

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

const (
	storagePatchFile = "storage-patch.yaml"
	storagePVCFile   = "storage-pvcs.yaml"
	hostnameLabel    = "kubernetes.io/hostname"
)

// storageApp is an Argo CD app with a Kustomize directory in the repo.
type storageApp struct {
	name      string // Argo CD Application name
	namespace string
	dir       string // kustomization directory
	workloads []*storageWorkload
	pvcs      map[string]string // claim -> size
}

type storageWorkload struct {
	kind, name string
	namespace  string
	pin        string // nodeSelector kubernetes.io/hostname
	recreate   bool   // Deployment strategy is Recreate
	puid       string // PUID env (linuxserver/hotio images), for the chown hint
	volumes    []*storageVolume
}

type storageVolume struct {
	name   string
	mounts []string // container mount paths (subPath shown in brackets)
	kind   string   // longhorn / host / emptydir / nfs / other
	claim  string
	path   string
	server string
}

func (v *storageVolume) describe(app *storageApp, w *storageWorkload) string {
	switch v.kind {
	case "longhorn":
		size := app.pvcs[v.claim]
		if size != "" {
			size = ", " + size
		}
		return "Longhorn volume " + v.claim + size
	case "host":
		node := w.pin
		if node == "" {
			node = "any node (not pinned)"
		}
		return "folder " + v.path + " on " + node
	case "nfs":
		return "NFS " + v.server + ":" + v.path
	case "emptydir":
		return "temporary (emptyDir, deleted with the pod)"
	}
	return v.kind
}

// ---------------------------------------------------------------------------
// The patch file (the user's choices)
// ---------------------------------------------------------------------------

type patchVolume struct {
	name  string
	claim string // Longhorn
	path  string // host folder
}

type patchWorkload struct {
	kind, name string
	namespace  string
	pin        string // "" = not set by the patch
	unpin      bool   // remove the app's own node pin
	recreate   bool
	volumes    []patchVolume
}

type storagePatch struct {
	workloads []*patchWorkload
}

func (p *storagePatch) get(kind, name string, create bool) *patchWorkload {
	for _, w := range p.workloads {
		if w.kind == kind && w.name == name {
			return w
		}
	}
	if !create {
		return nil
	}
	w := &patchWorkload{kind: kind, name: name}
	p.workloads = append(p.workloads, w)
	return w
}

func (w *patchWorkload) volume(name string) *patchVolume {
	for i := range w.volumes {
		if w.volumes[i].name == name {
			return &w.volumes[i]
		}
	}
	return nil
}

func (w *patchWorkload) setVolume(v patchVolume) {
	if cur := w.volume(v.name); cur != nil {
		*cur = v
		return
	}
	w.volumes = append(w.volumes, v)
}

func (w *patchWorkload) removeVolume(name string) {
	w.volumes = slices.DeleteFunc(w.volumes, func(v patchVolume) bool { return v.name == name })
}

func (w *patchWorkload) hostNode() bool {
	for _, v := range w.volumes {
		if v.path != "" {
			return true
		}
	}
	return false
}

func yamlDocs(data []byte) ([]map[string]any, error) {
	var docs []map[string]any
	dec := yaml.NewDecoder(bytes.NewReader(data))
	for {
		var d map[string]any
		err := dec.Decode(&d)
		if errors.Is(err, io.EOF) {
			return docs, nil
		}
		if err != nil {
			return nil, err
		}
		if d != nil {
			docs = append(docs, d)
		}
	}
}

// dig walks nested maps: dig(m, "spec", "template", "spec").
func dig(m map[string]any, keys ...string) map[string]any {
	for _, k := range keys {
		n, _ := m[k].(map[string]any)
		if n == nil {
			return nil
		}
		m = n
	}
	return m
}

func str(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

func readStoragePatch(dir string) (*storagePatch, error) {
	p := &storagePatch{}
	data, err := os.ReadFile(filepath.Join(dir, storagePatchFile))
	if errors.Is(err, os.ErrNotExist) {
		return p, nil
	}
	if err != nil {
		return nil, err
	}
	docs, err := yamlDocs(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", storagePatchFile, err)
	}
	for _, d := range docs {
		w := p.get(str(d, "kind"), str(dig(d, "metadata"), "name"), true)
		w.namespace = str(dig(d, "metadata"), "namespace")
		if strategy := dig(d, "spec", "strategy"); str(strategy, "type") == "Recreate" {
			w.recreate = true
		}
		pod := dig(d, "spec", "template", "spec")
		if ns, ok := pod["nodeSelector"].(map[string]any); ok {
			if v, has := ns[hostnameLabel]; has {
				if s, _ := v.(string); s != "" {
					w.pin = s
				} else {
					w.unpin = true
				}
			}
		}
		vols, _ := pod["volumes"].([]any)
		for _, x := range vols {
			v, _ := x.(map[string]any)
			pv := patchVolume{name: str(v, "name")}
			pv.claim = str(dig(v, "persistentVolumeClaim"), "claimName")
			pv.path = str(dig(v, "hostPath"), "path")
			if pv.name != "" && (pv.claim != "" || pv.path != "") {
				w.volumes = append(w.volumes, pv)
			}
		}
	}
	return p, nil
}

func yq(s string) string { return strconv.Quote(s) }

// The volume sources one volume can have; the patch clears the others so
// the result has exactly one.
var volumeSources = []string{"persistentVolumeClaim", "hostPath", "emptyDir", "nfs"}

func writeStoragePatch(dir string, p *storagePatch) error {
	var b strings.Builder
	b.WriteString("# Storage chosen with \"Change App Storage\" in KubesTUI, applied on top of\n" +
		"# this app's own files. Edit it here or run Change App Storage again;\n" +
		"# deleting a volume's entry puts back the app's original storage.\n")
	n := 0
	for _, w := range p.workloads {
		if len(w.volumes) == 0 && w.pin == "" && !w.unpin && !w.recreate {
			continue
		}
		if n > 0 {
			b.WriteString("---\n")
		}
		n++
		api := "apps/v1"
		fmt.Fprintf(&b, "apiVersion: %s\nkind: %s\nmetadata:\n  name: %s\n", api, w.kind, w.name)
		if w.namespace != "" {
			fmt.Fprintf(&b, "  namespace: %s\n", w.namespace)
		}
		b.WriteString("spec:\n")
		if w.recreate && w.kind == "Deployment" {
			b.WriteString("  # A Longhorn volume attaches to one node at a time: stop the old pod first.\n" +
				"  strategy:\n    type: Recreate\n    rollingUpdate: null\n")
		}
		b.WriteString("  template:\n    spec:\n")
		switch {
		case w.pin != "":
			fmt.Fprintf(&b, "      # Host folders are on this node, so the pod runs there.\n      nodeSelector:\n        %s: %s\n", hostnameLabel, yq(w.pin))
		case w.unpin:
			fmt.Fprintf(&b, "      nodeSelector:\n        %s: null\n", hostnameLabel)
		}
		if len(w.volumes) > 0 {
			b.WriteString("      volumes:\n")
		}
		for _, v := range w.volumes {
			fmt.Fprintf(&b, "        - name: %s\n", yq(v.name))
			keep := "persistentVolumeClaim"
			if v.path != "" {
				keep = "hostPath"
				fmt.Fprintf(&b, "          hostPath:\n            path: %s\n            type: DirectoryOrCreate\n", yq(v.path))
			} else {
				fmt.Fprintf(&b, "          persistentVolumeClaim:\n            claimName: %s\n", yq(v.claim))
			}
			for _, s := range volumeSources {
				if s != keep {
					fmt.Fprintf(&b, "          %s: null\n", s)
				}
			}
		}
	}
	path := filepath.Join(dir, storagePatchFile)
	if n == 0 {
		err := os.Remove(path)
		if errors.Is(err, os.ErrNotExist) {
			err = nil
		}
		return err
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

// ---------------------------------------------------------------------------
// New Longhorn volumes
// ---------------------------------------------------------------------------

func addStoragePVC(dir, namespace, name, size string) error {
	path := filepath.Join(dir, storagePVCFile)
	var buf bytes.Buffer
	if data, err := os.ReadFile(path); err == nil {
		buf.Write(bytes.TrimRight(data, "\n"))
		buf.WriteString("\n---\n")
	} else {
		buf.WriteString("# Longhorn volumes created with \"Change App Storage\" in KubesTUI.\n" +
			"# Removing one here deletes the volume and its data.\n")
	}
	doc := obj{
		"apiVersion": "v1",
		"kind":       "PersistentVolumeClaim",
		"metadata":   obj{"name": name},
		"spec": obj{
			"accessModes":      []string{"ReadWriteOnce"},
			"storageClassName": "longhorn",
			"resources":        obj{"requests": obj{"storage": size}},
		},
	}
	if namespace != "" {
		doc["metadata"].(obj)["namespace"] = namespace
	}
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return err
	}
	_ = enc.Close()
	return os.WriteFile(path, buf.Bytes(), 0o644)
}

// ---------------------------------------------------------------------------
// kustomization.yaml: reference the two files (text edit, so the rest of
// the file and its comments stay as they are)
// ---------------------------------------------------------------------------

func kustomizationPath(dir string) string {
	for _, n := range []string{"kustomization.yaml", "kustomization.yml", "Kustomization"} {
		if fileExists(filepath.Join(dir, n)) {
			return filepath.Join(dir, n)
		}
	}
	return ""
}

// addKustomizeEntry adds "item" to the top-level list "key" unless the
// file already mentions file.
func addKustomizeEntry(text, key, item, file string) string {
	if strings.Contains(text, file) {
		return text
	}
	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
	for i, l := range lines {
		if strings.TrimRight(l, " ") != key+":" {
			continue
		}
		indent := "  "
		for _, next := range lines[i+1:] {
			t := strings.TrimLeft(next, " ")
			if strings.HasPrefix(t, "- ") {
				indent = next[:len(next)-len(t)]
				break
			}
			if t != "" && !strings.HasPrefix(t, "#") {
				break
			}
		}
		out := append([]string{}, lines[:i+1]...)
		out = append(out, indent+"- "+item)
		out = append(out, lines[i+1:]...)
		return strings.Join(out, "\n") + "\n"
	}
	return strings.Join(lines, "\n") + "\n\n# Added by \"Change App Storage\" (KubesTUI)\n" + key + ":\n  - " + item + "\n"
}

// ---------------------------------------------------------------------------
// Reading the apps
// ---------------------------------------------------------------------------

func kustomizeBuild(dir string) ([]map[string]any, error) {
	cmd := exec.Command("kubectl", "kustomize", dir)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("kubectl kustomize %s: %v %s", dir, err, strings.TrimSpace(stderr.String()))
	}
	return yamlDocs(out)
}

// findStorageApps lists the Argo CD apps in the repo that have workloads
// with volumes that can be moved.
func findStorageApps(root string) ([]*storageApp, []string) {
	var apps []*storageApp
	var problems []string
	_ = filepath.WalkDir(filepath.Join(root, "apps"), func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Name() != "app.yaml" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		docs, err := yamlDocs(data)
		if err != nil || len(docs) == 0 || str(docs[0], "kind") != "Application" {
			return nil
		}
		a := docs[0]
		spec := dig(a, "spec")
		var paths []string
		if p := str(dig(spec, "source"), "path"); p != "" {
			paths = append(paths, p)
		}
		srcs, _ := spec["sources"].([]any)
		for _, s := range srcs {
			if m, _ := s.(map[string]any); m != nil && str(m, "path") != "" {
				paths = append(paths, str(m, "path"))
			}
		}
		for _, p := range paths {
			dir := filepath.Join(root, filepath.FromSlash(p))
			if kustomizationPath(dir) == "" {
				continue
			}
			app, err := loadStorageApp(str(dig(a, "metadata"), "name"), str(dig(spec, "destination"), "namespace"), dir)
			if err != nil {
				problems = append(problems, err.Error())
				continue
			}
			if len(app.workloads) > 0 {
				apps = append(apps, app)
			}
		}
		return nil
	})
	sort.Slice(apps, func(i, j int) bool { return apps[i].name < apps[j].name })
	return apps, problems
}

// System folders a pod may mount from its node; not app data.
var systemHostPath = regexp.MustCompile(`^/(dev|sys|proc|run|var/run|etc|lib/modules|var/lib/kubelet|var/lib/kubestui|usr)(/|$)`)

func loadStorageApp(name, namespace, dir string) (*storageApp, error) {
	docs, err := kustomizeBuild(dir)
	if err != nil {
		return nil, err
	}
	app := &storageApp{name: name, namespace: namespace, dir: dir, pvcs: map[string]string{}}
	for _, d := range docs {
		if str(d, "kind") == "PersistentVolumeClaim" {
			app.pvcs[str(dig(d, "metadata"), "name")] = str(dig(d, "spec", "resources", "requests"), "storage")
		}
	}
	for _, d := range docs {
		kind := str(d, "kind")
		if kind != "Deployment" && kind != "StatefulSet" {
			continue
		}
		if app.namespace == "" {
			app.namespace = str(dig(d, "metadata"), "namespace")
		}
		pod := dig(d, "spec", "template", "spec")
		w := &storageWorkload{kind: kind, name: str(dig(d, "metadata"), "name"), namespace: str(dig(d, "metadata"), "namespace")}
		if ns, ok := pod["nodeSelector"].(map[string]any); ok {
			w.pin = str(ns, hostnameLabel)
		}
		w.recreate = str(dig(d, "spec", "strategy"), "type") == "Recreate"

		mounts := map[string][]string{}
		for _, key := range []string{"initContainers", "containers"} {
			cs, _ := pod[key].([]any)
			for _, x := range cs {
				c, _ := x.(map[string]any)
				envs, _ := c["env"].([]any)
				for _, e := range envs {
					if m, _ := e.(map[string]any); str(m, "name") == "PUID" && w.puid == "" {
						w.puid = str(m, "value")
					}
				}
				vms, _ := c["volumeMounts"].([]any)
				for _, y := range vms {
					m, _ := y.(map[string]any)
					p := str(m, "mountPath")
					if sp := str(m, "subPath"); sp != "" {
						p += " [" + sp + "]"
					}
					if n := str(m, "name"); n != "" && !slices.Contains(mounts[n], p) {
						mounts[n] = append(mounts[n], p)
					}
				}
			}
		}

		vols, _ := pod["volumes"].([]any)
		for _, x := range vols {
			v, _ := x.(map[string]any)
			sv := &storageVolume{name: str(v, "name"), mounts: mounts[str(v, "name")]}
			switch {
			case dig(v, "persistentVolumeClaim") != nil:
				sv.kind, sv.claim = "longhorn", str(dig(v, "persistentVolumeClaim"), "claimName")
			case dig(v, "hostPath") != nil:
				sv.kind, sv.path = "host", str(dig(v, "hostPath"), "path")
				if systemHostPath.MatchString(sv.path) {
					continue
				}
			case dig(v, "nfs") != nil:
				sv.kind, sv.server, sv.path = "nfs", str(dig(v, "nfs"), "server"), str(dig(v, "nfs"), "path")
			case v["emptyDir"] != nil:
				sv.kind = "emptydir"
			default:
				continue // configMap, secret, projected: not data folders
			}
			if len(sv.mounts) == 0 {
				continue
			}
			w.volumes = append(w.volumes, sv)
		}
		if len(w.volumes) > 0 {
			// Stable numbering: Kustomize moves patched volumes first.
			sort.SliceStable(w.volumes, func(i, j int) bool { return w.volumes[i].mounts[0] < w.volumes[j].mounts[0] })
			app.workloads = append(app.workloads, w)
		}
	}
	return app, nil
}

// ---------------------------------------------------------------------------
// The command
// ---------------------------------------------------------------------------

// runAppStorage is `kubestui app-storage`.
func runAppStorage() int {
	in := &prompter{in: bufio.NewReader(os.Stdin)}
	root, err := gitopsDir()
	if err != nil {
		fmt.Println(cFail + err.Error())
		return 1
	}

	fmt.Println()
	fmt.Println("=============================================")
	fmt.Println(" Change App Storage")
	fmt.Println("=============================================")
	fmt.Println()
	fmt.Println("Choose where an app keeps a folder: a Longhorn volume (copied to")
	fmt.Println("several nodes, survives a node failure) or a folder on one node's")
	fmt.Println("own disk (the app then always runs on that node).")
	fmt.Println()

	apps, problems := findStorageApps(root)
	for _, p := range problems {
		fmt.Println(cWarn + p)
	}
	if len(apps) == 0 {
		fmt.Println("  No apps with storage found in the GitOps repository.")
		return 0
	}

	for i, a := range apps {
		n := 0
		for _, w := range a.workloads {
			n += len(w.volumes)
		}
		fmt.Printf("  %2d) %-22s %d folder(s)\n", i+1, a.name, n)
	}
	fmt.Println()
	app := apps[pickNumber(in, "App", len(apps))-1]

	// Every volume of the app, numbered.
	type choice struct {
		w *storageWorkload
		v *storageVolume
	}
	var list []choice
	patch, err := readStoragePatch(app.dir)
	if err != nil {
		fmt.Println(cFail + err.Error())
		return 1
	}
	fmt.Println()
	fmt.Println(app.name + ":")
	for _, w := range app.workloads {
		for _, v := range w.volumes {
			list = append(list, choice{w, v})
			mark := ""
			if pw := patch.get(w.kind, w.name, false); pw != nil && pw.volume(v.name) != nil {
				mark = "  (changed)"
			}
			label := strings.Join(v.mounts, ", ")
			if len(app.workloads) > 1 {
				label = w.name + ": " + label
			}
			fmt.Printf("  %2d) %-34s -> %s%s\n", len(list), label, v.describe(app, w), mark)
		}
	}
	fmt.Println()
	c := list[pickNumber(in, "Folder to change", len(list))-1]
	w, v := c.w, c.v
	pw := patch.get(w.kind, w.name, true)
	pw.namespace = w.namespace
	inPatch := pw.volume(v.name) != nil

	fmt.Println()
	fmt.Printf("%s is now: %s\n\n", strings.Join(v.mounts, ", "), v.describe(app, w))
	fmt.Println("  1) Longhorn volume")
	fmt.Println("  2) Folder on a node's disk")
	options := 2
	if inPatch {
		fmt.Println("  3) Back to the app's original storage")
		options = 3
	}
	fmt.Println()
	what := pickNumber(in, "New storage", options)

	newPVC := ""
	newSize := ""
	wasHost := v.kind == "host"
	switch what {
	case 1:
		claims := make([]string, 0, len(app.pvcs))
		for n := range app.pvcs {
			claims = append(claims, n)
		}
		sort.Strings(claims)
		fmt.Println()
		fmt.Println("  0) New Longhorn volume")
		for i, n := range claims {
			fmt.Printf("  %d) %s (%s)\n", i+1, n, orDefault(app.pvcs[n], "?"))
		}
		fmt.Println()
		k := pickNumberFrom(in, "Volume", 0, len(claims))
		claim := ""
		if k == 0 {
			def := dnsName(w.name + "-" + filepath.Base(strings.Fields(v.mounts[0])[0]))
			for i := 2; app.pvcs[def] != ""; i++ {
				def = dnsName(fmt.Sprintf("%s-%s-%d", w.name, filepath.Base(strings.Fields(v.mounts[0])[0]), i))
			}
			for {
				claim = dnsName(in.ask("  Name for the new volume", def))
				if _, taken := app.pvcs[claim]; taken || claim == "" || claim == "-" {
					fmt.Println("    [ERROR] " + claim + " already exists in this app; choose another name.")
					continue
				}
				break
			}
			newPVC, newSize = claim, in.size("  Size", "10Gi")
		} else {
			claim = claims[k-1]
		}
		pw.setVolume(patchVolume{name: v.name, claim: claim})
		if w.kind == "Deployment" && !w.recreate {
			pw.recreate = true
		}
	case 2:
		// The pod runs on one node: all its node folders must be there.
		required := ""
		for _, o := range w.volumes {
			if o == v || o.kind != "host" {
				continue
			}
			if p := pw.volume(o.name); p != nil && p.claim != "" {
				continue // moving to Longhorn in this patch
			}
			required = w.pin
		}
		nodes := nodeNames()
		def := required
		if def == "" {
			def = w.pin
		}
		if def == "" {
			def = nodeHostname()
		}
		fmt.Println()
		if len(nodes) > 0 {
			fmt.Println("  Nodes: " + strings.Join(nodes, ", "))
		}
		node := ""
		for {
			node = strings.ToLower(in.ask("  Node with the folder", def))
			switch {
			case len(nodes) > 0 && !slices.Contains(nodes, node):
				fmt.Println("    [ERROR] " + node + " isn't a node in this cluster.")
				continue
			case required != "" && node != required:
				fmt.Println("    [ERROR] " + w.name + "'s other node folders are on " + required + ", and a pod runs on one node, so this folder must be on " + required + " too.")
				continue
			}
			break
		}
		path := ""
		defPath := ""
		if v.kind == "host" {
			defPath = v.path
		}
		for {
			path = strings.TrimRight(strings.TrimSpace(in.ask("  Folder on "+node+" (full path, e.g. /mnt/data/shows)", defPath)), "/")
			switch {
			case !strings.HasPrefix(path, "/") || strings.Contains(path, ".."):
				fmt.Println("    [ERROR] Enter a full path starting with /.")
				continue
			case systemHostPath.MatchString(path) || path == "":
				fmt.Println("    [ERROR] That's a system folder; choose a data folder.")
				continue
			}
			break
		}
		pw.setVolume(patchVolume{name: v.name, path: path})
		pw.pin, pw.unpin = node, false
	case 3:
		pw.removeVolume(v.name)
	}

	// Write, then check that Kustomize accepts the result.
	kpath := kustomizationPath(app.dir)
	backups := map[string][]byte{}
	for _, f := range []string{kpath, filepath.Join(app.dir, storagePatchFile), filepath.Join(app.dir, storagePVCFile)} {
		if data, err := os.ReadFile(f); err == nil {
			backups[f] = data
		}
	}
	restore := func() {
		for _, f := range []string{filepath.Join(app.dir, storagePatchFile), filepath.Join(app.dir, storagePVCFile)} {
			if _, ok := backups[f]; !ok {
				_ = os.Remove(f)
			}
		}
		for f, data := range backups {
			_ = os.WriteFile(f, data, 0o644)
		}
	}
	fail := func(err error) int {
		restore()
		fmt.Println(cFail + err.Error())
		fmt.Println("Nothing was changed.")
		return 1
	}

	if newPVC != "" {
		if err := addStoragePVC(app.dir, app.namespace, newPVC, newSize); err != nil {
			return fail(err)
		}
	}
	// The node pin follows the node folders: the pod must run where they
	// are, and once none are left it may run anywhere again. Render once
	// without a pin from the patch to see the app's own pin and folders.
	hostPin := pw.pin
	if !pw.hostNode() {
		hostPin = ""
	}
	hadPin := pw.pin != "" || pw.unpin
	pw.pin, pw.unpin = "", false
	if what == 3 && len(pw.volumes) == 0 {
		pw.recreate = false
	}
	save := func() error {
		if err := writeStoragePatch(app.dir, patch); err != nil {
			return err
		}
		if err := writeStorageKustomization(app.dir, kpath, string(backups[kpath])); err != nil {
			return err
		}
		_, err := kustomizeBuild(app.dir)
		return err
	}
	err = save()
	if err != nil && strings.Contains(err.Error(), "no matches for Id") && pw.namespace != "" {
		// The kustomization sets the namespace itself (namespace:), so
		// the app's files, and the patch, have none.
		pw.namespace = ""
		err = save()
	}
	if err != nil {
		return fail(err)
	}
	base, err := loadStorageApp(app.name, app.namespace, app.dir)
	if err != nil {
		return fail(err)
	}
	if hostPin != "" {
		pw.pin = hostPin
	} else if bw := base.workload(w.kind, w.name); bw != nil && bw.pin != "" && !bw.hasHost() && (wasHost || hadPin) {
		pw.unpin = true // the pin was only there for node folders
	}
	if err := save(); err != nil {
		return fail(err)
	}

	after, _ := loadStorageApp(app.name, app.namespace, app.dir)
	fmt.Println()
	if after != nil {
		for _, aw := range after.workloads {
			if aw.name != w.name {
				continue
			}
			for _, av := range aw.volumes {
				if av.name == v.name {
					fmt.Println(cOK + strings.Join(av.mounts, ", ") + " -> " + av.describe(after, aw))
				}
			}
		}
	}
	rel, _ := filepath.Rel(root, filepath.Join(app.dir, storagePatchFile))
	fmt.Println("  Saved in " + filepath.ToSlash(rel))
	fmt.Println()
	fmt.Println(cWarn + "Files in the old location are not copied to the new one.")
	if what == 2 {
		if p := pw.volume(v.name); p != nil {
			owner := orDefault(w.puid, "1000")
			fmt.Println("  The folder is created if it's missing. If " + app.name + " can't write to it, run on " + pw.pin + ":")
			fmt.Println("    sudo chown -R " + owner + ":" + owner + " " + p.path)
		}
	}
	writeResult(app.name)
	return 0
}

// writeStorageKustomization makes kustomization.yaml (original text
// orig) reference the storage files that exist.
func writeStorageKustomization(dir, kpath, orig string) error {
	text := orig
	if fileExists(filepath.Join(dir, storagePatchFile)) {
		text = addKustomizeEntry(text, "patches", "path: "+storagePatchFile, storagePatchFile)
	} else {
		text = removeKustomizeEntry(text, storagePatchFile)
	}
	if fileExists(filepath.Join(dir, storagePVCFile)) {
		text = addKustomizeEntry(text, "resources", storagePVCFile, storagePVCFile)
	}
	return os.WriteFile(kpath, []byte(text), 0o644)
}

func (a *storageApp) workload(kind, name string) *storageWorkload {
	for _, w := range a.workloads {
		if w.kind == kind && w.name == name {
			return w
		}
	}
	return nil
}

func (w *storageWorkload) hasHost() bool {
	for _, v := range w.volumes {
		if v.kind == "host" {
			return true
		}
	}
	return false
}

// removeKustomizeEntry drops the line that references file.
func removeKustomizeEntry(text, file string) string {
	// The block addKustomizeEntry appended, if it's still as it was.
	block := "\n\n# Added by \"Change App Storage\" (KubesTUI)\npatches:\n  - path: " + file + "\n"
	if strings.Contains(text, block) {
		return strings.Replace(text, block, "\n", 1)
	}
	var out []string
	for _, l := range strings.Split(text, "\n") {
		if strings.Contains(l, file) && strings.HasPrefix(strings.TrimSpace(l), "-") {
			continue
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

func pickNumber(in *prompter, question string, n int) int {
	return pickNumberFrom(in, question, 1, n)
}

func pickNumberFrom(in *prompter, question string, from, to int) int {
	for {
		a := in.ask(fmt.Sprintf("%s [%d-%d]", question, from, to), "")
		if k, err := strconv.Atoi(a); err == nil && k >= from && k <= to {
			return k
		}
		fmt.Println("  [ERROR] Enter a number from the list.")
	}
}
