package main

// Workstation side of "Import Docker Compose App": pick a compose file on
// this computer, upload it (with .env and small referenced files) to the
// control plane, and run the import there in the built-in terminal.

import (
	"archive/tar"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/compose-spec/compose-go/v2/types"
	"github.com/gdamore/tcell/v2"
	"io"
	"net"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/rivo/tview"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

// findComposeFile accepts a compose file or the folder containing one.
func findComposeFile(path string) (string, error) {
	path = strings.Trim(strings.TrimSpace(path), `"'`)
	if strings.HasPrefix(path, "~") {
		if home, err := os.UserHomeDir(); err == nil {
			path = filepath.Join(home, strings.TrimPrefix(path, "~"))
		}
	}
	st, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if st.IsDir() {
		for _, n := range []string{"compose.yaml", "compose.yml", "docker-compose.yml", "docker-compose.yaml"} {
			if fileExists(filepath.Join(path, n)) {
				return filepath.Join(path, n), nil
			}
		}
		return "", fmt.Errorf("no compose file in %s", path)
	}
	return path, nil
}

// composeBundle tars the files the import needs, paths relative to the
// compose file's folder.
func composeBundle(file string) ([]byte, []string, error) {
	rels, err := composeLocalFiles(file)
	if err != nil {
		return nil, nil, err
	}
	base := filepath.Dir(must(filepath.Abs(file)))
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, rel := range rels {
		data, err := os.ReadFile(filepath.Join(base, rel))
		if err != nil {
			return nil, nil, err
		}
		hdr := &tar.Header{Name: filepath.ToSlash(rel), Mode: 0o600, Size: int64(len(data)), ModTime: time.Now()}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, nil, err
		}
		if _, err := tw.Write(data); err != nil {
			return nil, nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, nil, err
	}
	return buf.Bytes(), rels, nil
}

func (w *workstation) importCompose() { w.importComposeFrom("") }

// composeSource is a choice of "Compose file on".
type composeSource struct {
	label    string
	entry    *hostEntry // nil: this computer
	ready    bool
	external bool // another machine over SSH (not a cluster node)
	add      bool // "Another machine (SSH)…"
}

// importComposeFrom opens the import form; pick preselects a saved
// machine (its address).
func (w *workstation) importComposeFrom(pick string) {
	p := w.current
	if !p.demo && p.HomelabRoot == "" {
		w.clusterNote.SetText("  [yellow]homelabCD wasn't found on " + tview.Escape(p.Host) + "; imports run there.[-]")
		return
	}

	// Where the compose file is: this computer, one of the nodes, or
	// another machine over SSH (a CasaOS or Docker box). From a node or a
	// machine its data can come along into the new volumes.
	nodes, labels, ready := w.nodeChoices()
	srcs := []composeSource{{label: "This computer", ready: true}}
	for i := range nodes {
		srcs = append(srcs, composeSource{label: labels[i], entry: &nodes[i], ready: ready[i]})
	}
	machines := loadMachines(p)
	initial := 0
	for i := range machines {
		m := &machines[i]
		if m.Host == pick {
			initial = len(srcs)
		}
		srcs = append(srcs, composeSource{label: fmt.Sprintf("%s (%s) · other machine", orDefault(m.Name, m.Host), m.Host), entry: m, ready: true, external: true})
	}
	srcs = append(srcs, composeSource{label: "Another machine (SSH)…", add: true})
	sources := make([]string, len(srcs))
	for i, sc := range srcs {
		sources[i] = sc.label
	}

	errText := tview.NewTextView().SetDynamicColors(true)
	form := tview.NewForm()
	form.AddDropDown("Compose file on", sources, initial, nil)
	form.AddInputField("Compose file or folder", "", 52, nil, nil)
	sourceDD := form.GetFormItemByLabel("Compose file on").(*tview.DropDown)
	fileField := form.GetFormItemByLabel("Compose file or folder").(*tview.InputField)
	fileField.SetPlaceholderTextColor(tcell.ColorGray)
	cur := func() composeSource {
		i, _ := sourceDD.GetCurrentOption()
		if i < 0 || i >= len(srcs) {
			return srcs[0]
		}
		return srcs[i]
	}
	setPlaceholder := func() {
		if sc := cur(); sc.entry != nil {
			fileField.SetPlaceholder("Path on " + orDefault(sc.entry.Name, sc.entry.Host) + ", or Browse to find it…")
		} else {
			fileField.SetPlaceholder("Type a path, drop it here, or Browse…")
		}
	}
	last := initial
	sourceDD.SetSelectedFunc(func(_ string, i int) {
		if i >= 0 && i < len(srcs) && srcs[i].add {
			sourceDD.SetCurrentOption(last)
			if p.demo {
				errText.SetText("  [yellow]The demo has no other machines: on a real cluster this connects one over SSH.[-]")
				return
			}
			w.showMachineForm(func(host string) {
				w.pages.RemovePage("composeform")
				w.importComposeFrom(host)
			}, func() { w.pages.ShowPage("composeform"); w.app.SetFocus(form) })
			return
		}
		if i != last {
			fileField.SetText("")
		}
		last = i
		setPlaceholder()
	})
	setPlaceholder()

	showForm := func() {
		w.pages.SwitchToPage("cluster")
		w.pages.ShowPage("composeform")
		w.footer.SetText(" [aqua::b]TAB[-::-] Next field    [aqua::b]ENTER[-::-] Select    [aqua::b]ESC[-::-] Cancel")
		w.app.SetFocus(form)
	}
	closeForm := func() {
		w.pages.RemovePage("composeform")
		w.showCluster()
	}

	form.AddButton("Browse…", func() {
		sc := cur()
		if sc.entry == nil {
			if !pickerAvailable() {
				errText.SetText("  [yellow]No file picker here: type the path.[-]")
				return
			}
			errText.SetText("  [aqua]Opening the Windows file picker (it may open behind this window)…[-]")
			go func() {
				paths, err := pickPaths(false)
				w.app.QueueUpdateDraw(func() {
					errText.SetText("")
					if err != nil {
						errText.SetText("  [red]File picker: " + tview.Escape(err.Error()) + "[-]")
					} else if len(paths) > 0 {
						fileField.SetText(paths[0])
					}
				})
			}()
			return
		}
		target := *sc.entry
		if !sc.ready {
			errText.SetText("  [red]" + tview.Escape(target.Name) + " is off; choose a node that's on.[-]")
			return
		}
		errText.SetText("  [aqua]Connecting to " + tview.Escape(target.Name) + "…[-]")
		go func() {
			var fs nodeFS = demoFS{}
			var err error
			if !p.demo {
				fs, err = openSSHFS(target, []string{p.keyPath()})
			}
			w.app.QueueUpdateDraw(func() {
				if err != nil {
					errText.SetText("  [red]" + tview.Escape(err.Error()) + "[-]")
					return
				}
				errText.SetText("")
				start := strings.TrimSpace(fileField.GetText())
				if start != "" && !strings.HasSuffix(start, "/") {
					start = path.Dir(start)
				}
				openNodeBrowser(w.app, w.pages, w.footer,
					fmt.Sprintf("BROWSE  %s@%s  ·  pick the compose file (or ^P its folder)", target.User, target.Name),
					fs, start,
					func(picked string, _ bool) { fileField.SetText(picked); showForm() },
					showForm)
			})
		}()
	})
	form.AddButton("Import", func() {
		text := strings.TrimSpace(fileField.GetText())
		if sc := cur(); sc.entry != nil {
			switch {
			case !sc.ready:
				errText.SetText("  [red]" + tview.Escape(sc.entry.Name) + " is off; choose a node that's on.[-]")
			case !strings.HasPrefix(text, "/"):
				errText.SetText("  [red]Enter the full path on " + tview.Escape(orDefault(sc.entry.Name, sc.entry.Host)) + " (or use Browse).[-]")
			default:
				w.pages.RemovePage("composeform")
				w.launchComposeImport(text, sc.entry, sc.external)
			}
			return
		}
		file, err := findComposeFile(localPath(text))
		if err == nil && !p.demo {
			_, _, err = composeBundle(file) // validates the compose file here first
		}
		if err != nil && !p.demo {
			errText.SetText("  [red]" + tview.Escape(err.Error()) + "[-]")
			return
		}
		w.pages.RemovePage("composeform")
		w.launchComposeImport(file, nil, false)
	})
	form.AddButton("Cancel", closeForm)
	form.SetCancelFunc(closeForm)
	styleForm(form)
	form.SetBorder(false)

	panel := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(tview.NewTextView().SetDynamicColors(true).SetText(
			"\n  [yellow::b]Import a Docker Compose app[-::-]\n"+
				"  The compose file, its .env and small files it mounts go to "+tview.Escape(p.Host)+"\n"+
				"  for the import. Folders and files it mounts become Longhorn volumes. From a\n"+
				"  node or another machine (CasaOS: /var/lib/casaos/apps/<app>) their data is\n"+
				"  measured and copied in. [gray]Browse to search; Ctrl+F finds compose files.[-]"), 7, 0, false).
		AddItem(form, 0, 1, true).
		AddItem(errText, 1, 0, false)
	panel.SetBorder(true).SetTitle(" DOCKER COMPOSE ").SetTitleAlign(tview.AlignLeft)
	w.pages.AddPage("composeform", centered(panel, 84, 19), true, true)
	w.footer.SetText(" [aqua::b]TAB[-::-] Next field    [aqua::b]ENTER[-::-] Select    [aqua::b]ESC[-::-] Cancel")
	w.app.SetFocus(form)
}

// fetchComposeFromNode copies a compose file from a node, with the small
// files next to it (.env, config files it may mount), into a temporary
// folder here. Data folders stay on the node. Returns the local compose
// file and its folder on the node.
func fetchComposeFromNode(node hostEntry, keys []string, remote string) (local, remoteDir string, sizes, files map[string]int64, cleanup func(), err error) {
	fs, err := openSSHFS(node, keys)
	if err != nil {
		return "", "", nil, nil, nil, err
	}
	defer fs.Close()

	// A folder: the compose file in it.
	out, err := fs.run(`p=` + shellQuote(remote) + `; if [ -d "$p" ]; then for n in compose.yaml compose.yml docker-compose.yml docker-compose.yaml; do [ -f "$p/$n" ] && { echo "$p/$n"; exit 0; }; done; echo "no compose file in $p" >&2; exit 1; fi; [ -f "$p" ] && echo "$p"`)
	if err != nil {
		return "", "", nil, nil, nil, err
	}
	file := strings.TrimSpace(out)
	if file == "" {
		return "", "", nil, nil, nil, fmt.Errorf("%s not found on %s", remote, node.Name)
	}
	remoteDir = path.Dir(file)

	// Small files up to two levels down (configs, .env), not the data.
	tarData, err := fs.run("cd " + shellQuote(remoteDir) + " && find . -maxdepth 2 -type f -size -513k -print0 2>/dev/null | head -z -n 300 | tar --null --ignore-failed-read -T - -cf - 2>/dev/null")
	if err != nil && tarData == "" {
		return "", "", nil, nil, nil, fmt.Errorf("reading %s on %s: %v", remoteDir, node.Name, err)
	}
	tmp, err := os.MkdirTemp("", "kubestui-compose-")
	if err != nil {
		return "", "", nil, nil, nil, err
	}
	cleanup = func() { _ = os.RemoveAll(tmp) }
	if err := untarInto(tmp, strings.NewReader(tarData)); err != nil {
		cleanup()
		return "", "", nil, nil, nil, err
	}
	local = filepath.Join(tmp, path.Base(file))
	if !fileExists(local) {
		cleanup()
		return "", "", nil, nil, nil, fmt.Errorf("couldn't read %s on %s", file, node.Name)
	}

	// How much data each mounted folder holds there, so the import can
	// suggest volume sizes that fit (and not copy huge media folders).
	sizes, files = map[string]int64{}, map[string]int64{}
	if proj, err := loadCompose(local); err == nil {
		var folders []string
		for _, s := range proj.Services {
			for _, v := range s.Volumes {
				if v.Type != types.VolumeTypeBind || strings.HasPrefix(v.Source, "/dev/") {
					continue
				}
				src := filepath.ToSlash(v.Source)
				if !path.IsAbs(src) {
					src = path.Join(remoteDir, src)
				}
				folders = append(folders, src)
			}
		}
		if len(folders) > 0 {
			q := make([]string, len(folders))
			for i, f := range folders {
				q[i] = shellQuote(f)
			}
			// Folders (D) and files (F): a file needs its own volume.
			out, _ := fs.run("for f in " + strings.Join(q, " ") + `; do if [ -d "$f" ]; then printf 'D\t%s\t%s\n' "$(timeout 20 du -sb "$f" 2>/dev/null | cut -f1)" "$f"; elif [ -f "$f" ]; then printf 'F\t%s\t%s\n' "$(stat -c %s "$f" 2>/dev/null)" "$f"; fi; done; true`)
			for _, line := range strings.Split(out, "\n") {
				parts := strings.SplitN(line, "\t", 3)
				if len(parts) != 3 {
					continue
				}
				b, err := strconv.ParseInt(parts[1], 10, 64)
				if err != nil {
					continue
				}
				if parts[0] == "D" {
					sizes[parts[2]] = b
					continue
				}
				files[parts[2]] = b
				// A small file outside the compose folder comes along
				// (the ones inside already did).
				if f := parts[2]; b <= maxConfigBytes && path.IsAbs(f) && !strings.HasPrefix(f, remoteDir+"/") {
					if data, err := fs.run("base64 < " + shellQuote(f)); err == nil {
						if raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(data), "")); err == nil {
							dst := filepath.Join(tmp, hostCopyDir, filepath.FromSlash(strings.TrimPrefix(f, "/")))
							if os.MkdirAll(filepath.Dir(dst), 0o700) == nil {
								_ = os.WriteFile(dst, raw, 0o600)
							}
						}
					}
				}
			}
		}
	}
	return local, remoteDir, sizes, files, cleanup, nil
}

// untarInto extracts regular files and folders (nothing outside dir).
func untarInto(dir string, r io.Reader) error {
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		name := filepath.Clean(filepath.FromSlash(hdr.Name))
		if name == "." || strings.HasPrefix(name, "..") || filepath.IsAbs(name) {
			continue
		}
		target := filepath.Join(dir, name)
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o700); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
			if err != nil {
				return err
			}
			_, err = io.Copy(f, io.LimitReader(tr, hdr.Size))
			f.Close()
			if err != nil {
				return err
			}
		}
	}
}

// launchComposeImport runs the import on the control plane. from is the
// node the compose file is on (nil: this computer; file is local).
func (w *workstation) launchComposeImport(file string, from *hostEntry, external bool) {
	p := w.current
	name := filepath.Base(filepath.Dir(file))
	if from != nil {
		name = path.Base(path.Dir(file))
		if !strings.Contains(path.Base(file), ".") {
			name = path.Base(file) // a folder was given
		}
	}
	if p.demo {
		termPage.Open(termLaunch{
			title:  "DEMO · IMPORT DOCKER COMPOSE  ·  " + p.Name,
			target: fmt.Sprintf("%s@%s:%d  compose-import", p.User, p.Host, p.port()),
			okText: "DEPLOYED",
			demo:   demoComposeImport,
		}, w.showCluster)
		return
	}
	var fwd agent.Agent
	if external && from != nil {
		k, err := profileAgent(p)
		if err != nil {
			w.clusterNote.SetText("  [red]" + tview.Escape(err.Error()) + "[-]")
			return
		}
		fwd = k
	}
	termPage.Open(termLaunch{
		agent:      fwd,
		title:      fmt.Sprintf("IMPORT %s  ·  %s", strings.ToUpper(name), p.Name),
		target:     fmt.Sprintf("%s@%s:%d  compose-import", p.User, p.Host, p.port()),
		okText:     "DEPLOYED",
		sshConnect: w.dialer(p),
		prepare: func(client *ssh.Client) (string, error) {
			local, env := file, ""
			if from != nil {
				f, remoteDir, sizes, files, cleanup, err := fetchComposeFromNode(*from, []string{p.keyPath()}, file)
				if err != nil {
					return "", fmt.Errorf("getting the compose file from %s: %v", from.Name, err)
				}
				defer cleanup()
				local = f
				env = " COMPOSE_SOURCE_NODE=" + shellQuote(orDefault(from.Name, from.Host)) + " COMPOSE_SOURCE_DIR=" + shellQuote(remoteDir)
				if external {
					// The control plane copies the data straight from the
					// machine, with this computer's key forwarded for the
					// session (agent) and the host key seen here.
					hk := knownHostLines(from.Host, from.portOr22())
					if hk == "" {
						return "", fmt.Errorf("no saved host key for %s", from.Host)
					}
					env += " COMPOSE_SOURCE_EXTERNAL=" + shellQuote(from.User+"@"+from.Host) +
						" COMPOSE_SOURCE_PORT=" + strconv.Itoa(from.portOr22()) +
						" COMPOSE_SOURCE_HOSTKEY=" + shellQuote(hk) + ` SSH_AUTH_SOCK="$SSH_AUTH_SOCK"`
				}
				if js, err := json.Marshal(sizes); err == nil && len(sizes) > 0 {
					env += " COMPOSE_SOURCE_SIZES=" + shellQuote(string(js))
				}
				if js, err := json.Marshal(files); err == nil && len(files) > 0 {
					env += " COMPOSE_SOURCE_FILES=" + shellQuote(string(js))
				}
			}
			bundle, rels, err := composeBundle(local)
			if err != nil {
				return "", err
			}
			out, err := runRemote(client, `umask 077; mktemp -d /tmp/kubestui-compose.XXXXXX`, "")
			dir := strings.TrimSpace(out)
			if err != nil || !strings.HasPrefix(dir, "/tmp/kubestui-compose.") {
				return "", fmt.Errorf("could not stage the files on %s: %v", p.Host, err)
			}
			if _, err := runRemote(client, "tar -xf - -C "+shellQuote(dir), string(bundle)); err != nil {
				_, _ = runRemote(client, "rm -rf "+shellQuote(dir), "")
				return "", fmt.Errorf("upload failed: %v", err)
			}
			composePath := dir + "/" + filepath.ToSlash(rels[0])
			cmd := "env COMPOSE_FILE=" + shellQuote(composePath) + env +
				" bash " + shellQuote(p.HomelabRoot+"/install.sh") + " --run compose-import"
			if p.User != "root" {
				cmd = "sudo -p '[sudo] password for %u: ' " + cmd
			}
			// The uploaded copy (it may hold passwords from .env) is always removed.
			return cmd + "; rc=$?; rm -rf " + shellQuote(dir) + "; exit $rc", nil
		},
	}, w.showCluster)
}

// ---------------------------------------------------------------------------
// Other machines (SSH): a CasaOS or Docker box that isn't in the cluster
// ---------------------------------------------------------------------------

// Machines are saved per cluster (their key is the cluster's key).
func machinesPath(p *clusterProfile) string { return filepath.Join(p.dir, "machines.json") }

func loadMachines(p *clusterProfile) []hostEntry {
	var m []hostEntry
	if p == nil || p.dir == "" {
		return nil
	}
	if data, err := os.ReadFile(machinesPath(p)); err == nil {
		_ = json.Unmarshal(data, &m)
	}
	return m
}

func saveMachine(p *clusterProfile, e hostEntry) error {
	m := loadMachines(p)
	out := []hostEntry{e}
	for _, x := range m {
		if x.Host != e.Host {
			out = append(out, x)
		}
	}
	data, _ := json.MarshalIndent(out, "", "  ")
	if err := os.MkdirAll(p.dir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(machinesPath(p), data, 0o600)
}

// profileAgent holds the cluster's key for one import session (forwarded
// to the control plane so it can read the machine; gone after 6 hours or
// when the session ends).
func profileAgent(p *clusterProfile) (agent.Agent, error) {
	data, err := os.ReadFile(p.keyPath())
	if err != nil {
		return nil, fmt.Errorf("this cluster's SSH key: %v", err)
	}
	key, err := ssh.ParseRawPrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("this cluster's SSH key: %v", err)
	}
	k := agent.NewKeyring()
	if err := k.Add(agent.AddedKey{PrivateKey: key, Comment: "kubestui import", LifetimeSecs: 6 * 3600}); err != nil {
		return nil, err
	}
	return k, nil
}

// knownHostLines: the saved known_hosts lines for host:port (trusted on
// the first connection here), for the control plane to check it too.
func knownHostLines(host string, port int) string {
	want := knownhosts.Normalize(net.JoinHostPort(host, strconv.Itoa(port)))
	data, err := os.ReadFile(knownHostsPath())
	if err != nil {
		return ""
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || strings.HasPrefix(f[0], "#") {
			continue
		}
		for _, h := range strings.Split(f[0], ",") {
			if h == want {
				out = append(out, want+" "+f[1]+" "+f[2])
				break
			}
		}
	}
	return strings.Join(out, "\n")
}

// showMachineForm connects another machine: the password is used once to
// install this cluster's key there (it's never saved), then the machine is
// remembered. done gets its address; cancel goes back.
func (w *workstation) showMachineForm(done func(host string), cancel func()) {
	p := w.current
	errText := tview.NewTextView().SetDynamicColors(true)
	form := tview.NewForm().
		AddInputField("Name", "", 24, nil, nil).
		AddInputField("Address", "", 32, nil, nil).
		AddInputField("SSH port", "22", 6, tview.InputFieldInteger, nil).
		AddInputField("User", "", 24, nil, nil).
		AddPasswordField("Password", "", 32, '*', nil)
	get := func(label string) string {
		return strings.TrimSpace(form.GetFormItemByLabel(label).(*tview.InputField).GetText())
	}
	closeIt := func() { w.pages.RemovePage("machineform") }
	busy := false
	connect := func() {
		if busy {
			return
		}
		host, user := get("Address"), get("User")
		port, _ := strconv.Atoi(get("SSH port"))
		if port <= 0 {
			port = 22
		}
		pw := form.GetFormItemByLabel("Password").(*tview.InputField).GetText()
		if host == "" || user == "" {
			errText.SetText("  [red]Enter the address and the user.[-]")
			return
		}
		e := hostEntry{Name: orDefault(get("Name"), host), Host: host, User: user, Port: port, KeyLogin: true, Custom: true}
		busy = true
		errText.SetText("  [aqua]Connecting to " + tview.Escape(host) + "…[-]")
		go func() {
			err := installMachineKey(p, e, pw)
			if err == nil {
				err = saveMachine(p, e)
			}
			w.app.QueueUpdateDraw(func() {
				busy = false
				if err != nil {
					errText.SetText("  [red]" + tview.Escape(err.Error()) + "[-]")
					return
				}
				closeIt()
				done(host)
			})
		}()
	}
	form.AddButton("Connect", connect)
	form.AddButton("Cancel", func() { closeIt(); cancel() })
	form.SetCancelFunc(func() { closeIt(); cancel() })
	form.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		if ev.Key() == tcell.KeyEnter {
			if i, _ := form.GetFocusedItemIndex(); i == 4 { // the password
				connect()
				return nil
			}
		}
		return ev
	})
	styleForm(form)
	form.SetBorder(false)
	panel := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(tview.NewTextView().SetDynamicColors(true).SetText(
			"\n  [yellow::b]Another machine (SSH)[-::-]\n"+
				"  A CasaOS or Docker box that isn't in the cluster. The password is used\n"+
				"  once to install this cluster's SSH key there and is never saved; imports\n"+
				"  then read its apps and copy their data straight into the cluster.\n"+
				"  [gray]Use a user that can read the apps' folders (root, or one with sudo).[-]"), 7, 0, false).
		AddItem(form, 0, 1, true).
		AddItem(errText, 1, 0, false)
	panel.SetBorder(true).SetTitle(" OTHER MACHINE ").SetTitleAlign(tview.AlignLeft)
	w.pages.AddPage("machineform", centered(panel, 84, 21), true, true)
	w.app.SetFocus(form)
}

// installMachineKey logs in with the password (or a key that already
// works), authorizes this cluster's key and checks the key alone logs in.
func installMachineKey(p *clusterProfile, e hostEntry, password string) error {
	key := p.keyPath()
	pub, err := publicKeyLine(key)
	if err != nil {
		return fmt.Errorf("this cluster's SSH key: %v", err)
	}
	c, err := dialSSH(dialTarget{Host: e.Host, Port: e.Port, User: e.User, Keys: []string{key}, Password: password})
	if err != nil {
		return fmt.Errorf("can't log in to %s@%s: %v", e.User, e.Host, err)
	}
	err = authorizeKey(c, pub)
	c.Close()
	if err != nil {
		return fmt.Errorf("installing the key on %s: %v", e.Host, err)
	}
	c, err = dialSSH(dialTarget{Host: e.Host, Port: e.Port, User: e.User, Keys: []string{key}, OnlyKeys: true})
	if err != nil {
		return fmt.Errorf("the key was installed but doesn't log in to %s (is PubkeyAuthentication off?): %v", e.Host, err)
	}
	c.Close()
	return nil
}
