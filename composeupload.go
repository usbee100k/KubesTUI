package main

// Workstation side of "Import Docker Compose App": pick a compose file on
// this computer, upload it (with .env and small referenced files) to the
// control plane, and run the import there in the built-in terminal.

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/compose-spec/compose-go/v2/types"
	"github.com/gdamore/tcell/v2"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/rivo/tview"
	"golang.org/x/crypto/ssh"
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

func (w *workstation) importCompose() {
	p := w.current
	if !p.demo && p.HomelabRoot == "" {
		w.clusterNote.SetText("  [yellow]homelabCD wasn't found on " + tview.Escape(p.Host) + "; imports run there.[-]")
		return
	}

	// Where the compose file is: this computer, or one of the nodes (then
	// its data folders can come along into the new volumes).
	nodes, labels, ready := w.nodeChoices()
	sources := append([]string{"This computer"}, labels...)

	errText := tview.NewTextView().SetDynamicColors(true)
	form := tview.NewForm()
	form.AddDropDown("Compose file on", sources, 0, nil)
	form.AddInputField("Compose file or folder", "", 52, nil, nil)
	sourceDD := form.GetFormItemByLabel("Compose file on").(*tview.DropDown)
	fileField := form.GetFormItemByLabel("Compose file or folder").(*tview.InputField)
	fileField.SetPlaceholderTextColor(tcell.ColorGray)
	node := func() int { i, _ := sourceDD.GetCurrentOption(); return i - 1 } // -1: this computer
	setPlaceholder := func() {
		if n := node(); n >= 0 {
			fileField.SetPlaceholder("Path on " + nodes[n].Name + ", or Browse to find it…")
		} else {
			fileField.SetPlaceholder("Type a path, drop it here, or Browse…")
		}
	}
	sourceDD.SetSelectedFunc(func(string, int) { fileField.SetText(""); setPlaceholder() })
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
		n := node()
		if n < 0 {
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
		target := nodes[n]
		if !ready[n] {
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
		if n := node(); n >= 0 {
			switch {
			case !ready[n]:
				errText.SetText("  [red]" + tview.Escape(nodes[n].Name) + " is off; choose a node that's on.[-]")
			case !strings.HasPrefix(text, "/"):
				errText.SetText("  [red]Enter the full path on " + tview.Escape(nodes[n].Name) + " (or use Browse).[-]")
			default:
				w.pages.RemovePage("composeform")
				w.launchComposeImport(text, &nodes[n])
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
		w.launchComposeImport(file, nil)
	})
	form.AddButton("Cancel", closeForm)
	form.SetCancelFunc(closeForm)
	styleForm(form)
	form.SetBorder(false)

	panel := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(tview.NewTextView().SetDynamicColors(true).SetText(
			"\n  [yellow::b]Import a Docker Compose app[-::-]\n"+
				"  The compose file, its .env and small files it mounts go to "+tview.Escape(p.Host)+"\n"+
				"  for the import. Folders it mounts become Longhorn volumes; when the\n"+
				"  compose file is on a node, their data can be copied in (configs: ~1Gi).\n"+
				"  [gray]Browse a node to search its folders, or Ctrl+F to find compose files.[-]"), 7, 0, false).
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
func fetchComposeFromNode(node hostEntry, keys []string, remote string) (local, remoteDir string, sizes map[string]int64, cleanup func(), err error) {
	fs, err := openSSHFS(node, keys)
	if err != nil {
		return "", "", nil, nil, err
	}
	defer fs.Close()

	// A folder: the compose file in it.
	out, err := fs.run(`p=` + shellQuote(remote) + `; if [ -d "$p" ]; then for n in compose.yaml compose.yml docker-compose.yml docker-compose.yaml; do [ -f "$p/$n" ] && { echo "$p/$n"; exit 0; }; done; echo "no compose file in $p" >&2; exit 1; fi; [ -f "$p" ] && echo "$p"`)
	if err != nil {
		return "", "", nil, nil, err
	}
	file := strings.TrimSpace(out)
	if file == "" {
		return "", "", nil, nil, fmt.Errorf("%s not found on %s", remote, node.Name)
	}
	remoteDir = path.Dir(file)

	// Small files up to two levels down (configs, .env), not the data.
	tarData, err := fs.run("cd " + shellQuote(remoteDir) + " && find . -maxdepth 2 -type f -size -513k -print0 2>/dev/null | head -z -n 300 | tar --null --ignore-failed-read -T - -cf - 2>/dev/null")
	if err != nil && tarData == "" {
		return "", "", nil, nil, fmt.Errorf("reading %s on %s: %v", remoteDir, node.Name, err)
	}
	tmp, err := os.MkdirTemp("", "kubestui-compose-")
	if err != nil {
		return "", "", nil, nil, err
	}
	cleanup = func() { _ = os.RemoveAll(tmp) }
	if err := untarInto(tmp, strings.NewReader(tarData)); err != nil {
		cleanup()
		return "", "", nil, nil, err
	}
	local = filepath.Join(tmp, path.Base(file))
	if !fileExists(local) {
		cleanup()
		return "", "", nil, nil, fmt.Errorf("couldn't read %s on %s", file, node.Name)
	}

	// How much data each mounted folder holds there, so the import can
	// suggest volume sizes that fit (and not copy huge media folders).
	sizes = map[string]int64{}
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
			out, _ := fs.run("for f in " + strings.Join(q, " ") + `; do [ -d "$f" ] && printf '%s\t%s\n' "$(timeout 20 du -sb "$f" 2>/dev/null | cut -f1)" "$f"; done; true`)
			for _, line := range strings.Split(out, "\n") {
				if n, f, ok := strings.Cut(line, "\t"); ok {
					if b, err := strconv.ParseInt(n, 10, 64); err == nil {
						sizes[f] = b
					}
				}
			}
		}
	}
	return local, remoteDir, sizes, cleanup, nil
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
func (w *workstation) launchComposeImport(file string, from *hostEntry) {
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
	termPage.Open(termLaunch{
		title:      fmt.Sprintf("IMPORT %s  ·  %s", strings.ToUpper(name), p.Name),
		target:     fmt.Sprintf("%s@%s:%d  compose-import", p.User, p.Host, p.port()),
		okText:     "DEPLOYED",
		sshConnect: w.dialer(p),
		prepare: func(client *ssh.Client) (string, error) {
			local, env := file, ""
			if from != nil {
				f, remoteDir, sizes, cleanup, err := fetchComposeFromNode(*from, []string{p.keyPath()}, file)
				if err != nil {
					return "", fmt.Errorf("getting the compose file from %s: %v", from.Name, err)
				}
				defer cleanup()
				local = f
				env = " COMPOSE_SOURCE_NODE=" + shellQuote(from.Name) + " COMPOSE_SOURCE_DIR=" + shellQuote(remoteDir)
				if js, err := json.Marshal(sizes); err == nil && len(sizes) > 0 {
					env += " COMPOSE_SOURCE_SIZES=" + shellQuote(string(js))
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
