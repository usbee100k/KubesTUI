package main

// Workstation side of "Import Docker Compose App": pick a compose file on
// this computer, upload it (with .env and small referenced files) to the
// control plane, and run the import there in the built-in terminal.

import (
	"archive/tar"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
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

	errText := tview.NewTextView().SetDynamicColors(true)
	form := tview.NewForm().AddInputField("Compose file or folder", "", 52, nil, nil)
	closeForm := func() {
		w.pages.RemovePage("composeform")
		w.showCluster()
	}
	form.AddButton("Import", func() {
		file, err := findComposeFile(form.GetFormItem(0).(*tview.InputField).GetText())
		if err == nil && !p.demo {
			_, _, err = composeBundle(file) // validates the compose file here first
		}
		if err != nil && !p.demo {
			errText.SetText("  [red]" + tview.Escape(err.Error()) + "[-]")
			return
		}
		w.pages.RemovePage("composeform")
		w.launchComposeImport(file)
	})
	form.AddButton("Cancel", closeForm)
	form.SetCancelFunc(closeForm)
	styleForm(form)
	form.SetBorder(false)

	hint := `e.g. C:\docker\jellyfin   or   C:\docker\jellyfin\docker-compose.yml`
	if runtime.GOOS != "windows" {
		hint = "e.g. ~/docker/jellyfin   or   ~/docker/jellyfin/docker-compose.yml"
	}
	panel := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(tview.NewTextView().SetDynamicColors(true).SetText(
			"\n  [yellow::b]Import a Docker Compose app[-::-]\n"+
				"  The compose file, its .env and small files it mounts are uploaded to\n"+
				"  "+tview.Escape(p.Host)+" for the import, then deleted there. Folders it mounts\n"+
				"  become new Longhorn volumes (copy data over afterwards if needed).\n"+
				"  [gray]"+tview.Escape(hint)+"[-]"), 7, 0, false).
		AddItem(form, 0, 1, true).
		AddItem(errText, 1, 0, false)
	panel.SetBorder(true).SetTitle(" DOCKER COMPOSE ").SetTitleAlign(tview.AlignLeft)
	w.pages.AddPage("composeform", centered(panel, 80, 17), true, true)
	w.footer.SetText(" [aqua::b]ENTER[-::-] Import    [aqua::b]ESC[-::-] Cancel")
	w.app.SetFocus(form)
}

func (w *workstation) launchComposeImport(file string) {
	p := w.current
	name := filepath.Base(filepath.Dir(file))
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
			bundle, rels, err := composeBundle(file)
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
			cmd := "env COMPOSE_FILE=" + shellQuote(composePath) +
				" bash " + shellQuote(p.HomelabRoot+"/install.sh") + " --run compose-import"
			if p.User != "root" {
				cmd = "sudo -p '[sudo] password for %u: ' " + cmd
			}
			// The uploaded copy (it may hold passwords from .env) is always removed.
			return cmd + "; rc=$?; rm -rf " + shellQuote(dir) + "; exit $rc", nil
		},
	}, w.showCluster)
}
