package main

// Opening Files from the workstation and from the node menu: which
// locations a pane can show, and how node-to-node copies reach kubectl.

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

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
func (w *workstation) openFiles() {
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
	isNode := func(name string) bool { _, ok := status[name]; return ok }
	if p.demo {
		kube = nil
	}

	openFileManager(w.app, w.pages, w.footer, locations, kube, isNode, func() {
		mu.Lock()
		if cp != nil {
			cp.Close()
		}
		mu.Unlock()
		w.showCluster()
	})
}

// openNodeFiles (node menu): this node and the other nodes, reached with
// this machine's SSH key (the SSH Console's K installs it); node-to-node
// copies run kubectl here.
func openNodeFiles(app *tview.Application, pages *tview.Pages, footer *tview.TextView, rows []nodeRow, back func()) {
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
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	isNode := func(name string) bool { _, ok := status[name]; return ok }
	openFileManager(app, pages, footer, locations, kube, isNode, back)
}
