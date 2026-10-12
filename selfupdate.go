package main

// "Update KubesTUI on This Computer" (workstation mode). The control plane
// keeps KubesTUI's sources current ("Update homelabCD and KubesTUI"), so it
// builds just this computer's binary from them over SSH (no sudo, one
// platform only), then KubesTUI copies it back and swaps it in. Restart
// KubesTUI to use it.

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/rivo/tview"
)

// remoteUpdateDir is where the control plane leaves the build, under the SSH
// user's home, one file per platform.
const remoteUpdateDir = "$HOME/.cache/kubestui-update"

func updateBinaryName() string {
	name := fmt.Sprintf("kubestui-%s-%s", runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return name
}

func selfPath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	return exe, nil
}

// cleanupOldBinary removes the copy a Windows update had to set aside (a
// running .exe can be renamed but not replaced).
func cleanupOldBinary() {
	if exe, err := selfPath(); err == nil {
		_ = os.Remove(exe + ".old")
	}
}

func (w *workstation) selfUpdate() {
	p := w.current
	if p.demo {
		w.clusterNote.SetText("  [black:yellow:b] DEMO [-:-:-] [gray] Updating needs a real cluster to build on.[-]")
		return
	}
	if p.HomelabRoot == "" {
		w.clusterNote.SetText("  [yellow]homelabCD wasn't found on " + tview.Escape(p.Host) + "; it holds the KubesTUI sources to build from.[-]")
		return
	}
	exe, err := selfPath()
	if err != nil {
		w.clusterNote.SetText("  [red]Can't find this program's file: " + tview.Escape(err.Error()) + "[-]")
		return
	}

	src := p.HomelabRoot + "/.src/KubesTUI"
	out := remoteUpdateDir + "/" + updateBinaryName()
	build := strings.Join([]string{
		"set -e",
		"export PATH=/usr/local/go/bin:$PATH",
		"src=" + shellQuote(src),
		`cd "$src"`,
		`v=$(git -c safe.directory="$src" describe --tags --always --dirty 2>/dev/null || echo dev)`,
		"mkdir -p " + remoteUpdateDir,
		fmt.Sprintf(`echo "Building KubesTUI $v for %s/%s on $(hostname) (a minute or two)..."`, runtime.GOOS, runtime.GOARCH),
		// The version comes from git describe above. Go's own VCS stamping
		// runs git without safe.directory and fails (exit 128) when the
		// sources belong to another user, e.g. root after an update.
		fmt.Sprintf(`CGO_ENABLED=0 GOOS=%s GOARCH=%s go build -trimpath -buildvcs=false -ldflags "-s -w -X main.version=$v" -o "%s.tmp" .`,
			runtime.GOOS, runtime.GOARCH, out),
		fmt.Sprintf(`mv "%s.tmp" "%s"`, out, out),
		fmt.Sprintf(`echo "$v" > "%s.version"`, out),
		`echo "Built $v."`,
	}, "\n")

	showConfirm("UPDATE KUBESTUI",
		fmt.Sprintf("Build the newest KubesTUI for this computer (%s/%s) on %s and install it over\n%s?\n\n"+
			"It builds from the sources on %s, so run \"Update homelabCD and KubesTUI\" first to get the latest.",
			runtime.GOOS, runtime.GOARCH, p.Host, exe, p.Host),
		"Update", "Cancel", func(ok bool) {
			if !ok {
				return
			}
			termPage.Open(termLaunch{
				title:      "UPDATE KUBESTUI ON THIS COMPUTER  ·  build on " + p.Name,
				target:     fmt.Sprintf("%s@%s:%d  %s/%s", p.User, p.Host, p.port(), runtime.GOOS, runtime.GOARCH),
				okText:     "BUILT",
				sshConnect: w.dialer(p),
				command:    build,
				onFinish: func(code int) {
					if code == 0 {
						w.pendingNote = "  [aqua]Copying the new KubesTUI from " + tview.Escape(p.Host) + "…[-]"
						go w.installUpdate(p, exe, out)
					}
				},
			}, w.showCluster)
		})
}

// installUpdate copies the built binary back over SSH and swaps it in.
func (w *workstation) installUpdate(p *clusterProfile, exe, remote string) {
	msg := func() string {
		client, err := w.dialer(p)()
		if err != nil {
			return "  [red]Update: SSH failed: " + tview.Escape(err.Error()) + "[-]"
		}
		defer client.Close()

		data, err := runRemote(client, fmt.Sprintf(`cat "%s"`, remote), "")
		if err != nil {
			return "  [red]Update: couldn't copy the build: " + tview.Escape(err.Error()) + "[-]"
		}
		ver, _ := runRemote(client, fmt.Sprintf(`cat "%s.version"`, remote), "")
		ver = strings.TrimSpace(ver)
		bin := []byte(data)

		if err := checkExecutable(bin); err != nil {
			return "  [red]Update: " + tview.Escape(err.Error()) + "; nothing was changed.[-]"
		}
		if cur, err := os.ReadFile(exe); err == nil && sha256.Sum256(cur) == sha256.Sum256(bin) {
			return "  [green]KubesTUI is already up to date (" + tview.Escape(version) + ").[-]"
		}
		if err := replaceExecutable(exe, bin); err != nil {
			return "  [red]Update: couldn't install over " + tview.Escape(exe) + ": " + tview.Escape(err.Error()) + "[-]"
		}
		return fmt.Sprintf("  [green]Updated KubesTUI %s → %s.[-] Press [aqua::b]Q[-::-] and start kubestui again to use it.",
			tview.Escape(version), tview.Escape(ver))
	}()

	w.app.QueueUpdateDraw(func() {
		if name, _ := w.pages.GetFrontPage(); name == "cluster" {
			w.pendingNote = ""
			w.clusterNote.SetText(msg)
		} else {
			w.pendingNote = msg
		}
	})
}

// checkExecutable rejects anything that isn't a program for this OS (an
// error message or truncated copy must never replace KubesTUI).
func checkExecutable(bin []byte) error {
	if len(bin) < 1<<20 {
		return fmt.Errorf("the build is too small (%d bytes)", len(bin))
	}
	var magic [][]byte
	switch runtime.GOOS {
	case "windows":
		magic = [][]byte{[]byte("MZ")}
	case "darwin":
		magic = [][]byte{{0xcf, 0xfa, 0xed, 0xfe}, {0xce, 0xfa, 0xed, 0xfe}}
	default:
		magic = [][]byte{{0x7f, 'E', 'L', 'F'}}
	}
	for _, m := range magic {
		if bytes.HasPrefix(bin, m) {
			return nil
		}
	}
	return fmt.Errorf("the build isn't a %s program", runtime.GOOS)
}

// replaceExecutable installs bin as exe. Windows can't overwrite a running
// .exe, but can rename it: the old copy is set aside as .old and removed the
// next time KubesTUI starts.
func replaceExecutable(exe string, bin []byte) error {
	mode := os.FileMode(0o755)
	if st, err := os.Stat(exe); err == nil {
		mode = st.Mode().Perm()
	}
	tmp := exe + ".new"
	if err := os.WriteFile(tmp, bin, mode); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		old := exe + ".old"
		_ = os.Remove(old)
		if err := os.Rename(exe, old); err != nil {
			_ = os.Remove(tmp)
			return err
		}
		if err := os.Rename(tmp, exe); err != nil {
			_ = os.Rename(old, exe) // put the working copy back
			_ = os.Remove(tmp)
			return err
		}
		return nil
	}
	if err := os.Rename(tmp, exe); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
