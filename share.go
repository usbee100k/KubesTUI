package main

// "Share KubesTUI with a Workstation" (node mode): serves the KubesTUI
// builds for Windows/macOS/Linux and the one-line installers on the LAN for
// a limited time, under a random one-time path. Only the program is shared:
// cluster access is set up afterwards inside KubesTUI over SSH (pairing).

import (
	"context"
	"crypto/rand"
	"embed"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

//go:embed scripts/install.ps1 scripts/install.sh
var installScripts embed.FS

const (
	githubDownloadBase = "https://github.com/usbee100k/KubesTUI/releases/latest/download"
	shareDuration      = 15 * time.Minute
	sharePort          = 8765
)

type sharePage struct {
	app    *tview.Application
	pages  *tview.Pages
	footer *tview.TextView
	onBack func()

	screen *tview.Flex
	info   *tview.TextView
	log    *tview.TextView

	server  *http.Server
	expires time.Time
	stop    chan struct{}
	winCmd  string
	unixCmd string
	notice  string
}

var sharer *sharePage

func newSharePage(app *tview.Application, pages *tview.Pages, footer *tview.TextView, onBack func()) *sharePage {
	s := &sharePage{app: app, pages: pages, footer: footer, onBack: onBack}
	s.info = tview.NewTextView().SetDynamicColors(true).SetWrap(true)
	s.log = tview.NewTextView().SetDynamicColors(true).SetScrollable(true)
	s.log.SetBorder(true).SetTitle(" DOWNLOADS ").SetTitleAlign(tview.AlignLeft)

	body := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(s.info, 0, 3, false).
		AddItem(s.log, 0, 1, false)
	body.SetBorder(true).SetTitle(" SHARE KUBESTUI WITH A WORKSTATION ").SetTitleAlign(tview.AlignLeft)

	s.screen = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(body, 0, 1, true).
		AddItem(footer, 1, 0, false)
	return s
}

func distDir() string {
	return filepath.Join(os.Getenv("HOMELABCD_ROOT"), "bin", "dist")
}

// distReady reports whether workstation builds exist and are at least as new
// as this node's own KubesTUI binary.
func distReady() bool {
	sums, err := os.Stat(filepath.Join(distDir(), "SHA256SUMS"))
	if err != nil {
		return false
	}
	if self, err := os.Stat(filepath.Join(os.Getenv("HOMELABCD_ROOT"), "bin", "kubestui")); err == nil {
		return !sums.ModTime().Before(self.ModTime())
	}
	return true
}

// Start builds the workstation binaries if needed, then serves them.
func (s *sharePage) Start() {
	if os.Getenv("HOMELABCD_ROOT") == "" {
		s.showError("HOMELABCD_ROOT is not set. Launch KubesTUI with kbtui or install.sh.")
		return
	}
	if distReady() {
		s.serve()
		return
	}
	termPage.Open(termLaunch{
		title:  "BUILD KUBESTUI FOR WORKSTATIONS",
		target: "Windows · macOS · Linux  (amd64, arm64)",
		name:   "bash",
		args:   []string{installerPath(), "--run", "kubestui-dist"},
		env:    termEnv(),
		okText: "BUILT",
		onFinish: func(code int) {
			if code == 0 {
				s.serve()
			}
		},
	}, s.onBack)
}

func (s *sharePage) showError(msg string) {
	s.info.SetText("\n  [red]" + tview.Escape(msg) + "[-]")
	s.pages.AddAndSwitchToPage("share", s.screen, true)
	s.footer.SetText(" [aqua::b]ESC[-::-] Back")
}

// lanIP returns this node's LAN address.
func lanIP() string {
	if ip := strings.TrimSpace(os.Getenv("LOCAL_IP")); ip != "" {
		return ip
	}
	if c, err := net.Dial("udp", "1.1.1.1:80"); err == nil {
		defer c.Close()
		return c.LocalAddr().(*net.UDPAddr).IP.String()
	}
	return "127.0.0.1"
}

func randomCode(n int) string {
	const alphabet = "abcdefghjkmnpqrstuvwxyz23456789" // no look-alikes
	b := make([]byte, n)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}

func (s *sharePage) logLine(format string, args ...any) {
	line := fmt.Sprintf(format, args...)
	s.app.QueueUpdateDraw(func() {
		fmt.Fprintln(s.log, " "+line)
		s.log.ScrollToEnd()
	})
}

func (s *sharePage) serve() {
	s.Stop()

	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", sharePort))
	if err != nil {
		ln, err = net.Listen("tcp", ":0") // port taken: any free port
	}
	if err != nil {
		s.showError("Could not open a port: " + err.Error())
		return
	}
	port := ln.Addr().(*net.TCPAddr).Port
	code := randomCode(8)
	base := fmt.Sprintf("http://%s:%d/%s", lanIP(), port, code)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(rw http.ResponseWriter, r *http.Request) {
		name, ok := strings.CutPrefix(r.URL.Path, "/"+code+"/")
		status := http.StatusOK
		defer func() {
			if ok {
				s.logLine("[gray]%s[-]  %-15s  %s  %s", time.Now().Format("15:04:05"),
					strings.Split(r.RemoteAddr, ":")[0], tview.Escape(name), statusLabel(status))
			}
		}()
		if !ok || strings.Contains(name, "/") || strings.Contains(name, "..") {
			status = http.StatusNotFound
			http.NotFound(rw, r)
			return
		}
		switch {
		case name == "install.ps1" || name == "install.sh":
			data, _ := installScripts.ReadFile("scripts/" + name)
			text := strings.Replace(string(data), githubDownloadBase, base, 1)
			rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = rw.Write([]byte(text))
		case name == "SHA256SUMS" || strings.HasPrefix(name, "kubestui-"):
			path := filepath.Join(distDir(), name)
			if _, err := os.Stat(path); err != nil {
				status = http.StatusNotFound
				http.NotFound(rw, r)
				return
			}
			if name == "SHA256SUMS" {
				rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
			} else {
				rw.Header().Set("Content-Type", "application/octet-stream")
			}
			http.ServeFile(rw, r, path)
		default:
			status = http.StatusNotFound
			http.NotFound(rw, r)
		}
	})

	s.server = &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	s.expires = time.Now().Add(shareDuration)
	s.stop = make(chan struct{})
	s.winCmd = fmt.Sprintf("irm %s/install.ps1 | iex", base)
	s.unixCmd = fmt.Sprintf("curl -fsSL %s/install.sh | sh", base)
	s.notice = ""

	go func() { _ = s.server.Serve(ln) }()

	s.log.SetText("")
	s.pages.AddAndSwitchToPage("share", s.screen, true)
	s.footer.SetText(" [aqua::b]W[-::-] Copy Windows command    [aqua::b]M[-::-] Copy macOS/Linux command    [aqua::b]ESC[-::-] Stop sharing")
	s.render()

	stop := s.stop
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				s.app.QueueUpdateDraw(func() {
					if time.Now().After(s.expires) {
						s.Stop()
					}
					s.render()
				})
			}
		}
	}()
}

func statusLabel(code int) string {
	if code == http.StatusOK {
		return "[green]sent[-]"
	}
	return fmt.Sprintf("[red]%d[-]", code)
}

func (s *sharePage) render() {
	var state string
	if s.server != nil {
		left := time.Until(s.expires).Round(time.Second)
		state = fmt.Sprintf("[black:green:b] ● SHARING [-:-:-]  [gray]stops in %s[-]", formatElapsed(left))
	} else {
		state = "[black:gray:b] ■ STOPPED [-:-:-]  [gray]the link no longer works[-]"
	}
	notice := ""
	if s.notice != "" {
		notice = "\n  [yellow]" + tview.Escape(s.notice) + "[-]\n"
	}
	s.info.SetText(fmt.Sprintf(`
  %s
%s
  On the computer you want to control the cluster from, open a terminal and run:

  [yellow::b]Windows[-::-] (PowerShell)
    [white::b]%s[-::-]

  [yellow::b]macOS / Linux[-::-]
    [white::b]%s[-::-]

  It downloads KubesTUI for that computer, checks its SHA-256 checksum and
  installs it for the current user. Then run [aqua::b]kubestui[-::-] there and choose
  [aqua::b]Connect a new cluster[-::-]: enter this node's IP and your SSH login.

  [gray]Only the program is shared here (plain HTTP on your LAN, behind a one-time
  link). Cluster credentials are set up later over SSH, never through this link.
  Away from this network? Install from GitHub instead:
  irm https://raw.githubusercontent.com/usbee100k/KubesTUI/main/scripts/install.ps1 | iex[-]
`, state, notice, tview.Escape(s.winCmd), tview.Escape(s.unixCmd)))
}

// Stop shuts the server down; the link stops working immediately.
func (s *sharePage) Stop() {
	if s.stop != nil {
		close(s.stop)
		s.stop = nil
	}
	if s.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = s.server.Shutdown(ctx)
		cancel()
		s.server = nil
	}
}

// HandleKey is the input capture for the "share" page.
func (s *sharePage) HandleKey(ev *tcell.EventKey) *tcell.EventKey {
	switch ev.Key() {
	case tcell.KeyEscape:
		s.Stop()
		s.onBack()
		return nil
	case tcell.KeyRune:
		switch ev.Rune() {
		case 'w', 'W':
			if s.winCmd != "" && copyToClipboard(s.winCmd) {
				s.notice = "Copied the Windows command"
			}
		case 'm', 'M':
			if s.unixCmd != "" && copyToClipboard(s.unixCmd) {
				s.notice = "Copied the macOS/Linux command"
			}
		}
		s.render()
		return nil
	}
	return nil
}
