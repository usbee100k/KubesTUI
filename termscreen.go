package main

// Framed full-screen page around a termView: a title bar with a live
// connection badge and timer, the terminal itself, and a key hint footer.
//
// Scrollback keys work at any time: Shift+PgUp/PgDn/Up/Down/Home/End or the
// mouse wheel. While scrolled back (or after the session ends) Y copies the
// whole log to the clipboard and S saves it to ~/kubestui-logs.

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"golang.org/x/crypto/ssh"
)

var termPage *termScreen

type termLaunch struct {
	title    string // frame title, e.g. "SSH  root@cp1"
	target   string // shown in the status bar
	name     string
	args     []string
	env      []string
	extra    func() ([]*os.File, error) // fresh fds per launch (pipes)
	okText   string                     // status text on exit 0
	onFinish func(code int)

	// SSH session instead of a local program (works on every platform):
	// sshConnect dials (it may prompt), then command runs (empty = shell).
	sshConnect func() (*ssh.Client, error)
	command    string
	// prepare, if set, runs on the new connection and returns the command
	// to run instead of command (e.g. after uploading a file).
	prepare func(client *ssh.Client) (string, error)

	// demo, if set, runs a simulated session instead (demo.go).
	demo func(dt *demoTerm) int
}

type termScreen struct {
	app    *tview.Application
	pages  *tview.Pages
	footer *tview.TextView

	screen *tview.Flex
	body   *tview.Flex
	status *tview.TextView
	tv     *termView

	launch     termLaunch
	onBack     func()
	startedAt  time.Time
	ended      bool
	endCode    int
	closed     bool // ended because the user closed it (Ctrl+] / Esc Esc Esc)
	connecting bool
	ticker     chan struct{}

	noticeText  string
	noticeUntil time.Time

	escs closeKeys // Esc Esc Esc closes the session
}

// closeKeys detects Esc pressed three times within a second: a way to
// close a session that works on every keyboard layout (Ctrl+] needs a
// "]" key, which many layouts only have behind AltGr).
type closeKeys struct {
	times [3]time.Time
	n     int
}

func (c *closeKeys) press(ev *tcell.EventKey) bool {
	if ev.Key() != tcell.KeyEscape {
		c.n = 0
		return false
	}
	now := time.Now()
	c.times[c.n%3] = now
	c.n++
	if c.n >= 3 && now.Sub(c.times[(c.n)%3]) < time.Second {
		c.n = 0
		return true
	}
	return false
}

func newTermScreen(app *tview.Application, pages *tview.Pages, footer *tview.TextView) *termScreen {
	s := &termScreen{app: app, pages: pages, footer: footer}

	s.status = tview.NewTextView().SetDynamicColors(true)
	s.tv = newTermView(app)

	s.body = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(s.status, 2, 0, false).
		AddItem(s.tv, 0, 1, true)
	s.body.SetBorder(true).SetTitleAlign(tview.AlignLeft)

	s.screen = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(s.body, 0, 1, true).
		AddItem(footer, 1, 0, false)

	return s
}

func (s *termScreen) statusText() string {
	elapsed := formatElapsed(time.Since(s.startedAt))
	if s.connecting {
		return fmt.Sprintf(" [black:yellow:b] ◌ CONNECTING [-:-:-]  [white::b]%s[-::-]   [gray]%s[-]",
			tview.Escape(s.launch.target), elapsed)
	}
	if !s.ended {
		return fmt.Sprintf(" [black:green:b] ● LIVE [-:-:-]  [white::b]%s[-::-]   [gray]%s[-]",
			tview.Escape(s.launch.target), elapsed)
	}
	if s.tv.ConnectionLost() {
		return fmt.Sprintf(" [white:red:b] ✗ CONNECTION LOST [-:-:-]  [white::b]%s[-::-]   [gray]no reply for 30s; the device is off or unreachable[-]",
			tview.Escape(s.launch.target))
	}
	if s.closed {
		return fmt.Sprintf(" [black:gray:b] ■ CLOSED [-:-:-]  [white::b]%s[-::-]   [gray]%s[-]",
			tview.Escape(s.launch.target), elapsed)
	}
	if s.endCode == 0 {
		text := s.launch.okText
		if text == "" {
			text = "SESSION ENDED"
		}
		return fmt.Sprintf(" [black:green:b] ✓ %s [-:-:-]  [white::b]%s[-::-]   [gray]%s[-]",
			text, tview.Escape(s.launch.target), elapsed)
	}
	return fmt.Sprintf(" [white:red:b] ✗ ENDED (exit %d) [-:-:-]  [white::b]%s[-::-]   [gray]%s[-]",
		s.endCode, tview.Escape(s.launch.target), elapsed)
}

func (s *termScreen) footerText() string {
	switch {
	case s.tv.Scrolled():
		return " [aqua::b]SHIFT+PGUP/PGDN[-::-] Scroll    [aqua::b]Y[-::-] Copy all    [aqua::b]S[-::-] Save log    [aqua::b]ESC[-::-] Back to live"
	case s.connecting:
		return " [aqua::b]ESC[-::-] Cancel"
	case !s.ended:
		return " [aqua::b]CTRL+][-::-] or [aqua::b]ESC ESC ESC[-::-] Close    [aqua::b]SHIFT+PGUP[-::-] Scrollback    [aqua::b]DRAG[-::-] Copy    [gray]Other keys go to the terminal[-]"
	}
	return " [aqua::b]ESC/ENTER[-::-] Back    [aqua::b]R[-::-] Run again    [aqua::b]SHIFT+PGUP[-::-] Scroll    [aqua::b]Y[-::-] Copy all    [aqua::b]S[-::-] Save log"
}

// refresh redraws the status bar (with any current notice) and footer.
func (s *termScreen) refresh() {
	text := s.statusText()
	if s.noticeText != "" && time.Now().Before(s.noticeUntil) {
		text += "\n [yellow]" + tview.Escape(s.noticeText) + "[-]"
	}
	s.status.SetText(text)
	s.footer.SetText(s.footerText())
}

func (s *termScreen) notify(msg string) {
	s.noticeText = msg
	s.noticeUntil = time.Now().Add(6 * time.Second)
	s.refresh()
	go func() {
		time.Sleep(6*time.Second + 100*time.Millisecond)
		s.app.QueueUpdateDraw(s.refresh)
	}()
}

func (s *termScreen) copyAll() {
	text := s.tv.AllText()
	n := strings.Count(text, "\n")
	if copyToClipboard(text) {
		s.notify(fmt.Sprintf("Copied %d lines to the clipboard", n))
	} else {
		s.notify("Clipboard unavailable here; press S to save the log to a file")
	}
}

func (s *termScreen) saveAll() {
	path, err := saveLog(s.launch.title, s.tv.AllText())
	if err != nil {
		s.notify("Could not save log: " + err.Error())
		return
	}
	s.notify("Saved log to " + shortPath(path))
}

// handleScrollKey handles Shift+navigation keys. Returns true if consumed.
func (s *termScreen) handleScrollKey(ev *tcell.EventKey) bool {
	if ev.Modifiers()&tcell.ModShift == 0 {
		return false
	}
	switch ev.Key() {
	case tcell.KeyPgUp:
		s.tv.ScrollBy(s.tv.PageSize())
	case tcell.KeyPgDn:
		s.tv.ScrollBy(-s.tv.PageSize())
	case tcell.KeyUp:
		s.tv.ScrollBy(1)
	case tcell.KeyDown:
		s.tv.ScrollBy(-1)
	case tcell.KeyHome:
		s.tv.ScrollToTop()
	case tcell.KeyEnd:
		s.tv.ScrollToBottom()
	default:
		return false
	}
	return true
}

// Open shows the screen and starts l. onBack runs when the user leaves.
func (s *termScreen) Open(l termLaunch, onBack func()) {
	s.launch = l
	s.onBack = onBack
	s.ended = false
	s.endCode = 0
	s.closed = false
	s.connecting = false
	s.startedAt = time.Now()

	// A fresh emulator per session, so old output never lingers.
	tv := newTermView(s.app)
	s.body.RemoveItem(s.tv)
	s.tv = tv
	s.body.AddItem(s.tv, 0, 1, true)
	s.body.SetTitle(" " + l.title + " ")
	tv.onNotice = s.notify
	tv.onScrollChange = func() { s.footer.SetText(s.footerText()) }
	s.noticeText = ""

	s.pages.AddAndSwitchToPage("term", s.screen, true)

	var extra []*os.File
	if l.extra != nil {
		files, err := l.extra()
		if err != nil {
			s.fail("Could not prepare session: " + err.Error())
			return
		}
		extra = files
	}

	onExit := func(code int) {
		if s.tv != tv || s.ended {
			return // replaced by a newer session, or already closed by force
		}
		s.ended = true
		s.endCode = code
		if s.noticeText == "Closing..." {
			s.noticeText = ""
		}
		s.stopTicker()
		s.refresh()
		if l.onFinish != nil {
			l.onFinish(code)
		}
	}

	if l.demo != nil {
		tv.StartDemo(l.demo, onExit)
	} else if l.sshConnect != nil {
		s.connecting = true
		go func() {
			client, err := l.sshConnect()
			command := l.command
			if err == nil && l.prepare != nil {
				command, err = l.prepare(client)
				if err != nil {
					client.Close()
					client = nil
				}
			}
			s.app.QueueUpdateDraw(func() {
				if s.tv != tv || !s.connecting {
					// Cancelled or replaced while connecting.
					if client != nil {
						client.Close()
					}
					return
				}
				s.connecting = false
				if err == nil {
					err = tv.StartSSH(client, command, onExit)
					if err != nil {
						client.Close()
					}
				}
				if err != nil {
					s.fail("Connection failed: " + err.Error())
					return
				}
				s.refresh()
			})
		}()
	} else {
		err := tv.Start(l.name, l.args, l.env, extra, onExit)
		for _, f := range extra {
			f.Close() // the child has its own copies now
		}
		if err != nil {
			s.fail("Could not start " + l.name + ": " + err.Error())
			return
		}
	}

	s.refresh()
	s.app.SetFocus(s.tv)

	// Keep the timer moving.
	stop := make(chan struct{})
	s.ticker = stop
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				s.app.QueueUpdateDraw(func() {
					if !s.ended {
						s.refresh()
					}
				})
			}
		}
	}()
}

// closeSession hangs up the session. If it still hasn't ended after 6
// seconds (a stuck process or connection), the screen is released anyway.
func (s *termScreen) closeSession() {
	s.closed = true
	s.notify("Closing...")
	tv := s.tv
	tv.Close()
	go func() {
		time.Sleep(6 * time.Second)
		s.app.QueueUpdateDraw(func() {
			if s.tv == tv && !s.ended {
				s.ended, s.endCode = true, -1
				s.stopTicker()
				s.notify("The session did not respond; closed it anyway")
				if s.launch.onFinish != nil {
					s.launch.onFinish(-1)
				}
			}
		})
	}()
}

func (s *termScreen) stopTicker() {
	if s.ticker != nil {
		close(s.ticker)
		s.ticker = nil
	}
}

func (s *termScreen) fail(msg string) {
	s.ended = true
	s.endCode = -1
	s.connecting = false
	s.stopTicker()
	s.status.SetText(s.statusText() + "\n [red]" + tview.Escape(msg) + "[-]")
	s.footer.SetText(s.footerText())
}

// HandleKey is the input capture for the "term" page.
func (s *termScreen) HandleKey(ev *tcell.EventKey) *tcell.EventKey {
	if s.connecting {
		if ev.Key() == tcell.KeyEscape || ev.Key() == tcell.KeyCtrlRightSq {
			s.connecting = false
			s.stopTicker()
			if s.onBack != nil {
				s.onBack()
			}
		}
		return nil
	}

	if s.handleScrollKey(ev) {
		return nil
	}

	// Any key clears a mouse selection highlight.
	s.tv.ClearSelection()

	// Scrollback mode: a few keys act on the log instead of the session.
	if s.tv.Scrolled() {
		switch {
		case ev.Key() == tcell.KeyEscape:
			s.tv.ScrollToBottom()
			return nil
		case ev.Key() == tcell.KeyRune && (ev.Rune() == 'y' || ev.Rune() == 'Y'):
			s.copyAll()
			return nil
		case ev.Key() == tcell.KeyRune && (ev.Rune() == 's' || ev.Rune() == 'S'):
			s.saveAll()
			return nil
		}
		// Anything else returns to the live screen and is handled normally.
		s.tv.ScrollToBottom()
	}

	if !s.ended {
		// Ctrl+] (like telnet) never reaches the session. Esc Esc Esc
		// closes it too (the Escs are still sent, for vim and friends).
		triple := s.escs.press(ev)
		if ev.Key() == tcell.KeyCtrlRightSq || triple {
			s.closeSession()
			return nil
		}
		s.tv.HandleKey(ev)
		return nil // every key belongs to the session, including Ctrl+C and q
	}

	switch ev.Key() {
	case tcell.KeyEscape, tcell.KeyEnter:
		if s.onBack != nil {
			s.onBack()
		}
		return nil
	case tcell.KeyRune:
		switch ev.Rune() {
		case 'r', 'R':
			s.Open(s.launch, s.onBack)
		case 'y', 'Y':
			s.copyAll()
		case 's', 'S':
			s.saveAll()
		}
	}
	return nil
}

// lastCtrlQ is when Ctrl+Q was last pressed (see emergencyQuit).
var lastCtrlQ time.Time

// emergencyQuit quits KubesTUI from any screen when Ctrl+Q is pressed twice
// within 1.5 seconds, even in the middle of a session or an operation
// (the first press still goes where it normally would). Running sessions
// and operations are ended first.
func emergencyQuit(app *tview.Application, ev *tcell.EventKey) bool {
	if ev.Key() != tcell.KeyCtrlQ {
		return false
	}
	now := time.Now()
	if now.Sub(lastCtrlQ) > 1500*time.Millisecond {
		lastCtrlQ = now
		return false
	}
	if tuiRunner != nil && tuiRunner.running {
		// Hang up, then make sure nothing is left running in the background.
		hangupSession(tuiRunner.pid)
		time.Sleep(500 * time.Millisecond)
		killSession(tuiRunner.pid)
	}
	if termPage != nil && termPage.tv != nil {
		termPage.tv.Close()
	}
	// Restoring the terminal can block if it is gone; never wait forever.
	time.AfterFunc(3*time.Second, func() { os.Exit(1) })
	app.Stop()
	return true
}
