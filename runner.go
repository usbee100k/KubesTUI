package main

// In-TUI operation runner.
//
// Runs `install.sh --run <op>` on a pseudo-terminal and streams its output
// into a styled panel, so operations never leave KubesTUI. Because the
// script sees a real terminal, prompts, `sudo`, `ssh -t` and hidden password
// input keep working: typed lines are sent through the input bar, and the
// bar masks itself whenever the program turns terminal echo off.

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// tuiRunner is created in main and used by runOperation.
var tuiRunner *runner

const maxOutputLines = 5000

// ---------------------------------------------------------------------------
// Output buffer: turns a raw terminal byte stream into styled lines
// ---------------------------------------------------------------------------

// OSC sequences (window titles etc.), terminated by BEL or ESC \.
var oscPattern = regexp.MustCompile("\x1b\\][^\x07\x1b]*(\x07|\x1b\\\\)")

// Any escape sequence, for the plain-text copy of the output.
var ansiPattern = regexp.MustCompile("\x1b\\[[0-9;?]*[ -/]*[@-~]|\x1b[()][0-9A-Za-z]|\x1b[=>78DEHM]")

func plainLine(s string) string {
	return ansiPattern.ReplaceAllString(oscPattern.ReplaceAllString(s, ""), "")
}

type termBuffer struct {
	mu        sync.Mutex
	lines     []logLine // committed lines shown on screen
	base      int       // absolute number of lines[0] (cleared/trimmed count)
	style     tcell.Style
	styleSet  bool
	plain     []string // all output as plain text, for copy/save
	sshKey    string   // last public SSH key seen in the output
	cleared   bool     // the screen was cleared since the last render
	current   []rune   // raw text of the line being written
	crPending bool
	dirty     bool
}

// clearScreen is what `clear` (and the installer between steps) sends.
const clearScreen = "\x1b[2J"

func (b *termBuffer) write(p []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()

	// A screen clear starts a fresh view. The full output is still kept
	// in plain for copy all (Y) and save log (S).
	s := string(p)
	for {
		i := strings.Index(s, clearScreen)
		if i < 0 {
			break
		}
		b.writeLocked(s[:i])
		b.current = b.current[:0]
		b.crPending = false
		b.base += len(b.lines)
		b.lines = nil
		b.cleared = true
		s = s[i+len(clearScreen):]
	}
	b.writeLocked(s)
	b.dirty = true
}

func (b *termBuffer) writeLocked(s string) {
	for _, r := range s {
		if b.crPending {
			b.crPending = false
			if r != '\n' {
				// A bare carriage return redraws the line (progress bars).
				b.current = b.current[:0]
			}
		}
		switch r {
		case '\r':
			b.crPending = true
		case '\n':
			b.commitLocked()
		case '\b':
			if len(b.current) > 0 {
				b.current = b.current[:len(b.current)-1]
			}
		case '\a':
			// bell: ignore
		default:
			b.current = append(b.current, r)
		}
	}
}

func (b *termBuffer) commitLocked() {
	raw := string(b.current)
	var line logLine
	line, b.style = parseANSI(raw, b.curStyle())
	b.lines = append(b.lines, line)
	b.plain = append(b.plain, plainLine(raw))
	if k := sshPublicKey.FindString(b.plain[len(b.plain)-1]); k != "" {
		b.sshKey = strings.TrimSpace(k)
	}
	b.current = b.current[:0]
	if n := len(b.lines) - maxOutputLines; n > 0 {
		b.lines = b.lines[n:]
		b.base += n
	}
	if n := len(b.plain) - maxOutputLines; n > 0 {
		b.plain = b.plain[n:]
	}
}

func (b *termBuffer) curStyle() tcell.Style {
	if !b.styleSet {
		b.style, b.styleSet = baseLogStyle(), true
	}
	return b.style
}

// appendLine adds a line of KubesTUI's own (e.g. "-- Completed --").
func (b *termBuffer) appendLine(text string, st tcell.Style) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.current) > 0 {
		b.commitLocked()
	}
	b.lines = append(b.lines, styledLine(text, st))
	b.plain = append(b.plain, text)
	b.dirty = true
}

// lastSSHKey returns the most recent public SSH key printed, if any.
func (b *termBuffer) lastSSHKey() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.sshKey
}

// text returns the whole output as plain text.
func (b *termBuffer) text() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := strings.Join(b.plain, "\n")
	if len(b.current) > 0 {
		out += "\n" + plainLine(string(b.current))
	}
	return out + "\n"
}

// takeCleared reports (once) that the screen was cleared.
func (b *termBuffer) takeCleared() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	c := b.cleared
	b.cleared = false
	return c
}

// render returns the lines on screen (and the absolute number of the
// first) if they changed since the last call.
func (b *termBuffer) render() ([]logLine, int, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.dirty {
		return nil, 0, false
	}
	b.dirty = false
	lines := append([]logLine(nil), b.lines...)
	if len(b.current) > 0 {
		line, _ := parseANSI(string(b.current), b.curStyle())
		lines = append(lines, line)
	}
	return lines, b.base, true
}

// ---------------------------------------------------------------------------
// Runner screen
// ---------------------------------------------------------------------------

type runner struct {
	app    *tview.Application
	pages  *tview.Pages
	footer *tview.TextView
	onBack func(op operation)

	screen *tview.Flex
	body   *tview.Flex
	header *tview.TextView
	output *logView
	input  *tview.InputField

	mu        sync.Mutex
	op        operation
	running   bool
	masterFd  int
	master    *os.File
	buf       *termBuffer
	startedAt time.Time
	elapsed   time.Duration
	status    string // markup for the status badge
	notice    string // short message in the header ("Saved log to ...")
	shownKey  string // SSH key the user was told about
	pid       int    // session leader of the running operation
	gen       int    // increments per run, so a stale finish is ignored
	escs      closeKeys
	lastCols  int
	lastRows  int
	masked    bool
}

func newRunner(app *tview.Application, pages *tview.Pages, footer *tview.TextView, onBack func(op operation)) *runner {
	r := &runner{app: app, pages: pages, footer: footer, onBack: onBack}

	r.header = tview.NewTextView().SetDynamicColors(true)

	// Drag to select and copy; clicking while it runs goes to the input bar.
	r.output = newLogView(app)
	r.output.SetBorderPadding(0, 0, 2, 1)
	r.output.clickFocus = func() tview.Primitive {
		if r.running {
			return r.input
		}
		return r.output
	}
	r.output.onCopy = func(text string) {
		n := strings.Count(text, "\n") + 1
		r.copyText(text, fmt.Sprintf("%d line(s)", n))
	}

	r.input = tview.NewInputField().
		SetLabel("  INPUT > ").
		SetLabelColor(tcell.ColorAqua).
		SetFieldBackgroundColor(tcell.ColorDefault).
		SetFieldTextColor(tcell.ColorWhite)
	r.input.SetDoneFunc(func(key tcell.Key) {
		if key == tcell.KeyEnter {
			r.send(r.input.GetText() + "\n")
			r.input.SetText("")
		}
	})

	divider := tview.NewBox()
	divider.SetDrawFunc(func(screen tcell.Screen, x, y, width, height int) (int, int, int, int) {
		style := tcell.StyleDefault.Foreground(tcell.ColorGray)
		for i := x + 2; i < x+width-1; i++ {
			screen.SetContent(i, y, '-', nil, style)
		}
		return x, y, width, height
	})

	r.body = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(r.header, 3, 0, false).
		AddItem(divider, 1, 0, false).
		AddItem(r.output, 0, 1, false).
		AddItem(r.input, 1, 0, true)
	r.body.SetBorder(true).
		SetTitle(" HOMELAB KUBERNETES PLATFORM ").
		SetTitleAlign(tview.AlignLeft)

	// Click anywhere while it's running to type an answer: focus goes to
	// the input bar. (Clicks in the output select text and focus it too.)
	r.body.SetMouseCapture(func(action tview.MouseAction, event *tcell.EventMouse) (tview.MouseAction, *tcell.EventMouse) {
		x, y := event.Position()
		if r.running && !r.output.InRect(x, y) && (action == tview.MouseLeftDown || action == tview.MouseLeftClick) {
			r.app.SetFocus(r.input)
			return action, nil
		}
		return action, event
	})

	r.screen = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(r.body, 0, 1, true).
		AddItem(footer, 1, 0, false)

	return r
}

func (r *runner) footerText() string {
	key := ""
	if r.buf != nil && r.buf.lastSSHKey() != "" {
		key = "    [aqua::b]CTRL+K[-::-] Copy SSH key"
	}
	if r.running {
		return " [aqua::b]ENTER[-::-] Send input    [aqua::b]PGUP/PGDN[-::-] Scroll    [aqua::b]CTRL+Y[-::-] Copy all" + key + "    [aqua::b]CTRL+C[-::-] Interrupt    [aqua::b]ESC ESC ESC[-::-] Force stop"
	}
	return " [aqua::b]ESC[-::-] Back    [aqua::b]R[-::-] Run again    [aqua::b]PGUP/PGDN[-::-] Scroll    [aqua::b]Y[-::-] Copy all" + key + "    [aqua::b]S[-::-] Save log    [aqua::b]Q[-::-] Quit"
}

// sshPublicKey matches an OpenSSH public key line (e.g. a deploy key the
// bootstrap asks you to add to GitHub).
var sshPublicKey = regexp.MustCompile(`(?:ssh-(?:ed25519|rsa|dss)|ecdsa-sha2-nistp\d+|sk-(?:ssh-ed25519|ecdsa-sha2-nistp256)@openssh\.com) [A-Za-z0-9+/]{40,}={0,3}(?: [^\s]+)?`)

// copyText copies to the clipboard and reports it in the header.
func (r *runner) copyText(text, what string) {
	if copyToClipboard(text) {
		r.notice = "Copied " + what + " to the clipboard"
	} else {
		r.notice = "Clipboard unavailable; press S when finished to save the log"
	}
	r.header.SetText(r.headerText())
}

func (r *runner) headerText() string {
	install := installerPath()
	elapsed := r.elapsed
	if r.running {
		elapsed = time.Since(r.startedAt)
	}
	notice := ""
	if r.notice != "" {
		notice = "   [yellow]" + tview.Escape(r.notice) + "[-]"
	}
	return fmt.Sprintf(
		"\n  [yellow::b]%s[-::-]\n  %s   [gray]%s   $ %s --run %s[-]%s",
		tview.Escape(r.op.Title),
		r.status,
		formatElapsed(elapsed),
		tview.Escape(filepath.Base(install)),
		tview.Escape(r.op.Op),
		notice,
	)
}

func formatElapsed(d time.Duration) string {
	d = d.Round(time.Second)
	return fmt.Sprintf("%02d:%02d", int(d.Minutes()), int(d.Seconds())%60)
}

func (r *runner) send(s string) {
	r.mu.Lock()
	master, running := r.master, r.running
	r.mu.Unlock()
	if running && master != nil {
		_, _ = master.WriteString(s)
	}
}

// start launches op and switches to the runner screen. Called on the UI goroutine.
func (r *runner) start(op operation) {
	r.op = op
	r.notice = ""
	r.shownKey = ""
	r.buf = &termBuffer{}
	r.lastCols, r.lastRows = 0, 0
	r.masked = false
	r.input.SetText("").SetLabel("  INPUT > ").SetMaskCharacter(0)
	r.output.Reset()
	r.body.ResizeItem(r.input, 1, 0)

	r.pages.AddAndSwitchToPage("run", r.screen, true)

	install := installerPath()
	if install == "" {
		r.finishNow("[red::b]NOT STARTED[-::-]",
			"HOMELABCD_INSTALL is not set. Launch this TUI from homelabCD install.sh.")
		return
	}

	master, slave, err := openPTY()
	if err != nil {
		r.finishNow("[red::b]NOT STARTED[-::-]",
			"Could not open a terminal for the operation: "+err.Error())
		return
	}

	cmd := exec.Command("bash", install, "--run", op.Op)
	cmd.Env = append(os.Environ(), "TERM=xterm-256color", "KUBESTUI_EMBEDDED=1")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	// New session with the pty as controlling terminal, so Ctrl+C and
	// password prompts reading /dev/tty reach this operation.
	cmd.SysProcAttr = ptyProcAttr()

	r.setWinsize(int(master.Fd()), 120, 40)

	if err := cmd.Start(); err != nil {
		slave.Close()
		master.Close()
		r.finishNow("[red::b]NOT STARTED[-::-]",
			err.Error())
		return
	}
	slave.Close()

	r.gen++
	gen := r.gen
	r.pid = cmd.Process.Pid

	r.mu.Lock()
	r.master = master
	r.masterFd = int(master.Fd())
	r.running = true
	r.startedAt = time.Now()
	r.status = "[black:yellow:b] RUNNING [-:-:-]"
	r.mu.Unlock()

	r.header.SetText(r.headerText())
	r.footer.SetText(r.footerText())
	r.app.SetFocus(r.input)

	buf := r.buf
	readDone := make(chan struct{})

	go func() {
		defer close(readDone)
		chunk := make([]byte, 8192)
		for {
			n, err := master.Read(chunk)
			if n > 0 {
				buf.write(chunk[:n])
			}
			if err != nil {
				return
			}
		}
	}()

	stopTicker := make(chan struct{})
	go func() {
		t := time.NewTicker(100 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-stopTicker:
				return
			case <-t.C:
				r.app.QueueUpdateDraw(r.tick)
			}
		}
	}()

	go func() {
		waitErr := cmd.Wait()
		// Give the reader a moment to drain output written just before exit.
		select {
		case <-readDone:
		case <-time.After(500 * time.Millisecond):
		}
		master.Close()
		<-readDone
		close(stopTicker)

		code := 0
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			code = exitErr.ExitCode()
			// Killed by a signal: report it the way a shell does (128 + signal),
			// so Ctrl+C (SIGINT) shows as 130 / Interrupted.
			if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
				code = 128 + int(ws.Signal())
			}
		} else if waitErr != nil {
			code = -1
		}

		r.app.QueueUpdateDraw(func() {
			if r.gen == gen && r.running { // not already stopped by force
				r.finish(buf, code)
			}
		})
	}()
}

// tick refreshes output, header, input masking and terminal size. UI goroutine.
func (r *runner) tick() {
	if !r.running {
		return
	}

	if r.buf.takeCleared() {
		// The screen was cleared (new installer step): start at the top
		// and keep following.
		r.output.ScrollToEnd()
	}
	if lines, base, changed := r.buf.render(); changed {
		r.output.SetLines(lines, base)
	}

	// A public SSH key was printed (e.g. the GitHub deploy key): offer it.
	if k := r.buf.lastSSHKey(); k != "" && k != r.shownKey {
		r.shownKey = k
		r.notice = "SSH key shown: press Ctrl+K to copy it"
		r.footer.SetText(r.footerText())
	}

	r.header.SetText(r.headerText())

	// Mask the input bar while the program has echo off (passwords).
	if masked, ok := ptyEchoOff(r.masterFd); ok {
		if masked != r.masked {
			r.masked = masked
			if masked {
				r.input.SetLabel("  SECRET > ").SetMaskCharacter('*')
			} else {
				r.input.SetLabel("  INPUT > ").SetMaskCharacter(0)
			}
		}
	}

	_, _, w, h := r.output.GetInnerRect()
	r.setWinsize(r.masterFd, w, h)
}

func (r *runner) setWinsize(fd, cols, rows int) {
	if cols < 20 || rows < 5 || (cols == r.lastCols && rows == r.lastRows) {
		return
	}
	r.lastCols, r.lastRows = cols, rows
	ptySetSize(fd, cols, rows)
}

func (r *runner) finish(buf *termBuffer, code int) {
	r.mu.Lock()
	r.running = false
	r.master = nil
	r.elapsed = time.Since(r.startedAt)
	r.mu.Unlock()

	var line string
	st := baseLogStyle().Bold(true)
	switch {
	case code == 0:
		r.status = "[black:green:b] COMPLETED [-:-:-]"
		line = fmt.Sprintf("-- Completed in %s --", formatElapsed(r.elapsed))
		st = st.Foreground(tcell.ColorGreen)
	case code == 129 || code == 137: // hung up / killed (force stop)
		r.status = "[black:yellow:b] STOPPED [-:-:-]"
		if r.notice == "Stopping..." {
			r.notice = ""
		}
		line = "-- Stopped --"
		st = st.Foreground(tcell.ColorYellow)
	case code == 130:
		r.status = "[black:yellow:b] INTERRUPTED [-:-:-]"
		line = "-- Interrupted --"
		st = st.Foreground(tcell.ColorYellow)
	default:
		r.status = fmt.Sprintf("[white:red:b] FAILED (exit %d) [-:-:-]", code)
		line = fmt.Sprintf("-- Failed with exit code %d after %s --", code, formatElapsed(r.elapsed))
		st = st.Foreground(tcell.ColorRed)
	}

	buf.appendLine("", baseLogStyle())
	buf.appendLine(line, st)

	if lines, base, changed := buf.render(); changed {
		r.output.SetLines(lines, base)
	}

	r.header.SetText(r.headerText())
	r.body.ResizeItem(r.input, 0, 0)
	r.footer.SetText(r.footerText())
	r.app.SetFocus(r.output)
}

func (r *runner) finishNow(status, message string) {
	r.running = false
	r.status = status
	r.elapsed = 0
	r.buf.appendLine(message, baseLogStyle().Foreground(tcell.ColorRed))
	if lines, base, changed := r.buf.render(); changed {
		r.output.SetLines(lines, base)
	}
	r.header.SetText(r.headerText())
	r.body.ResizeItem(r.input, 0, 0)
	r.footer.SetText(r.footerText())
	r.app.SetFocus(r.output)
}

func (r *runner) scrollBy(delta int) { r.output.ScrollBy(delta) }

// forceStop ends a stuck operation: hang up (like closing the terminal),
// kill it 3 seconds later, and if even that doesn't end it, release the
// screen anyway. UI goroutine.
func (r *runner) forceStop() {
	if !r.running {
		return
	}
	gen, pid, buf := r.gen, r.pid, r.buf
	r.notice = "Stopping..."
	r.header.SetText(r.headerText())
	hangupSession(pid)

	later := func(d time.Duration, fn func()) {
		time.AfterFunc(d, func() {
			r.app.QueueUpdateDraw(func() {
				if r.gen == gen && r.running {
					fn()
				}
			})
		})
	}
	later(3*time.Second, func() {
		killSession(pid)
		r.mu.Lock()
		if r.master != nil {
			_ = r.master.Close()
		}
		r.mu.Unlock()
	})
	later(6*time.Second, func() {
		r.notice = "The operation did not respond; stopped waiting for it"
		r.finish(buf, 137)
	})
}

// handleKey is the runner page's input capture. UI goroutine.
func (r *runner) handleKey(ev *tcell.EventKey) *tcell.EventKey {
	_, _, _, h := r.output.GetInnerRect()
	page := h - 1
	if page < 1 {
		page = 1
	}

	// Ctrl+] or Esc Esc Esc force-stops a stuck operation.
	if triple := r.escs.press(ev); r.running && (triple || ev.Key() == tcell.KeyCtrlRightSq) {
		r.forceStop()
		return nil
	}

	switch ev.Key() {
	case tcell.KeyCtrlK:
		if k := r.buf.lastSSHKey(); k != "" {
			r.copyText(k, "the SSH key")
		}
		return nil
	case tcell.KeyCtrlY:
		text := r.buf.text()
		r.copyText(text, fmt.Sprintf("%d lines", strings.Count(text, "\n")))
		return nil
	case tcell.KeyCtrlC:
		if r.running {
			r.send("\x03")
		}
		return nil // never quit KubesTUI from this screen
	case tcell.KeyCtrlD:
		if r.running {
			r.send("\x04")
		}
		return nil
	case tcell.KeyPgUp:
		r.scrollBy(-page)
		return nil
	case tcell.KeyPgDn:
		r.scrollBy(page)
		return nil
	case tcell.KeyUp:
		r.scrollBy(-1)
		return nil
	case tcell.KeyDown:
		r.scrollBy(1)
		return nil
	case tcell.KeyHome:
		if !r.running {
			r.output.ScrollToBeginning()
			return nil
		}
	case tcell.KeyEnd:
		r.output.ScrollToEnd()
		return nil
	case tcell.KeyEscape:
		if !r.running {
			r.onBack(r.op)
		}
		return nil
	case tcell.KeyRune:
		if !r.running {
			switch ev.Rune() {
			case 'r', 'R':
				r.start(r.op)
				return nil
			case 'q', 'Q':
				r.app.Stop()
				return nil
			case 'y', 'Y':
				text := r.buf.text()
				if copyToClipboard(text) {
					r.notice = fmt.Sprintf("Copied %d lines to the clipboard", strings.Count(text, "\n"))
				} else {
					r.notice = "Clipboard unavailable; press S to save to a file"
				}
				r.header.SetText(r.headerText())
				return nil
			case 's', 'S':
				if path, err := saveLog(r.op.Op, r.buf.text()); err != nil {
					r.notice = "Could not save log: " + err.Error()
				} else {
					r.notice = "Saved log to " + shortPath(path)
				}
				r.header.SetText(r.headerText())
				return nil
			}
		}
	}
	return ev
}
