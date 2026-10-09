package main

// Embedded terminal widget.
//
// Runs a program on a pseudo-terminal and renders it with a VT100/xterm
// emulator (vt10x), so full-screen programs (htop, vim, less), colors,
// cursor movement and password prompts behave exactly as in a real
// terminal. Used for SSH sessions and remote joins.
//
// Scrollback: lines that scroll off the top are kept (maxScrollback) and can
// be viewed with Shift+PgUp/PgDn or the mouse wheel. Dragging with the mouse
// selects text and copies it to the clipboard on release.

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"golang.org/x/crypto/ssh"
	"homelab-tui/third_party/vt10x"
)

// Glyph mode bits, mirroring vt10x's unexported attr* constants.
const (
	vtAttrReverse   = 1 << 0
	vtAttrUnderline = 1 << 1
	vtAttrBold      = 1 << 2
	vtAttrItalic    = 1 << 4
	vtAttrBlink     = 1 << 5
)

type termView struct {
	*tview.Box

	app *tview.Application

	mu       sync.Mutex
	vt       vt10x.Terminal
	backend  termBackend
	cols     int
	rows     int
	running  bool
	exitCode int
	lost     atomic.Bool // the SSH connection stopped answering

	dirty  atomic.Bool
	stop   chan struct{}
	onExit func(code int)

	// Scrollback. history is guarded by histMu; it is appended to while the
	// emulator is locked, so always lock the emulator before histMu.
	histMu  sync.Mutex
	history [][]vt10x.Glyph
	added   atomic.Int64 // lines added since the last draw

	// UI goroutine only.
	scroll    int  // lines scrolled back from the live screen; 0 = live
	selecting bool // mouse button held
	hasSel    bool
	selA      cellPos
	selB      cellPos
	lastX     int          // mouse column during a drag
	drag      dragScroller // keeps scrolling while dragged past an edge

	onNotice       func(msg string) // short status messages ("Copied ...")
	onScrollChange func()
}

// cellPos is a position in the combined history+screen buffer.
type cellPos struct{ line, col int }

const maxScrollback = 10000

func (t *termView) pushHistory(line []vt10x.Glyph) {
	t.histMu.Lock()
	t.history = append(t.history, line)
	if len(t.history) > maxScrollback+500 {
		// Trim in batches so the backing array is reallocated rarely.
		t.history = append([][]vt10x.Glyph(nil), t.history[len(t.history)-maxScrollback:]...)
	}
	t.histMu.Unlock()
	t.added.Add(1)
}

func newTermView(app *tview.Application) *termView {
	t := &termView{
		Box:  tview.NewBox(),
		app:  app,
		cols: 100,
		rows: 30,
	}
	t.drag.app = app
	return t
}

// dragStep scrolls during a drag past an edge and extends the selection.
func (t *termView) dragStep(dir int) {
	if !t.selecting {
		t.drag.update(0, nil)
		return
	}
	t.ScrollBy(-dir) // scroll counts lines back from the live screen
	_, iy, _, h := t.GetInnerRect()
	y := iy
	if dir > 0 {
		y = iy + h - 1
	}
	t.selB = t.posAt(t.lastX, y)
	t.hasSel = t.selA != t.selB
}

// termBackend is where the terminal's keystrokes go and how it is resized:
// a local pseudo-terminal (Linux) or an SSH session (any platform).
type termBackend interface {
	io.Writer
	Resize(cols, rows int)
	Hangup()
	// Kill ends the session by force when Hangup wasn't enough.
	Kill()
}

type ptyBackend struct {
	master *os.File
	fd     int
	cmd    *exec.Cmd
}

func (p *ptyBackend) Write(b []byte) (int, error) { return p.master.Write(b) }
func (p *ptyBackend) Resize(cols, rows int)       { ptySetSize(p.fd, cols, rows) }
func (p *ptyBackend) Hangup() {
	if p.cmd.Process != nil {
		// Signal the whole session so ssh and its children all get SIGHUP.
		hangupSession(p.cmd.Process.Pid)
	}
}
func (p *ptyBackend) Kill() {
	if p.cmd.Process != nil {
		killSession(p.cmd.Process.Pid)
	}
	_ = p.master.Close()
}

type sshBackend struct {
	client  *ssh.Client
	session *ssh.Session
	stdin   io.WriteCloser
	keys    chan []byte // typed keys, written by sendKeys
	closed  chan struct{}
	once    sync.Once
}

// Write queues keys for the session. Writing happens on another goroutine,
// so a stalled connection can never freeze the UI.
func (s *sshBackend) Write(b []byte) (int, error) {
	c := append([]byte(nil), b...)
	select {
	case s.keys <- c:
	case <-s.closed:
	default: // the connection isn't taking input; drop rather than block
	}
	return len(b), nil
}

func (s *sshBackend) sendKeys() {
	for {
		select {
		case b := <-s.keys:
			if _, err := s.stdin.Write(b); err != nil {
				return
			}
		case <-s.closed:
			return
		}
	}
}

func (s *sshBackend) Resize(cols, rows int) {
	go func() { _ = s.session.WindowChange(rows, cols) }()
}

func (s *sshBackend) Hangup() {
	s.once.Do(func() { close(s.closed) })
	// Each step can stall on a dead connection; closing the client last
	// always ends the session.
	go func() {
		_ = s.session.Signal(ssh.SIGHUP)
		_ = s.session.Close()
	}()
	_ = s.client.Close()
}
func (s *sshBackend) Kill() { s.Hangup() }

// sshKeepalive closes client when the other side stops answering (device
// off, network gone), so a dead session ends instead of hanging forever.
// lost is set when that happens.
func sshKeepalive(client *ssh.Client, lost *atomic.Bool) {
	const every, misses = 10 * time.Second, 3
	go func() {
		failed := 0
		for {
			time.Sleep(every)
			reply := make(chan error, 1)
			go func() {
				_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
				reply <- err
			}()
			select {
			case err := <-reply:
				if err != nil {
					return // the client was closed
				}
				failed = 0
			case <-time.After(every):
				failed++
				if failed >= misses {
					lost.Store(true)
					_ = client.Close()
					return
				}
			}
		}
	}()
}

// begin resets the emulator for a new session writing replies to w.
func (t *termView) begin(w io.Writer, onExit func(code int)) vt10x.Terminal {
	vt := vt10x.New(
		vt10x.WithWriter(w),
		vt10x.WithSize(t.cols, t.rows),
		vt10x.WithScrollback(t.pushHistory),
	)

	t.mu.Lock()
	t.vt = vt
	t.running = true
	t.exitCode = 0
	t.onExit = onExit
	t.stop = make(chan struct{})
	t.mu.Unlock()

	t.histMu.Lock()
	t.history = nil
	t.histMu.Unlock()
	t.added.Store(0)
	t.scroll = 0
	t.hasSel = false
	return vt
}

// pump feeds output into the emulator, redraws, and reports the exit code
// from wait (which must return after the program ends).
func (t *termView) pump(vt vt10x.Terminal, out io.Reader, wait func() int, cleanup func()) {
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		br := bufio.NewReaderSize(out, 32*1024)
		for {
			if err := vt.Parse(br); err != nil {
				return
			}
			t.dirty.Store(true)
		}
	}()

	// Coalesce redraws: at most ~30 per second.
	stop := t.stop
	go func() {
		tick := time.NewTicker(33 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				if t.dirty.Swap(false) {
					t.app.QueueUpdateDraw(func() {})
				}
			}
		}
	}()

	go func() {
		code := wait()
		select {
		case <-readDone:
		case <-time.After(500 * time.Millisecond):
		}
		cleanup()
		<-readDone
		close(stop)
		t.dirty.Store(false)

		t.app.QueueUpdateDraw(func() {
			t.mu.Lock()
			t.running = false
			t.exitCode = code
			cb := t.onExit
			t.mu.Unlock()
			if cb != nil {
				cb(code)
			}
		})
	}()
}

// Start runs name/args on a new pseudo-terminal (Linux). extraFiles become
// fds 3+ in the child. onExit runs on the UI goroutine when it ends.
func (t *termView) Start(name string, args, env []string, extraFiles []*os.File, onExit func(code int)) error {
	master, slave, err := openPTY()
	if err != nil {
		return err
	}

	cmd := exec.Command(name, args...)
	cmd.Env = env
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	cmd.ExtraFiles = extraFiles
	cmd.SysProcAttr = ptyProcAttr()

	backend := &ptyBackend{master: master, fd: int(master.Fd()), cmd: cmd}
	backend.Resize(t.cols, t.rows)

	if err := cmd.Start(); err != nil {
		slave.Close()
		master.Close()
		return err
	}
	slave.Close()

	vt := t.begin(master, onExit)
	t.mu.Lock()
	t.backend = backend
	t.mu.Unlock()

	t.pump(vt, master, func() int {
		waitErr := cmd.Wait()
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
				return 128 + int(ws.Signal())
			}
			return exitErr.ExitCode()
		}
		if waitErr != nil {
			return -1
		}
		return 0
	}, func() { master.Close() })

	return nil
}

// signalNumbers maps SSH signal names to their usual numbers, for 128+N codes.
var signalNumbers = map[ssh.Signal]int{
	ssh.SIGHUP: 1, ssh.SIGINT: 2, ssh.SIGQUIT: 3, ssh.SIGKILL: 9,
	ssh.SIGPIPE: 13, ssh.SIGALRM: 14, ssh.SIGTERM: 15,
}

// StartSSH runs command (or a login shell if empty) in an SSH session with a
// remote pseudo-terminal. Works on every platform. The client is closed when
// the session ends.
func (t *termView) StartSSH(client *ssh.Client, command string, onExit func(code int)) error {
	session, err := client.NewSession()
	if err != nil {
		return err
	}

	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 38400,
		ssh.TTY_OP_OSPEED: 38400,
	}
	if err := session.RequestPty("xterm-256color", t.rows, t.cols, modes); err != nil {
		session.Close()
		return fmt.Errorf("remote terminal: %w", err)
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		session.Close()
		return err
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		session.Close()
		return err
	}

	if command == "" {
		err = session.Shell()
	} else {
		err = session.Start(command)
	}
	if err != nil {
		session.Close()
		return err
	}

	backend := &sshBackend{client: client, session: session, stdin: stdin,
		keys: make(chan []byte, 256), closed: make(chan struct{})}
	go backend.sendKeys()
	sshKeepalive(client, &t.lost)
	// The emulator's replies (cursor reports etc.) go through the same queue.
	vt := t.begin(backend, onExit)
	t.mu.Lock()
	t.backend = backend
	t.mu.Unlock()

	t.pump(vt, stdout, func() int {
		waitErr := session.Wait()
		var exitErr *ssh.ExitError
		switch {
		case waitErr == nil:
			return 0
		case errors.As(waitErr, &exitErr):
			if sig := ssh.Signal(exitErr.Signal()); sig != "" {
				if n, ok := signalNumbers[sig]; ok {
					return 128 + n
				}
			}
			return exitErr.ExitStatus()
		}
		return -1 // connection dropped without an exit status
	}, func() {
		session.Close()
		client.Close()
	})
	return nil
}

// StartDemo runs a simulated session (see demo.go): script writes output and
// reads keystrokes through dt. Works on every platform, no network.
func (t *termView) StartDemo(script func(dt *demoTerm) int, onExit func(code int)) {
	pr, pw := io.Pipe()
	backend := &demoBackend{keys: make(chan []byte, 256), done: make(chan struct{})}
	vt := t.begin(io.Discard, onExit)
	t.mu.Lock()
	t.backend = backend
	t.mu.Unlock()

	dt := &demoTerm{out: pw, b: backend, view: t}
	codeCh := make(chan int, 1)
	go func() {
		code := script(dt)
		pw.Close()
		codeCh <- code
	}()
	t.pump(vt, pr, func() int { return <-codeCh }, backend.Hangup)
}

func (t *termView) Running() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.running
}

// Send writes raw bytes to the program's terminal.
func (t *termView) Send(b []byte) {
	t.mu.Lock()
	backend, running := t.backend, t.running
	t.mu.Unlock()
	if running && backend != nil {
		_, _ = backend.Write(b)
	}
}

// Close hangs up the session (like closing a terminal window). If it is
// still running 3 seconds later it is killed.
func (t *termView) Close() {
	t.mu.Lock()
	backend, running := t.backend, t.running
	t.mu.Unlock()
	if !running || backend == nil {
		return
	}
	backend.Hangup()
	go func() {
		time.Sleep(3 * time.Second)
		if t.Running() {
			backend.Kill()
		}
	}()
}

// ConnectionLost reports whether the session ended because the SSH
// connection stopped answering.
func (t *termView) ConnectionLost() bool { return t.lost.Load() }

func vtColor(c vt10x.Color) tcell.Color {
	switch {
	case c == vt10x.DefaultFG || c == vt10x.DefaultBG || c == vt10x.DefaultCursor:
		return tcell.ColorDefault
	case c < 256:
		return tcell.PaletteColor(int(c))
	case c < 1<<24:
		return tcell.NewHexColor(int32(c))
	}
	return tcell.ColorDefault
}

func glyphStyle(g vt10x.Glyph) tcell.Style {
	fg, bg := g.FG, g.BG
	reverse := g.Mode&vtAttrReverse != 0
	if reverse {
		// vt10x already swapped the colors; undo that and let tcell reverse,
		// so reverse video also works on default-colored text.
		fg, bg = bg, fg
	}
	return tcell.StyleDefault.
		Foreground(vtColor(fg)).
		Background(vtColor(bg)).
		Reverse(reverse).
		Bold(g.Mode&vtAttrBold != 0).
		Underline(g.Mode&vtAttrUnderline != 0).
		Italic(g.Mode&vtAttrItalic != 0).
		Blink(g.Mode&vtAttrBlink != 0)
}

func (t *termView) Draw(screen tcell.Screen) {
	t.DrawForSubclass(screen, t)
	x, y, w, h := t.GetInnerRect()
	if w <= 0 || h <= 0 {
		return
	}

	t.mu.Lock()
	vt, running, backend := t.vt, t.running, t.backend
	if vt != nil && (w != t.cols || h != t.rows) {
		t.cols, t.rows = w, h
		vt.Resize(w, h)
		if running && backend != nil {
			backend.Resize(w, h)
		}
	}
	t.mu.Unlock()

	if vt == nil {
		return
	}

	vt.Lock()
	defer vt.Unlock()
	t.histMu.Lock()
	defer t.histMu.Unlock()

	hist := len(t.history)

	// Keep a scrolled-back view anchored while new output arrives.
	if added := int(t.added.Swap(0)); added > 0 && t.scroll > 0 {
		t.scroll += added
	}
	if t.scroll > hist {
		t.scroll = hist
	}

	cols, rows := vt.Size()
	top := hist - t.scroll // absolute line shown on the first row

	for row := 0; row < h; row++ {
		abs := top + row
		for col := 0; col < w; col++ {
			var g vt10x.Glyph
			switch {
			case abs < hist:
				if line := t.history[abs]; col < len(line) {
					g = line[col]
				} else {
					g = vt10x.Glyph{Char: ' ', FG: vt10x.DefaultFG, BG: vt10x.DefaultBG}
				}
			case abs-hist < rows && col < cols:
				g = vt.Cell(col, abs-hist)
			default:
				g = vt10x.Glyph{Char: ' ', FG: vt10x.DefaultFG, BG: vt10x.DefaultBG}
			}
			ch := g.Char
			if ch == 0 {
				ch = ' '
			}
			style := glyphStyle(g)
			if t.hasSel && t.inSelection(cellPos{abs, col}) {
				style = tcell.StyleDefault.Background(tcell.ColorAqua).Foreground(tcell.ColorBlack)
			}
			screen.SetContent(x+col, y+row, ch, nil, style)
		}
	}

	if t.scroll > 0 {
		badge := fmt.Sprintf(" ▲ SCROLLBACK  %d / %d lines ", t.scroll, hist)
		bx := x + w - utf8.RuneCountInString(badge) - 1
		if bx < x {
			bx = x
		}
		style := tcell.StyleDefault.Background(tcell.ColorYellow).Foreground(tcell.ColorBlack).Bold(true)
		for i, r := range []rune(badge) {
			screen.SetContent(bx+i, y, r, nil, style)
		}
		return
	}

	if running && t.HasFocus() && vt.CursorVisible() {
		c := vt.Cursor()
		if c.X < w && c.Y < h {
			screen.ShowCursor(x+c.X, y+c.Y)
		}
	}
}

// ---------------------------------------------------------------------------
// Scrolling
// ---------------------------------------------------------------------------

// Scrolled reports whether the view is showing scrollback.
func (t *termView) Scrolled() bool { return t.scroll > 0 }

// ScrollBy moves the view n lines back (positive) or forward (negative).
func (t *termView) ScrollBy(n int) {
	t.histMu.Lock()
	hist := len(t.history)
	t.histMu.Unlock()

	was := t.scroll
	t.scroll += n
	if t.scroll < 0 {
		t.scroll = 0
	}
	if t.scroll > hist {
		t.scroll = hist
	}
	if (was > 0) != (t.scroll > 0) && t.onScrollChange != nil {
		t.onScrollChange()
	}
}

func (t *termView) ScrollToTop()    { t.ScrollBy(1 << 30) }
func (t *termView) ScrollToBottom() { t.ScrollBy(-(1 << 30)) }

func (t *termView) PageSize() int {
	_, _, _, h := t.GetInnerRect()
	if h > 2 {
		return h - 1
	}
	return 1
}

// ---------------------------------------------------------------------------
// Selection and text
// ---------------------------------------------------------------------------

func (t *termView) ClearSelection() { t.hasSel, t.selecting = false, false }

func selOrder(a, b cellPos) (cellPos, cellPos) {
	if b.line < a.line || (b.line == a.line && b.col < a.col) {
		return b, a
	}
	return a, b
}

func (t *termView) inSelection(p cellPos) bool {
	a, b := selOrder(t.selA, t.selB)
	if p.line < a.line || p.line > b.line {
		return false
	}
	if p.line == a.line && p.col < a.col {
		return false
	}
	if p.line == b.line && p.col > b.col {
		return false
	}
	return true
}

// lineGlyphs returns the glyphs of an absolute line. Callers hold vt and histMu.
func (t *termView) lineGlyphs(vt vt10x.Terminal, abs int) []vt10x.Glyph {
	hist := len(t.history)
	if abs < hist {
		return t.history[abs]
	}
	cols, rows := vt.Size()
	r := abs - hist
	if r < 0 || r >= rows {
		return nil
	}
	out := make([]vt10x.Glyph, cols)
	for c := 0; c < cols; c++ {
		out[c] = vt.Cell(c, r)
	}
	return out
}

func glyphText(line []vt10x.Glyph, from, to int) string {
	var sb strings.Builder
	for c := from; c <= to && c < len(line); c++ {
		ch := line[c].Char
		if ch == 0 {
			ch = ' '
		}
		sb.WriteRune(ch)
	}
	return strings.TrimRight(sb.String(), " ")
}

func (t *termView) withBuffer(fn func(vt vt10x.Terminal)) {
	t.mu.Lock()
	vt := t.vt
	t.mu.Unlock()
	if vt == nil {
		return
	}
	vt.Lock()
	defer vt.Unlock()
	t.histMu.Lock()
	defer t.histMu.Unlock()
	fn(vt)
}

// SelectionText returns the selected text.
func (t *termView) SelectionText() string {
	var lines []string
	t.withBuffer(func(vt vt10x.Terminal) {
		a, b := selOrder(t.selA, t.selB)
		for l := a.line; l <= b.line; l++ {
			from, to := 0, 1<<30
			if l == a.line {
				from = a.col
			}
			if l == b.line {
				to = b.col
			}
			lines = append(lines, glyphText(t.lineGlyphs(vt, l), from, to))
		}
	})
	return strings.Join(lines, "\n")
}

// AllText returns the whole scrollback plus the screen, without trailing
// blank lines.
func (t *termView) AllText() string {
	var lines []string
	t.withBuffer(func(vt vt10x.Terminal) {
		_, rows := vt.Size()
		for l := 0; l < len(t.history)+rows; l++ {
			lines = append(lines, glyphText(t.lineGlyphs(vt, l), 0, 1<<30))
		}
	})
	for len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return strings.Join(lines, "\n") + "\n"
}

// posAt maps a screen point inside the view to a buffer position.
func (t *termView) posAt(x, y int) cellPos {
	ix, iy, w, h := t.GetInnerRect()
	col := min(max(x-ix, 0), w-1)
	row := min(max(y-iy, 0), h-1)
	t.histMu.Lock()
	hist := len(t.history)
	t.histMu.Unlock()
	return cellPos{line: hist - t.scroll + row, col: col}
}

func (t *termView) notice(msg string) {
	if t.onNotice != nil {
		t.onNotice(msg)
	}
}

// MouseHandler: wheel scrolls the scrollback; drag selects and copies.
func (t *termView) MouseHandler() func(action tview.MouseAction, event *tcell.EventMouse, setFocus func(p tview.Primitive)) (bool, tview.Primitive) {
	return t.WrapMouseHandler(func(action tview.MouseAction, event *tcell.EventMouse, setFocus func(p tview.Primitive)) (bool, tview.Primitive) {
		x, y := event.Position()
		inside := t.InRect(x, y)

		switch action {
		case tview.MouseScrollUp:
			if inside {
				t.ScrollBy(3)
				return true, nil
			}
		case tview.MouseScrollDown:
			if inside {
				t.ScrollBy(-3)
				return true, nil
			}
		case tview.MouseLeftDown:
			if inside {
				setFocus(t)
				p := t.posAt(x, y)
				t.selA, t.selB, t.lastX = p, p, x
				t.selecting, t.hasSel = true, false
				return true, t // capture the drag
			}
		case tview.MouseMove:
			if t.selecting {
				_, iy, _, h := t.GetInnerRect()
				dir := 0
				if y < iy {
					dir = -1 // above the top: scroll back
				} else if y >= iy+h {
					dir = 1
				}
				t.lastX = x
				t.drag.update(dir, t.dragStep)
				t.selB = t.posAt(x, y)
				t.hasSel = t.selA != t.selB
				return true, t
			}
		case tview.MouseLeftUp:
			if t.selecting {
				t.selecting = false
				t.drag.update(0, nil)
				if t.hasSel {
					text := t.SelectionText()
					n := strings.Count(text, "\n") + 1
					if copyToClipboard(text) {
						t.notice(fmt.Sprintf("Copied %d line(s) to the clipboard", n))
					} else {
						t.notice("Clipboard unavailable here; use S to save the log to a file")
					}
				}
				return true, nil
			}
		}
		return false, nil
	})
}

// keyBytes translates a key event into what a terminal would send.
func keyBytes(ev *tcell.EventKey, appCursor bool) []byte {
	alt := ev.Modifiers()&tcell.ModAlt != 0
	prefix := func(b []byte) []byte {
		if alt {
			return append([]byte{0x1b}, b...)
		}
		return b
	}

	cursor := func(final byte) []byte {
		if appCursor {
			return []byte{0x1b, 'O', final}
		}
		return []byte{0x1b, '[', final}
	}

	switch ev.Key() {
	case tcell.KeyRune:
		buf := make([]byte, utf8.UTFMax)
		n := utf8.EncodeRune(buf, ev.Rune())
		return prefix(buf[:n])
	case tcell.KeyEnter:
		return prefix([]byte{'\r'})
	case tcell.KeyTab:
		return []byte{'\t'}
	case tcell.KeyBacktab:
		return []byte("\x1b[Z")
	case tcell.KeyBackspace, tcell.KeyBackspace2:
		return prefix([]byte{0x7f})
	case tcell.KeyEscape:
		return []byte{0x1b}
	case tcell.KeyUp:
		return prefix(cursor('A'))
	case tcell.KeyDown:
		return prefix(cursor('B'))
	case tcell.KeyRight:
		return prefix(cursor('C'))
	case tcell.KeyLeft:
		return prefix(cursor('D'))
	case tcell.KeyHome:
		return prefix(cursor('H'))
	case tcell.KeyEnd:
		return prefix(cursor('F'))
	case tcell.KeyInsert:
		return []byte("\x1b[2~")
	case tcell.KeyDelete:
		return []byte("\x1b[3~")
	case tcell.KeyPgUp:
		return []byte("\x1b[5~")
	case tcell.KeyPgDn:
		return []byte("\x1b[6~")
	case tcell.KeyF1:
		return []byte("\x1bOP")
	case tcell.KeyF2:
		return []byte("\x1bOQ")
	case tcell.KeyF3:
		return []byte("\x1bOR")
	case tcell.KeyF4:
		return []byte("\x1bOS")
	case tcell.KeyF5:
		return []byte("\x1b[15~")
	case tcell.KeyF6:
		return []byte("\x1b[17~")
	case tcell.KeyF7:
		return []byte("\x1b[18~")
	case tcell.KeyF8:
		return []byte("\x1b[19~")
	case tcell.KeyF9:
		return []byte("\x1b[20~")
	case tcell.KeyF10:
		return []byte("\x1b[21~")
	case tcell.KeyF11:
		return []byte("\x1b[23~")
	case tcell.KeyF12:
		return []byte("\x1b[24~")
	}

	// tcell numbers Ctrl+Space .. Ctrl+_ from 64 upwards (KeyCtrlA is 65),
	// so subtracting KeyCtrlSpace gives the ASCII control code (Ctrl+C = 3).
	if k := ev.Key(); k >= tcell.KeyCtrlSpace && k <= tcell.KeyCtrlUnderscore {
		return prefix([]byte{byte(k - tcell.KeyCtrlSpace)})
	}
	// Raw control codes some terminals report directly.
	if k := ev.Key(); k < 32 {
		return prefix([]byte{byte(k)})
	}
	return nil
}

// HandleKey forwards a key to the program. Returns false if it was not sent.
func (t *termView) HandleKey(ev *tcell.EventKey) bool {
	t.mu.Lock()
	vt := t.vt
	t.mu.Unlock()
	appCursor := false
	if vt != nil {
		vt.Lock()
		appCursor = vt.Mode()&vt10x.ModeAppCursor != 0
		vt.Unlock()
	}
	b := keyBytes(ev, appCursor)
	if b == nil {
		return false
	}
	t.Send(b)
	return true
}

// PasteHandler forwards pasted text unchanged.
func (t *termView) PasteHandler() func(text string, setFocus func(p tview.Primitive)) {
	return t.WrapPasteHandler(func(text string, setFocus func(p tview.Primitive)) {
		t.Send([]byte(text))
	})
}
