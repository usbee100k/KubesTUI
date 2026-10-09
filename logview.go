package main

// Operation output panel.
//
// Shows the colored output of an operation, wrapped to the panel width,
// and lets you select text with the mouse like a terminal: drag to select
// (no Shift needed), and the selection is copied to the clipboard when the
// button is released. Dragging past the top or bottom edge keeps scrolling
// while the button is held. The mouse wheel scrolls.

import (
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"github.com/rivo/uniseg"
)

// ---------------------------------------------------------------------------
// Styled lines (ANSI escape sequences parsed into cells)
// ---------------------------------------------------------------------------

type logCell struct {
	r  rune
	w  int // display width: 1, or 2 for wide characters
	st tcell.Style
}

type logLine []logCell

// baseLogStyle is plain output text, the same as a tview TextView's.
func baseLogStyle() tcell.Style {
	return tcell.StyleDefault.
		Foreground(tview.Styles.PrimaryTextColor).
		Background(tview.Styles.PrimitiveBackgroundColor)
}

// parseANSI turns raw terminal text into cells. Colors and attributes
// carry over from st (they persist across lines in a terminal); the style
// at the end of the text is returned.
func parseANSI(raw string, st tcell.Style) (logLine, tcell.Style) {
	var out logLine
	col := 0
	rs := []rune(raw)
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		switch {
		case r == 0x1b && i+1 < len(rs):
			i++
			switch rs[i] {
			case '[': // CSI: parameters, then a final byte
				j := i + 1
				for j < len(rs) && (rs[j] < 0x40 || rs[j] > 0x7e) {
					j++
				}
				if j < len(rs) && rs[j] == 'm' {
					st = applySGR(st, string(rs[i+1:j]))
				}
				i = j
			case ']': // OSC (window title etc.): up to BEL or ESC \
				j := i + 1
				for j < len(rs) && rs[j] != 0x07 && !(rs[j] == 0x1b && j+1 < len(rs) && rs[j+1] == '\\') {
					j++
				}
				if j < len(rs) && rs[j] == 0x1b {
					j++
				}
				i = j
			case '(', ')': // character set selection
				i++
			}
		case r == '\t':
			for n := 8 - col%8; n > 0; n-- {
				out = append(out, logCell{' ', 1, st})
				col++
			}
		case r < 0x20 || r == 0x7f:
			// other control characters: nothing to show
		default:
			w := uniseg.StringWidth(string(r))
			if w <= 0 {
				continue // combining marks etc.
			}
			out = append(out, logCell{r, w, st})
			col += w
		}
	}
	return out, st
}

// applySGR applies "Select Graphic Rendition" parameters (colors, bold...).
func applySGR(st tcell.Style, params string) tcell.Style {
	if params == "" {
		return baseLogStyle()
	}
	var p []int
	for _, f := range strings.FieldsFunc(params, func(r rune) bool { return r == ';' || r == ':' }) {
		n, _ := strconv.Atoi(f)
		p = append(p, n)
	}
	// extended reads a 38/48 color: 5;n or 2;r;g;b.
	extended := func(i int) (tcell.Color, int) {
		if i+1 < len(p) && p[i+1] == 5 && i+2 < len(p) {
			return tcell.PaletteColor(p[i+2]), i + 2
		}
		if i+1 < len(p) && p[i+1] == 2 && i+4 < len(p) {
			return tcell.NewRGBColor(int32(p[i+2]), int32(p[i+3]), int32(p[i+4])), i + 4
		}
		return tcell.ColorDefault, len(p)
	}
	for i := 0; i < len(p); i++ {
		n := p[i]
		switch {
		case n == 0:
			st = baseLogStyle()
		case n == 1:
			st = st.Bold(true)
		case n == 2:
			st = st.Dim(true)
		case n == 3:
			st = st.Italic(true)
		case n == 4:
			st = st.Underline(true)
		case n == 7:
			st = st.Reverse(true)
		case n == 22:
			st = st.Bold(false).Dim(false)
		case n == 23:
			st = st.Italic(false)
		case n == 24:
			st = st.Underline(false)
		case n == 27:
			st = st.Reverse(false)
		case n >= 30 && n <= 37:
			st = st.Foreground(tcell.PaletteColor(n - 30))
		case n == 38:
			var c tcell.Color
			c, i = extended(i)
			st = st.Foreground(c)
		case n == 39:
			st = st.Foreground(tview.Styles.PrimaryTextColor)
		case n >= 40 && n <= 47:
			st = st.Background(tcell.PaletteColor(n - 40))
		case n == 48:
			var c tcell.Color
			c, i = extended(i)
			st = st.Background(c)
		case n == 49:
			st = st.Background(tview.Styles.PrimitiveBackgroundColor)
		case n >= 90 && n <= 97:
			st = st.Foreground(tcell.PaletteColor(n - 90 + 8))
		case n >= 100 && n <= 107:
			st = st.Background(tcell.PaletteColor(n - 100 + 8))
		}
	}
	return st
}

// styledLine is one line in a single style (messages KubesTUI adds itself).
func styledLine(text string, st tcell.Style) logLine {
	line, _ := parseANSI(text, st)
	return line
}

// ---------------------------------------------------------------------------
// Auto-scroll while dragging past an edge
// ---------------------------------------------------------------------------

// dragScroller calls step on the UI goroutine every 60ms while the mouse
// is held past the top (-1) or bottom (+1) edge of a view.
type dragScroller struct {
	app     *tview.Application
	dir     atomic.Int32
	running atomic.Bool
}

func (d *dragScroller) update(dir int, step func(dir int)) {
	d.dir.Store(int32(dir))
	if dir == 0 || d.app == nil || !d.running.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer d.running.Store(false)
		t := time.NewTicker(60 * time.Millisecond)
		defer t.Stop()
		for range t.C {
			dir := int(d.dir.Load())
			if dir == 0 {
				return
			}
			d.app.QueueUpdateDraw(func() { step(dir) })
		}
	}()
}

// ---------------------------------------------------------------------------
// The view
// ---------------------------------------------------------------------------

// logPos is a position in the output: an absolute line number (lines
// dropped from the top still count) and a cell index in that line.
type logPos struct{ line, cell int }

// logRow is one screen row: cells [from, to) of lines[line].
type logRow struct{ line, from, to int }

type logView struct {
	*tview.Box

	lines []logLine
	base  int // absolute number of lines[0]

	rows      []logRow
	rowsWidth int
	rowsDirty bool

	top    int // first visible row
	height int // inner height at the last draw
	follow bool

	selecting bool
	hasSel    bool
	selA      logPos
	selB      logPos
	lastX     int
	drag      dragScroller

	// clickFocus picks what gets focus when the panel is clicked.
	clickFocus func() tview.Primitive
	// onCopy receives the selected text when the mouse button is released.
	onCopy func(text string)
}

func newLogView(app *tview.Application) *logView {
	v := &logView{Box: tview.NewBox(), follow: true}
	v.drag.app = app
	return v
}

// SetLines replaces the content. base is the absolute number of lines[0].
func (v *logView) SetLines(lines []logLine, base int) {
	v.lines, v.base = lines, base
	v.rowsDirty = true
	if v.hasSel || v.selecting {
		if a, _ := v.order(); a.line < base {
			// The selected text is gone (the screen was cleared).
			v.hasSel, v.selecting = false, false
		}
	}
}

// Reset empties the panel and follows new output from the top.
func (v *logView) Reset() {
	v.SetLines(nil, 0)
	v.top, v.follow = 0, true
	v.hasSel, v.selecting = false, false
}

func (v *logView) layout(width int) {
	if !v.rowsDirty && width == v.rowsWidth {
		return
	}
	v.rowsDirty, v.rowsWidth = false, width
	v.rows = v.rows[:0]
	if width < 1 {
		width = 1
	}
	for li, line := range v.lines {
		from, col := 0, 0
		for ci, c := range line {
			if col+c.w > width && ci > from {
				v.rows = append(v.rows, logRow{li, from, ci})
				from, col = ci, 0
			}
			col += c.w
		}
		v.rows = append(v.rows, logRow{li, from, len(line)})
	}
}

func (v *logView) maxTop() int {
	return max(len(v.rows)-max(v.height, 1), 0)
}

func (v *logView) clampTop() {
	if v.follow {
		v.top = v.maxTop()
	}
	v.top = min(max(v.top, 0), v.maxTop())
}

// ScrollBy scrolls by n rows. Reaching the bottom follows new output again.
func (v *logView) ScrollBy(n int) {
	_, _, w, _ := v.GetInnerRect()
	v.layout(w)
	v.clampTop()
	v.top = min(max(v.top+n, 0), v.maxTop())
	v.follow = v.top >= v.maxTop()
}

// HasSelection reports whether text is selected (and not still being dragged).
func (v *logView) HasSelection() bool { return v.hasSel && !v.selecting }

func (v *logView) ScrollToBeginning() { v.top, v.follow = 0, false }
func (v *logView) ScrollToEnd()       { v.follow = true }
func (v *logView) Following() bool    { return v.follow }

func (v *logView) Draw(screen tcell.Screen) {
	v.DrawForSubclass(screen, v)
	x, y, w, h := v.GetInnerRect()
	v.height = h
	v.layout(w)
	v.clampTop()

	a, b := v.order()
	for i := 0; i < h && v.top+i < len(v.rows); i++ {
		row := v.rows[v.top+i]
		line := v.lines[row.line]
		abs := v.base + row.line
		cx := x
		for c := row.from; c < row.to; c++ {
			cell := line[c]
			st := cell.st
			if v.hasSel && inLogSel(a, b, logPos{abs, c}) {
				st = st.Reverse(true)
			}
			screen.SetContent(cx, y+i, cell.r, nil, st)
			cx += cell.w
		}
	}
}

func (v *logView) order() (logPos, logPos) {
	a, b := v.selA, v.selB
	if b.line < a.line || (b.line == a.line && b.cell < a.cell) {
		return b, a
	}
	return a, b
}

func inLogSel(a, b, p logPos) bool {
	if p.line < a.line || p.line > b.line {
		return false
	}
	if p.line == a.line && p.cell < a.cell {
		return false
	}
	return !(p.line == b.line && p.cell > b.cell)
}

// posAt maps a screen point to an output position. Points past the end of
// a row land just after its last cell; above/below the panel, on the
// first/last visible row.
func (v *logView) posAt(x, y int) logPos {
	ix, iy, w, h := v.GetInnerRect()
	v.layout(w)
	if len(v.rows) == 0 {
		return logPos{v.base, 0}
	}
	r := min(max(v.top+y-iy, v.top), v.top+h-1)
	r = min(max(r, 0), len(v.rows)-1)
	row := v.rows[r]
	line := v.lines[row.line]
	col := 0
	for c := row.from; c < row.to; c++ {
		if col+line[c].w > x-ix {
			return logPos{v.base + row.line, c}
		}
		col += line[c].w
	}
	return logPos{v.base + row.line, row.to}
}

// SelectionText returns the selected text; wrapped lines stay one line.
func (v *logView) SelectionText() string {
	a, b := v.order()
	var out []string
	for l := a.line; l <= b.line; l++ {
		i := l - v.base
		if i < 0 || i >= len(v.lines) {
			continue
		}
		line := v.lines[i]
		from, to := 0, len(line)-1
		if l == a.line {
			from = a.cell
		}
		if l == b.line {
			to = min(b.cell, len(line)-1)
		}
		var sb strings.Builder
		for c := from; c <= to; c++ {
			sb.WriteRune(line[c].r)
		}
		out = append(out, strings.TrimRight(sb.String(), " "))
	}
	return strings.Join(out, "\n")
}

// dragStep scrolls during a drag past an edge and extends the selection.
func (v *logView) dragStep(dir int) {
	if !v.selecting {
		v.drag.update(0, nil)
		return
	}
	v.ScrollBy(dir)
	_, iy, _, h := v.GetInnerRect()
	y := iy
	if dir > 0 {
		y = iy + h - 1
	}
	v.selB = v.posAt(v.lastX, y)
	v.hasSel = v.selA != v.selB
}

func (v *logView) MouseHandler() func(action tview.MouseAction, event *tcell.EventMouse, setFocus func(p tview.Primitive)) (bool, tview.Primitive) {
	return v.WrapMouseHandler(func(action tview.MouseAction, event *tcell.EventMouse, setFocus func(p tview.Primitive)) (bool, tview.Primitive) {
		x, y := event.Position()
		inside := v.InRect(x, y)
		_, iy, _, h := v.GetInnerRect()

		switch action {
		case tview.MouseScrollUp:
			if inside {
				v.ScrollBy(-3)
				return true, nil
			}
		case tview.MouseScrollDown:
			if inside {
				v.ScrollBy(3)
				return true, nil
			}
		case tview.MouseLeftDown:
			if inside {
				if v.clickFocus != nil {
					setFocus(v.clickFocus())
				} else {
					setFocus(v)
				}
				p := v.posAt(x, y)
				v.selA, v.selB, v.lastX = p, p, x
				v.selecting, v.hasSel = true, false
				return true, v // capture the drag
			}
		case tview.MouseMove:
			if v.selecting {
				v.lastX = x
				dir := 0
				if y < iy {
					dir = -1
				} else if y >= iy+h {
					dir = 1
				}
				v.drag.update(dir, v.dragStep)
				v.selB = v.posAt(x, y)
				v.hasSel = v.selA != v.selB
				return true, v
			}
		case tview.MouseLeftUp:
			if v.selecting {
				v.selecting = false
				v.drag.update(0, nil)
				if v.hasSel && v.onCopy != nil {
					v.onCopy(v.SelectionText())
				}
				return true, nil
			}
		case tview.MouseLeftClick, tview.MouseLeftDoubleClick:
			if inside {
				return true, nil
			}
		}
		return false, nil
	})
}
