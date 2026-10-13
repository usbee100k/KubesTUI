package main

// Command Center drawing helpers: boxes, meters, sparklines, graphs and a
// small table engine that drops less important columns on narrow screens.
// Text is tview color-tagged; plain values are escaped when drawn.

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"github.com/rivo/uniseg"
)

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------

func fmtBytes(b int64) string {
	f := float64(b)
	for _, u := range []string{"", "K", "M", "G", "T", "P"} {
		if math.Abs(f) < 1024 || u == "P" {
			switch {
			case u == "":
				return fmt.Sprintf("%dB", int64(f))
			case f >= 100:
				return fmt.Sprintf("%.0f%s", f, u)
			case f >= 10:
				return fmt.Sprintf("%.1f%s", f, u)
			}
			return fmt.Sprintf("%.2f%s", f, u)
		}
		f /= 1024
	}
	return "?"
}

func fmtRate(bps float64) string {
	return strings.TrimSuffix(fmtBytes(int64(bps)), "B") + "/s"
}

func fmtCPU(m int64) string {
	if m < 1000 {
		return fmt.Sprintf("%dm", m)
	}
	return fmt.Sprintf("%.2f", float64(m)/1000)
}

func fmtCores(m int64) string {
	if m%1000 == 0 {
		return fmt.Sprintf("%d", m/1000)
	}
	return fmt.Sprintf("%.1f", float64(m)/1000)
}

func fmtAge(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return fmtDur(time.Since(t))
}

func fmtDur(d time.Duration) string {
	switch {
	case d < 0:
		return "0s"
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}

// pctColor goes green → yellow → orange → red as usage rises.
func pctColor(p float64) string {
	switch {
	case p < 60:
		return "green"
	case p < 80:
		return "yellow"
	case p < 90:
		return "orange"
	}
	return "red"
}

func strWidth(s string) int { return uniseg.StringWidth(s) }

// fit truncates s to w columns (with …) and pads it.
func fit(s string, w int, right bool) string {
	if w <= 0 {
		return ""
	}
	if strWidth(s) > w {
		var b strings.Builder
		width := 0
		g := uniseg.NewGraphemes(s)
		for g.Next() {
			cw := g.Width()
			if width+cw > w-1 {
				break
			}
			b.WriteString(g.Str())
			width += cw
		}
		return b.String() + "…" + strings.Repeat(" ", max(0, w-1-width))
	}
	pad := strings.Repeat(" ", w-strWidth(s))
	if right {
		return pad + s
	}
	return s + pad
}

// ---------------------------------------------------------------------------
// Meters, sparklines, graphs
// ---------------------------------------------------------------------------

// meter is a w-wide bar, each cell colored by how far along it is (btop's
// gradient), the empty part dim.
func meter(p float64, w int) string {
	if w <= 0 {
		return ""
	}
	filled := int(math.Round(p / 100 * float64(w)))
	if p > 0 && filled == 0 {
		filled = 1
	}
	var b strings.Builder
	last := ""
	for i := 0; i < w; i++ {
		c := "#3a3a3a"
		ch := "■"
		if i < filled {
			c = pctColor(float64(i+1) * 100 / float64(w))
		}
		if c != last {
			b.WriteString("[" + c + "]")
			last = c
		}
		b.WriteString(ch)
	}
	return b.String() + "[-]"
}

var sparkRunes = []rune(" ▁▂▃▄▅▆▇█")

// spark is the last w values (0..top) as a one-line bar chart.
func spark(vals []float64, w int, top float64) string {
	if w <= 0 {
		return ""
	}
	if top <= 0 {
		top = 1
	}
	var b strings.Builder
	start := len(vals) - w
	for i := 0; i < w; i++ {
		j := start + i
		if j < 0 {
			b.WriteString(" ")
			continue
		}
		v := math.Max(0, math.Min(1, vals[j]/top))
		idx := int(math.Round(v * 8))
		if idx == 0 && vals[j] > 0 {
			idx = 1
		}
		b.WriteString("[" + pctColor(v*100) + "]" + string(sparkRunes[idx]))
	}
	return b.String() + "[-]"
}

// graph draws vals (0..top) as a w×h area chart, newest on the right, each
// row colored by its height like btop.
func graph(vals []float64, w, h int, top float64, colors func(rowFrac float64) string) []string {
	lines := make([]string, h)
	if w <= 0 || h <= 0 {
		return lines
	}
	if top <= 0 {
		top = 1
	}
	start := len(vals) - w
	for r := 0; r < h; r++ {
		level := h - 1 - r // 0 = bottom row
		var b strings.Builder
		b.WriteString("[" + colors(float64(level+1)/float64(h)) + "]")
		for i := 0; i < w; i++ {
			j := start + i
			if j < 0 {
				b.WriteByte(' ')
				continue
			}
			v := math.Max(0, math.Min(1, vals[j]/top))
			eighths := v*float64(h*8) - float64(level*8)
			switch {
			case eighths >= 8:
				b.WriteRune('█')
			case eighths <= 0:
				if level == 0 && vals[j] > 0 {
					b.WriteRune('▁')
				} else {
					b.WriteByte(' ')
				}
			default:
				b.WriteRune(sparkRunes[int(math.Max(1, math.Round(eighths)))])
			}
		}
		b.WriteString("[-]")
		lines[r] = b.String()
	}
	return lines
}

func heatColors(f float64) string { return pctColor(f * 100) }

func coolColors(f float64) string {
	switch {
	case f < 0.34:
		return "#2e86de"
	case f < 0.67:
		return "#48dbfb"
	}
	return "#c8f7ff"
}

// ---------------------------------------------------------------------------
// Boxes
// ---------------------------------------------------------------------------

type ccRect struct{ x, y, w, h int }

func (r ccRect) contains(x, y int) bool {
	return x >= r.x && x < r.x+r.w && y >= r.y && y < r.y+r.h
}

func (r ccRect) inner() ccRect { return ccRect{r.x + 1, r.y + 1, r.w - 2, r.h - 2} }

// drawBox draws a rounded box in color.
func drawBox(screen tcell.Screen, r ccRect, color tcell.Color) {
	if r.w < 2 || r.h < 2 {
		return
	}
	st := tcell.StyleDefault.Foreground(color).Background(tview.Styles.PrimitiveBackgroundColor)
	for x := r.x + 1; x < r.x+r.w-1; x++ {
		screen.SetContent(x, r.y, '─', nil, st)
		screen.SetContent(x, r.y+r.h-1, '─', nil, st)
	}
	for y := r.y + 1; y < r.y+r.h-1; y++ {
		screen.SetContent(r.x, y, '│', nil, st)
		screen.SetContent(r.x+r.w-1, y, '│', nil, st)
	}
	screen.SetContent(r.x, r.y, '╭', nil, st)
	screen.SetContent(r.x+r.w-1, r.y, '╮', nil, st)
	screen.SetContent(r.x, r.y+r.h-1, '╰', nil, st)
	screen.SetContent(r.x+r.w-1, r.y+r.h-1, '╯', nil, st)
}

// clearRect blanks an area (under an overlay).
func clearRect(screen tcell.Screen, r ccRect) {
	st := tcell.StyleDefault.Background(tview.Styles.PrimitiveBackgroundColor)
	for y := r.y; y < r.y+r.h; y++ {
		for x := r.x; x < r.x+r.w; x++ {
			screen.SetContent(x, y, ' ', nil, st)
		}
	}
}

// put prints tagged text, cut at w columns. Returns the width used.
func put(screen tcell.Screen, text string, x, y, w int) int {
	if w <= 0 {
		return 0
	}
	_, used := tview.Print(screen, text, x, y, w, tview.AlignLeft, tview.Styles.PrimaryTextColor)
	return used
}

// ---------------------------------------------------------------------------
// Tables
// ---------------------------------------------------------------------------

type ccCol struct {
	title string
	width int  // 0: takes the space left (at least min)
	min   int  // flex columns
	right bool // right-aligned
	drop  int  // 0 always shown; higher numbers are hidden first when narrow
}

type ccCell struct {
	text  string             // plain
	color string             // tview color name, "" default
	rich  func(w int) string // tagged rendering at width w (meters)
}

type ccRow struct {
	key   string
	cells []ccCell
	dim   bool
}

type ccTable struct {
	head  []string // tagged lines above the table
	cols  []ccCol
	rows  []ccRow
	empty string // shown when there are no rows
}

// fitCols picks the columns that fit in width and their widths.
func fitCols(cols []ccCol, width int) (show []int, widths []int) {
	shown := make([]bool, len(cols))
	for i := range shown {
		shown[i] = true
	}
	need := func() int {
		total, n := 0, 0
		for i, c := range cols {
			if !shown[i] {
				continue
			}
			n++
			if c.width > 0 {
				total += c.width
			} else {
				total += c.min
			}
		}
		return total + max(0, n-1)
	}
	for need() > width {
		worst := -1
		for i, c := range cols {
			if shown[i] && c.drop > 0 && (worst < 0 || c.drop > cols[worst].drop) {
				worst = i
			}
		}
		if worst < 0 {
			break
		}
		shown[worst] = false
	}
	spare := width - need()
	flexes := 0
	for i, c := range cols {
		if shown[i] && c.width == 0 {
			flexes++
		}
	}
	for i, c := range cols {
		if !shown[i] {
			continue
		}
		w := c.width
		if w == 0 {
			w = c.min
			if flexes > 0 && spare > 0 {
				w += spare / flexes
			}
		}
		show = append(show, i)
		widths = append(widths, w)
	}
	return show, widths
}

func (t *ccTable) headerLine(show, widths []int) string {
	var b strings.Builder
	for k, i := range show {
		if k > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(tview.Escape(fit(t.cols[i].title, widths[k], t.cols[i].right)))
	}
	return "[::b]" + b.String() + "[::-]"
}

func (t *ccTable) rowLine(r ccRow, show, widths []int, selected bool) string {
	var b strings.Builder
	if selected {
		b.WriteString("[black:aqua]")
	}
	for k, i := range show {
		if k > 0 {
			b.WriteByte(' ')
		}
		if i >= len(r.cells) {
			b.WriteString(strings.Repeat(" ", widths[k]))
			continue
		}
		c, w := r.cells[i], widths[k]
		switch {
		case selected:
			b.WriteString(tview.Escape(fit(c.text, w, t.cols[i].right)))
		case c.rich != nil:
			b.WriteString(c.rich(w))
		default:
			color := c.color
			if r.dim && color == "" {
				color = "gray"
			}
			s := tview.Escape(fit(c.text, w, t.cols[i].right))
			if color != "" {
				s = "[" + color + "]" + s + "[-]"
			}
			b.WriteString(s)
		}
	}
	if selected {
		b.WriteString("[-:-]")
	}
	return b.String()
}
