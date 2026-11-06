package main

// The look: heavy lines for every border (menus, dialogs, Help, the
// Command Center panels, the file manager) in vivid red, magenta and
// violet that slowly flow clockwise around the window (brighter on the
// panel that has focus), over a near-black red background with warm
// off-white text. On
// the Linux text console, whose font has no heavy lines, thin ones are used.
//
// The colours are settings, so they can be tried without rebuilding:
//
//   ~/.kubestui/theme (one per line; names like darkred or #rrggbb)
//       border     = #ff1f2d   borders, at the top of the window
//       border_mid = #d4137a   borders, halfway ("none": straight top to end)
//       border_end = #7b2fff   borders, at the bottom ("none": one colour)
//       focus      = #ff5a5a   the focused panel's border, top
//       focus_mid  = #ff4fbf   ... halfway
//       focus_end  = #b98cff   ... bottom
//       background = #170404   everything ("default": the terminal's own)
//       panel      = #3a0b0b   dialogs, input fields
//       text       = #f5e9e9   normal text
//       flow       = 8         seconds per turn of the colours (0: still,
//                              shaded top to bottom instead)
//       banner_font = bubble       the banner's letters: bubble, graffiti,
//                              bloody (spray-painted, with drips) or blocks
//       banner_top, banner_mid, banner_bottom
//                              the banner's colours, top to bottom
//                              (default: border, border_mid, border_end),
//                              e.g. #00f0ff, #6a8cff, #c62cff
//
//   KUBESTUI_BORDER_COLOR, _BORDER_MID_COLOR, _BORDER_END_COLOR,
//   _BORDER_FOCUS_COLOR, _BORDER_FOCUS_MID_COLOR, _BORDER_FOCUS_END_COLOR,
//   _BACKGROUND, _PANEL_COLOR, _TEXT_COLOR and _BORDER_FLOW (all
//   KUBESTUI_...) override the file.
//
//       style      = standard  or sleek: the terminal's own background,
//                              white thin borders (aqua on the focused
//                              panel), no banner, no colour settings
//                              ("Switch to Sleek/Standard Look" in the
//                              Cluster tab toggles it; KUBESTUI_STYLE)
//
// The file is read at start: quit and reopen KubesTUI to see a change.
// (In node mode kbtui runs as root, so the file there is /root/.kubestui/theme.)

import (
	"bufio"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

var (
	borderColor      = tcell.GetColor("#ff1f2d") // vivid red
	borderMidColor   = tcell.GetColor("#d4137a") // magenta
	borderEndColor   = tcell.GetColor("#7b2fff") // violet
	borderFocusColor = tcell.GetColor("#ff5a5a")
	focusMidColor    = tcell.GetColor("#ff4fbf")
	focusEndColor    = tcell.GetColor("#b98cff")
	bgColor          = tcell.GetColor("#170404") // black red
	panelColor       = tcell.GetColor("#3a0b0b")
	textColor        = tcell.GetColor("#f5e9e9") // warm off-white

	flowSeconds = 8.0 // one clockwise turn of the border colours

	themeStyle = "standard" // or "sleek"
)

func sleekLook() bool { return themeStyle == "sleek" }

func themePath() string { return filepath.Join(kubestuiDir(), "theme") }

// loadTheme reads the colours: the theme file, then the environment.
func loadTheme() {
	set := func(dst *tcell.Color, value string) {
		value = strings.TrimSpace(strings.Trim(strings.TrimSpace(value), `"'`))
		if value == "" {
			return
		}
		switch strings.ToLower(value) {
		case "default", "none", "terminal":
			*dst = tcell.ColorDefault
			return
		}
		if c := tcell.GetColor(strings.ToLower(value)); c != tcell.ColorDefault {
			*dst = c
		}
	}
	settings := map[string]*tcell.Color{
		"border": &borderColor, "border_mid": &borderMidColor, "border_end": &borderEndColor,
		"focus": &borderFocusColor, "focus_mid": &focusMidColor, "focus_end": &focusEndColor,
		"background": &bgColor, "panel": &panelColor, "text": &textColor,
		"banner_top": &bannerTop, "banner_mid": &bannerMid, "banner_bottom": &bannerBottom,
	}
	aliases := map[string]string{"gradient": "border_end", "border_focus": "focus",
		"border_focus_mid": "focus_mid", "border_focus_end": "focus_end", "bg": "background"}

	if f, err := os.Open(themePath()); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") && !strings.Contains(line, "=") {
				continue
			}
			key, value, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			key = strings.ToLower(strings.TrimSpace(key))
			if a, ok := aliases[key]; ok {
				key = a
			}
			if dst, ok := settings[key]; ok {
				set(dst, value)
			} else if key == "flow" {
				setFlow(value)
			} else if key == "banner_font" {
				setBannerFont(value)
			} else if key == "style" {
				setStyle(value)
			}
		}
		f.Close()
	}
	for env, key := range map[string]string{
		"KUBESTUI_BORDER_COLOR": "border", "KUBESTUI_BORDER_MID_COLOR": "border_mid",
		"KUBESTUI_BORDER_END_COLOR": "border_end", "KUBESTUI_BORDER_FOCUS_COLOR": "focus",
		"KUBESTUI_BORDER_FOCUS_MID_COLOR": "focus_mid", "KUBESTUI_BORDER_FOCUS_END_COLOR": "focus_end",
		"KUBESTUI_BACKGROUND": "background", "KUBESTUI_PANEL_COLOR": "panel", "KUBESTUI_TEXT_COLOR": "text",
	} {
		set(settings[key], os.Getenv(env))
	}
	setFlow(os.Getenv("KUBESTUI_BORDER_FLOW"))
	// "none" for an end colour: one colour, no gradient.
	if borderEndColor == tcell.ColorDefault {
		borderEndColor = borderColor
	}
	if focusEndColor == tcell.ColorDefault {
		focusEndColor = borderFocusColor
	}
	setStyle(os.Getenv("KUBESTUI_STYLE"))

	if sleekLook() {
		borderColor, borderMidColor, borderEndColor = tcell.ColorWhite, tcell.ColorDefault, tcell.ColorWhite
		borderFocusColor, focusMidColor, focusEndColor = tcell.ColorAqua, tcell.ColorDefault, tcell.ColorAqua
		bgColor, panelColor, textColor = tcell.ColorDefault, tcell.ColorDarkSlateGray, tcell.ColorWhite
		flowSeconds = 0
	}
}

func setStyle(value string) {
	switch strings.ToLower(strings.TrimSpace(strings.Trim(strings.TrimSpace(value), `"'`))) {
	case "sleek":
		themeStyle = "sleek"
	case "standard":
		themeStyle = "standard"
	}
}

// saveThemeSetting sets key = value in the theme file, keeping its other
// lines (and creating it if needed).
func saveThemeSetting(key, value string) error {
	var out []string
	done := false
	if data, err := os.ReadFile(themePath()); err == nil {
		for _, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
			if k, _, ok := strings.Cut(line, "="); ok && strings.EqualFold(strings.TrimSpace(k), key) {
				if !done {
					out = append(out, key+" = "+value)
					done = true
				}
				continue
			}
			out = append(out, line)
		}
	}
	if !done {
		out = append(out, key+" = "+value)
	}
	if err := os.MkdirAll(kubestuiDir(), 0o700); err != nil {
		return err
	}
	return os.WriteFile(themePath(), []byte(strings.Join(out, "\n")+"\n"), 0o600)
}

// lookToggle is the menu item that switches between the two looks.
func lookToggle() (title, desc string, run func()) {
	to := "sleek"
	title, desc = "Switch to Sleek Look", "Plain: your terminal's background, thin white borders, no banner (KubesTUI restarts)"
	if sleekLook() {
		to = "standard"
		title, desc = "Switch to Standard Look", "The homelabCD look: banner, black-red background, flowing red-violet borders (KubesTUI restarts)"
	}
	return title, desc, func() {
		if err := saveThemeSetting("style", to); err != nil {
			showConfirm("LOOK", "Could not save the setting:\n"+err.Error(), "OK", "Close", func(bool) {})
			return
		}
		restartRequested = true
		uiApp.Stop()
	}
}

// restartRequested: after the UI stops, start KubesTUI again (same
// arguments and environment), e.g. to apply a new look.
var restartRequested bool

// relaunchIfRequested runs a fresh KubesTUI in this terminal and exits
// with its status, when a restart was asked for.
func relaunchIfRequested() {
	if !restartRequested {
		return
	}
	exe, err := os.Executable()
	if err != nil {
		return
	}
	cmd := exec.Command(exe, os.Args[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = os.Environ()
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			os.Exit(ee.ExitCode())
		}
		os.Exit(1)
	}
	os.Exit(0)
}

// setFlow reads the seconds per turn ("off" or 0: no movement).
func setFlow(value string) {
	value = strings.ToLower(strings.TrimSpace(strings.Trim(strings.TrimSpace(value), `"'`)))
	switch value {
	case "":
		return
	case "off", "no", "none", "false":
		flowSeconds = 0
		return
	}
	if f, err := strconv.ParseFloat(strings.TrimSuffix(value, "s"), 64); err == nil && f >= 0 {
		flowSeconds = f
	}
}

// plainBorders: the Linux text console's font has no heavy lines.
func plainBorders() bool { return os.Getenv("TERM") == "linux" }

// borderLines are the line characters of every border.
type borderLines struct {
	h, v, tl, tr, bl, br, lt, rt, tt, bt, cross rune
}

func lines() borderLines {
	if sleekLook() && !plainBorders() {
		return borderLines{'─', '│', '╭', '╮', '╰', '╯', '├', '┤', '┬', '┴', '┼'}
	}
	if plainBorders() {
		return borderLines{'─', '│', '┌', '┐', '└', '┘', '├', '┤', '┬', '┴', '┼'}
	}
	return borderLines{'━', '┃', '┏', '┓', '┗', '┛', '┣', '┫', '┳', '┻', '╋'}
}

// applyBorders sets tview's border lines and the colours of every widget.
func applyBorders() {
	loadTheme()
	l := lines()
	b := &tview.Borders
	b.Horizontal, b.Vertical = l.h, l.v
	b.TopLeft, b.TopRight, b.BottomLeft, b.BottomRight = l.tl, l.tr, l.bl, l.br
	b.LeftT, b.RightT, b.TopT, b.BottomT, b.Cross = l.lt, l.rt, l.tt, l.bt, l.cross
	// Focused boxes keep the same lines: only the Command Center and the
	// file manager mark focus, with the colour.
	b.HorizontalFocus, b.VerticalFocus = l.h, l.v
	b.TopLeftFocus, b.TopRightFocus, b.BottomLeftFocus, b.BottomRightFocus = l.tl, l.tr, l.bl, l.br

	s := &tview.Styles
	s.BorderColor = borderColor
	s.PrimitiveBackgroundColor = bgColor
	s.ContrastBackgroundColor = panelColor     // input fields, buttons
	s.MoreContrastBackgroundColor = panelColor // drop-downs
	s.PrimaryTextColor = textColor
	s.TitleColor = textColor
	s.GraphicsColor = borderColor
	s.ContrastSecondaryTextColor = tcell.ColorGray // placeholders
}

// uiStyle is the plain style: theme background and text. Drawing code
// starts from it instead of tcell.StyleDefault (the terminal's colours).
func uiStyle() tcell.Style {
	return tcell.StyleDefault.Background(bgColor).Foreground(textColor)
}

// colorTag is c as a tview colour tag ("" for the default colour).
func colorTag(c tcell.Color) string {
	if c == tcell.ColorDefault || c.Hex() < 0 {
		return ""
	}
	return fmt.Sprintf("[#%06x]", c.Hex())
}

// inBorder frames a tagged title set into a border drawn in color:
// ┫title┣ with the tees in the border's colour (so they shade with it).
func inBorder(color tcell.Color, title string) string {
	l := lines()
	return colorTag(color) + string(l.rt) + "[-]" + title + colorTag(color) + string(l.lt) + "[-]"
}

// Border cells found in the last full draw, recoloured on every frame.
type borderCell struct {
	x, y  int
	focus bool
}

var (
	borderCells  []borderCell
	shadeScreen  tcell.Screen
	flowStart    = time.Now()
	flowQueued   atomic.Bool
	borderStill  = func() bool { return flowSeconds <= 0 }
	gradientNone = func() bool {
		return borderColor == tcell.ColorDefault ||
			(borderEndColor == borderColor && focusEndColor == borderFocusColor)
	}
)

// shadeBorders runs after every full draw (Application.SetAfterDrawFunc):
// it notes the cells drawn in the border colours and colours them.
func shadeBorders(screen tcell.Screen) {
	if gradientNone() {
		return
	}
	borderCells = borderCells[:0]
	shadeScreen = screen
	w, h := screen.Size()
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			_, _, st, _ := screen.GetContent(x, y)
			switch fg, _, _ := st.Decompose(); fg {
			case borderColor:
				borderCells = append(borderCells, borderCell{x, y, false})
			case borderFocusColor:
				borderCells = append(borderCells, borderCell{x, y, true})
			}
		}
	}
	paintBorders(screen)
}

// paintBorders colours the noted border cells. Still: top to bottom.
// Flowing: a colour wheel around the window's centre, turning clockwise.
func paintBorders(screen tcell.Screen) {
	w, h := screen.Size()
	plain := []tcell.Color{borderColor, borderMidColor, borderEndColor}
	focus := []tcell.Color{borderFocusColor, focusMidColor, focusEndColor}
	phase := 0.0
	if !borderStill() {
		phase = math.Mod(time.Since(flowStart).Seconds()/flowSeconds, 1)
	}
	cx, cy := float64(w-1)/2, float64(h-1)/2
	for _, c := range borderCells {
		var color tcell.Color
		stops := plain
		if c.focus {
			stops = focus
		}
		if borderStill() {
			color = gradientAt(stops[0], stops[1], stops[2], c.y, h)
		} else {
			// Cells are about twice as tall as wide: halve x for a round wheel.
			angle := math.Atan2(float64(c.y)-cy, (float64(c.x)-cx)/2) // clockwise on screen
			color = wheelAt(stops, angle/(2*math.Pi)-phase)
		}
		r, comb, st, _ := screen.GetContent(c.x, c.y)
		screen.SetContent(c.x, c.y, r, comb, st.Foreground(color))
	}
}

// wheelAt is the colour at position t (any real; one turn = 1) of a loop
// top, mid, end, mid, back to top, so the wheel has no seam.
func wheelAt(stops []tcell.Color, t float64) tcell.Color {
	top, mid, end := stops[0], stops[1], stops[2]
	if mid == tcell.ColorDefault {
		mid = mixColor(top, end, 1, 2)
	}
	loop := []tcell.Color{top, mid, end, mid}
	t -= math.Floor(t)
	pos := t * float64(len(loop))
	i := int(pos) % len(loop)
	frac := pos - math.Floor(pos)
	return mixColor(loop[i], loop[(i+1)%len(loop)], int(frac*1000), 1000)
}

// startBorderFlow turns the colour wheel: about 12 times a second it
// recolours just the border cells (no full redraw).
func startBorderFlow(app *tview.Application) {
	if borderStill() || gradientNone() {
		return
	}
	go func() {
		t := time.NewTicker(80 * time.Millisecond)
		defer t.Stop()
		for range t.C {
			if !flowQueued.CompareAndSwap(false, true) {
				continue // the last frame hasn't been drawn yet
			}
			app.QueueUpdate(func() {
				defer flowQueued.Store(false)
				if s := shadeScreen; s != nil {
					paintBorders(s)
					s.Show()
				}
			})
		}
	}()
}

// gradientAt is the colour at row y of h: top, through mid (if set) at
// half height, to end at the bottom.
func gradientAt(top, mid, end tcell.Color, y, h int) tcell.Color {
	if h <= 1 {
		return top
	}
	if mid == tcell.ColorDefault {
		return mixColor(top, end, y, h-1)
	}
	half := (h - 1) / 2
	if y <= half {
		return mixColor(top, mid, y, half)
	}
	return mixColor(mid, end, y-half, h-1-half)
}

// mixColor is the colour step of steps between from and to.
func mixColor(from, to tcell.Color, step, steps int) tcell.Color {
	if from == to || steps <= 0 {
		return from
	}
	r1, g1, b1 := from.RGB()
	r2, g2, b2 := to.RGB()
	if r1 < 0 || r2 < 0 {
		return from
	}
	mix := func(a, b int32) int32 { return a + (b-a)*int32(step)/int32(steps) }
	return tcell.NewRGBColor(mix(r1, r2), mix(g1, g2), mix(b1, b2))
}
