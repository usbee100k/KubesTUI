package main

// The banner at the top of the main screens: "homelabCD" in big letters,
// centered, shaded down the theme's border colours (red, magenta, violet),
// with a small "by usbee100k" under its right end. A window too small for
// it gets a compact one-line version instead.
//
// The default lettering is bubble letters: a rounded font rendered to
// pixels, two per character cell (half blocks), each pixel row its own
// colour, with a cream outline, a shine along the tops, a darker shade at
// the bottoms and a 3D extrusion (banner_bubble.go). There are two sizes;
// the biggest that fits is used.
//
// Settings in ~/.kubestui/theme:
//   banner_font = bubble (default), graffiti (spray-tag letters), bloody
//                 (bold, spray-painted with drips) or blocks (ANSI Shadow)
//   banner_top, banner_mid, banner_bottom = its colours, top to bottom
//                 (default: border, border_mid, border_end)

import (
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

func init() {
	// HOMELABCD in ANSI Shadow capitals.
	letters := [][6]string{
		{"██╗  ██╗", "██║  ██║", "███████║", "██╔══██║", "██║  ██║", "╚═╝  ╚═╝"},
		{" ██████╗ ", "██╔═══██╗", "██║   ██║", "██║   ██║", "╚██████╔╝", " ╚═════╝ "},
		{"███╗   ███╗", "████╗ ████║", "██╔████╔██║", "██║╚██╔╝██║", "██║ ╚═╝ ██║", "╚═╝     ╚═╝"},
		{"███████╗", "██╔════╝", "█████╗  ", "██╔══╝  ", "███████╗", "╚══════╝"},
		{"██╗     ", "██║     ", "██║     ", "██║     ", "███████╗", "╚══════╝"},
		{" █████╗ ", "██╔══██╗", "███████║", "██╔══██║", "██║  ██║", "╚═╝  ╚═╝"},
		{"██████╗ ", "██╔══██╗", "██████╔╝", "██╔══██╗", "██████╔╝", "╚═════╝ "},
		{" ██████╗", "██╔════╝", "██║     ", "██║     ", "╚██████╗", " ╚═════╝"},
		{"██████╗ ", "██╔══██╗", "██║  ██║", "██║  ██║", "██████╔╝", "╚═════╝ "},
	}
	rows := make([]string, 6)
	for _, l := range letters {
		for i := range rows {
			rows[i] += l[i]
		}
	}
	bannerFonts["blocks"] = rows
}

const (
	bannerBrand  = "homelabCD"
	bannerAuthor = "by usbee100k"
)

var (
	bannerFont   = "bubble"
	bannerTop    = tcell.ColorDefault // default: the border colours
	bannerMid    = tcell.ColorDefault
	bannerBottom = tcell.ColorDefault
)

// setBannerFont picks the banner's letters (unknown names are ignored).
func setBannerFont(name string) {
	name = strings.ToLower(strings.TrimSpace(strings.Trim(strings.TrimSpace(name), `"'`)))
	if _, ok := bannerFonts[name]; ok || name == "bubble" {
		bannerFont = name
	}
}

func bannerArt() []string { return bannerFonts[bannerFont] }

func bannerWidth() int {
	w := 0
	for _, l := range bannerArt() {
		w = max(w, len([]rune(l)))
	}
	return w
}

type bannerView struct {
	*tview.Box
}

func newBanner() *bannerView { return &bannerView{Box: tview.NewBox()} }

// bigBanner is the lettering for an area of w x h: its height in cells
// and, for bubble letters, the pixel rows; 0 when only the compact line
// fits (the big letters must leave room for the menu below).
func bigBanner(w, h int) (cells int, pixels []string) {
	if bannerFont == "bubble" {
		for _, px := range bannerBubble {
			if c := len(px) / 2; w >= len(px[0])+4 && h >= c+24 {
				return c, px
			}
		}
		return 0, nil
	}
	if art := len(bannerArt()); w >= bannerWidth()+4 && h >= art+24 {
		return art, nil
	}
	return 0, nil
}

// rows is the height the banner takes in an area of w x h.
func (b *bannerView) rows(w, h int) int {
	if sleekLook() {
		return 0 // no banner; the title carries the name
	}
	if cells, _ := bigBanner(w, h); cells > 0 {
		return cells + 2 // a blank line, the letters, the author
	}
	return 2 // a blank line, the compact line
}

// bannerColors are the colours down the banner, top to bottom.
func bannerColors() (top, mid, bottom tcell.Color) {
	top, mid, bottom = borderColor, borderMidColor, borderEndColor
	if bannerTop != tcell.ColorDefault {
		top = bannerTop
	}
	if bannerMid != tcell.ColorDefault {
		mid = bannerMid
	}
	if bannerBottom != tcell.ColorDefault {
		bottom = bannerBottom
	}
	if top == tcell.ColorDefault {
		top, mid, bottom = tcell.ColorRed, tcell.ColorPurple, tcell.ColorPurple
	}
	return
}

// notBorder nudges a colour off the border colours, so the border
// animation (which recolours cells in those exact colours) leaves the
// banner alone.
func notBorder(c tcell.Color) tcell.Color {
	if c != borderColor && c != borderFocusColor {
		return c
	}
	r, g, b := c.RGB()
	if r > 0 {
		r--
	} else {
		r++
	}
	return tcell.NewRGBColor(r, g, b)
}

// bannerFaint: outline and spray-shading characters, drawn dimmer.
func bannerFaint(r rune) bool { return strings.ContainsRune("╗║╝═╔╚░▒", r) }

func (b *bannerView) Draw(screen tcell.Screen) {
	b.Box.DrawForSubclass(screen, b)
	x, y, w, h := b.GetInnerRect()
	if w <= 0 || h <= 0 || sleekLook() {
		return
	}
	top, mid, bottom := bannerColors()
	base := uiStyle()

	// The size the parent gave: the big letters for it, if any.
	cells, pixels := 0, []string(nil)
	if h > 2 {
		cells, pixels = bigBanner(w, h+24)
	}
	if pixels != nil {
		b.drawBubble(screen, x, y, w, h, pixels, top, mid, bottom)
		return
	}
	art := bannerArt()

	if cells == 0 || bannerFont == "bubble" { // the compact line
		line := len(bannerBrand) + 1 + len(bannerAuthor)
		cx := x + max(0, (w-line)/2)
		for i, r := range bannerBrand {
			c := notBorder(gradientAt(top, mid, bottom, i, len(bannerBrand)))
			screen.SetContent(cx, y+1, r, nil, base.Foreground(c).Bold(true))
			cx++
		}
		tview.Print(screen, " [gray]"+bannerAuthor+"[-]", cx, y+1, w-(cx-x), tview.AlignLeft, textColor)
		return
	}

	x0 := x + (w-bannerWidth())/2
	for i, line := range art {
		row := y + 1 + i
		if row >= y+h {
			break
		}
		c := notBorder(gradientAt(top, mid, bottom, i, len(art)))
		solid := base.Foreground(c)
		faint := base.Foreground(notBorder(mixColor(c, bgColor, 45, 100)))
		cx := x0
		for _, r := range line {
			if cx >= x+w {
				break
			}
			if r != ' ' {
				st := solid
				if bannerFaint(r) {
					st = faint
				}
				screen.SetContent(cx, row, r, nil, st)
			}
			cx++
		}
	}
	// The author, small and dim, under the right end of the letters.
	if ay := y + 1 + len(art); ay < y+h {
		ax := x0 + bannerWidth() - len(bannerAuthor)
		tview.Print(screen, "[gray::i]"+bannerAuthor, ax, ay, len(bannerAuthor), tview.AlignLeft, textColor)
	}
}

// drawBubble draws bubble-letter pixels, two per cell: the top pixel as
// the foreground of '▀' and the bottom one as its background.
func (b *bannerView) drawBubble(screen tcell.Screen, x, y, w, h int, px []string, top, mid, bottom tcell.Color) {
	width := len(px[0])
	x0 := x + (w-width)/2
	white, black := tcell.NewRGBColor(255, 255, 255), tcell.NewRGBColor(0, 0, 0)
	color := func(kind byte, py int) (tcell.Color, bool) {
		g := gradientAt(top, mid, bottom, py, len(px))
		switch kind {
		case 'F':
			return g, true
		case 'H':
			return mixColor(g, white, 75, 100), true
		case 'G':
			return mixColor(g, white, 35, 100), true
		case 'D':
			return mixColor(g, black, 30, 100), true
		case 'O':
			return textColor, true
		case 'S':
			return mixColor(g, black, 68, 100), true
		}
		return bgColor, false
	}
	for row := 0; row*2 < len(px) && y+1+row < y+h; row++ {
		upper, lower := px[row*2], px[row*2+1]
		for i := 0; i < width && x0+i < x+w; i++ {
			ct, tok := color(upper[i], row*2)
			cb, bok := color(lower[i], row*2+1)
			switch {
			case tok:
				screen.SetContent(x0+i, y+1+row, '▀', nil, tcell.StyleDefault.Foreground(notBorder(ct)).Background(cb))
			case bok:
				screen.SetContent(x0+i, y+1+row, '▄', nil, tcell.StyleDefault.Foreground(notBorder(cb)).Background(bgColor))
			}
		}
	}
	if ay := y + 1 + len(px)/2; ay < y+h {
		ax := x0 + width - len(bannerAuthor) - 3
		tview.Print(screen, "[gray::i]"+bannerAuthor, ax, ay, len(bannerAuthor), tview.AlignLeft, textColor)
	}
}

// bannerFlex is a Flex whose banner item takes the rows the banner wants
// at the current size.
type bannerFlex struct {
	*tview.Flex
	banner *bannerView
}

func (f *bannerFlex) Draw(screen tcell.Screen) {
	_, _, w, h := f.GetInnerRect()
	f.ResizeItem(f.banner, f.banner.rows(w, h), 0)
	f.Flex.Draw(screen)
}
