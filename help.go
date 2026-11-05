package main

// Help: homelabCD's README inside KubesTUI, split into topics at its ## and
// ### headings, so nobody has to leave the TUI to look something up.
//
//   - The Help tab (also ? in a menu) lists Search Help and every topic.
//   - A topic opens in a reader wrapped to the window: ↑/↓ scroll, ←/→ the
//     previous/next topic, / search.
//   - Search Help filters the topics as you type; the one you open has the
//     words highlighted, and n/N jump between them.
//
// The text: on a node, the README of the homelabCD that started KubesTUI
// (always current); elsewhere the copy built in. homelabCD's build copies
// its README to help/homelabcd.md before compiling; a build without it
// (e.g. on a developer machine) falls back to help/placeholder.md.

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

//go:embed help
var helpFiles embed.FS

type helpTopic struct {
	title  string
	parent string // the ## topic a ### topic belongs to
	level  int    // 1: # or ##, 2: ###
	lines  []string
	desc   string // first sentence, for the menu
	search string // lower-case plain text, for search
}

var (
	helpOnce   sync.Once
	helpTopics []helpTopic
)

func loadHelp() []helpTopic {
	helpOnce.Do(func() { helpTopics = parseHelp(helpSource()) })
	return helpTopics
}

func helpSource() string {
	if root := os.Getenv("HOMELABCD_ROOT"); root != "" {
		if b, err := os.ReadFile(filepath.Join(root, "README.md")); err == nil {
			return string(b)
		}
	}
	for _, f := range []string{"help/homelabcd.md", "help/placeholder.md"} {
		if b, err := helpFiles.ReadFile(f); err == nil {
			return string(b)
		}
	}
	return "# Help\n\nThis build has no help text.\n"
}

var (
	helpFenceRe = regexp.MustCompile("^\\s*(```|~~~)")
	helpListRe  = regexp.MustCompile(`^(\s*)([-*+]|\d+[.)])\s+(.*)$`)
	helpLinkRe  = regexp.MustCompile(`\[([^\]]+)\]\(([^)\s]+)\)`)
	helpSentRe  = regexp.MustCompile(`^(.*?[.!?])(\s|$)`)
)

// parseHelp splits markdown into topics: the text before the first ##
// heading is "Overview", then one topic per ## and ### heading.
func parseHelp(md string) []helpTopic {
	var topics []helpTopic
	parent := ""
	inCode := false
	for _, line := range strings.Split(strings.ReplaceAll(md, "\r\n", "\n"), "\n") {
		if helpFenceRe.MatchString(line) {
			inCode = !inCode
		}
		if !inCode {
			level, title := 0, ""
			switch {
			case strings.HasPrefix(line, "# "):
				level, title = 1, "Overview"
			case strings.HasPrefix(line, "## "):
				level, title = 1, strings.TrimSpace(line[3:])
			case strings.HasPrefix(line, "### "):
				level, title = 2, strings.TrimSpace(line[4:])
			}
			if level > 0 {
				t := helpTopic{title: title, level: level}
				if level == 1 {
					parent = title
				} else {
					t.parent = parent
				}
				topics = append(topics, t)
				continue
			}
		}
		if len(topics) == 0 {
			topics = append(topics, helpTopic{title: "Overview", level: 1})
		}
		topics[len(topics)-1].lines = append(topics[len(topics)-1].lines, line)
	}

	for i := range topics {
		t := &topics[i]
		// No blank lines or rules at either end.
		edge := func(s string) bool { s = strings.TrimSpace(s); return s == "" || s == "---" || s == "***" }
		for len(t.lines) > 0 && edge(t.lines[0]) {
			t.lines = t.lines[1:]
		}
		for len(t.lines) > 0 && edge(t.lines[len(t.lines)-1]) {
			t.lines = t.lines[:len(t.lines)-1]
		}
		t.desc = topicDesc(t.lines)
		var b strings.Builder
		b.WriteString(strings.ToLower(t.title))
		for _, l := range t.lines {
			b.WriteString("\n")
			b.WriteString(strings.ToLower(plainInline(l)))
		}
		t.search = b.String()
	}
	return topics
}

// topicDesc is the first sentence of a topic's first paragraph or item.
func topicDesc(lines []string) string {
	var para, firstCol []string
	inCode := false
	for _, l := range lines {
		t := strings.TrimSpace(l)
		if helpFenceRe.MatchString(l) {
			inCode = !inCode
			continue
		}
		if strings.HasPrefix(t, "|") && len(para) == 0 && len(firstCol) < 6 {
			if cells := tableCells(t); strings.Trim(strings.Join(cells, ""), "-: ") != "" {
				firstCol = append(firstCol, cells[0])
			}
			continue
		}
		if len(firstCol) > 1 { // a table came first: name what it lists
			break
		}
		if inCode || strings.HasPrefix(t, "|") || strings.HasPrefix(t, "#") || strings.HasPrefix(t, "<") {
			if len(para) > 0 {
				break
			}
			continue
		}
		if t == "" || t == "---" {
			if len(para) > 0 {
				break
			}
			continue
		}
		if m := helpListRe.FindStringSubmatch(l); m != nil {
			if len(para) > 0 {
				break
			}
			t = m[3]
		}
		para = append(para, strings.TrimPrefix(t, "> "))
	}
	if len(para) == 0 && len(firstCol) > 1 {
		return plainInline(strings.Join(firstCol[1:], ", ")) + ", …" // [0] is the header
	}
	s := plainInline(strings.Join(para, " "))
	if m := helpSentRe.FindStringSubmatch(s); m != nil {
		s = m[1]
	}
	if r := []rune(s); len(r) > 110 {
		s = string(r[:109]) + "…"
	}
	return s
}

// plainInline drops inline markdown: **bold**, `code`, [text](url).
func plainInline(s string) string {
	s = helpLinkRe.ReplaceAllString(s, "$1")
	s = strings.ReplaceAll(s, "**", "")
	s = strings.ReplaceAll(s, "`", "")
	return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(s), ">"))
}

// ---------------------------------------------------------------------------
// Rendering: markdown to wrapped tview text
// ---------------------------------------------------------------------------

// Styles are complete tview tags (foreground:background:attributes), so
// every piece of text sets its own and nothing has to be restored.
const (
	hsText    = "white:-:-"
	hsBold    = "white:-:b"
	hsCode    = "aqua:-:-"
	hsBlock   = "green:-:-"
	hsLink    = "aqua:-:u"
	hsDim     = "gray:-:-"
	hsHeading = "yellow:-:b"
	hsBullet  = "aqua:-:-"
	hsMark    = "black:yellow:-"
	hsCurrent = "black:aqua:b"
)

type hspan struct {
	text  string
	style string
	mark  int // search match number, or -1
}

// inlineSpans parses `code`, **bold** and [links](url) into styled spans.
func inlineSpans(s, base string) []hspan {
	var out []hspan
	var plain strings.Builder
	flush := func() {
		if plain.Len() > 0 {
			out = append(out, hspan{plain.String(), base, -1})
			plain.Reset()
		}
	}
	for i := 0; i < len(s); {
		switch {
		case s[i] == '`':
			if j := strings.IndexByte(s[i+1:], '`'); j >= 0 {
				flush()
				out = append(out, hspan{s[i+1 : i+1+j], hsCode, -1})
				i += j + 2
				continue
			}
		case strings.HasPrefix(s[i:], "**"):
			if j := strings.Index(s[i+2:], "**"); j >= 0 {
				flush()
				bold := hsBold
				if base == hsHeading {
					bold = hsHeading
				}
				out = append(out, inlineSpans(s[i+2:i+2+j], bold)...)
				i += j + 4
				continue
			}
		case s[i] == '[':
			if m := helpLinkRe.FindStringSubmatchIndex(s[i:]); m != nil && m[0] == 0 {
				flush()
				out = append(out, inlineSpans(s[i+m[2]:i+m[3]], hsLink)...)
				if url := s[i+m[4] : i+m[5]]; !strings.HasPrefix(url, "#") {
					out = append(out, hspan{" (" + url + ")", hsDim, -1})
				}
				i += m[1]
				continue
			}
		}
		plain.WriteByte(s[i])
		i++
	}
	flush()
	return out
}

// marker numbers search matches in the order they are laid out.
type marker struct {
	terms   []string
	n       int   // matches so far
	current int   // the match to show as current
	lines   []int // line of each match
}

// mark splits spans at the search terms' matches.
func (m *marker) mark(spans []hspan) []hspan {
	if m == nil || len(m.terms) == 0 {
		return spans
	}
	var out []hspan
	for _, sp := range spans {
		text := sp.text
		lower := strings.ToLower(text)
		if len(lower) != len(text) { // case folding changed the length: leave it
			out = append(out, sp)
			continue
		}
		for len(text) > 0 {
			at, size := -1, 0
			for _, t := range m.terms {
				if k := strings.Index(lower, t); k >= 0 && (at < 0 || k < at) {
					at, size = k, len(t)
				}
			}
			if at < 0 {
				out = append(out, hspan{text, sp.style, sp.mark})
				break
			}
			if at > 0 {
				out = append(out, hspan{text[:at], sp.style, sp.mark})
			}
			out = append(out, hspan{text[at : at+size], sp.style, 0}) // numbered at layout
			text, lower = text[at+size:], lower[at+size:]
		}
	}
	return out
}

// helpDoc collects rendered lines.
type helpDoc struct {
	width int
	lines []string
	m     *marker
}

func (d *helpDoc) blank() {
	if n := len(d.lines); n > 0 && d.lines[n-1] != "" {
		d.lines = append(d.lines, "")
	}
}

func (d *helpDoc) emit(p hspan) string {
	if p.mark < 0 || d.m == nil || len(d.m.terms) == 0 {
		return "[" + p.style + "]" + tview.Escape(p.text)
	}
	n := d.m.n
	d.m.n++
	d.m.lines = append(d.m.lines, len(d.lines))
	style := hsMark
	if n == d.m.current {
		style = hsCurrent
	}
	return "[" + style + "]" + tview.Escape(p.text)
}

// wrap lays spans out in lines of at most d.width cells, the first line
// after prefix first and the others after rest.
func (d *helpDoc) wrap(spans []hspan, first, rest hspan) {
	spans = d.m.mark(spans)

	type word struct {
		parts []hspan
		w     int
	}
	var words []word
	var cur word
	for _, sp := range spans {
		text := sp.text
		for text != "" {
			k := strings.IndexAny(text, " \t")
			if k < 0 {
				cur.parts = append(cur.parts, hspan{text, sp.style, sp.mark})
				cur.w += strWidth(text)
				break
			}
			if k > 0 {
				cur.parts = append(cur.parts, hspan{text[:k], sp.style, sp.mark})
				cur.w += strWidth(text[:k])
			}
			if len(cur.parts) > 0 {
				words = append(words, cur)
				cur = word{}
			}
			text = strings.TrimLeft(text[k:], " \t")
		}
	}
	if len(cur.parts) > 0 {
		words = append(words, cur)
	}

	var b strings.Builder
	prefix := first
	used := 0
	start := func() {
		b.Reset()
		b.WriteString("[" + prefix.style + "]" + tview.Escape(prefix.text))
		used = 0
	}
	start()
	avail := max(10, d.width-strWidth(prefix.text))
	for _, wd := range words {
		if used > 0 && used+1+wd.w > avail {
			d.lines = append(d.lines, b.String())
			prefix = rest
			avail = max(10, d.width-strWidth(prefix.text))
			start()
		}
		if used > 0 {
			b.WriteString("[" + hsText + "] ")
			used++
		}
		for _, p := range wd.parts {
			b.WriteString(d.emit(p))
		}
		used += wd.w
	}
	d.lines = append(d.lines, b.String())
}

// code adds a code line, cut into pieces that fit (indented under it).
func (d *helpDoc) code(line string) {
	line = strings.ReplaceAll(line, "\t", "    ")
	avail := max(10, d.width-4)
	r := []rune(line)
	first := true
	for first || len(r) > 0 {
		n := min(len(r), avail)
		if n < len(r) { // break at a space when there is one late enough
			for j := n - 1; j > n/2; j-- {
				if r[j] == ' ' {
					n = j + 1
					break
				}
			}
		}
		prefix := "    "
		if first {
			prefix = "  "
			avail = max(10, d.width-4)
		}
		var b strings.Builder
		b.WriteString(prefix)
		for _, p := range d.m.mark([]hspan{{string(r[:n]), hsBlock, -1}}) {
			b.WriteString(d.emit(p))
		}
		d.lines = append(d.lines, b.String())
		r = r[n:]
		first = false
	}
}

func isSpecialLine(l string) bool {
	t := strings.TrimSpace(l)
	return t == "" || t == "---" || t == "***" || strings.HasPrefix(t, "#") ||
		strings.HasPrefix(t, "|") || strings.HasPrefix(t, ">") || strings.HasPrefix(t, "<") ||
		helpFenceRe.MatchString(l) || helpListRe.MatchString(l)
}

func tableCells(row string) []string {
	row = strings.TrimSpace(row)
	row = strings.TrimSuffix(strings.TrimPrefix(row, "|"), "|")
	cells := strings.Split(row, "|")
	for i := range cells {
		cells[i] = strings.TrimSpace(cells[i])
	}
	return cells
}

// render lays out topic i for a window width, with search terms marked;
// it returns the text and the line of each match.
func renderHelpTopic(topics []helpTopic, i, width int, terms []string, current int) (string, []int) {
	t := topics[i]
	d := &helpDoc{width: max(20, width-2), m: &marker{terms: terms, current: current}}
	none := hspan{"", hsText, -1}

	if t.parent != "" {
		d.lines = append(d.lines, "[gray:-:-]"+tview.Escape(t.parent)+" ›")
	}
	d.wrap(inlineSpans(t.title, hsHeading), none, none)
	d.lines = append(d.lines, "[yellow:-:-]"+strings.Repeat("─", min(d.width, strWidth(plainInline(t.title))+2)))
	d.lines = append(d.lines, "")

	lines := t.lines
	for k := 0; k < len(lines); {
		line := lines[k]
		trim := strings.TrimSpace(line)
		switch {
		case helpFenceRe.MatchString(line):
			k++
			for k < len(lines) && !helpFenceRe.MatchString(lines[k]) {
				d.code(lines[k])
				k++
			}
			k++
		case trim == "":
			d.blank()
			k++
		case trim == "---" || trim == "***":
			d.blank()
			d.lines = append(d.lines, "[gray:-:-]"+strings.Repeat("─", min(d.width, 60)), "")
			k++
		case strings.HasPrefix(trim, "#"):
			d.blank()
			d.wrap(inlineSpans(strings.TrimSpace(strings.TrimLeft(trim, "#")), hsHeading), none, none)
			k++
		case strings.HasPrefix(trim, "|"):
			header := true
			for ; k < len(lines) && strings.HasPrefix(strings.TrimSpace(lines[k]), "|"); k++ {
				cells := tableCells(lines[k])
				if strings.Trim(strings.Join(cells, ""), "-: ") == "" {
					continue // the |---|---| row
				}
				if header { // the column names, dimmed, as a key for the rows
					header = false
					d.wrap([]hspan{{plainInline(strings.Join(cells, " — ")), hsDim, -1}},
						hspan{"    ", hsText, -1}, hspan{"    ", hsText, -1})
					continue
				}
				spans := inlineSpans(cells[0], hsBold)
				if len(cells) > 1 {
					spans = append(spans, hspan{" — ", hsDim, -1})
					for c, cell := range cells[1:] {
						if c > 0 {
							spans = append(spans, hspan{" · ", hsDim, -1})
						}
						spans = append(spans, inlineSpans(cell, hsText)...)
					}
				}
				d.wrap(spans, hspan{"  • ", hsBullet, -1}, hspan{"    ", hsText, -1})
			}
		case strings.HasPrefix(trim, ">"):
			var parts []string
			for ; k < len(lines) && strings.HasPrefix(strings.TrimSpace(lines[k]), ">"); k++ {
				parts = append(parts, strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(lines[k]), ">")))
			}
			bar := hspan{"  ┃ ", hsBullet, -1}
			d.wrap(inlineSpans(strings.Join(parts, " "), hsText), bar, bar)
		case strings.HasPrefix(trim, "<"):
			k++ // HTML: comments, <details> and the like
		case helpListRe.MatchString(line):
			m := helpListRe.FindStringSubmatch(line)
			text := []string{m[3]}
			for k++; k < len(lines) && !isSpecialLine(lines[k]); k++ {
				text = append(text, strings.TrimSpace(lines[k]))
			}
			level := min(3, len(strings.ReplaceAll(m[1], "\t", "  "))/2)
			bullet := "•"
			if m[2] != "-" && m[2] != "*" && m[2] != "+" {
				bullet = m[2]
			}
			pad := strings.Repeat("  ", level+1)
			first := hspan{pad + bullet + " ", hsBullet, -1}
			d.wrap(inlineSpans(strings.Join(text, " "), hsText), first,
				hspan{strings.Repeat(" ", strWidth(first.text)), hsText, -1})
		default:
			text := []string{trim}
			for k++; k < len(lines) && !isSpecialLine(lines[k]); k++ {
				text = append(text, strings.TrimSpace(lines[k]))
			}
			d.wrap(inlineSpans(strings.Join(text, " "), hsText), none, none)
		}
	}

	// A ## topic lists the topics under it.
	if t.level == 1 {
		var kids []string
		for _, o := range topics[i+1:] {
			if o.level == 1 {
				break
			}
			kids = append(kids, o.title)
		}
		if len(kids) > 0 {
			d.blank()
			d.wrap([]hspan{{"In this section (→ next topic): " + strings.Join(kids, " · "), hsDim, -1}}, none, none)
		}
	}
	return strings.Join(d.lines, "\n"), d.m.lines
}

// searchTerms splits a query into lower-case words.
func searchTerms(q string) []string { return strings.Fields(strings.ToLower(q)) }

// helpMatches says whether topic t contains every term.
func helpMatches(t helpTopic, terms []string) bool {
	for _, term := range terms {
		if !strings.Contains(t.search, term) {
			return false
		}
	}
	return true
}

// helpScore ranks a search result: words in the title count most, then
// how often the words appear.
func helpScore(t helpTopic, terms []string) int {
	score := 0
	title := strings.ToLower(t.title)
	for _, term := range terms {
		if strings.Contains(title, term) {
			score += 1000
		}
		score += min(strings.Count(t.search, term), 100)
	}
	return score
}

// topicBlocks is a topic's text as plain blocks: each paragraph, list item
// and table row on one line.
func topicBlocks(lines []string) []string {
	var out []string
	var cur []string
	flush := func() {
		if len(cur) > 0 {
			out = append(out, plainInline(strings.Join(cur, " ")))
			cur = nil
		}
	}
	for _, l := range lines {
		t := strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(t, "|"):
			flush()
			out = append(out, plainInline(strings.Join(tableCells(l), " — ")))
		case helpListRe.MatchString(l):
			flush()
			cur = append(cur, helpListRe.FindStringSubmatch(l)[3])
		case isSpecialLine(l) && !strings.HasPrefix(t, ">"):
			flush()
			if t != "" && !strings.HasPrefix(t, "<") && t != "---" {
				out = append(out, plainInline(t))
			}
		default:
			cur = append(cur, strings.TrimPrefix(t, "> "))
		}
	}
	flush()
	return out
}

// helpSnippet is the first block of t that has the first term, cut around it.
func helpSnippet(t helpTopic, terms []string) string {
	if len(terms) == 0 {
		return t.desc
	}
	for _, p := range topicBlocks(t.lines) {
		k := strings.Index(strings.ToLower(p), terms[0])
		if k < 0 || len(strings.ToLower(p)) != len(p) {
			continue
		}
		start := max(0, k-35)
		for start > 0 && start < len(p) && p[start-1] != ' ' {
			start--
		}
		s := p[start:]
		if start > 0 {
			s = "…" + s
		}
		if r := []rune(s); len(r) > 100 {
			s = string(r[:99]) + "…"
		}
		return s
	}
	return t.desc
}

// ---------------------------------------------------------------------------
// Screens
// ---------------------------------------------------------------------------

// helpText is a TextView laid out by our own wrapping, again whenever its
// width changes (so lists keep their hanging indent).
type helpText struct {
	*tview.TextView
	render     func(width int) (string, []int)
	width      int
	dirty      bool
	markLines  []int
	scrollMark int // match to scroll into view after the next layout, or -1
}

func (h *helpText) Draw(screen tcell.Screen) {
	_, _, w, ht := h.GetInnerRect()
	if h.render != nil && (w != h.width || h.dirty) {
		h.width, h.dirty = w, false
		text, lines := h.render(w)
		h.markLines = lines
		h.SetText(text)
		if m := h.scrollMark; m >= 0 && m < len(lines) {
			row, _ := h.GetScrollOffset()
			if lines[m] < row || lines[m] >= row+ht {
				h.ScrollTo(max(0, lines[m]-ht/3), 0)
			}
		}
		h.scrollMark = -1
	}
	h.TextView.Draw(screen)
}

type helpScreen struct {
	app    *tview.Application
	pages  *tview.Pages
	footer *tview.TextView

	// reader
	view   *helpText
	reader *tview.Flex
	cur    int
	terms  []string
	mark   int
	back   func()

	// topic list and search
	input     *tview.InputField
	list      *tview.List
	index     *tview.Flex
	results   []int
	indexBack func()
}

var helpPg *helpScreen

func newHelpScreen(app *tview.Application, pages *tview.Pages, footer *tview.TextView) *helpScreen {
	h := &helpScreen{app: app, pages: pages, footer: footer}

	h.view = &helpText{TextView: tview.NewTextView().SetDynamicColors(true).SetWrap(false).SetScrollable(true), scrollMark: -1}
	h.view.SetBorder(true).SetTitleAlign(tview.AlignLeft)
	h.reader = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(h.view, 0, 1, true).
		AddItem(footer, 1, 0, false)

	h.input = tview.NewInputField().
		SetLabel(" Search: ").
		SetLabelColor(tcell.ColorYellow).
		SetPlaceholder("type words, e.g. longhorn disk").
		SetFieldBackgroundColor(panelColor).
		SetChangedFunc(func(string) { h.refreshIndex() })
	h.list = tview.NewList().
		ShowSecondaryText(true).
		SetHighlightFullLine(true).
		SetMainTextColor(tcell.ColorWhite).
		SetSecondaryTextColor(tcell.ColorGray).
		SetSelectedTextColor(tcell.ColorBlack).
		SetSelectedBackgroundColor(tcell.ColorAqua)
	body := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(nil, 1, 0, false).
		AddItem(h.input, 1, 0, true).
		AddItem(nil, 1, 0, false).
		AddItem(h.list, 0, 1, false)
	body.SetBorder(true).SetTitle(" HELP ").SetTitleAlign(tview.AlignLeft)
	h.index = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(body, 0, 1, true).
		AddItem(footer, 1, 0, false)
	return h
}

// helpMenuItems is the Help tab: Search Help, then every topic. back
// returns to the menu.
func helpMenuItems(back func()) []menuItem {
	items := []menuItem{{title: "Search Help",
		desc: "Type a few words (e.g. \"longhorn disk\") to find the right topic",
		run:  func() { helpPg.openIndex(back, true) }}}
	for i, t := range loadHelp() {
		i := i
		title := t.title
		if t.level == 2 {
			title = "   " + title
		}
		items = append(items, menuItem{title: title, desc: t.desc, run: func() { helpPg.openTopic(i, nil, back) }})
	}
	return items
}

// openTopic shows topic i, with terms highlighted (none: from the top).
func (h *helpScreen) openTopic(i int, terms []string, back func()) {
	topics := loadHelp()
	if i < 0 || i >= len(topics) {
		return
	}
	h.cur, h.terms, h.mark, h.back = i, terms, 0, back
	h.view.render = func(w int) (string, []int) {
		return renderHelpTopic(loadHelp(), h.cur, w, h.terms, h.mark)
	}
	h.view.dirty = true
	h.view.ScrollToBeginning()
	h.view.scrollMark = -1
	if len(terms) > 0 {
		h.view.scrollMark = 0
	}
	h.view.SetTitle(fmt.Sprintf(" HELP  ·  %d/%d ", i+1, len(topics)))
	h.pages.AddAndSwitchToPage("help", h.reader, true)
	h.readerFooter()
	h.app.SetFocus(h.view)
}

func (h *helpScreen) readerFooter() {
	s := " [aqua::b]↑/↓[-::-] Scroll    [aqua::b]←/→[-::-] Topic    [aqua::b]/[-::-] Search"
	if len(h.terms) > 0 {
		s += "    [aqua::b]N[-::-] Next match"
	}
	h.footer.SetText(s + "    [aqua::b]ESC[-::-] Back")
}

func (h *helpScreen) nextMark(dir int) {
	n := len(h.view.markLines)
	if n == 0 {
		return
	}
	h.mark = (h.mark + dir + n) % n
	h.view.dirty = true
	h.view.scrollMark = h.mark
}

// HandleKey handles keys on the reader ("help" page).
func (h *helpScreen) HandleKey(ev *tcell.EventKey) *tcell.EventKey {
	switch ev.Key() {
	case tcell.KeyEscape, tcell.KeyBackspace, tcell.KeyBackspace2:
		h.back()
		return nil
	case tcell.KeyLeft:
		h.openTopic(h.cur-1, nil, h.back)
		return nil
	case tcell.KeyRight:
		h.openTopic(h.cur+1, nil, h.back)
		return nil
	case tcell.KeyRune:
		switch ev.Rune() {
		case '/':
			h.openIndex(h.back, true)
			return nil
		case 'n':
			h.nextMark(1)
			return nil
		case 'N':
			h.nextMark(-1)
			return nil
		case 'q', 'Q':
			h.back()
			return nil
		}
	}
	return ev
}

// openIndex shows the topic list with the search box; back leaves it.
func (h *helpScreen) openIndex(back func(), search bool) {
	h.indexBack = back
	h.refreshIndex()
	h.showIndex(search)
}

func (h *helpScreen) showIndex(search bool) {
	h.pages.AddAndSwitchToPage("helpindex", h.index, true)
	h.footer.SetText(" [aqua::b]Type[-::-] Search    [aqua::b]↑/↓[-::-] Choose    [aqua::b]ENTER[-::-] Open    [aqua::b]ESC[-::-] Back")
	if search || len(h.results) == 0 {
		h.app.SetFocus(h.input)
	} else {
		h.app.SetFocus(h.list)
	}
}

func (h *helpScreen) refreshIndex() {
	topics := loadHelp()
	terms := searchTerms(h.input.GetText())
	h.results = h.results[:0]
	h.list.Clear()
	for i, t := range topics {
		if helpMatches(t, terms) {
			h.results = append(h.results, i)
		}
	}
	if len(terms) > 0 { // best first; without a search, in README order
		sort.SliceStable(h.results, func(a, b int) bool {
			return helpScore(topics[h.results[a]], terms) > helpScore(topics[h.results[b]], terms)
		})
	}
	for _, i := range h.results {
		t := topics[i]
		title := t.title
		if t.level == 2 {
			title = "   " + title
			if len(terms) > 0 {
				title = "   " + t.title + "  [gray](" + tview.Escape(t.parent) + ")[-]"
			}
		}
		i := i
		h.list.AddItem("  "+title, "    "+tview.Escape(helpSnippet(t, terms)), 0, func() {
			h.openTopic(i, searchTerms(h.input.GetText()), func() { h.showIndex(false) })
		})
	}
	if len(h.results) == 0 {
		h.list.AddItem("  [gray]No topic has all of: "+tview.Escape(strings.Join(terms, " "))+"[-]", "", 0, nil)
	}
}

// HandleIndexKey handles keys on the topic list ("helpindex" page).
func (h *helpScreen) HandleIndexKey(ev *tcell.EventKey) *tcell.EventKey {
	if ev.Key() == tcell.KeyEscape {
		h.indexBack()
		return nil
	}
	if h.input.HasFocus() {
		switch ev.Key() {
		case tcell.KeyEnter:
			if len(h.results) > 0 {
				i := h.results[h.list.GetCurrentItem()%len(h.results)]
				h.openTopic(i, searchTerms(h.input.GetText()), func() { h.showIndex(false) })
			}
			return nil
		case tcell.KeyDown, tcell.KeyTab:
			h.app.SetFocus(h.list)
			return nil
		}
		return ev
	}
	switch ev.Key() {
	case tcell.KeyUp:
		if h.list.GetCurrentItem() == 0 {
			h.app.SetFocus(h.input)
			return nil
		}
	case tcell.KeyBacktab:
		h.app.SetFocus(h.input)
		return nil
	case tcell.KeyRune:
		// Typing in the list goes on in the search box.
		if r := ev.Rune(); r != ' ' {
			h.input.SetText(h.input.GetText() + string(r))
			h.app.SetFocus(h.input)
			return nil
		}
	}
	return ev
}
