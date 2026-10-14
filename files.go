package main

// Files: a two-pane file manager across this computer and every node
// (like superfile / Midnight Commander). Each pane shows any location;
// copy and move go from the active pane to the other one (files_copy.go).

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// fmLocation is a place a pane can show.
type fmLocation struct {
	label  string // "This computer", a node's name, or "vol <ns>/<claim>"
	light  string // status light markup ("" for this computer)
	note   string // shown after the label in the device list
	volume bool
	open   func() (fileSys, error)
}

// firstVolume as a start location: the first Longhorn volume.
const firstVolume = "vol:"

// volumeLabel is the start location for a volume ("" = the first one).
func volumeLabel(ns, pvc string) string {
	if ns == "" {
		return firstVolume
	}
	return "vol " + ns + "/" + pvc
}

// fmOptions configures Files.
type fmOptions struct {
	locations []fmLocation
	// more loads extra locations in the background (Longhorn volumes).
	more   func() ([]fmLocation, error)
	kube   kubeRunner
	isNode func(string) bool
	// start: the location labels the panes open on ("" = the defaults:
	// the first location, then the second).
	start [2]string
	back  func()
}

type fmPane struct {
	fm      *fileManager
	idx     int
	fs      fileSys
	loc     string
	dir     string
	entries []fsEntry
	results []fsHit // search results; nil when browsing
	shown   []int
	marks   map[string]bool // marked names (in dir)
	filter  string
	hidden  bool // show dotfiles
	status  string
	seq     int
	dirs    map[string]string // last folder per location

	head  *tview.TextView
	table *tview.Table
	box   *tview.Flex
}

type fileManager struct {
	app    *tview.Application
	pages  *tview.Pages
	footer *tview.TextView
	back   func()

	locations []fmLocation
	kube      kubeRunner
	isNode    func(string) bool

	panes  [2]*fmPane
	active int
	note   *tview.TextView
	screen *tview.Flex
	input  string // "filter", "search", "goto" while typing those
	typed  string
}

func (fm *fileManager) log(line string) {
	f, err := os.OpenFile(filepath.Join(kubestuiDir(), "files.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s %s\n", time.Now().Format(time.RFC3339), line)
}

// openFileManager shows Files. Pane 1 starts on the first location, pane 2
// on the second (the first node), so copying across is one key away.
func openFileManager(app *tview.Application, pages *tview.Pages, footer *tview.TextView, opt fmOptions) {
	locations, kube, isNode, back := opt.locations, opt.kube, opt.isNode, opt.back
	fm := &fileManager{app: app, pages: pages, footer: footer, back: back,
		locations: locations, kube: kube, isNode: isNode}
	fm.note = tview.NewTextView().SetDynamicColors(true)

	cols := tview.NewFlex()
	for i := range fm.panes {
		p := &fmPane{fm: fm, idx: i, marks: map[string]bool{}, dirs: map[string]string{}}
		p.head = tview.NewTextView().SetDynamicColors(true)
		p.table = tview.NewTable().SetSelectable(true, false).SetFixed(1, 0)
		p.table.SetBorderPadding(0, 0, 1, 1)
		p.box = tview.NewFlex().SetDirection(tview.FlexRow).
			AddItem(p.head, 2, 0, false).
			AddItem(p.table, 0, 1, true)
		p.box.SetBorder(true)
		fm.panes[i] = p
		cols.AddItem(p.box, 0, 1, i == 0)
	}

	body := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(cols, 0, 1, true).
		AddItem(fm.note, 1, 0, false)
	fm.screen = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(body, 0, 1, true).
		AddItem(footer, 1, 0, false)
	fm.screen.SetInputCapture(fm.key)
	fm.screen.SetMouseCapture(func(action tview.MouseAction, ev *tcell.EventMouse) (tview.MouseAction, *tcell.EventMouse) {
		if action == tview.MouseLeftClick {
			if name, _ := fm.pages.GetFrontPage(); name != "files" {
				return action, ev
			}
			for i, p := range fm.panes {
				if !p.box.InRect(ev.Position()) {
					continue
				}
				if i != fm.active {
					fm.focus(i)
				}
				if _, y := ev.Position(); y == func() int { _, hy, _, _ := p.head.GetInnerRect(); return hy }() {
					fm.pickLocation() // the device line
					return tview.MouseConsumed, nil
				}
			}
		}
		return action, ev
	})

	pages.AddAndSwitchToPage("files", fm.screen, true)
	fm.setFooter()
	fm.focus(0)
	// Default devices; a requested one (e.g. a volume from the Command
	// Center) opens once it's in the list.
	openStart := func(pane int, def int) bool { // false: wait for more
		want := opt.start[pane]
		for i, l := range fm.locations {
			if want != "" && (l.label == want || (want == firstVolume && l.volume)) {
				fm.panes[pane].openLocation(i)
				return true
			}
		}
		if want == "" || opt.more == nil {
			fm.panes[pane].openLocation(min(def, len(fm.locations)-1))
			return true
		}
		return false
	}
	waiting := [2]bool{!openStart(0, 0), !openStart(1, 1)}
	if opt.more != nil {
		go func() {
			more, err := opt.more()
			fm.app.QueueUpdateDraw(func() {
				if err != nil {
					fm.flash("[yellow]Longhorn volumes unavailable: " + tview.Escape(err.Error()) + "[-]")
				}
				fm.locations = append(fm.locations, more...)
				for pane := range fm.panes {
					if waiting[pane] && !openStart(pane, pane) {
						// The wanted volume isn't there: the default.
						fm.panes[pane].openLocation(min(pane, len(fm.locations)-1))
						fm.flash("[yellow]" + tview.Escape(opt.start[pane]) + " wasn't found.[-]")
					}
				}
			})
		}()
	}
}

func (fm *fileManager) setFooter() {
	fm.footer.SetText(" [aqua::b]TAB[-::-] Pane  [aqua::b]o [ ][-::-] Device  [aqua::b]ENTER[-::-] Open  [aqua::b]←[-::-] Up  [aqua::b]SPACE[-::-] Mark  " +
		"[aqua::b]c[-::-] Copy→  [aqua::b]m[-::-] Move→  [aqua::b]r[-::-] Rename  [aqua::b]d[-::-] Delete  [aqua::b]n[-::-] New folder  " +
		"[aqua::b]/[-::-] Filter  [aqua::b]?[-::-] Search  [aqua::b]g[-::-] Go to  [aqua::b]i[-::-] Size  [aqua::b]ESC[-::-] Back")
}

func (fm *fileManager) focus(i int) {
	fm.active = i
	for j, p := range fm.panes {
		color := tcell.ColorGray
		style := tcell.StyleDefault.Background(tcell.ColorDarkSlateGray).Foreground(tcell.ColorWhite)
		if j == i {
			color = tcell.ColorAqua
			style = tcell.StyleDefault.Background(tcell.ColorAqua).Foreground(tcell.ColorBlack)
		}
		p.box.SetBorderColor(color)
		p.table.SetSelectedStyle(style)
		p.render()
	}
	fm.app.SetFocus(fm.panes[i].table)
}

func (fm *fileManager) cur() *fmPane   { return fm.panes[fm.active] }
func (fm *fileManager) other() *fmPane { return fm.panes[1-fm.active] }

func (fm *fileManager) close() {
	for _, p := range fm.panes {
		p.seq++
		if p.fs != nil {
			p.fs.Close()
		}
	}
	fm.pages.RemovePage("files")
	fm.back()
}

// show returns to Files (after a copy or a dialog) and reloads both panes.
func (fm *fileManager) show() {
	fm.pages.SwitchToPage("files")
	fm.setFooter()
	fm.focus(fm.active)
	for _, p := range fm.panes {
		p.reload()
	}
}

// ---------------------------------------------------------------------------
// A pane
// ---------------------------------------------------------------------------

func (p *fmPane) openLocation(i int) {
	loc := p.fm.locations[i]
	p.seq++
	seq := p.seq
	p.status = "[gray]Connecting to " + tview.Escape(loc.label) + "…[-]"
	p.render()
	go func() {
		fs, err := loc.open()
		p.fm.app.QueueUpdateDraw(func() {
			if seq != p.seq {
				if fs != nil && err == nil {
					fs.Close()
				}
				return
			}
			if err != nil {
				p.status = "[red]" + tview.Escape(loc.label) + ": " + tview.Escape(err.Error()) + "[-]"
				p.render()
				return
			}
			if p.fs != nil && p.fs != p.fm.other().fs {
				p.fs.Close()
			}
			if p.fs != nil {
				p.dirs[p.loc] = p.dir
			}
			p.fs, p.loc = fs, loc.label
			dir := p.dirs[loc.label]
			if dir == "" {
				dir = fs.Home()
			}
			p.cd(dir)
		})
	}()
}

// root is the top of the pane's device ("/", or /data for a volume).
func (p *fmPane) root() string {
	if r, ok := p.fs.(interface{ Root() string }); ok {
		return r.Root()
	}
	return "/"
}

func (p *fmPane) cd(dir string) {
	if p.fs == nil {
		return
	}
	dir = path.Clean("/" + dir)
	if root := p.root(); dir != root && !strings.HasPrefix(dir, strings.TrimSuffix(root, "/")+"/") {
		dir = root // a volume: nothing above it
	}
	if dir != p.dir {
		p.marks = map[string]bool{}
	}
	p.dir, p.results, p.filter = dir, nil, ""
	p.reload()
}

// reload lists the folder again (keeps marks and the selected row).
func (p *fmPane) reload() {
	if p.fs == nil {
		return
	}
	if p.results != nil {
		return
	}
	p.status = "[gray]Loading…[-]"
	p.render()
	p.seq++
	seq, fs, dir := p.seq, p.fs, p.dir
	go func() {
		entries, err := fs.List(dir)
		p.fm.app.QueueUpdateDraw(func() {
			if seq != p.seq {
				return
			}
			p.status = ""
			if err != nil {
				p.status = "[red]" + tview.Escape(err.Error()) + "[-]"
			}
			sort.SliceStable(entries, func(i, j int) bool {
				if entries[i].dir != entries[j].dir {
					return entries[i].dir
				}
				return strings.ToLower(entries[i].name) < strings.ToLower(entries[j].name)
			})
			p.entries = entries
			for n := range p.marks { // forget marks on names that are gone
				found := false
				for _, e := range entries {
					found = found || e.name == n
				}
				if !found {
					delete(p.marks, n)
				}
			}
			p.render()
		})
	}()
}

func (p *fmPane) render() {
	light, label := "", p.loc
	for _, l := range p.fm.locations {
		if l.label == p.loc {
			light = l.light
		}
	}
	if label == "" {
		label = "…"
	}
	marks := ""
	if n := len(p.marks); n > 0 {
		marks = fmt.Sprintf("  [yellow]%d marked[-]", n)
	}
	hint := ""
	if p.fm.active == p.idx {
		hint = "  [gray]o / [ ] change device[-]"
	}
	head := " " + light + " [::b]" + tview.Escape(label) + " ▾[::-]" + marks + hint + "\n [yellow]" + tview.Escape(p.dir) + "[-]"
	if p.fm.active == p.idx && p.fm.input != "" {
		head = " " + light + " [::b]" + tview.Escape(label) + " ▾[::-]\n [aqua::b]" +
			map[string]string{"filter": "Filter:", "search": "Search below:", "goto": "Go to:"}[p.fm.input] +
			"[-::-] " + tview.Escape(p.fm.typed) + "▌"
	} else if p.filter != "" {
		head += "  [aqua]filter: " + tview.Escape(p.filter) + "[-]"
	}
	p.head.SetText(head)
	p.box.SetTitle("")
	if p.status != "" {
		p.box.SetTitle(" " + p.status + " ")
	}

	sel, _ := p.table.GetSelection()
	p.table.Clear()
	p.shown = p.shown[:0]
	f := strings.ToLower(p.filter)

	if p.results != nil {
		p.table.SetCell(0, 0, tview.NewTableCell(" FOUND (ESC back)").SetTextColor(tcell.ColorYellow).SetSelectable(false).SetExpansion(1))
		for i, h := range p.results {
			if f != "" && !strings.Contains(strings.ToLower(h.path), f) {
				continue
			}
			p.shown = append(p.shown, i)
			name, color := " "+h.path, tcell.ColorWhite
			if h.dir {
				name, color = name+"/", tcell.ColorAqua
			}
			p.table.SetCell(len(p.shown), 0, tview.NewTableCell(tview.Escape(name)).SetTextColor(color).SetExpansion(1))
		}
	} else {
		for i, h := range []string{" NAME", "SIZE ", " MODIFIED"} {
			c := tview.NewTableCell(h).SetTextColor(tcell.ColorYellow).SetSelectable(false)
			if i == 0 {
				c.SetExpansion(1)
			} else if i == 1 {
				c.SetAlign(tview.AlignRight)
			}
			p.table.SetCell(0, i, c)
		}
		if p.dir != p.root() && f == "" {
			p.shown = append(p.shown, -1)
			p.table.SetCell(1, 0, tview.NewTableCell(" ../").SetTextColor(tcell.ColorAqua).SetExpansion(1))
			p.table.SetCell(1, 1, tview.NewTableCell(""))
			p.table.SetCell(1, 2, tview.NewTableCell(""))
		}
		for i, e := range p.entries {
			if !p.hidden && strings.HasPrefix(e.name, ".") {
				continue
			}
			if f != "" && !strings.Contains(strings.ToLower(e.name), f) {
				continue
			}
			p.shown = append(p.shown, i)
			row := len(p.shown)
			mark := "  "
			if p.marks[e.name] {
				mark = "✓ "
			}
			name, color, size := mark+e.name, tcell.ColorWhite, fmtBytes(e.size)
			switch {
			case e.dir:
				name, color, size = name+"/", tcell.ColorAqua, ""
			case isComposeName(e.name):
				color = tcell.ColorGreen
			}
			if e.link {
				name += " →"
			}
			if p.marks[e.name] {
				color = tcell.ColorYellow
			}
			p.table.SetCell(row, 0, tview.NewTableCell(tview.Escape(name)).SetTextColor(color).SetExpansion(1))
			p.table.SetCell(row, 1, tview.NewTableCell(size+" ").SetTextColor(tcell.ColorGray).SetAlign(tview.AlignRight))
			p.table.SetCell(row, 2, tview.NewTableCell(" "+e.mod).SetTextColor(tcell.ColorGray))
		}
	}
	if sel < 1 || sel > len(p.shown) {
		sel = 1
	}
	p.table.Select(sel, 0)
}

// current returns the entry under the cursor (nil for ".." or none).
func (p *fmPane) current() *fsEntry {
	row, _ := p.table.GetSelection()
	if p.results != nil || row < 1 || row > len(p.shown) || p.shown[row-1] < 0 {
		return nil
	}
	return &p.entries[p.shown[row-1]]
}

// selection: the marked names, else the one under the cursor.
func (p *fmPane) selection() []string {
	var names []string
	for _, e := range p.entries {
		if p.marks[e.name] {
			names = append(names, e.name)
		}
	}
	if len(names) == 0 {
		if e := p.current(); e != nil {
			names = []string{e.name}
		}
	}
	return names
}

func (p *fmPane) open() {
	row, _ := p.table.GetSelection()
	if row < 1 || row > len(p.shown) {
		return
	}
	if p.results != nil {
		h := p.results[p.shown[row-1]]
		if h.dir {
			p.cd(h.path)
		} else {
			p.cd(path.Dir(h.path))
		}
		return
	}
	i := p.shown[row-1]
	if i < 0 {
		p.cd(path.Dir(p.dir))
		return
	}
	e := p.entries[i]
	if e.dir {
		p.cd(path.Join(p.dir, e.name))
		return
	}
	p.fm.preview(p, path.Join(p.dir, e.name), e)
}

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

func (fm *fileManager) flash(text string) { fm.note.SetText("  " + text) }

func (fm *fileManager) preview(p *fmPane, file string, e fsEntry) {
	fs := p.fs
	fm.flash("[gray]Reading " + tview.Escape(path.Base(file)) + "…[-]")
	go func() {
		data, err := fs.ReadHead(file, 64*1024)
		fm.app.QueueUpdateDraw(func() {
			fm.flash("")
			var text string
			switch {
			case err != nil:
				text = "[red]" + tview.Escape(err.Error()) + "[-]"
			case strings.ContainsRune(string(data), 0) || !utf8.Valid(data):
				text = fmt.Sprintf("[gray]A binary file (%s), not shown as text.[-]", fmtBytes(e.size))
			default:
				text = tview.Escape(string(data))
				if e.size > int64(len(data)) {
					text += fmt.Sprintf("\n[gray]… (first %s of %s)[-]", fmtBytes(int64(len(data))), fmtBytes(e.size))
				}
			}
			tv := tview.NewTextView().SetDynamicColors(true).SetScrollable(true).SetText(text)
			tv.SetBorder(true).SetTitle(" " + tview.Escape(fs.Label()+":"+file) + "  (ESC closes) ").SetTitleAlign(tview.AlignLeft)
			tv.SetDoneFunc(func(tcell.Key) { fm.pages.RemovePage("fmpreview"); fm.focus(fm.active) })
			fm.pages.AddPage("fmpreview", tv, true, true)
			fm.app.SetFocus(tv)
		})
	}()
}

// ask shows a one-line question; done gets the answer (ok=false: cancelled).
func (fm *fileManager) ask(title, label, initial string, done func(string, bool)) {
	form := tview.NewForm().AddInputField(label, initial, 48, nil, nil)
	finish := func(text string, ok bool) {
		fm.pages.RemovePage("fmask")
		fm.focus(fm.active)
		done(text, ok)
	}
	field := form.GetFormItem(0).(*tview.InputField)
	field.SetDoneFunc(func(k tcell.Key) { // ENTER answers right away
		if k == tcell.KeyEnter {
			// After the form has handled the key (it moves focus to its
			// next item), or that would take the focus back.
			text := strings.TrimSpace(field.GetText())
			go fm.app.QueueUpdateDraw(func() { finish(text, true) })
		}
	})
	form.AddButton("OK", func() { finish(strings.TrimSpace(field.GetText()), true) })
	form.AddButton("Cancel", func() { finish("", false) })
	form.SetCancelFunc(func() { finish("", false) })
	styleForm(form)
	form.SetTitle(" " + title + " ")
	fm.pages.AddPage("fmask", centered(form, 70, 9), true, true)
	fm.app.SetFocus(form)
}

// guard refuses changes in system folders.
func (fm *fileManager) guard(paths ...string) bool {
	for _, pth := range paths {
		if why := protectedPath(pth); why != "" {
			fm.flash("[red]Not changed: " + tview.Escape(why) + " (browsing it is fine).[-]")
			return false
		}
	}
	return true
}

// do runs a change in the background, then reloads both panes.
func (fm *fileManager) do(what string, fn func() error) {
	fm.flash("[gray]" + tview.Escape(what) + "…[-]")
	go func() {
		err := fn()
		fm.app.QueueUpdateDraw(func() {
			if err != nil {
				fm.flash("[red]" + tview.Escape(what) + ": " + tview.Escape(err.Error()) + "[-]")
				fm.log(what + " FAILED: " + err.Error())
			} else {
				fm.flash("[green]" + tview.Escape(what) + ": done.[-]")
				fm.log(what)
			}
			for _, p := range fm.panes {
				p.reload()
			}
		})
	}()
}

func (fm *fileManager) rename() {
	p := fm.cur()
	e := p.current()
	if e == nil || p.fs == nil {
		return
	}
	from := path.Join(p.dir, e.name)
	if !fm.guard(from) {
		return
	}
	fm.ask("RENAME", "New name", e.name, func(name string, ok bool) {
		if !ok || name == "" || name == e.name {
			return
		}
		if strings.ContainsRune(name, '/') {
			fm.flash("[red]A name can't contain /.[-]")
			return
		}
		to := path.Join(p.dir, name)
		fm.do(fmt.Sprintf("Rename %s:%s to %s", p.fs.Label(), from, name), func() error { return p.fs.Rename(from, to) })
	})
}

func (fm *fileManager) mkdir() {
	p := fm.cur()
	if p.fs == nil {
		return
	}
	fm.ask("NEW FOLDER", "Name", "", func(name string, ok bool) {
		if !ok || name == "" {
			return
		}
		dir := path.Join(p.dir, name)
		if !fm.guard(dir) {
			return
		}
		fm.do("New folder "+p.fs.Label()+":"+dir, func() error { return p.fs.Mkdir(dir) })
	})
}

func (fm *fileManager) remove() {
	p := fm.cur()
	names := p.selection()
	if len(names) == 0 || p.fs == nil {
		return
	}
	var paths []string
	for _, n := range names {
		paths = append(paths, path.Join(p.dir, n))
	}
	if !fm.guard(paths...) {
		return
	}
	list := strings.Join(names, "\n")
	if len(names) > 8 {
		list = strings.Join(names[:8], "\n") + fmt.Sprintf("\n… and %d more", len(names)-8)
	}
	showConfirm("DELETE", fmt.Sprintf("Delete %d item(s) on %s?\n%s\n\n%s\n\nThis can't be undone.", len(names), p.fs.Label(), p.dir, list),
		"Delete", "Cancel", func(ok bool) {
			fm.focus(fm.active)
			if !ok {
				return
			}
			p.marks = map[string]bool{}
			fm.do(fmt.Sprintf("Delete %d item(s) on %s in %s %v", len(names), p.fs.Label(), p.dir, names), func() error { return p.fs.Remove(paths) })
		})
}

func (fm *fileManager) size() {
	p := fm.cur()
	names := p.selection()
	if len(names) == 0 || p.fs == nil {
		return
	}
	var paths []string
	for _, n := range names {
		paths = append(paths, path.Join(p.dir, n))
	}
	fs := p.fs
	fm.flash("[gray]Measuring…[-]")
	go func() {
		b, err := fs.DiskUsage(paths)
		fm.app.QueueUpdateDraw(func() {
			if err != nil {
				fm.flash("[red]" + tview.Escape(err.Error()) + "[-]")
				return
			}
			what := names[0]
			if len(names) > 1 {
				what = fmt.Sprintf("%d items", len(names))
			}
			fm.flash(fmt.Sprintf("[green]%s: %s[-]", tview.Escape(what), fmtBytes(b)))
		})
	}()
}

func (fm *fileManager) transfer(move bool) {
	src, dst := fm.cur(), fm.other()
	names := src.selection()
	if len(names) == 0 || src.fs == nil || dst.fs == nil {
		fm.flash("[yellow]Select something (SPACE marks several), and open a folder in the other pane.[-]")
		return
	}
	if dst.results != nil {
		fm.flash("[yellow]The other pane shows search results: open a folder there first.[-]")
		return
	}
	verb := "Copy"
	if move {
		verb = "Move"
	}
	same := src.fs.Label() == dst.fs.Label()
	for _, n := range names {
		sp := path.Join(src.dir, n)
		if same && (dst.dir == src.dir || dst.dir == sp || strings.HasPrefix(dst.dir, sp+"/")) {
			fm.flash("[red]" + verb + " into the same folder or into itself isn't possible.[-]")
			return
		}
	}
	if !fm.guard(dst.dir + "/x") {
		return
	}
	if move {
		var paths []string
		for _, n := range names {
			paths = append(paths, path.Join(src.dir, n))
		}
		if !fm.guard(paths...) {
			return
		}
	}
	var replace []string
	for _, n := range names {
		for _, e := range dst.entries {
			if e.name == n {
				replace = append(replace, n)
			}
		}
	}
	text := fmt.Sprintf("%s %d item(s)\n\nfrom  %s:%s\nto    %s:%s", verb, len(names), src.fs.Label(), src.dir, dst.fs.Label(), dst.dir)
	if len(replace) > 0 {
		text += fmt.Sprintf("\n\n%d already there will be overwritten:\n  %s", len(replace), strings.Join(replace, ", "))
	}
	showConfirm(strings.ToUpper(verb), text, verb, "Cancel", func(ok bool) {
		fm.focus(fm.active)
		if !ok {
			return
		}
		plan := &copyPlan{src: src.fs, dst: dst.fs, srcDir: src.dir, names: names, dest: dst.dir,
			move: move, kube: fm.kube, isNode: fm.isNode, log: fm.log}
		src.marks = map[string]bool{}
		termPage.Open(termLaunch{
			title:  fmt.Sprintf("%s  %s → %s", strings.ToUpper(verb), src.fs.Label(), dst.fs.Label()),
			target: fmt.Sprintf("%s:%s → %s:%s", src.fs.Label(), src.dir, dst.fs.Label(), dst.dir),
			okText: map[bool]string{true: "MOVED", false: "COPIED"}[move],
			demo:   plan.script(),
		}, fm.show)
	})
}

// cycleLocation shows the previous/next device in the active pane.
func (fm *fileManager) cycleLocation(step int) {
	p, n := fm.cur(), len(fm.locations)
	cur := 0
	for i, l := range fm.locations {
		if l.label == p.loc {
			cur = i
		}
	}
	p.openLocation(((cur+step)%n + n) % n)
}

func (fm *fileManager) pickLocation() {
	list := tview.NewList().ShowSecondaryText(false).SetHighlightFullLine(true).
		SetSelectedBackgroundColor(tcell.ColorAqua).SetSelectedTextColor(tcell.ColorBlack)
	closeList := func() { fm.pages.RemovePage("fmloc"); fm.focus(fm.active) }
	p := fm.cur()
	shownVolumes := false
	for i, l := range fm.locations {
		i := i
		if l.volume && !shownVolumes {
			shownVolumes = true
			list.AddItem("  [yellow::b]Longhorn volumes[-::-]", "", 0, nil)
		}
		light := l.light
		if light == "" {
			light = "■"
		}
		text := "  " + light + " " + tview.Escape(l.label)
		if l.label == p.loc {
			text += "  [aqua](showing)[-]"
			defer list.SetCurrentItem(list.GetItemCount()) // this item's row
		} else if l.label == fm.other().loc {
			text += "  [gray](other pane)[-]"
		}
		if l.note != "" {
			text += "  [gray]" + tview.Escape(l.note) + "[-]"
		}
		list.AddItem(text, "", 0, func() { closeList(); p.openLocation(i) })
	}
	if !shownVolumes && fm.kube != nil {
		list.AddItem("  [gray]Longhorn volumes: loading… (open this list again)[-]", "", 0, nil)
	}
	list.SetDoneFunc(closeList)
	side := map[int]string{0: "LEFT", 1: "RIGHT"}[p.idx]
	list.SetBorder(true).SetTitle(" DEVICE FOR THE " + side + " PANE ").SetTitleAlign(tview.AlignLeft)
	fm.pages.AddPage("fmloc", centered(list, 84, min(list.GetItemCount()+2, 24)), true, true)
	fm.app.SetFocus(list)
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

func (fm *fileManager) key(ev *tcell.EventKey) *tcell.EventKey {
	if name, _ := fm.pages.GetFrontPage(); name != "files" {
		return ev // a dialog or preview has the keys
	}
	p := fm.cur()

	if fm.input != "" { // typing a filter (live), a search term or a path
		mode := fm.input
		switch ev.Key() {
		case tcell.KeyEscape:
			fm.input, fm.typed = "", ""
			if mode == "filter" {
				p.filter = ""
			}
		case tcell.KeyEnter:
			typed := strings.TrimSpace(fm.typed)
			fm.input, fm.typed = "", ""
			switch {
			case mode == "search" && typed != "":
				fm.search(p, typed)
			case mode == "goto" && typed != "":
				if !strings.HasPrefix(typed, "/") {
					typed = path.Join(p.dir, typed)
				}
				p.cd(typed)
			}
		case tcell.KeyBackspace, tcell.KeyBackspace2:
			if r := []rune(fm.typed); len(r) > 0 {
				fm.typed = string(r[:len(r)-1])
			}
		case tcell.KeyRune:
			fm.typed += string(ev.Rune())
		}
		if fm.input == "filter" {
			p.filter = fm.typed
		}
		p.render()
		return nil
	}

	switch ev.Key() {
	case tcell.KeyTab, tcell.KeyBacktab:
		fm.focus(1 - fm.active)
		return nil
	case tcell.KeyEscape:
		switch {
		case p.filter != "":
			p.filter = ""
			p.render()
		case p.results != nil:
			p.results = nil
			p.reload()
		default:
			fm.close()
		}
		return nil
	case tcell.KeyEnter, tcell.KeyRight:
		p.open()
		return nil
	case tcell.KeyLeft, tcell.KeyBackspace, tcell.KeyBackspace2:
		p.cd(path.Dir(p.dir))
		return nil
	case tcell.KeyF5:
		fm.transfer(false)
		return nil
	case tcell.KeyF6:
		fm.transfer(true)
		return nil
	case tcell.KeyF2:
		fm.rename()
		return nil
	case tcell.KeyF7:
		fm.mkdir()
		return nil
	case tcell.KeyF8, tcell.KeyDelete:
		fm.remove()
		return nil
	case tcell.KeyCtrlR:
		p.reload()
		return nil
	case tcell.KeyCtrlA:
		all := len(p.marks) == 0
		p.marks = map[string]bool{}
		if all {
			for _, e := range p.entries {
				if p.hidden || !strings.HasPrefix(e.name, ".") {
					p.marks[e.name] = true
				}
			}
		}
		p.render()
		return nil
	case tcell.KeyRune:
		switch ev.Rune() {
		case ' ':
			if e := p.current(); e != nil {
				if p.marks[e.name] {
					delete(p.marks, e.name)
				} else {
					p.marks[e.name] = true
				}
				row, _ := p.table.GetSelection()
				p.render()
				p.table.Select(min(row+1, len(p.shown)), 0)
			}
		case 'c':
			fm.transfer(false)
		case 'm':
			fm.transfer(true)
		case 'r':
			fm.rename()
		case 'd':
			fm.remove()
		case 'n':
			fm.mkdir()
		case 'o':
			fm.pickLocation()
		case '[', ']':
			fm.cycleLocation(map[rune]int{'[': -1, ']': 1}[ev.Rune()])
		case 'i':
			fm.size()
		case '.':
			p.hidden = !p.hidden
			p.render()
		case '~':
			if p.fs != nil {
				p.cd(p.fs.Home())
			}
		case '/':
			fm.input, fm.typed = "filter", p.filter
			p.render()
		case '?':
			fm.input, fm.typed = "search", ""
			p.render()
		case 'g':
			fm.input, fm.typed = "goto", ""
			p.render()
		case 'q':
			fm.close()
		}
		return nil
	}
	return ev
}

func (fm *fileManager) search(p *fmPane, term string) {
	if p.fs == nil {
		return
	}
	fs, dir := p.fs, p.dir
	p.results = []fsHit{}
	p.status = "[gray]Searching \"" + tview.Escape(term) + "\" below " + tview.Escape(dir) + "…[-]"
	p.render()
	p.seq++
	seq := p.seq
	go func() {
		hits, err := fs.Find(dir, term)
		fm.app.QueueUpdateDraw(func() {
			if seq != p.seq {
				return
			}
			p.results = hits
			if p.results == nil {
				p.results = []fsHit{}
			}
			switch {
			case err != nil && len(hits) == 0:
				p.status = "[red]" + tview.Escape(err.Error()) + "[-]"
			default:
				p.status = fmt.Sprintf("[green]%d found[-]", len(hits))
			}
			p.render()
		})
	}()
}
