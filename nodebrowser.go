package main

// Node file browser: look through any node's file system over SSH and
// pick a file or folder. Type to filter the folder, / searches by name in
// this folder and below, Ctrl+F finds every compose file on the node.
// Listings run in the background, so the screen never waits.

import (
	"errors"
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"golang.org/x/crypto/ssh"
)

type fsEntry struct {
	name string
	dir  bool
	link bool
	size int64
	mod  string
}

// fsHit is a search result.
type fsHit struct {
	path string
	dir  bool
}

// nodeFS is a node's file system (over SSH, or the demo's).
type nodeFS interface {
	List(dir string) ([]fsEntry, error)
	Find(dir, name string) ([]fsHit, error)
	FindCompose() ([]fsHit, error)
	Home() string
	Close()
}

// ---------------------------------------------------------------------------
// Over SSH
// ---------------------------------------------------------------------------

type sshFS struct {
	client *ssh.Client
	label  string    // the node's name
	node   hostEntry // how to reach it (for new connections)
	keys   []string
	home   string

	// A Longhorn volume instead of a node (files_vol.go): commands run in
	// a helper pod, nothing outside root is shown, and closing removes
	// the pod.
	exec    func(cmd string) (string, error)
	root    string
	onClose func()
	vol     *volInfo
	pod     string // the helper pod
	stream  kubeStreamer
	mu      sync.Mutex
	sudo    int // 0 unknown, 1 sudo -n works, -1 it doesn't
}

func openSSHFS(node hostEntry, keys []string) (*sshFS, error) {
	c, err := dialSSH(dialTarget{Host: node.Host, Port: node.portOr22(), User: node.User, Keys: keys, Prompt: true})
	if err != nil {
		return nil, err
	}
	f := &sshFS{client: c, label: node.Name, node: node, keys: keys}
	if out, err := runRemote(c, `printf %s "$HOME"`, ""); err == nil {
		f.home = strings.TrimSpace(out)
	}
	if f.home == "" {
		f.home = "/"
	}
	return f, nil
}

func (f *sshFS) Home() string { return f.home }
func (f *sshFS) Close() {
	if f.client != nil {
		f.client.Close()
	}
	if f.onClose != nil {
		f.onClose()
	}
}

// Root is the top a pane may go up to ("/" for nodes).
func (f *sshFS) Root() string {
	if f.root != "" {
		return f.root
	}
	return "/"
}

// run runs a read-only command, retrying with sudo -n (no password) when
// the SSH user may not read there.
func (f *sshFS) run(cmd string) (string, error) {
	if f.exec != nil {
		return f.exec(cmd)
	}
	out, err := runRemote(f.client, cmd, "")
	if err == nil || !strings.Contains(err.Error(), "ermission denied") {
		return out, err
	}
	f.mu.Lock()
	if f.sudo == 0 {
		f.sudo = -1
		if _, e := runRemote(f.client, "sudo -n true", ""); e == nil {
			f.sudo = 1
		}
	}
	can := f.sudo == 1
	f.mu.Unlock()
	if !can {
		return out, errors.New("permission denied (the SSH user can't read here)")
	}
	return runRemote(f.client, "sudo -n sh -c "+shellQuote(cmd), "")
}

func (f *sshFS) List(dir string) ([]fsEntry, error) {
	// An explicit "Permission denied" (not the shell's "can't cd") lets
	// run retry with sudo.
	out, err := f.run("d=" + shellQuote(dir) + "; [ -r \"$d\" ] && [ -x \"$d\" ] || { echo \"$d: Permission denied\" >&2; exit 13; }; cd -- \"$d\" && LC_ALL=C find . -mindepth 1 -maxdepth 1 -printf '%Y\\t%y\\t%s\\t%TY-%Tm-%Td %TH:%TM\\t%f\\n'")
	if err != nil {
		return nil, err
	}
	var entries []fsEntry
	for _, line := range strings.Split(out, "\n") {
		parts := strings.SplitN(line, "\t", 5)
		if len(parts) != 5 {
			continue
		}
		size, _ := strconv.ParseInt(parts[2], 10, 64)
		mod := parts[3]
		if i := strings.IndexByte(mod, '.'); i > 0 {
			mod = mod[:i]
		}
		entries = append(entries, fsEntry{name: parts[4], dir: parts[0] == "d", link: parts[1] == "l", size: size, mod: mod})
	}
	return entries, nil
}

// Folders a search skips: virtual file systems and container internals.
const findPrune = `\( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /snap ` +
	`-o -path /var/lib/containerd -o -path /var/lib/kubelet -o -path /var/lib/longhorn ` +
	`-o -path /var/log/pods -o -path /var/lib/docker/overlay2 \) -prune -o `

// find runs a find that prints "TYPE<tab>PATH" lines (%Y: d for folders,
// following links).
func (f *sshFS) find(cmd string) ([]fsHit, error) {
	out, err := f.run(cmd)
	var hits []fsHit
	for _, l := range strings.Split(out, "\n") {
		if t, p, ok := strings.Cut(strings.TrimRight(l, "\r"), "\t"); ok && p != "" {
			hits = append(hits, fsHit{path: p, dir: t == "d"})
		}
	}
	if len(hits) > 0 {
		return hits, nil // a timeout still returns what it found
	}
	return nil, err
}

func (f *sshFS) Find(dir, name string) ([]fsHit, error) {
	return f.find("timeout 20 find " + shellQuote(dir) + " " + findPrune +
		"-iname " + shellQuote("*"+name+"*") + " -printf '%Y\\t%p\\n' 2>/dev/null | head -n 300")
}

func (f *sshFS) FindCompose() ([]fsHit, error) {
	return f.find("timeout 30 find / " + findPrune +
		`-type f \( -name docker-compose.yml -o -name docker-compose.yaml -o -name compose.yml -o -name compose.yaml \) -printf '%Y\t%p\n' 2>/dev/null | head -n 200`)
}

// ---------------------------------------------------------------------------
// Demo
// ---------------------------------------------------------------------------

type demoFS struct{}

var demoTree = map[string][]fsEntry{
	"/":                           {{name: "home", dir: true}, {name: "opt", dir: true}, {name: "mnt", dir: true}, {name: "etc", dir: true}, {name: "var", dir: true}},
	"/home":                       {{name: "admin", dir: true}},
	"/home/admin":                 {{name: "docker", dir: true}, {name: ".bashrc", size: 3771}, {name: "notes.txt", size: 812}},
	"/home/admin/docker":          {{name: "jellyfin", dir: true}, {name: "sonarr", dir: true}},
	"/home/admin/docker/jellyfin": {{name: "config", dir: true}, {name: "docker-compose.yml", size: 642}, {name: ".env", size: 88}},
	"/home/admin/docker/sonarr":   {{name: "config", dir: true}, {name: "compose.yaml", size: 511}},
	"/opt":                        {{name: "appdata", dir: true}},
	"/opt/appdata":                {{name: "qbittorrent", dir: true}, {name: "docker-compose.yml", size: 903}},
	"/mnt":                        {{name: "hdd", dir: true}},
	"/mnt/hdd":                    {{name: "media", dir: true}, {name: "torrents", dir: true}},
	"/etc":                        {{name: "hostname", size: 4}, {name: "fstab", size: 612}},
	"/var":                        {{name: "log", dir: true}},
}

func (demoFS) Home() string { return "/home/admin" }
func (demoFS) Close()       {}

func (demoFS) List(dir string) ([]fsEntry, error) {
	time.Sleep(120 * time.Millisecond)
	if e, ok := demoTree[dir]; ok {
		for i := range e {
			if e[i].mod == "" {
				e[i].mod = "2026-09-30 18:42"
			}
			if e[i].dir {
				e[i].size = 4096
			}
		}
		return e, nil
	}
	return nil, nil
}

func (demoFS) Find(dir, name string) ([]fsHit, error) {
	var out []fsHit
	for d, entries := range demoTree {
		if !strings.HasPrefix(d, dir) {
			continue
		}
		for _, e := range entries {
			if strings.Contains(strings.ToLower(e.name), strings.ToLower(name)) {
				out = append(out, fsHit{path: path.Join(d, e.name), dir: e.dir})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].path < out[j].path })
	return out, nil
}

func (demoFS) FindCompose() ([]fsHit, error) {
	time.Sleep(400 * time.Millisecond)
	return []fsHit{{path: "/home/admin/docker/jellyfin/docker-compose.yml"}, {path: "/home/admin/docker/sonarr/compose.yaml"}, {path: "/opt/appdata/docker-compose.yml"}}, nil
}

// ---------------------------------------------------------------------------
// The screen
// ---------------------------------------------------------------------------

type nodeBrowser struct {
	app    *tview.Application
	pages  *tview.Pages
	footer *tview.TextView
	fs     nodeFS
	title  string

	head   *tview.TextView
	line   *tview.TextView // filter / search prompt / status
	table  *tview.Table
	screen *tview.Flex

	dir     string
	entries []fsEntry
	results []fsHit // search results; nil when browsing
	shown   []int   // entries (or results) shown, after the filter
	filter  string
	input   string // "search" or "goto" while typing those, else ""
	typed   string
	status  string
	seq     int

	onPick   func(path string, dir bool)
	onCancel func()
}

// openNodeBrowser shows the browser; onPick gets the chosen file (dir=false)
// or folder (dir=true).
func openNodeBrowser(app *tview.Application, pages *tview.Pages, footer *tview.TextView,
	title string, fs nodeFS, start string, onPick func(path string, dir bool), onCancel func()) {

	b := &nodeBrowser{app: app, pages: pages, footer: footer, fs: fs, title: title, onPick: onPick, onCancel: onCancel}
	b.head = tview.NewTextView().SetDynamicColors(true)
	b.line = tview.NewTextView().SetDynamicColors(true)
	b.table = tview.NewTable().SetSelectable(true, false).SetFixed(1, 0).
		SetSelectedStyle(tcell.StyleDefault.Background(tcell.ColorAqua).Foreground(tcell.ColorBlack))
	b.table.SetBorderPadding(0, 0, 1, 1)
	b.table.SetInputCapture(b.key)
	b.table.SetSelectedFunc(func(row, _ int) { b.open(row) })

	body := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(b.head, 2, 0, false).
		AddItem(b.line, 1, 0, false).
		AddItem(b.table, 0, 1, true)
	body.SetBorder(true).SetTitle(" " + title + " ").SetTitleAlign(tview.AlignLeft)
	b.screen = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(body, 0, 1, true).
		AddItem(footer, 1, 0, false)

	pages.AddAndSwitchToPage("nodebrowse", b.screen, true)
	footer.SetText(" [aqua::b]type[-::-] Filter  [aqua::b]ENTER[-::-] Open/pick  [aqua::b]←[-::-] Up  [aqua::b]/[-::-] Search below  " +
		"[aqua::b]^F[-::-] Find compose files  [aqua::b]~[-::-] Home  [aqua::b]^G[-::-] Go to  [aqua::b]^P[-::-] Pick folder  [aqua::b]ESC[-::-] Back")
	app.SetFocus(b.table)
	if start == "" {
		start = fs.Home()
	}
	b.cd(start)
}

func (b *nodeBrowser) close() {
	b.seq++ // drop answers still on their way
	b.pages.RemovePage("nodebrowse")
	b.fs.Close()
}

// cd lists dir in the background.
func (b *nodeBrowser) cd(dir string) {
	dir = path.Clean("/" + dir)
	b.dir, b.results, b.filter = dir, nil, ""
	b.status = "[gray]Loading…[-]"
	b.render()
	b.seq++
	seq := b.seq
	go func() {
		entries, err := b.fs.List(dir)
		b.app.QueueUpdateDraw(func() {
			if seq != b.seq {
				return
			}
			b.status = ""
			if err != nil {
				b.status = "[red]" + tview.Escape(err.Error()) + "[-]"
			}
			sort.SliceStable(entries, func(i, j int) bool {
				if entries[i].dir != entries[j].dir {
					return entries[i].dir
				}
				return strings.ToLower(entries[i].name) < strings.ToLower(entries[j].name)
			})
			b.entries = entries
			b.render()
		})
	}()
}

// search runs a name search (or the compose-file search) in the background.
func (b *nodeBrowser) search(label string, fn func() ([]fsHit, error)) {
	b.results, b.filter = []fsHit{}, ""
	b.status = "[gray]Searching " + tview.Escape(label) + "… (up to 30s)[-]"
	b.render()
	b.seq++
	seq := b.seq
	go func() {
		paths, err := fn()
		b.app.QueueUpdateDraw(func() {
			if seq != b.seq {
				return
			}
			b.results = paths
			switch {
			case err != nil && len(paths) == 0:
				b.status = "[red]" + tview.Escape(err.Error()) + "[-]"
			case len(paths) == 0:
				b.status = "[yellow]Nothing found: " + tview.Escape(label) + "[-]"
			default:
				b.status = fmt.Sprintf("[green]%d found: %s[-] [gray](ESC back to the folder)[-]", len(paths), tview.Escape(label))
			}
			b.render()
		})
	}()
}

func (b *nodeBrowser) render() {
	b.head.SetText("  [yellow::b]" + tview.Escape(b.dir) + "[-::-]")
	switch {
	case b.input == "search":
		b.line.SetText("  [aqua::b]Search names below " + tview.Escape(b.dir) + ":[-::-] " + tview.Escape(b.typed) + "▌  [gray](ENTER search, ESC cancel)[-]")
	case b.input == "goto":
		b.line.SetText("  [aqua::b]Go to:[-::-] " + tview.Escape(b.typed) + "▌  [gray](ENTER go, ESC cancel)[-]")
	case b.filter != "":
		b.line.SetText("  [aqua::b]Filter:[-::-] " + tview.Escape(b.filter) + "▌  " + b.status)
	default:
		b.line.SetText("  " + b.status)
	}

	sel, _ := b.table.GetSelection()
	b.table.Clear()
	b.shown = b.shown[:0]
	f := strings.ToLower(b.filter)

	if b.results != nil {
		b.table.SetCell(0, 0, tview.NewTableCell(" PATH").SetTextColor(tcell.ColorYellow).SetSelectable(false).SetExpansion(1))
		for i, h := range b.results {
			if f != "" && !strings.Contains(strings.ToLower(h.path), f) {
				continue
			}
			b.shown = append(b.shown, i)
			name, color := " "+h.path, tcell.ColorWhite
			switch {
			case h.dir:
				name, color = name+"/", tcell.ColorAqua
			case isComposeName(path.Base(h.path)):
				color = tcell.ColorGreen
			}
			b.table.SetCell(len(b.shown), 0, tview.NewTableCell(tview.Escape(name)).SetTextColor(color).SetExpansion(1))
		}
	} else {
		for i, h := range []string{" NAME", "SIZE ", " MODIFIED"} {
			c := tview.NewTableCell(h).SetTextColor(tcell.ColorYellow).SetSelectable(false)
			if i == 0 {
				c.SetExpansion(1)
			}
			if i == 1 {
				c.SetAlign(tview.AlignRight)
			}
			b.table.SetCell(0, i, c)
		}
		if b.dir != "/" && f == "" {
			b.shown = append(b.shown, -1) // ".."
			b.table.SetCell(1, 0, tview.NewTableCell(" ../").SetTextColor(tcell.ColorAqua).SetExpansion(1))
			b.table.SetCell(1, 1, tview.NewTableCell(""))
			b.table.SetCell(1, 2, tview.NewTableCell(""))
		}
		for i, e := range b.entries {
			if f != "" && !strings.Contains(strings.ToLower(e.name), f) {
				continue
			}
			b.shown = append(b.shown, i)
			row := len(b.shown)
			name, color, size := " "+e.name, tcell.ColorWhite, fmtBytes(e.size)
			switch {
			case e.dir:
				name, color, size = name+"/", tcell.ColorAqua, ""
			case isComposeName(e.name):
				color = tcell.ColorGreen
			case strings.HasPrefix(e.name, "."):
				color = tcell.ColorGray
			}
			if e.link {
				name += " →"
			}
			b.table.SetCell(row, 0, tview.NewTableCell(tview.Escape(name)).SetTextColor(color).SetExpansion(1))
			b.table.SetCell(row, 1, tview.NewTableCell(size+" ").SetTextColor(tcell.ColorGray).SetAlign(tview.AlignRight))
			b.table.SetCell(row, 2, tview.NewTableCell(" "+e.mod).SetTextColor(tcell.ColorGray))
		}
	}
	if sel < 1 || sel > len(b.shown) {
		sel = 1
	}
	b.table.Select(sel, 0)
}

func isComposeName(n string) bool {
	switch n {
	case "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml":
		return true
	}
	return false
}

// open acts on a row: enter a folder, pick a file.
func (b *nodeBrowser) open(row int) {
	if row < 1 || row > len(b.shown) {
		return
	}
	i := b.shown[row-1]
	if b.results != nil {
		// A search result: folders are entered, files picked.
		if h := b.results[i]; h.dir {
			b.cd(h.path)
		} else {
			b.pick(h.path, false)
		}
		return
	}
	if i == -1 {
		b.cd(path.Dir(b.dir))
		return
	}
	e := b.entries[i]
	if e.dir {
		b.cd(path.Join(b.dir, e.name))
		return
	}
	b.pick(path.Join(b.dir, e.name), false)
}

func (b *nodeBrowser) pick(p string, dir bool) {
	b.close()
	b.onPick(p, dir)
}

func (b *nodeBrowser) key(ev *tcell.EventKey) *tcell.EventKey {
	// Typing a search term or a path.
	if b.input != "" {
		switch ev.Key() {
		case tcell.KeyEscape:
			b.input, b.typed = "", ""
		case tcell.KeyEnter:
			typed, mode := strings.TrimSpace(b.typed), b.input
			b.input, b.typed = "", ""
			if typed != "" && mode == "search" {
				dir := b.dir
				b.search("\""+typed+"\" below "+dir, func() ([]fsHit, error) { return b.fs.Find(dir, typed) })
				return nil
			}
			if typed != "" && mode == "goto" {
				if !strings.HasPrefix(typed, "/") {
					typed = path.Join(b.dir, typed)
				}
				b.cd(typed)
				return nil
			}
		case tcell.KeyBackspace, tcell.KeyBackspace2:
			if r := []rune(b.typed); len(r) > 0 {
				b.typed = string(r[:len(r)-1])
			}
		case tcell.KeyRune:
			b.typed += string(ev.Rune())
		}
		b.render()
		return nil
	}

	switch ev.Key() {
	case tcell.KeyEscape:
		switch {
		case b.filter != "":
			b.filter = ""
			b.render()
		case b.results != nil:
			b.cd(b.dir)
		default:
			b.close()
			b.onCancel()
		}
		return nil
	case tcell.KeyLeft:
		b.cd(path.Dir(b.dir))
		return nil
	case tcell.KeyRight:
		row, _ := b.table.GetSelection()
		if row >= 1 && row <= len(b.shown) && b.results == nil {
			if i := b.shown[row-1]; i == -1 || b.entries[i].dir {
				b.open(row)
			}
		}
		return nil
	case tcell.KeyBackspace, tcell.KeyBackspace2:
		if r := []rune(b.filter); len(r) > 0 {
			b.filter = string(r[:len(r)-1])
			b.render()
		} else if b.results == nil {
			b.cd(path.Dir(b.dir))
		}
		return nil
	case tcell.KeyCtrlF:
		b.search("compose files on the whole node", b.fs.FindCompose)
		return nil
	case tcell.KeyCtrlG:
		b.input, b.typed = "goto", ""
		b.render()
		return nil
	case tcell.KeyCtrlP:
		b.pick(b.dir, true)
		return nil
	case tcell.KeyRune:
		switch r := ev.Rune(); {
		case r == '/' && b.filter == "":
			b.input, b.typed = "search", ""
		case r == '~' && b.filter == "":
			b.cd(b.fs.Home())
			return nil
		default:
			b.filter += string(r)
		}
		b.render()
		return nil
	}
	return ev
}
