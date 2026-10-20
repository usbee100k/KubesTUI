package main

// Sectioned main menu: a row of section tabs (Command Center, Cluster,
// VPN, Update, Remote Join, Bootstrappers) above a list that shows the
// current section's items. LEFT/RIGHT or 1-9 switch sections; tabs can be
// clicked. Used by the node menu (kbtui) and the workstation cluster page.

import (
	"strconv"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

type menuItem struct {
	title, desc string
	run         func()
}

type menuSection struct {
	name  string
	items []menuItem
}

// Section names, in tab order.
const (
	secCommandCenter = "Command Center"
	secCluster       = "Cluster"
	secVPN           = "VPN"
	secUpdate        = "Update"
	secRemoteJoin    = "Remote Join"
	secBootstrappers = "Bootstrappers"
)

var menuSectionOrder = []string{secCommandCenter, secCluster, secVPN, secUpdate, secRemoteJoin, secBootstrappers}

// tabBar draws the section tabs and a rule under them (2 rows).
type tabBar struct {
	*tview.Box
	names    []string
	cur      int
	onSelect func(i int)
	hits     [][2]int // x range of each tab, for clicks
}

func newTabBar() *tabBar { return &tabBar{Box: tview.NewBox()} }

func (t *tabBar) Draw(screen tcell.Screen) {
	t.Box.DrawForSubclass(screen, t)
	x, y, w, h := t.GetInnerRect()
	if h <= 0 || w <= 0 {
		return
	}
	// Widest form that fits: "1 Command Center", then "Command Center",
	// then only the current tab's name (others by number).
	label := func(i, form int) string {
		n := strconv.Itoa(i+1) + " " + t.names[i]
		switch {
		case form == 1:
			n = t.names[i]
		case form == 2 && i != t.cur:
			n = strconv.Itoa(i + 1)
		}
		return " " + n + " "
	}
	form := 0
	for ; form < 2; form++ {
		total := 2
		for i := range t.names {
			total += len([]rune(label(i, form))) + 1
		}
		if total <= w {
			break
		}
	}
	t.hits = t.hits[:0]
	cx := x + 2
	for i := range t.names {
		l := label(i, form)
		style := tcell.StyleDefault.Foreground(tcell.ColorAqua)
		if i == t.cur {
			style = tcell.StyleDefault.Background(tcell.ColorAqua).Foreground(tcell.ColorBlack).Bold(true)
		}
		start := cx
		for _, r := range l {
			if cx >= x+w {
				break
			}
			screen.SetContent(cx, y, r, nil, style)
			cx++
		}
		t.hits = append(t.hits, [2]int{start, cx})
		cx++
	}
	if h > 1 {
		rule := tcell.StyleDefault.Foreground(tcell.ColorDarkSlateGray)
		for i := x + 1; i < x+w-1; i++ {
			screen.SetContent(i, y+1, '─', nil, rule)
		}
	}
}

func (t *tabBar) MouseHandler() func(action tview.MouseAction, event *tcell.EventMouse, setFocus func(p tview.Primitive)) (bool, tview.Primitive) {
	return t.WrapMouseHandler(func(action tview.MouseAction, event *tcell.EventMouse, setFocus func(p tview.Primitive)) (bool, tview.Primitive) {
		if action != tview.MouseLeftClick || !t.InRect(event.Position()) {
			return false, nil
		}
		mx, my := event.Position()
		_, y, _, _ := t.GetInnerRect()
		if my != y {
			return false, nil
		}
		for i, r := range t.hits {
			if mx >= r[0] && mx < r[1] && t.onSelect != nil {
				t.onSelect(i)
				return true, nil
			}
		}
		return false, nil
	})
}

// tabbedMenu ties the tab bar to a list.
type tabbedMenu struct {
	bar      *tabBar
	list     *tview.List
	sections []menuSection
	cur      int
	showDesc bool // put each item's description under it
	selected map[int]int
}

func newTabbedMenu(list *tview.List, showDesc bool) *tabbedMenu {
	m := &tabbedMenu{bar: newTabBar(), list: list, showDesc: showDesc, selected: map[int]int{}}
	m.bar.onSelect = m.show
	list.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		switch ev.Key() {
		case tcell.KeyRight, tcell.KeyTab:
			m.show((m.cur + 1) % max(1, len(m.sections)))
			return nil
		case tcell.KeyLeft, tcell.KeyBacktab:
			m.show((m.cur + len(m.sections) - 1) % max(1, len(m.sections)))
			return nil
		case tcell.KeyRune:
			if r := ev.Rune(); r >= '1' && r <= '9' && int(r-'1') < len(m.sections) {
				m.show(int(r - '1'))
				return nil
			}
		}
		return ev
	})
	return m
}

// setSections replaces the items, keeping the current section and row.
func (m *tabbedMenu) setSections(secs []menuSection) {
	cur := ""
	if m.cur < len(m.sections) {
		cur = m.sections[m.cur].name
	}
	m.sections = secs
	m.cur = 0
	for i, s := range secs {
		if s.name == cur {
			m.cur = i
		}
	}
	names := make([]string, len(secs))
	for i, s := range secs {
		names[i] = s.name
	}
	m.bar.names = names
	m.show(m.cur)
}

func (m *tabbedMenu) show(i int) {
	if i < 0 || i >= len(m.sections) {
		return
	}
	if m.cur < len(m.sections) {
		m.selected[m.cur] = m.list.GetCurrentItem()
	}
	m.cur = i
	m.bar.cur = i
	m.list.Clear()
	for _, it := range m.sections[i].items {
		it := it
		second := ""
		if m.showDesc && it.desc != "" {
			second = "    " + it.desc
		}
		m.list.AddItem("  "+it.title, second, 0, it.run)
	}
	if row := m.selected[i]; row > 0 && row < m.list.GetItemCount() {
		m.list.SetCurrentItem(row)
	}
}

// sectionsFrom groups items by section name, in menuSectionOrder, leaving
// out empty sections.
func sectionsFrom(bySection map[string][]menuItem) []menuSection {
	var out []menuSection
	for _, n := range menuSectionOrder {
		if items := bySection[n]; len(items) > 0 {
			out = append(out, menuSection{name: n, items: items})
		}
	}
	return out
}

// menuFooter is the footer for a sectioned menu.
func menuFooter(extra string) string {
	return " [aqua::b]←/→[-::-] Section    [aqua::b]↑/↓[-::-] Navigate    [aqua::b]ENTER[-::-] Select" + extra + "    [aqua::b]Q[-::-] Quit"
}

// opSection says which section of the node menu an operation belongs to.
func opSection(op string) string {
	switch op {
	case "bootstrap", "controlplane", "worker":
		return secBootstrappers
	case "remote-controlplane", "remote-worker", "join-commands":
		return secRemoteJoin
	case "vpn-status", "vpn-setup", "torrent-vpn":
		return secVPN
	case "os-update", "update", "gitops-update":
		return secUpdate
	}
	return secCluster
}

// clusterOrder puts the Cluster section's operations in a sensible order
// (checks first, then changes).
var clusterOrder = []string{"health", "config", "rename", "repair", "pod-cleanup", "decommission", "services", "hermes-llm", "web-logins", "longhorn-disk", "longhorn-spread", "compose-import", "app-storage", "compose-remove"}

func clusterRank(op string) int {
	for i, o := range clusterOrder {
		if o == op {
			return i
		}
	}
	return len(clusterOrder)
}
