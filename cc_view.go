package main

// Command Center: a btop-style live view of the whole cluster. Panels:
//
//   1 cluster     API, VIP, versions, totals; CPU / memory / network graphs
//   2 nodes       every node: IP, role, CPU, memory, disk, network, pods
//   3 pods        all pods, sortable and searchable (like btop's processes)
//   4 namespaces  pods and usage per namespace; ENTER filters the pods
//   5 apps        Argo CD applications: sync and health
//   6 network     MetalLB LoadBalancer IPs and ingress hostnames
//   7 storage     Longhorn disks and volumes, other claims
//   8 alerts      what needs attention, then recent warning events
//
// The layout adapts to the terminal: three columns when wide, panels share
// a tabbed box when it isn't. ENTER opens details (live), L shows a pod's
// logs, X restarts a pod, C cordons a node.

import (
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

type ccPanelID int

const (
	pCluster ccPanelID = iota
	pNodes
	pPods
	pNamespaces
	pApps
	pNetwork
	pStorage
	pAlerts
	ccPanelCount
)

var ccPanelNames = [ccPanelCount]string{"cluster", "nodes", "pods", "namespaces", "apps", "network", "storage", "alerts"}

type ccPanelState struct {
	sel     int
	selKey  string
	top     int
	keys    []string // row keys at the last draw
	visible int      // rows that fit at the last draw
}

type ccSlot struct {
	r      ccRect
	panels []ccPanelID
	group  string
}

// ccHit remembers where things were drawn, for the mouse.
type ccHit struct {
	r     ccRect
	panel ccPanelID
	rowsY int // screen row of the first table row (-1: none)
	tabs  []ccTabHit
}

type ccTabHit struct {
	x0, x1 int
	panel  ccPanelID
}

type ccOverlay struct {
	title  string
	target ccTarget
	build  func(width int) []string // rebuilt every draw: stays live
	top    int
	lines  int // at the last draw
	height int
}

type commandCenter struct {
	*tview.Box
	app    *tview.Application
	pages  *tview.Pages
	footer *tview.TextView
	page   *tview.Flex
	back   func()
	name   string

	src   ccSource
	coll  *ccCollector
	snap  *ccSnapshot
	hist  *ccHistory
	stop  chan struct{}
	kick  chan struct{}
	every atomic.Int64 // refresh interval, ns
	pause atomic.Bool

	focus ccPanelID
	zoom  bool
	st    [ccPanelCount]ccPanelState
	tabs  map[string]ccPanelID
	hits  []ccHit

	podSort, nsSort, nodeSort int
	reverse                   bool
	nsFilter                  string
	search                    string
	searching                 bool

	note   string
	noteAt time.Time

	overlay *ccOverlay
	logs    *ccLogs
	soc     *socState // the SOC console (alerts panel zoomed)

	socShowBase bool       // V in the SOC console: list baseline findings
	socPage     int        // 0 incidents, 1 network, 2 DNS (N forward, ESC back)
	socBoxes    []socBox   // the current page's boxes (rebuilt every draw)
	socBig      int        // TAB: box shown alone over the page (1-based, 0 none)
	socBigTop   int        // its scroll position
	socBigH     int        // its visible rows
	net         *netSensor // started when the SOC console first opens

	// actionsBlocked explains why changes aren't allowed ("" = allowed).
	actionsBlocked func() string

	// onStorage opens "Change App Storage" (E in the Storage panel);
	// nil hides it.
	onStorage func()

	// onFiles opens Files on a Longhorn volume (F in the Storage panel).
	onFiles func(ns, pvc string)

	// onSpread opens "Spread Storage Across Nodes" (B in the Storage
	// panel); nil hides it.
	onSpread func()
}

var ccPage *commandCenter

var (
	podSorts  = []string{"cpu", "mem", "restarts", "age", "name", "status"}
	nsSorts   = []string{"mem", "cpu", "pods", "name"}
	nodeSorts = []string{"name", "cpu", "mem"}
)

func newCommandCenter(app *tview.Application, pages *tview.Pages, footer *tview.TextView) *commandCenter {
	c := &commandCenter{Box: tview.NewBox(), app: app, pages: pages, footer: footer,
		tabs: map[string]ccPanelID{}, kick: make(chan struct{}, 1), focus: pPods,
		actionsBlocked: func() string { return "" }}
	c.every.Store(int64(2 * time.Second))
	c.page = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(c, 0, 1, true).
		AddItem(footer, 1, 0, false)
	c.logs = newCCLogs(c)
	return c
}

// Open shows the Command Center for a cluster, reading it through src.
func (c *commandCenter) Open(src ccSource, name string, back func()) {
	c.Close()
	c.src, c.name, c.back = src, name, back
	c.coll = newCCCollector(src)
	c.snap, c.hist, c.soc = nil, newCCHistory(), newSOCState()
	c.netStop()
	c.socPage, c.socBig = 0, 0
	c.overlay, c.zoom, c.searching = nil, false, false
	c.nsFilter, c.search = "", ""
	c.st = [ccPanelCount]ccPanelState{}
	c.pause.Store(false)
	c.start()
	c.show()
}

func (c *commandCenter) show() {
	c.pages.AddAndSwitchToPage("cc", c.page, true)
	c.setFooter()
	c.app.SetFocus(c)
}

// Close stops polling (leaving the screen).
func (c *commandCenter) Close() {
	if c.stop != nil {
		close(c.stop)
		c.stop = nil
	}
	c.logs.stopPolling()
	c.netStop()
	if c.src != nil {
		c.src.Close()
		c.src = nil
	}
}

// suspend stops polling but keeps the source and everything on screen
// (panel, zoom, selection), for a screen opened from here that comes
// back with resume (Files from the Storage panel).
func (c *commandCenter) suspend() {
	if c.stop != nil {
		close(c.stop)
		c.stop = nil
	}
	c.logs.stopPolling()
}

// resume shows the Command Center again as it was left.
func (c *commandCenter) resume() {
	if c.src == nil {
		return
	}
	if c.stop == nil {
		c.start()
	}
	c.show()
	c.refreshNow()
}

func (c *commandCenter) leave() {
	c.Close()
	if c.back != nil {
		c.back()
	}
}

func (c *commandCenter) start() {
	stop, coll := make(chan struct{}), c.coll
	c.stop = stop
	go func() {
		for {
			snap := coll.Collect()
			select {
			case <-stop:
				return
			default:
			}
			c.app.QueueUpdateDraw(func() {
				if c.stop == stop {
					c.snap = snap
					c.hist.add(snap)
					if c.net != nil {
						c.net.setTargets(snap)
					}
					c.soc.observe(snap, c.netFindings())
				}
			})
			for {
				select {
				case <-stop:
					return
				case <-c.kick:
				case <-time.After(time.Duration(c.every.Load())):
				}
				if !c.pause.Load() {
					break
				}
			}
		}
	}()
}

// refreshNow polls at once (after an action or un-pausing).
func (c *commandCenter) refreshNow() {
	select {
	case c.kick <- struct{}{}:
	default:
	}
}

func (c *commandCenter) flash(msg string) {
	c.note, c.noteAt = msg, time.Now()
}

func (c *commandCenter) setFooter() {
	if c.overlay != nil {
		extra := ""
		switch c.overlay.target.Kind {
		case "Pod":
			extra = "    [aqua::b]L[-::-] Logs    [aqua::b]X[-::-] Restart pod"
		case "Node":
			extra = "    [aqua::b]C[-::-] Cordon/uncordon"
		case "Device":
			extra = "    [aqua::b]K[-::-] Mark known"
		}
		c.footer.SetText(" [aqua::b]↑↓[-::-] Scroll" + extra + "    [aqua::b]ESC[-::-] Close")
		return
	}
	c.footer.SetText(" [aqua::b]1-8[-::-] Panel  [aqua::b]TAB[-::-] Next  [aqua::b]↑↓[-::-] Select  [aqua::b]ENTER[-::-] Details  " +
		"[aqua::b]/[-::-] Search  [aqua::b]S[-::-] Sort  [aqua::b]Z[-::-] Zoom  [aqua::b]+/-[-::-] Speed  [aqua::b]P[-::-] Pause  [aqua::b]ESC[-::-] Back")
}

// ---------------------------------------------------------------------------
// Layout
// ---------------------------------------------------------------------------

func (c *commandCenter) nodeCount() int {
	if c.snap == nil {
		return 3
	}
	return len(c.snap.Nodes)
}

func (c *commandCenter) layout(x, y, w, h int) []ccSlot {
	all := ccRect{x, y, w, h}
	if c.zoom {
		return []ccSlot{{r: all, panels: []ccPanelID{c.focus}, group: "zoom"}}
	}
	clusterH := 11
	switch {
	case h < 28:
		clusterH = 7
	case h < 40:
		clusterH = 9
	}
	nodesH := min(max(c.nodeCount()+3, 5), max(5, h/3))
	rest := h - clusterH - nodesH
	if rest < 6 { // tiny terminal: everything but the cluster box shares one
		return []ccSlot{
			{r: ccRect{x, y, w, min(clusterH, h)}, panels: []ccPanelID{pCluster}},
			{r: ccRect{x, y + clusterH, w, max(0, h-clusterH)}, panels: []ccPanelID{pNodes, pPods, pNamespaces, pApps, pNetwork, pStorage, pAlerts}, group: "all"},
		}
	}
	slots := []ccSlot{
		{r: ccRect{x, y, w, clusterH}, panels: []ccPanelID{pCluster}},
		{r: ccRect{x, y + clusterH, w, nodesH}, panels: []ccPanelID{pNodes}},
	}
	by := y + clusterH + nodesH
	switch {
	case w >= 150:
		podW := w * 46 / 100
		midW := w * 27 / 100
		rightW := w - podW - midW
		half := rest / 2
		third := rest / 3
		slots = append(slots,
			ccSlot{r: ccRect{x, by, podW, rest}, panels: []ccPanelID{pPods}},
			ccSlot{r: ccRect{x + podW, by, midW, half}, panels: []ccPanelID{pNamespaces}},
			ccSlot{r: ccRect{x + podW, by + half, midW, rest - half}, panels: []ccPanelID{pApps}},
			ccSlot{r: ccRect{x + podW + midW, by, rightW, third}, panels: []ccPanelID{pNetwork}},
			ccSlot{r: ccRect{x + podW + midW, by + third, rightW, third}, panels: []ccPanelID{pStorage}},
			ccSlot{r: ccRect{x + podW + midW, by + 2*third, rightW, rest - 2*third}, panels: []ccPanelID{pAlerts}},
		)
	case w >= 100:
		podW := w * 55 / 100
		half := rest / 2
		slots = append(slots,
			ccSlot{r: ccRect{x, by, podW, rest}, panels: []ccPanelID{pPods}},
			ccSlot{r: ccRect{x + podW, by, w - podW, half}, panels: []ccPanelID{pAlerts, pNamespaces, pApps}, group: "right1"},
			ccSlot{r: ccRect{x + podW, by + half, w - podW, rest - half}, panels: []ccPanelID{pNetwork, pStorage}, group: "right2"},
		)
	default:
		slots = append(slots,
			ccSlot{r: ccRect{x, by, w, rest}, panels: []ccPanelID{pPods, pNamespaces, pApps, pNetwork, pStorage, pAlerts}, group: "bottom"})
	}
	return slots
}

// active is the panel a slot shows (its selected tab).
func (c *commandCenter) active(s ccSlot) ccPanelID {
	if len(s.panels) == 1 {
		return s.panels[0]
	}
	if p, ok := c.tabs[s.group]; ok {
		for _, q := range s.panels {
			if q == p {
				return p
			}
		}
	}
	return s.panels[0]
}

// focusPanel focuses a panel, switching its box's tab if needed.
func (c *commandCenter) focusPanel(p ccPanelID) {
	c.focus = p
	_, _, w, h := c.GetInnerRect()
	for _, s := range c.layout(0, 0, w, h) {
		for _, q := range s.panels {
			if q == p && s.group != "" {
				c.tabs[s.group] = p
			}
		}
	}
}

// visiblePanels in drawing order (for TAB).
func (c *commandCenter) visiblePanels() []ccPanelID {
	var out []ccPanelID
	for _, h := range c.hits {
		out = append(out, h.panel)
	}
	return out
}

// ---------------------------------------------------------------------------
// Drawing
// ---------------------------------------------------------------------------

func (c *commandCenter) Draw(screen tcell.Screen) {
	c.Box.DrawForSubclass(screen, c)
	x, y, w, h := c.GetInnerRect()
	c.hits = c.hits[:0]
	for _, s := range c.layout(x, y, w, h) {
		c.drawSlot(screen, s)
	}
	if c.overlay != nil {
		c.drawOverlay(screen, ccRect{x, y, w, h})
	}
}

func (c *commandCenter) drawSlot(screen tcell.Screen, s ccSlot) {
	if s.r.w < 4 || s.r.h < 3 {
		return
	}
	act := c.active(s)
	color := tcell.ColorGray
	if act == c.focus {
		color = tcell.ColorAqua
	}
	drawBox(screen, s.r, color)

	hit := ccHit{r: s.r, panel: act, rowsY: -1}

	// Title: the panel (or tabs), then the panel's own info on the right.
	tx := s.r.x + 2
	for _, p := range s.panels {
		label := fmt.Sprintf("[orange]%d[-]%s", int(p)+1, ccPanelNames[p])
		switch {
		case p == act && p == c.focus:
			label = fmt.Sprintf("[orange::b]%d[white::b]%s[-::-]", int(p)+1, ccPanelNames[p])
		case p == act:
			label = fmt.Sprintf("[orange]%d[white]%s[-]", int(p)+1, ccPanelNames[p])
		case len(s.panels) > 1:
			label = fmt.Sprintf("[#806020]%d[gray]%s[-]", int(p)+1, ccPanelNames[p])
		}
		width := tview.TaggedStringWidth(label) + 2
		if tx+width > s.r.x+s.r.w-2 {
			break
		}
		put(screen, "┤"+label+"├", tx, s.r.y, width)
		hit.tabs = append(hit.tabs, ccTabHit{tx, tx + width, p})
		tx += width
	}
	if info := c.titleInfo(act); info != "" {
		iw := tview.TaggedStringWidth(info) + 2
		if ix := s.r.x + s.r.w - 2 - iw; ix > tx+1 {
			put(screen, "┤"+info+"├", ix, s.r.y, iw)
		}
	}

	in := s.r.inner()
	if act == pCluster {
		c.drawCluster(screen, in)
	} else if act == pAlerts && c.socMode() {
		c.netStart()
		c.socBoxes = c.socBoxes[:0]
		nh := len(c.hits)
		if c.socPage == 1 && c.net != nil {
			c.drawNet(screen, in) // adds the table's own hit
		} else if c.socPage == 2 && c.net != nil {
			c.drawDNS(screen, in)
		} else {
			c.drawSOC(screen, in)
		}
		if c.socBig > 0 {
			c.drawSOCBig(screen, in, nh)
		}
	} else {
		hit.rowsY = c.drawTable(screen, act, in)
	}
	c.hits = append(c.hits, hit)
}

// titleInfo is the right side of a panel's title bar.
func (c *commandCenter) titleInfo(p ccPanelID) string {
	s := c.snap
	switch p {
	case pCluster:
		state := "[green]live[-]"
		if c.pause.Load() {
			state = "[yellow]paused[-]"
		}
		return fmt.Sprintf("%s [gray]every %s · %s[-]", state, time.Duration(c.every.Load()), time.Now().Format("15:04:05"))
	case pPods:
		var parts []string
		dir := "↓"
		if c.reverse {
			dir = "↑"
		}
		parts = append(parts, "[gray]sort[-] "+podSorts[c.podSort]+dir)
		if c.nsFilter != "" {
			parts = append(parts, "[gray]ns[-] [yellow]"+tview.Escape(c.nsFilter)+"[-]")
		}
		if c.searching {
			parts = append(parts, "[aqua]/"+tview.Escape(c.search)+"▌[-]")
		} else if c.search != "" {
			parts = append(parts, "[aqua]/"+tview.Escape(c.search)+"[-]")
		}
		if s != nil {
			parts = append(parts, fmt.Sprintf("[gray]%d[-]", len(c.podRows())))
		}
		return strings.Join(parts, " ")
	case pNamespaces:
		return "[gray]sort[-] " + nsSorts[c.nsSort]
	case pStorage:
		hints := []string{}
		if c.onFiles != nil {
			hints = append(hints, "[aqua::b]F[-::-] [gray]files in the volume[-]")
		}
		if c.onStorage != nil {
			hints = append(hints, "[aqua::b]E[-::-] [gray]change app storage[-]")
		}
		if c.onSpread != nil {
			hints = append(hints, "[aqua::b]B[-::-] [gray]spread copies[-]")
		}
		return strings.Join(hints, "  ")
	case pNodes:
		if s != nil && s.Version != "" {
			return "[gray]sort[-] " + nodeSorts[c.nodeSort]
		}
	case pAlerts:
		if s != nil && c.socMode() {
			threat, _, _ := c.soc.scores()
			level, col := socLevel(threat)
			var tabs []string
			for i, name := range []string{"INCIDENTS", "NETWORK", "DNS"} {
				if i == c.socPage {
					tabs = append(tabs, "[white::b]"+name+"[-::-]")
				} else {
					tabs = append(tabs, "[gray]"+strings.ToLower(name)+"[-]")
				}
			}
			pages := strings.Join(tabs, " ")
			hint := "N network · ENTER case · V baseline · TAB boxes"
			switch c.socPage {
			case 1:
				hint = "N DNS · ENTER device · K known · U sweep · TAB boxes · ESC back"
			case 2:
				hint = "ENTER device · C connect · A fix site records · TAB boxes · ESC back"
			}
			return fmt.Sprintf("[#48dbfb::b]◉ SOC[-::-] %s [gray]· threat[-] [%s::b]%s[-::-] [gray]· %s · %s[-]", pages, col, level, hint, time.Now().Format("15:04:05"))
		}
		if s != nil {
			crit, warn := 0, 0
			for _, a := range s.Alerts {
				if a.Level == 2 {
					crit++
				} else {
					warn++
				}
			}
			switch {
			case crit > 0:
				return fmt.Sprintf("[red]%d critical[-] [yellow]%d warning[-]", crit, warn)
			case warn > 0:
				return fmt.Sprintf("[yellow]%d warning[-]", warn)
			}
			return "[green]all good[-]"
		}
	}
	return ""
}

// drawTable draws a panel's table with selection and scrolling. Returns
// the screen row of the first data row.
func (c *commandCenter) drawTable(screen tcell.Screen, p ccPanelID, in ccRect) int {
	t := c.table(p, in.w)
	st := &c.st[p]
	y := in.y
	for _, line := range t.head {
		if y >= in.y+in.h {
			return -1
		}
		put(screen, line, in.x, y, in.w)
		y++
	}
	if len(t.rows) == 0 {
		if y < in.y+in.h {
			put(screen, "[gray]"+t.empty+"[-]", in.x, y, in.w)
		}
		st.keys, st.visible = nil, 0
		return -1
	}
	show, widths := fitCols(t.cols, in.w)
	if y < in.y+in.h {
		put(screen, "[gray]"+t.headerLine(show, widths)+"[-]", in.x, y, in.w)
		y++
	}
	visible := in.y + in.h - y
	if visible <= 0 {
		return -1
	}

	// Keep the selection on the same row (by key) as data changes.
	st.keys = st.keys[:0]
	for _, r := range t.rows {
		st.keys = append(st.keys, r.key)
	}
	if st.selKey != "" {
		for i, k := range st.keys {
			if k == st.selKey {
				st.sel = i
				break
			}
		}
	}
	st.sel = max(0, min(st.sel, len(t.rows)-1))
	st.selKey = t.rows[st.sel].key
	if st.sel < st.top {
		st.top = st.sel
	}
	if st.sel >= st.top+visible {
		st.top = st.sel - visible + 1
	}
	st.top = max(0, min(st.top, len(t.rows)-visible))
	st.visible = visible

	focused := p == c.focus && c.overlay == nil
	for i := 0; i < visible && st.top+i < len(t.rows); i++ {
		idx := st.top + i
		put(screen, t.rowLine(t.rows[idx], show, widths, idx == st.sel && focused), in.x, y+i, in.w)
	}
	// Scroll position on the right border.
	if len(t.rows) > visible {
		pos := fmt.Sprintf("%d/%d", st.sel+1, len(t.rows))
		put(screen, "[gray]"+pos+"[-]", in.x+in.w-len(pos), in.y+in.h, len(pos))
	}
	return y
}

func (c *commandCenter) table(p ccPanelID, width int) *ccTable {
	if c.snap == nil {
		return &ccTable{empty: "connecting…"}
	}
	switch p {
	case pNodes:
		return c.nodesTable(width)
	case pPods:
		return c.podsTable()
	case pNamespaces:
		return c.nsTable()
	case pApps:
		return c.appsTable()
	case pNetwork:
		return c.networkTable()
	case pStorage:
		return c.storageTable(width)
	case pAlerts:
		if c.netPage() {
			return c.netTable()
		}
		if c.dnsPage() {
			return c.dnsTable()
		}
		if c.socMode() {
			return c.socTable()
		}
		return c.alertsTable()
	}
	return &ccTable{}
}

// ---------------------------------------------------------------------------
// Panel 1: cluster
// ---------------------------------------------------------------------------

func (c *commandCenter) drawCluster(screen tcell.Screen, in ccRect) {
	s := c.snap
	if s == nil {
		put(screen, "[gray]Connecting to "+tview.Escape(c.name)+"…[-]", in.x+1, in.y, in.w-1)
		return
	}
	infoW := in.w
	switch {
	case in.w >= 150:
		infoW = 60
	case in.w >= 80:
		infoW = 52
	}
	lines := c.clusterLines(infoW - 1)
	for i, l := range lines {
		if i >= in.h {
			break
		}
		put(screen, l, in.x+1, in.y+i, infoW-1)
	}
	gw := in.w - infoW - 1
	if gw < 20 {
		return
	}
	gx := in.x + infoW + 1
	n := max(1, min(3, gw/30))
	each := (gw - (n - 1)) / n
	type gdef struct {
		title string
		vals  []float64
		top   float64
		col   func(float64) string
	}
	cpuNow, memNow := c.hist.cpu.last(), c.hist.mem.last()
	var cu, ca, mu, ma int64
	for _, nd := range s.Nodes {
		if nd.HasUsage {
			cu, ca, mu, ma = cu+nd.CPUUse, ca+nd.CPUAlloc, mu+nd.MemUse, ma+nd.MemAlloc
		}
	}
	defs := []gdef{
		{fmt.Sprintf("[::b]CPU[::-] [%s]%3.0f%%[-] [gray]%s/%s cores[-]", pctColor(cpuNow), cpuNow, fmtCores(cu), fmtCores(ca)), c.hist.cpu.v, 100, heatColors},
		{fmt.Sprintf("[::b]MEM[::-] [%s]%3.0f%%[-] [gray]%s/%s[-]", pctColor(memNow), memNow, fmtBytes(mu), fmtBytes(ma)), c.hist.mem.v, 100, heatColors},
	}
	if n == 3 {
		top := 1.0
		for _, v := range c.hist.rx.v {
			top = max(top, v)
		}
		for _, v := range c.hist.tx.v {
			top = max(top, v)
		}
		defs = append(defs, gdef{fmt.Sprintf("[::b]NET[::-] [#48dbfb]↓%s[-] [#ff9ff3]↑%s[-]", fmtRate(c.hist.rx.last()), fmtRate(c.hist.tx.last())),
			c.hist.rx.v, top * 1.1, coolColors})
	}
	if !s.HasMetrics {
		put(screen, "[yellow]No usage graphs: "+tview.Escape(orDefault(s.Errs["metrics"], "metrics-server not available"))+"[-]", gx, in.y+1, gw)
		return
	}
	for i, d := range defs[:min(n, len(defs))] {
		x := gx + i*(each+1)
		put(screen, d.title, x, in.y, each)
		for r, line := range graph(d.vals, each, in.h-1, d.top, d.col) {
			put(screen, line, x, in.y+1+r, each)
		}
	}
}

func (c *commandCenter) clusterLines(w int) []string {
	s := c.snap
	k := func(label string) string { return fmt.Sprintf("[yellow::b]%-10s[-::-] ", label) }
	var lines []string

	api := "[green]● ok[-]"
	if e := s.Errs["api"]; e != "" {
		api = "[red]● unreachable[-]"
	} else if s.Readyz != "ok" && s.Readyz != "" {
		api = "[red]● " + tview.Escape(s.Readyz) + "[-]"
	}
	lines = append(lines, fmt.Sprintf("[::b]%s[::-] [gray]%s[-]  %s [gray]%s[-]",
		tview.Escape(strings.ToUpper(c.name)), tview.Escape(orDefault(s.Version, "")), api, s.APIRTT.Round(time.Millisecond)))
	lines = append(lines, k("API")+tview.Escape(s.Source))

	ready, cpuCap, memCap := 0, int64(0), int64(0)
	var oldest time.Time
	for _, n := range s.Nodes {
		if n.Ready && !n.Unreachable {
			ready++
		}
		cpuCap += n.CPUAlloc
		memCap += n.MemAlloc
		if oldest.IsZero() || n.Created.Before(oldest) {
			oldest = n.Created
		}
	}
	nc := "green"
	if ready < len(s.Nodes) {
		nc = "yellow"
		if ready == 0 {
			nc = "red"
		}
	}
	lines = append(lines, k("NODES")+fmt.Sprintf("[%s]%d/%d Ready[-] [gray]· %s cores · %s · age %s[-]", nc, ready, len(s.Nodes), fmtCores(cpuCap), fmtBytes(memCap), fmtAge(oldest)))

	running, pending, bad := 0, 0, 0
	for _, p := range s.Pods {
		switch {
		case p.Status == "Running" && !p.problem():
			running++
		case p.Status == "Pending" || strings.HasPrefix(p.Status, "Init:") || p.Status == "ContainerCreating":
			pending++
		case p.problem():
			bad++
		}
	}
	pl := fmt.Sprintf("[green]%d running[-]", running)
	if pending > 0 {
		pl += fmt.Sprintf(" [yellow]%d pending[-]", pending)
	}
	if bad > 0 {
		pl += fmt.Sprintf(" [red]%d failing[-]", bad)
	}
	lines = append(lines, k("PODS")+pl+fmt.Sprintf(" [gray]of %d · %d namespaces[-]", len(s.Pods), len(s.Namespaces)))

	wr, wt := 0, len(s.Workloads)
	for _, wl := range s.Workloads {
		if wl.Ready >= wl.Want {
			wr++
		}
	}
	if wt > 0 {
		wc := "green"
		if wr < wt {
			wc = "yellow"
		}
		lines = append(lines, k("WORKLOADS")+fmt.Sprintf("[%s]%d/%d ready[-]", wc, wr, wt))
	}
	if s.HasApps {
		healthy, outOfSync := 0, 0
		for _, a := range s.Apps {
			if a.Health == "Healthy" {
				healthy++
			}
			if a.Sync != "Synced" {
				outOfSync++
			}
		}
		ac := "green"
		if healthy < len(s.Apps) {
			ac = "yellow"
		}
		l := fmt.Sprintf("[%s]%d/%d Healthy[-]", ac, healthy, len(s.Apps))
		if outOfSync > 0 {
			l += fmt.Sprintf(" [yellow]%d OutOfSync[-]", outOfSync)
		}
		lines = append(lines, k("ARGO CD")+l)
	}
	lbs := 0
	for _, svc := range s.Services {
		if svc.Type == "LoadBalancer" && svc.ExternalIP != "" {
			lbs++
		}
	}
	net := fmt.Sprintf("%d LB IPs · %d hosts", lbs, len(s.Ingresses))
	if len(s.Pools) > 0 {
		net += " [gray]· pool " + tview.Escape(strings.Join(s.Pools, ",")) + "[-]"
	}
	lines = append(lines, k("NETWORK")+net)
	if len(s.Volumes) > 0 {
		healthy, degraded := 0, 0
		for _, v := range s.Volumes {
			switch {
			case v.Robustness == "degraded" || v.Robustness == "faulted" || v.State == "pending":
				degraded++
			default:
				healthy++
			}
		}
		l := fmt.Sprintf("%d volumes", len(s.Volumes))
		if degraded > 0 {
			l += fmt.Sprintf(" [yellow]%d need attention[-]", degraded)
		}
		lines = append(lines, k("STORAGE")+l)
	}
	age := time.Since(s.Time).Round(100 * time.Millisecond)
	st := fmt.Sprintf("[gray]updated %s ago (took %s)[-]", age, s.Took.Round(time.Millisecond))
	if c.note != "" && time.Since(c.noteAt) < 6*time.Second {
		st = c.note
	}
	lines = append(lines, st)
	return lines
}

// ccHint explains a failed read in plain words.
func ccHint(e string) string {
	switch {
	case strings.Contains(e, "401") || strings.Contains(e, "Unauthorized"):
		return "the credential was rejected (remove the cluster and pair again)"
	case strings.Contains(e, "403") || strings.Contains(e, "forbidden"):
		return "this credential may not read the cluster: " + e
	case strings.Contains(e, "executable file not found"):
		return "no kubectl or kubeconfig on this machine: open the Command Center on a control plane, or from a workstation"
	case strings.Contains(e, "localhost:8080"):
		return "no cluster access on this node (workers have none): open it on a control plane, or from a workstation"
	case strings.Contains(e, "timeout") || strings.Contains(e, "refused") || strings.Contains(e, "no route") ||
		strings.Contains(e, "unreachable"):
		return "can't reach the API (away? connect the VPN); retrying: " + e
	case strings.Contains(e, "certificate"):
		return "TLS check failed: " + e
	}
	return e
}

// ---------------------------------------------------------------------------
// Panel 2: nodes
// ---------------------------------------------------------------------------

func (c *commandCenter) sortedNodes() []ccNode {
	nodes := append([]ccNode{}, c.snap.Nodes...)
	switch nodeSorts[c.nodeSort] {
	case "cpu":
		sort.SliceStable(nodes, func(i, j int) bool { return nodes[i].cpuPct() > nodes[j].cpuPct() })
	case "mem":
		sort.SliceStable(nodes, func(i, j int) bool { return nodes[i].memPct() > nodes[j].memPct() })
	}
	if c.reverse {
		for i, j := 0, len(nodes)-1; i < j; i, j = i+1, j-1 {
			nodes[i], nodes[j] = nodes[j], nodes[i]
		}
	}
	return nodes
}

func statusColor(ok bool) string {
	if ok {
		return "green"
	}
	return "red"
}

func (c *commandCenter) nodesTable(width int) *ccTable {
	s := c.snap
	t := &ccTable{
		cols: []ccCol{
			{title: "", width: 1},
			{title: "NODE", width: 10},
			{title: "IP", width: 15, drop: 4},
			{title: "ROLE", width: 13, drop: 6},
			{title: "CPU", min: 15},
			{title: "", min: 12, drop: 3},
			{title: "MEMORY", min: 22},
			{title: "DISK", width: 11, drop: 5},
			{title: "NET ↓ ↑", width: 17, drop: 7},
			{title: "PODS", width: 7, right: true, drop: 8},
			{title: "STATUS", width: 11},
			{title: "KUBELET", width: 8, drop: 9},
			{title: "AGE", width: 4, right: true, drop: 10},
		},
		empty: "no nodes",
	}
	if e := s.Errs["api"]; e != "" {
		msg := "[red]Can't read the cluster: " + tview.Escape(ccHint(e)) + "[-]"
		if len(s.Nodes) > 0 {
			msg += " [gray](showing the last data)[-]"
		}
		t.head = append(t.head, msg)
	}
	for _, n := range c.sortedNodes() {
		n := n
		ok := n.Ready && !n.Unreachable
		dot := ccCell{text: "●", color: statusColor(ok)}
		if ok && (len(n.Pressure) > 0 || n.Unschedulable) {
			dot.color = "yellow"
		}
		row := ccRow{key: n.Name, dim: !ok}
		cpu := ccCell{text: "-"}
		mem := ccCell{text: "-"}
		sp := ccCell{text: ""}
		if n.HasUsage && ok {
			cp, mp := n.cpuPct(), n.memPct()
			cpu = ccCell{text: fmt.Sprintf("%.0f%%", cp), rich: func(w int) string {
				return meter(cp, w-5) + fmt.Sprintf(" [%s]%3.0f%%[-]", pctColor(cp), cp)
			}}
			used := fmtBytes(n.MemUse) + "/" + fmtBytes(n.MemAlloc)
			mem = ccCell{text: used, rich: func(w int) string {
				label := fit(used, 11, true)
				return meter(mp, w-12) + " [" + pctColor(mp) + "]" + label + "[-]"
			}}
			if r := c.hist.nodeCPU[n.Name]; r != nil {
				vals := r.v
				sp = ccCell{text: "", rich: func(w int) string { return spark(vals, w, 100) }}
			}
		}
		disk := ccCell{text: "-"}
		netc := ccCell{text: "-", color: "gray"}
		if n.HasStats && ok {
			if n.FSCap > 0 {
				dp := pct(n.FSUsed, n.FSCap)
				disk = ccCell{text: fmt.Sprintf("%.0f%%", dp), rich: func(w int) string {
					return meter(dp, w-5) + fmt.Sprintf(" [%s]%3.0f%%[-]", pctColor(dp), dp)
				}}
			}
			netc = ccCell{text: fmtRate(n.RxRate) + " " + fmtRate(n.TxRate), rich: func(w int) string {
				half := (w - 1) / 2
				return "[#48dbfb]" + fit(fmtRate(n.RxRate), half, true) + "[-] [#ff9ff3]" + fit(fmtRate(n.TxRate), w-1-half, true) + "[-]"
			}}
		}
		status := n.status()
		stc := "green"
		switch {
		case !ok:
			stc = "red"
		case status != "Ready":
			stc = "yellow"
		}
		pods := fmt.Sprintf("%d", n.Pods)
		if n.PodCap > 0 {
			pods = fmt.Sprintf("%d/%d", n.Pods, n.PodCap)
		}
		row.cells = []ccCell{
			dot, {text: n.Name, color: "white"}, {text: n.IP}, {text: n.Roles, color: "gray"},
			cpu, sp, mem, disk, netc, {text: pods}, {text: status, color: stc},
			{text: n.Kubelet, color: "gray"}, {text: fmtAge(n.Created), color: "gray"},
		}
		t.rows = append(t.rows, row)
	}
	_ = width
	return t
}

// ---------------------------------------------------------------------------
// Panel 3: pods
// ---------------------------------------------------------------------------

func (c *commandCenter) podRows() []ccPod {
	q := strings.ToLower(c.search)
	var out []ccPod
	for _, p := range c.snap.Pods {
		if c.nsFilter != "" && p.NS != c.nsFilter {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(p.Name+" "+p.NS+" "+p.Node+" "+p.Status), q) {
			continue
		}
		out = append(out, p)
	}
	less := map[string]func(a, b *ccPod) bool{
		"cpu":      func(a, b *ccPod) bool { return a.CPUUse > b.CPUUse },
		"mem":      func(a, b *ccPod) bool { return a.MemUse > b.MemUse },
		"restarts": func(a, b *ccPod) bool { return a.Restarts > b.Restarts },
		"age":      func(a, b *ccPod) bool { return a.Created.After(b.Created) },
		"name":     func(a, b *ccPod) bool { return a.Name < b.Name },
		"status":   func(a, b *ccPod) bool { return a.problem() && !b.problem() },
	}[podSorts[c.podSort]]
	sort.SliceStable(out, func(i, j int) bool {
		if c.reverse {
			return less(&out[j], &out[i])
		}
		return less(&out[i], &out[j])
	})
	return out
}

func podColor(p *ccPod) string {
	switch {
	case p.Status == "Completed":
		return "gray"
	case p.Status == "Running" && !p.problem():
		return "green"
	case p.Status == "Pending" || p.Status == "ContainerCreating" || strings.HasPrefix(p.Status, "Init:") || p.Status == "Terminating" ||
		(p.Status == "Running" && p.problem()):
		return "yellow"
	}
	return "red"
}

func (c *commandCenter) podsTable() *ccTable {
	t := &ccTable{
		cols: []ccCol{
			{title: "", width: 1},
			{title: "POD", min: 20},
			{title: "NAMESPACE", width: 14, drop: 3},
			{title: "NODE", width: 7, drop: 6},
			{title: "READY", width: 5, drop: 7},
			{title: "RST", width: 3, right: true, drop: 5},
			{title: "CPU", width: 5, right: true},
			{title: "MEM", width: 5, right: true},
			{title: "STATUS", width: 14},
			{title: "AGE", width: 3, right: true, drop: 8},
			{title: "IP", width: 14, drop: 9},
		},
		empty: "no pods match",
	}
	if e := c.snap.Errs["pods"]; e != "" {
		t.empty = "can't list pods: " + e
	}
	for _, p := range c.podRows() {
		p := p
		col := podColor(&p)
		rst := ccCell{text: fmt.Sprint(p.Restarts), color: "gray"}
		if p.Restarts > 0 {
			rst.color = "yellow"
			if p.Restarts > 5 {
				rst.color = "red"
			}
		}
		cpu, mem := ccCell{text: "-", color: "gray"}, ccCell{text: "-", color: "gray"}
		if p.HasUsage {
			cpu = ccCell{text: fmtCPU(p.CPUUse)}
			mem = ccCell{text: fmtBytes(p.MemUse)}
			if p.MemLim > 0 && pct(p.MemUse, p.MemLim) > 85 {
				mem.color = "orange"
			}
		}
		ready := ccCell{text: fmt.Sprintf("%d/%d", p.Ready, p.Total)}
		if p.Ready < p.Total && p.Status != "Completed" {
			ready.color = "yellow"
		}
		t.rows = append(t.rows, ccRow{key: p.key(), dim: p.Status == "Completed", cells: []ccCell{
			{text: "●", color: col}, {text: p.Name}, {text: p.NS, color: "#8fb3ff"}, {text: orDefault(p.Node, "-"), color: "gray"},
			ready, rst, cpu, mem, {text: p.Status, color: col}, {text: fmtAge(p.Created), color: "gray"}, {text: p.IP, color: "gray"},
		}})
	}
	return t
}

// ---------------------------------------------------------------------------
// Panel 4: namespaces
// ---------------------------------------------------------------------------

func (c *commandCenter) nsTable() *ccTable {
	s := c.snap
	t := &ccTable{
		cols: []ccCol{
			{title: "NAMESPACE", min: 10},
			{title: "PODS", width: 7, right: true},
			{title: "!", width: 2, right: true},
			{title: "CPU", width: 6, right: true},
			{title: "MEM", width: 6, right: true},
			{title: "", width: 10, drop: 2},
		},
		empty: "no namespaces",
	}
	var memTotal int64
	for _, n := range s.Nodes {
		memTotal += n.MemAlloc
	}
	nss := append([]ccNamespace{}, s.Namespaces...)
	less := map[string]func(a, b *ccNamespace) bool{
		"mem":  func(a, b *ccNamespace) bool { return a.MemUse > b.MemUse },
		"cpu":  func(a, b *ccNamespace) bool { return a.CPUUse > b.CPUUse },
		"pods": func(a, b *ccNamespace) bool { return a.Pods > b.Pods },
		"name": func(a, b *ccNamespace) bool { return a.Name < b.Name },
	}[nsSorts[c.nsSort]]
	sort.SliceStable(nss, func(i, j int) bool {
		if c.reverse {
			return less(&nss[j], &nss[i])
		}
		return less(&nss[i], &nss[j])
	})
	for _, ns := range nss {
		ns := ns
		prob := ccCell{text: "", color: "red"}
		if ns.Problems > 0 {
			prob.text = fmt.Sprint(ns.Problems)
		}
		name := ccCell{text: ns.Name}
		if ns.Name == c.nsFilter {
			name.color = "yellow"
		}
		share := pct(ns.MemUse, memTotal)
		t.rows = append(t.rows, ccRow{key: ns.Name, dim: ns.Pods == 0, cells: []ccCell{
			name, {text: fmt.Sprintf("%d/%d", ns.Running, ns.Pods)}, prob,
			{text: fmtCPU(ns.CPUUse)}, {text: fmtBytes(ns.MemUse)},
			{text: fmt.Sprintf("%.0f%%", share), rich: func(w int) string { return meter(min(100, share*4), w) }},
		}})
	}
	return t
}

// ---------------------------------------------------------------------------
// Panel 5: Argo CD apps
// ---------------------------------------------------------------------------

func appColor(a ccApp) string {
	switch {
	case a.Health == "Degraded" || a.Health == "Missing" || a.Phase == "Failed" || a.Phase == "Error":
		return "red"
	case a.Health != "Healthy" || a.Sync != "Synced":
		return "yellow"
	}
	return "green"
}

func (c *commandCenter) appsTable() *ccTable {
	s := c.snap
	t := &ccTable{
		cols: []ccCol{
			{title: "", width: 1},
			{title: "APP", min: 10},
			{title: "SYNC", width: 10},
			{title: "HEALTH", width: 11},
			{title: "NAMESPACE", width: 15, drop: 2},
		},
		empty: "no Argo CD applications",
	}
	if !s.HasApps {
		t.empty = orDefault(s.Errs["apps"], "Argo CD not installed")
		return t
	}
	apps := append([]ccApp{}, s.Apps...)
	rank := map[string]int{"red": 0, "yellow": 1, "green": 2}
	sort.SliceStable(apps, func(i, j int) bool { return rank[appColor(apps[i])] < rank[appColor(apps[j])] })
	for _, a := range apps {
		col := appColor(a)
		sc := "green"
		if a.Sync != "Synced" {
			sc = "yellow"
		}
		hc := map[string]string{"Healthy": "green", "Degraded": "red", "Missing": "red", "Progressing": "aqua", "Suspended": "gray"}[a.Health]
		if hc == "" {
			hc = "yellow"
		}
		t.rows = append(t.rows, ccRow{key: a.Name, cells: []ccCell{
			{text: "●", color: col}, {text: a.Name}, {text: a.Sync, color: sc}, {text: a.Health, color: hc}, {text: a.Dest, color: "gray"},
		}})
	}
	return t
}

// ---------------------------------------------------------------------------
// Panel 6: network
// ---------------------------------------------------------------------------

func (c *commandCenter) networkTable() *ccTable {
	s := c.snap
	t := &ccTable{
		cols: []ccCol{
			{title: "", width: 3},
			{title: "ADDRESS", min: 14},
			{title: "SERVICE", width: 26, drop: 2},
		},
		empty: "no LoadBalancer services or ingresses",
	}
	if e := s.Errs["network"]; e != "" {
		t.empty = e
	}
	lbs := 0
	for _, svc := range s.Services {
		if svc.Type != "LoadBalancer" {
			continue
		}
		addr := orDefault(svc.ExternalIP, "<pending>")
		col := "white"
		if svc.ExternalIP == "" {
			col = "yellow"
		} else {
			lbs++
		}
		t.rows = append(t.rows, ccRow{key: "svc/" + svc.NS + "/" + svc.Name, cells: []ccCell{
			{text: "LB", color: "aqua"}, {text: addr + " :" + strings.Join(svc.Ports, ","), color: col}, {text: svc.NS + "/" + svc.Name, color: "gray"},
		}})
	}
	for _, ing := range s.Ingresses {
		scheme := "http://"
		if ing.TLS {
			scheme = "https://"
		}
		t.rows = append(t.rows, ccRow{key: "ing/" + ing.NS + "/" + ing.Name + "/" + ing.Host, cells: []ccCell{
			{text: "WEB", color: "green"}, {text: scheme + ing.Host}, {text: ing.NS + "/" + ing.Backend, color: "gray"},
		}})
	}
	if len(s.Pools) > 0 {
		size := 0
		for _, p := range s.Pools {
			size += len(poolAddresses(p))
		}
		head := fmt.Sprintf("[gray]MetalLB pool[-] %s [gray]·[-] %d", tview.Escape(strings.Join(s.Pools, ", ")), lbs)
		if size > 0 {
			head += fmt.Sprintf("[gray]/%d used[-]", size)
		}
		t.head = append(t.head, head)
	}
	return t
}

// ---------------------------------------------------------------------------
// Panel 7: storage
// ---------------------------------------------------------------------------

func volColor(v ccVolume) string {
	switch {
	case v.Robustness == "faulted":
		return "red"
	case v.Robustness == "degraded" || v.State == "pending" || v.State == "lost":
		return "yellow"
	case v.Longhorn && v.State == "detached":
		return "gray"
	}
	return "green"
}

func (c *commandCenter) storageTable(width int) *ccTable {
	s := c.snap
	t := &ccTable{
		cols: []ccCol{
			{title: "", width: 1},
			{title: "CLAIM", min: 12},
			{title: "SIZE", width: 6, right: true},
			{title: "USED", width: 6, right: true, drop: 3},
			{title: "STATE", width: 9},
			{title: "NODE", width: 7, drop: 4},
			{title: "COPIES", width: 14, drop: 2},
		},
		empty: "no volumes",
	}
	if e := s.Errs["storage"]; e != "" {
		t.empty = e
	}
	for _, d := range s.Disks {
		if d.Total <= 0 {
			continue
		}
		used := d.Total - d.Available
		p := pct(used, d.Total)
		label := fmt.Sprintf(" %s/%s", fmtBytes(used), fmtBytes(d.Total))
		bw := max(4, min(24, width-10-len(label)))
		t.head = append(t.head, fmt.Sprintf("[gray]%s[-] %s[%s]%s[-]", fit(d.Node, 8, false), meter(p, bw), pctColor(p), label))
	}
	if !s.HasLonghorn && len(s.Volumes) > 0 {
		t.head = append(t.head, "[gray]Longhorn not found: showing claims[-]")
	}
	for _, v := range s.Volumes {
		state := v.State
		if v.Longhorn && v.Robustness != "" && v.Robustness != "unknown" && v.State == "attached" {
			state = v.Robustness
		}
		claim := v.NS + "/" + orDefault(v.PVC, v.Name)
		used := "-"
		if v.Actual > 0 {
			used = fmtBytes(v.Actual)
		}
		copies, copyCol := "-", "gray"
		if v.Longhorn && s.HasLonghorn {
			on, n := v.copiesOn()
			copies = orDefault(on, "none")
			switch {
			case n == 0:
				copyCol = "red"
			case n == 1 && v.Replicas > 1:
				copyCol = "yellow" // one node going down takes the volume with it
			}
		}
		t.rows = append(t.rows, ccRow{key: "vol/" + v.Name + "/" + claim, cells: []ccCell{
			{text: "●", color: volColor(v)}, {text: claim}, {text: fmtBytes(v.Size)}, {text: used, color: "gray"},
			{text: state, color: volColor(v)}, {text: orDefault(v.Node, "-"), color: "gray"},
			{text: copies, color: copyCol},
		}})
	}
	return t
}

// ---------------------------------------------------------------------------
// Panel 8: alerts and events
// ---------------------------------------------------------------------------

func (c *commandCenter) alertsTable() *ccTable {
	s := c.snap
	t := &ccTable{
		cols: []ccCol{
			{title: "", width: 1},
			{title: "WHEN", width: 4, right: true, drop: 2},
			{title: "OBJECT", min: 18},
			{title: "WHAT", min: 22},
		},
	}
	if len(s.Alerts) == 0 {
		t.head = append(t.head, "[green]✓ Nothing needs attention.[-]")
	}
	for i, a := range s.Alerts {
		col := "yellow"
		if a.Level == 2 {
			col = "red"
		}
		when := "now"
		if !a.Since.IsZero() {
			when = fmtAge(a.Since)
		}
		t.rows = append(t.rows, ccRow{key: fmt.Sprintf("a/%s/%s", a.Object, a.Message), cells: []ccCell{
			{text: "●", color: col}, {text: when, color: "gray"}, {text: a.Object, color: col}, {text: a.Message},
		}})
		_ = i
	}
	for _, e := range s.Events {
		if time.Since(e.Time) > 6*time.Hour {
			continue
		}
		obj := strings.ToLower(e.Kind) + "/" + e.Name
		if e.NS != "" {
			obj = e.NS + "/" + obj
		}
		msg := e.Reason + ": " + e.Message
		if e.Count > 1 {
			msg = fmt.Sprintf("%s (×%d)", msg, e.Count)
		}
		t.rows = append(t.rows, ccRow{key: "e/" + obj + "/" + e.Reason, dim: true, cells: []ccCell{
			{text: "◆", color: "#806020"}, {text: fmtAge(e.Time), color: "gray"}, {text: obj, color: "gray"}, {text: msg, color: "gray"},
		}})
	}
	if e := s.Errs["events"]; e != "" && len(s.Events) == 0 {
		t.head = append(t.head, "[gray]events: "+tview.Escape(e)+"[-]")
	}
	t.empty = "no warnings in the last 6 hours"
	return t
}

// ---------------------------------------------------------------------------
// Selection and actions
// ---------------------------------------------------------------------------

func (c *commandCenter) selected(p ccPanelID) string {
	st := c.st[p]
	if st.sel >= 0 && st.sel < len(st.keys) {
		return st.keys[st.sel]
	}
	return ""
}

func (c *commandCenter) move(p ccPanelID, delta int) {
	st := &c.st[p]
	if len(st.keys) == 0 {
		return
	}
	st.sel = max(0, min(len(st.keys)-1, st.sel+delta))
	st.selKey = st.keys[st.sel]
}

// enter opens what the focused panel's selection points at.
func (c *commandCenter) enter() {
	if c.snap == nil {
		return
	}
	key := c.selected(c.focus)
	if key == "" {
		return
	}
	switch c.focus {
	case pNodes:
		c.openTarget(ccTarget{Kind: "Node", Name: key})
	case pPods:
		ns, name, _ := strings.Cut(key, "/")
		c.openTarget(ccTarget{Kind: "Pod", NS: ns, Name: name})
	case pNamespaces:
		if c.nsFilter == key {
			c.nsFilter = ""
			c.flash("[aqua]Showing pods in all namespaces.[-]")
		} else {
			c.nsFilter = key
			c.st[pPods].sel, c.st[pPods].selKey = 0, ""
			c.focusPanel(pPods)
			c.flash("[aqua]Pods in " + tview.Escape(key) + " (ENTER on it again or ESC shows all).[-]")
		}
	case pApps:
		c.openTarget(ccTarget{Kind: "App", Name: key})
	case pNetwork:
		c.openTarget(ccTarget{Kind: "Net", Name: key})
	case pStorage:
		c.openTarget(ccTarget{Kind: "Volume", Name: key})
	case pAlerts:
		if mac, ok := strings.CutPrefix(key, "d/"); ok {
			c.openNetDevice(mac)
			return
		}
		if ip, ok := strings.CutPrefix(key, "c/"); ok {
			c.openDNSClient(ip)
			return
		}
		if key == "base" {
			c.socShowBase = true
			return
		}
		if strings.HasPrefix(key, "s/") || strings.HasPrefix(key, "r/") {
			c.openSOCCase(key)
			return
		}
		if strings.HasPrefix(key, "a/") {
			for _, a := range c.snap.Alerts {
				if fmt.Sprintf("a/%s/%s", a.Object, a.Message) == key {
					switch a.Target.Kind {
					case "Pod", "Node", "App":
						c.openTarget(a.Target)
						return
					}
					c.openTarget(ccTarget{Kind: "Text", Name: a.Object + "\n\n" + a.Message})
					return
				}
			}
		}
		c.openTarget(ccTarget{Kind: "Event", Name: key})
	}
}

func (c *commandCenter) openTarget(t ccTarget) {
	o := &ccOverlay{target: t}
	switch t.Kind {
	case "Node":
		o.title = "NODE " + t.Name
		o.build = func(w int) []string { return c.nodeDetail(t.Name, w) }
	case "Pod":
		o.title = "POD " + t.NS + "/" + t.Name
		o.build = func(w int) []string { return c.podDetail(t.NS, t.Name, w) }
	case "App":
		o.title = "ARGO CD APP " + t.Name
		o.build = func(w int) []string { return c.appDetail(t.Name, w) }
	case "Net":
		o.title = "NETWORK"
		o.build = func(w int) []string { return c.netDetail(t.Name, w) }
	case "Volume":
		o.title = "VOLUME"
		o.build = func(w int) []string { return c.volumeDetail(t.Name, w) }
	case "Event":
		o.title = "EVENT"
		o.build = func(w int) []string { return c.eventDetail(t.Name, w) }
	default:
		o.title = "ALERT"
		o.build = func(w int) []string { return wrapText(t.Name, w) }
	}
	c.overlay = o
	c.setFooter()
}

func (c *commandCenter) closeOverlay() {
	c.overlay = nil
	c.setFooter()
}

// act runs a change after confirmation, then refreshes.
func (c *commandCenter) act(title, question, button string, r ccRequest, done string) {
	if why := c.actionsBlocked(); why != "" {
		c.flash("[yellow]" + tview.Escape(why) + "[-]")
		return
	}
	src := c.src
	showConfirm(title, question, button, "Cancel", func(ok bool) {
		if !ok {
			return
		}
		c.app.SetFocus(c)
		go func() {
			err := src.Do(r)
			c.app.QueueUpdateDraw(func() {
				if err != nil {
					c.flash("[red]" + tview.Escape(err.Error()) + "[-]")
				} else {
					c.flash("[green]" + tview.Escape(done) + "[-]")
				}
				c.refreshNow()
			})
		}()
	})
}

func (c *commandCenter) restartPod(ns, name string) {
	c.act("RESTART POD",
		fmt.Sprintf("Delete pod %s/%s?\n\nIts Deployment, StatefulSet or DaemonSet starts a fresh one. A pod nothing manages is gone for good.", ns, name),
		"Restart",
		ccRequest{Method: http.MethodDelete, Path: "/api/v1/namespaces/" + url.PathEscape(ns) + "/pods/" + url.PathEscape(name),
			Kubectl: []string{"delete", "pod", "-n", ns, name, "--wait=false"}},
		"Deleted "+ns+"/"+name+"; a new pod is starting.")
}

func (c *commandCenter) toggleCordon(name string) {
	n := c.snap.node(name)
	if n == nil {
		return
	}
	to, verb := !n.Unschedulable, "Cordon"
	text := "Stop scheduling new pods on " + name + "? Pods already there keep running."
	if !to {
		verb, text = "Uncordon", "Allow new pods on "+name+" again?"
	}
	args := []string{"cordon", name}
	if !to {
		args = []string{"uncordon", name}
	}
	c.act(strings.ToUpper(verb)+" NODE", text, verb,
		ccRequest{Method: http.MethodPatch, Path: "/api/v1/nodes/" + url.PathEscape(name),
			Body: fmt.Sprintf(`{"spec":{"unschedulable":%t}}`, to), ContentType: "application/merge-patch+json", Kubectl: args},
		verb+"ed "+name+".")
}

// ---------------------------------------------------------------------------
// Keys and mouse
// ---------------------------------------------------------------------------

func (c *commandCenter) HandleKey(ev *tcell.EventKey) *tcell.EventKey {
	if c.searching {
		switch ev.Key() {
		case tcell.KeyEnter:
			c.searching = false
		case tcell.KeyEscape:
			c.searching, c.search = false, ""
		case tcell.KeyBackspace, tcell.KeyBackspace2:
			if r := []rune(c.search); len(r) > 0 {
				c.search = string(r[:len(r)-1])
			}
		case tcell.KeyRune:
			c.search += string(ev.Rune())
			c.st[pPods].sel, c.st[pPods].selKey = 0, ""
		}
		return nil
	}

	if o := c.overlay; o != nil {
		switch ev.Key() {
		case tcell.KeyEscape, tcell.KeyEnter:
			c.closeOverlay()
		case tcell.KeyUp:
			o.top--
		case tcell.KeyDown:
			o.top++
		case tcell.KeyPgUp:
			o.top -= max(1, o.height-1)
		case tcell.KeyPgDn:
			o.top += max(1, o.height-1)
		case tcell.KeyHome:
			o.top = 0
		case tcell.KeyEnd:
			o.top = o.lines
		case tcell.KeyRune:
			switch ev.Rune() {
			case 'l', 'L':
				if o.target.Kind == "Pod" {
					c.logs.open(o.target.NS, o.target.Name)
				}
			case 'x', 'X':
				if o.target.Kind == "Pod" {
					c.restartPod(o.target.NS, o.target.Name)
				}
			case 'c', 'C':
				if o.target.Kind == "Node" {
					c.toggleCordon(o.target.Name)
				}
			case 'k', 'K':
				if o.target.Kind == "Device" && c.net != nil {
					c.net.markKnown(o.target.Name)
					c.flash("[green]" + tview.Escape(o.target.Name) + " marked known.[-]")
				}
			case 'q', 'Q':
				c.closeOverlay()
			}
		}
		return nil
	}

	st := &c.st[c.focus]
	switch ev.Key() {
	case tcell.KeyEscape:
		switch {
		case c.socBack():
		case c.zoom:
			c.zoom = false
		case c.search != "" || c.nsFilter != "":
			c.search, c.nsFilter = "", ""
			c.flash("[aqua]Filters cleared.[-]")
		default:
			c.leave()
		}
		return nil
	case tcell.KeyTab, tcell.KeyBacktab:
		if c.socMode() { // the SOC page's boxes, one at a time over the page
			n := len(c.socBoxes) + 1
			step := 1
			if ev.Key() == tcell.KeyBacktab {
				step = n - 1
			}
			c.socBig, c.socBigTop = (c.socBig+step)%n, 0
			return nil
		}
		vis := c.visiblePanels()
		for i, p := range vis {
			if p == c.focus {
				step := 1
				if ev.Key() == tcell.KeyBacktab {
					step = len(vis) - 1
				}
				c.focus = vis[(i+step)%len(vis)]
				return nil
			}
		}
		if len(vis) > 0 {
			c.focus = vis[0]
		}
		return nil
	case tcell.KeyUp, tcell.KeyDown, tcell.KeyPgUp, tcell.KeyPgDn, tcell.KeyHome, tcell.KeyEnd:
		if c.socScroll(ev.Key()) {
			return nil
		}
	}
	switch ev.Key() {
	case tcell.KeyUp:
		c.move(c.focus, -1)
	case tcell.KeyDown:
		c.move(c.focus, 1)
	case tcell.KeyPgUp:
		c.move(c.focus, -max(1, st.visible-1))
	case tcell.KeyPgDn:
		c.move(c.focus, max(1, st.visible-1))
	case tcell.KeyHome:
		c.move(c.focus, -len(st.keys))
	case tcell.KeyEnd:
		c.move(c.focus, len(st.keys))
	case tcell.KeyLeft, tcell.KeyRight:
		// Switch tabs in the focused box.
		_, _, w, h := c.GetInnerRect()
		for _, s := range c.layout(0, 0, w, h) {
			if len(s.panels) < 2 {
				continue
			}
			for i, p := range s.panels {
				if p == c.focus {
					step := 1
					if ev.Key() == tcell.KeyLeft {
						step = len(s.panels) - 1
					}
					c.focusPanel(s.panels[(i+step)%len(s.panels)])
					return nil
				}
			}
		}
	case tcell.KeyEnter:
		c.enter()
	case tcell.KeyRune:
		r := ev.Rune()
		switch {
		case r >= '1' && r <= '8':
			c.focusPanel(ccPanelID(r - '1'))
		case r == 'q' || r == 'Q':
			c.Close()
			c.app.Stop()
		case r == '/':
			c.searching = true
			c.focusPanel(pPods)
		case r == 's' || r == 'S':
			switch c.focus {
			case pNamespaces:
				c.nsSort = (c.nsSort + 1) % len(nsSorts)
			case pNodes:
				c.nodeSort = (c.nodeSort + 1) % len(nodeSorts)
			default:
				c.podSort = (c.podSort + 1) % len(podSorts)
				if c.focus != pPods {
					c.flash("[aqua]Pods sorted by " + podSorts[c.podSort] + ".[-]")
				}
			}
		case r == 'r' || r == 'R':
			c.reverse = !c.reverse
		case (r == 'f' || r == 'F') && c.focus == pStorage && c.onFiles != nil:
			// key: vol/<pv>/<ns>/<claim>
			// No row shown (a short window): Files opens on the first volume.
			ns, pvc := "", ""
			if parts := strings.SplitN(c.selected(pStorage), "/", 4); len(parts) == 4 && parts[0] == "vol" {
				ns, pvc = parts[2], parts[3]
			}
			open := c.onFiles
			c.suspend() // ESC in Files comes back here (resume)
			open(ns, pvc)
		case r == 'z' || r == 'Z' || r == 'f' || r == 'F':
			if !c.socBack() {
				c.zoom = !c.zoom
			}
		case r == 'p' || r == 'P' || r == ' ':
			c.pause.Store(!c.pause.Load())
			if !c.pause.Load() {
				c.refreshNow()
			}
		case r == '+' || r == '=':
			c.setEvery(-1)
		case r == '-' || r == '_':
			c.setEvery(1)
		case r == 'l' || r == 'L':
			if c.focus == pPods {
				if ns, name, ok := strings.Cut(c.selected(pPods), "/"); ok {
					c.logs.open(ns, name)
				}
			}
		case r == 'x' || r == 'X':
			if c.focus == pPods {
				if ns, name, ok := strings.Cut(c.selected(pPods), "/"); ok {
					c.restartPod(ns, name)
				}
			}
		case (r == 'c' || r == 'C') && c.dnsPage():
			c.dnsConnect()
		case (r == 'a' || r == 'A') && c.dnsPage():
			c.dnsFix()
		case r == 'c' || r == 'C':
			if c.focus == pNodes && c.snap != nil {
				if name := c.selected(pNodes); name != "" {
					c.toggleCordon(name)
				}
			}
		case r == 'n' || r == 'N':
			if c.socMode() { // INCIDENTS → NETWORK → DNS (ESC goes back)
				if c.socPage < 2 {
					c.socPage++
					c.socBig = 0
					c.st[pAlerts].sel, c.st[pAlerts].selKey, c.st[pAlerts].top = 0, "", 0
				}
				break
			}
			c.nsFilter = ""
		case r == 'e' || r == 'E':
			if c.focus == pStorage && c.onStorage != nil {
				open := c.onStorage
				c.Close()
				open()
			}
		case (r == 'v' || r == 'V') && c.socMode():
			c.socShowBase = !c.socShowBase
		case (r == 'u' || r == 'U') && c.netPage():
			c.net.Rescan()
			c.flash("[aqua]Sweeping the LAN now.[-]")
		case (r == 'k' || r == 'K') && c.netPage():
			if mac, ok := strings.CutPrefix(c.selected(pAlerts), "d/"); ok {
				c.net.markKnown(mac)
				c.flash("[green]" + tview.Escape(mac) + " marked known.[-]")
			}
		case r == 'b' || r == 'B':
			if c.focus == pStorage && c.onSpread != nil {
				open := c.onSpread
				c.Close()
				open()
			}
		}
	}
	return nil
}

var ccIntervals = []time.Duration{time.Second, 2 * time.Second, 3 * time.Second, 5 * time.Second, 10 * time.Second, 30 * time.Second}

// setEvery moves the refresh interval one step faster (-1) or slower (+1).
func (c *commandCenter) setEvery(dir int) {
	cur := time.Duration(c.every.Load())
	i := 0
	for k, d := range ccIntervals {
		if d == cur {
			i = k
		}
	}
	i = max(0, min(len(ccIntervals)-1, i+dir))
	c.every.Store(int64(ccIntervals[i]))
	c.flash("[aqua]Refreshing every " + ccIntervals[i].String() + ".[-]")
}

func (c *commandCenter) MouseHandler() func(action tview.MouseAction, event *tcell.EventMouse, setFocus func(p tview.Primitive)) (bool, tview.Primitive) {
	return c.WrapMouseHandler(func(action tview.MouseAction, event *tcell.EventMouse, setFocus func(p tview.Primitive)) (bool, tview.Primitive) {
		x, y := event.Position()
		if !c.InRect(x, y) {
			return false, nil
		}
		setFocus(c)
		if o := c.overlay; o != nil {
			switch action {
			case tview.MouseScrollUp:
				o.top -= 3
			case tview.MouseScrollDown:
				o.top += 3
			}
			return true, nil
		}
		for _, h := range c.hits {
			if !h.r.contains(x, y) {
				continue
			}
			switch action {
			case tview.MouseLeftClick, tview.MouseLeftDoubleClick:
				if y == h.r.y {
					for _, t := range h.tabs {
						if x >= t.x0 && x < t.x1 {
							c.focusPanel(t.panel)
							return true, nil
						}
					}
				}
				c.focus = h.panel
				if h.rowsY >= 0 && y >= h.rowsY {
					st := &c.st[h.panel]
					idx := st.top + (y - h.rowsY)
					if idx < len(st.keys) {
						st.sel, st.selKey = idx, st.keys[idx]
						if action == tview.MouseLeftDoubleClick {
							c.enter()
						}
					}
				}
			case tview.MouseScrollUp:
				c.move(h.panel, -3)
			case tview.MouseScrollDown:
				c.move(h.panel, 3)
			}
			return true, nil
		}
		return true, nil
	})
}

// ---------------------------------------------------------------------------
// Detail overlay
// ---------------------------------------------------------------------------

func (c *commandCenter) drawOverlay(screen tcell.Screen, all ccRect) {
	o := c.overlay
	w := min(all.w-4, max(60, all.w*4/5))
	h := min(all.h-2, max(12, all.h*4/5))
	r := ccRect{all.x + (all.w-w)/2, all.y + (all.h-h)/2, w, h}
	clearRect(screen, r)
	drawBox(screen, r, tcell.ColorAqua)
	put(screen, "┤[white::b]"+tview.Escape(o.title)+"[-::-]├", r.x+2, r.y, r.w-4)
	in := r.inner()
	in = ccRect{in.x + 1, in.y, in.w - 2, in.h}
	var lines []string
	if c.snap != nil {
		lines = o.build(in.w)
	}
	o.lines, o.height = len(lines), in.h
	o.top = max(0, min(o.top, len(lines)-in.h))
	for i := 0; i < in.h && o.top+i < len(lines); i++ {
		put(screen, lines[o.top+i], in.x, in.y+i, in.w)
	}
	if len(lines) > in.h {
		pos := fmt.Sprintf("%d-%d/%d", o.top+1, min(len(lines), o.top+in.h), len(lines))
		put(screen, "[gray]"+pos+"[-]", r.x+r.w-2-len(pos), r.y+r.h-1, len(pos))
	}
}

func wrapText(s string, w int) []string {
	var out []string
	for _, para := range strings.Split(s, "\n") {
		line := ""
		for _, word := range strings.Fields(para) {
			if line != "" && strWidth(line)+1+strWidth(word) > w {
				out = append(out, tview.Escape(line))
				line = ""
			}
			if line != "" {
				line += " "
			}
			line += word
		}
		out = append(out, tview.Escape(line))
	}
	return out
}

func orNone(v int64, f func(int64) string) string {
	if v <= 0 {
		return "none"
	}
	return f(v)
}

func kv(k, v string) string { return fmt.Sprintf("[yellow::b]%-12s[-::-] %s", k, v) }

func section(title string) string { return "[aqua::b]" + title + "[-::-]" }

func (c *commandCenter) nodeDetail(name string, w int) []string {
	n := c.snap.node(name)
	if n == nil {
		return []string{"[red]Node " + tview.Escape(name) + " is gone.[-]"}
	}
	ok := n.Ready && !n.Unreachable
	st := "[green]" + n.status() + "[-]"
	if !ok {
		st = "[red]" + n.status() + "[-]"
	}
	l := []string{
		kv("STATUS", st+"   [gray]role[-] "+tview.Escape(n.Roles)+"   [gray]IP[-] "+n.IP),
		kv("SYSTEM", tview.Escape(fmt.Sprintf("%s · kernel %s · %s · %s", n.OS, n.Kernel, n.Runtime, n.Arch))),
		kv("KUBELET", tview.Escape(n.Kubelet)+"   [gray]node age[-] "+fmtAge(n.Created)+map[bool]string{true: "   [gray]kubelet up[-] " + fmtAge(n.KubeletUp), false: ""}[!n.KubeletUp.IsZero()]),
		"",
	}
	bar := max(10, min(30, w-60))
	if n.HasUsage {
		l = append(l,
			kv("CPU", meter(n.cpuPct(), bar)+fmt.Sprintf(" [%s]%.0f%%[-] %s of %s cores · requests %s (%.0f%%) · limits %s",
				pctColor(n.cpuPct()), n.cpuPct(), fmtCores(n.CPUUse), fmtCores(n.CPUAlloc), fmtCores(n.CPUReq), pct(n.CPUReq, n.CPUAlloc), orNone(n.CPULim, fmtCores))),
			kv("MEMORY", meter(n.memPct(), bar)+fmt.Sprintf(" [%s]%.0f%%[-] %s of %s · requests %s (%.0f%%) · limits %s",
				pctColor(n.memPct()), n.memPct(), fmtBytes(n.MemUse), fmtBytes(n.MemAlloc), fmtBytes(n.MemReq), pct(n.MemReq, n.MemAlloc), orNone(n.MemLim, fmtBytes))))
	}
	if n.HasStats && n.FSCap > 0 {
		dp := pct(n.FSUsed, n.FSCap)
		l = append(l, kv("DISK", meter(dp, bar)+fmt.Sprintf(" [%s]%.0f%%[-] %s of %s (root filesystem)", pctColor(dp), dp, fmtBytes(n.FSUsed), fmtBytes(n.FSCap))),
			kv("NETWORK", fmt.Sprintf("[#48dbfb]↓ %s[-]   [#ff9ff3]↑ %s[-]", fmtRate(n.RxRate), fmtRate(n.TxRate))))
		if r, t := c.hist.nodeRx[n.Name], c.hist.nodeTx[n.Name]; r != nil && t != nil {
			top := 1.0
			for _, v := range append(append([]float64{}, r.v...), t.v...) {
				top = max(top, v)
			}
			l = append(l, kv("", "[#48dbfb]↓[-] "+spark(r.v, min(60, w-16), top)), kv("", "[#ff9ff3]↑[-] "+spark(t.v, min(60, w-16), top)))
		}
	}
	if r := c.hist.nodeCPU[n.Name]; r != nil && len(r.v) > 1 {
		l = append(l, kv("CPU HISTORY", spark(r.v, min(60, w-16), 100)))
	}
	if r := c.hist.nodeMem[n.Name]; r != nil && len(r.v) > 1 {
		l = append(l, kv("MEM HISTORY", spark(r.v, min(60, w-16), 100)))
	}
	l = append(l, kv("PODS", fmt.Sprintf("%d of %d", n.Pods, n.PodCap)), "", section("CONDITIONS"))
	for _, cond := range n.Conditions {
		good := (cond[0] == "Ready") == (cond[1] == "True")
		dot := "[green]●[-]"
		if !good {
			dot = "[red]●[-]"
		}
		l = append(l, fmt.Sprintf("  %s %-16s %-7s [gray]%s[-]", dot, cond[0], cond[1], tview.Escape(cond[2])))
	}
	if len(n.Taints) > 0 {
		l = append(l, "", section("TAINTS"))
		for _, t := range n.Taints {
			l = append(l, "  "+tview.Escape(t))
		}
	}
	if len(n.Labels) > 0 {
		l = append(l, "", section("LABELS"))
		for _, lb := range n.Labels {
			l = append(l, "  [gray]"+tview.Escape(lb)+"[-]")
		}
	}
	var pods []ccPod
	for _, p := range c.snap.Pods {
		if p.Node == name {
			pods = append(pods, p)
		}
	}
	sort.Slice(pods, func(i, j int) bool { return pods[i].CPUUse > pods[j].CPUUse })
	l = append(l, "", section(fmt.Sprintf("PODS ON %s (%d, busiest first)", strings.ToUpper(name), len(pods))))
	for _, p := range pods {
		l = append(l, fmt.Sprintf("  [%s]●[-] %s [#8fb3ff]%s[-] %6s %6s [%s]%s[-]", podColor(&p),
			tview.Escape(fit(p.Name, max(20, w-60), false)), tview.Escape(fit(p.NS, 16, false)), fmtCPU(p.CPUUse), fmtBytes(p.MemUse), podColor(&p), tview.Escape(p.Status)))
	}
	return l
}

func (c *commandCenter) podDetail(ns, name string, w int) []string {
	p := c.snap.pod(ns, name)
	if p == nil {
		return []string{"[yellow]Pod " + tview.Escape(ns+"/"+name) + " is gone (restarted or deleted).[-]", "", "[gray]Its replacement has a new name: ESC, then find it in the pods panel.[-]"}
	}
	col := podColor(p)
	l := []string{
		kv("STATUS", fmt.Sprintf("[%s]%s[-]   [gray]ready[-] %d/%d   [gray]restarts[-] %d", col, tview.Escape(p.Status), p.Ready, p.Total, p.Restarts)),
		kv("NODE", tview.Escape(orDefault(p.Node, "not scheduled"))+"   [gray]pod IP[-] "+orDefault(p.IP, "-")+"   [gray]QoS[-] "+tview.Escape(p.QoS)),
		kv("OWNER", tview.Escape(orDefault(p.Owner, "none (a bare pod: deleting it is permanent)"))),
		kv("AGE", fmtAge(p.Created)+map[bool]string{true: "   [gray]last restart[-] " + fmtAge(p.LastRestart) + " ago", false: ""}[!p.LastRestart.IsZero()]),
		"",
	}
	if p.HasUsage {
		cpuL, memL := "none", "none"
		if p.CPULim > 0 {
			cpuL = fmtCPU(p.CPULim)
		}
		if p.MemLim > 0 {
			memL = fmtBytes(p.MemLim)
		}
		l = append(l,
			kv("CPU", fmt.Sprintf("%s used · request %s · limit %s", fmtCPU(p.CPUUse), fmtCPU(p.CPUReq), cpuL)),
			kv("MEMORY", fmt.Sprintf("%s used · request %s · limit %s", fmtBytes(p.MemUse), fmtBytes(p.MemReq), memL)))
		if p.MemLim > 0 {
			mp := pct(p.MemUse, p.MemLim)
			l = append(l, kv("", meter(mp, 30)+fmt.Sprintf(" [%s]%.0f%%[-] of its memory limit", pctColor(mp), mp)))
		}
		l = append(l, "")
	}
	l = append(l, section("CONTAINERS"))
	for _, ct := range p.Containers {
		dot := "[green]●[-]"
		if !ct.Ready {
			dot = "[red]●[-]"
		}
		l = append(l, fmt.Sprintf("  %s [::b]%s[::-]  [gray]%s[-]", dot, tview.Escape(ct.Name), tview.Escape(ct.Image)))
		state := ct.State
		if ct.Reason != "" {
			state += ": " + ct.Reason
		}
		line := fmt.Sprintf("     %s · restarts %d", tview.Escape(state), ct.Restarts)
		if ct.LastReason != "" {
			line += " · [yellow]last exit " + tview.Escape(ct.LastReason) + "[-]"
		}
		l = append(l, line)
		if p.HasUsage {
			l = append(l, fmt.Sprintf("     [gray]cpu %s (req %s)  mem %s (req %s, limit %s)[-]",
				fmtCPU(ct.CPUUse), fmtCPU(ct.CPUReq), fmtBytes(ct.MemUse), fmtBytes(ct.MemReq), orDefault(map[bool]string{true: fmtBytes(ct.MemLim)}[ct.MemLim > 0], "none")))
		}
	}
	var evs []string
	for _, e := range c.snap.Events {
		if e.Kind == "Pod" && e.NS == ns && e.Name == name {
			evs = append(evs, fmt.Sprintf("  [yellow]%s[-] %s ago: %s", tview.Escape(e.Reason), fmtAge(e.Time), tview.Escape(e.Message)))
		}
	}
	if len(evs) > 0 {
		l = append(l, "", section("WARNINGS"))
		for _, e := range evs {
			l = append(l, wrapIndented(e, w)...)
		}
	}
	l = append(l, "", "[gray]L logs · X restart (delete; its controller starts a new one) · ESC close[-]")
	return l
}

// wrapIndented wraps an already-tagged line by plain width (keeps tags of
// the first segment only: fine for short colored prefixes).
func wrapIndented(line string, w int) []string {
	if tview.TaggedStringWidth(line) <= w {
		return []string{line}
	}
	var out []string
	for len(out) < 20 {
		if tview.TaggedStringWidth(line) <= w {
			out = append(out, line)
			break
		}
		// cut at w visible columns
		cut, vis, inTag := 0, 0, false
		for i, r := range line {
			switch {
			case r == '[':
				inTag = true
			case r == ']' && inTag:
				inTag = false
			case !inTag:
				vis++
			}
			if vis >= w {
				cut = i + 1
				break
			}
		}
		if cut == 0 {
			out = append(out, line)
			break
		}
		if sp := strings.LastIndex(line[:cut], " "); sp > cut/2 {
			cut = sp
		}
		out = append(out, line[:cut])
		line = "     " + strings.TrimLeft(line[cut:], " ")
	}
	return out
}

func (c *commandCenter) appDetail(name string, w int) []string {
	for _, a := range c.snap.Apps {
		if a.Name != name {
			continue
		}
		col := appColor(a)
		l := []string{
			kv("STATUS", fmt.Sprintf("[%s]%s · %s[-]", col, a.Sync, a.Health)+map[bool]string{true: "   [gray]last sync[-] " + tview.Escape(a.Phase), false: ""}[a.Phase != ""]),
			kv("SOURCE", tview.Escape(a.Repo)),
			kv("PATH", tview.Escape(a.Path)+"   [gray]revision[-] "+tview.Escape(a.Revision)),
			kv("NAMESPACE", tview.Escape(a.Dest)),
		}
		if a.Message != "" {
			l = append(l, "", section("MESSAGE"))
			l = append(l, wrapText(a.Message, w)...)
		}
		var pods []ccPod
		for _, p := range c.snap.Pods {
			if p.NS == a.Dest {
				pods = append(pods, p)
			}
		}
		l = append(l, "", section(fmt.Sprintf("PODS IN %s (%d)", strings.ToUpper(a.Dest), len(pods))))
		for _, p := range pods {
			l = append(l, fmt.Sprintf("  [%s]●[-] %s %6s %6s [%s]%s[-]", podColor(&p), tview.Escape(fit(p.Name, max(20, w-40), false)),
				fmtCPU(p.CPUUse), fmtBytes(p.MemUse), podColor(&p), tview.Escape(p.Status)))
		}
		l = append(l, "", "[gray]Sync or change it in the Argo CD web UI, or push to your GitOps repo.[-]")
		return l
	}
	return []string{"[yellow]App " + tview.Escape(name) + " is gone.[-]"}
}

func (c *commandCenter) netDetail(key string, w int) []string {
	s := c.snap
	for _, svc := range s.Services {
		if "svc/"+svc.NS+"/"+svc.Name == key {
			l := []string{
				kv("SERVICE", tview.Escape(svc.NS+"/"+svc.Name)),
				kv("TYPE", svc.Type),
				kv("LAN IP", orDefault(svc.ExternalIP, "[yellow]pending: no free MetalLB address?[-]")),
				kv("CLUSTER IP", svc.ClusterIP),
				kv("PORTS", tview.Escape(strings.Join(svc.Ports, ", "))),
			}
			var pods []string
			for _, p := range s.Pods {
				if p.NS == svc.NS {
					pods = append(pods, fmt.Sprintf("  [%s]●[-] %s", podColor(&p), tview.Escape(p.Name)))
				}
			}
			l = append(l, "", section("PODS IN "+strings.ToUpper(svc.NS)))
			return append(l, pods...)
		}
	}
	for _, ing := range s.Ingresses {
		if "ing/"+ing.NS+"/"+ing.Name+"/"+ing.Host == key {
			scheme := "http://"
			if ing.TLS {
				scheme = "https://"
			}
			return []string{
				kv("URL", tview.Escape(scheme+ing.Host)),
				kv("INGRESS", tview.Escape(ing.NS+"/"+ing.Name)),
				kv("BACKEND", tview.Escape(ing.Backend)),
				kv("ADDRESS", orDefault(ing.Address, "-")+"   [gray](the ingress controller's LAN IP: point DNS here)[-]"),
				kv("TLS", map[bool]string{true: "[green]yes[-]", false: "[yellow]no[-]"}[ing.TLS]),
			}
		}
	}
	return []string{"[yellow]Gone.[-]"}
}

func (c *commandCenter) volumeDetail(key string, w int) []string {
	for _, v := range c.snap.Volumes {
		if "vol/"+v.Name+"/"+v.NS+"/"+orDefault(v.PVC, v.Name) != key {
			continue
		}
		l := []string{
			kv("CLAIM", tview.Escape(v.NS+"/"+v.PVC)),
			kv("VOLUME", tview.Escape(v.Name)),
			kv("SIZE", fmtBytes(v.Size)+map[bool]string{true: "   [gray]used[-] " + fmtBytes(v.Actual), false: ""}[v.Actual > 0]),
			kv("STATE", fmt.Sprintf("[%s]%s[-]", volColor(v), tview.Escape(strings.TrimSpace(v.State+" "+v.Robustness)))),
		}
		if v.Longhorn {
			on, n := v.copiesOn()
			l = append(l, kv("ATTACHED TO", orDefault(v.Node, "-")+"   [gray](the node running its app)[-]"),
				kv("REPLICAS", fmt.Sprintf("%d wanted   [gray]copies on[-] %s", v.Replicas, tview.Escape(orDefault(on, "none")))))
			if v.Robustness == "degraded" {
				l = append(l, "", "[yellow]Degraded: a replica is missing (often its node is down). Longhorn rebuilds it when the node is back or on another node with space.[-]")
			}
			if v.Replicas > 1 && n <= 1 {
				l = append(l, "")
				for _, line := range wrapText("Every copy is on one node (or none exists): if that node goes down, so does the volume. B in the Storage panel spreads the copies across the nodes.", w) {
					l = append(l, "[yellow]"+line+"[-]")
				}
			}
		}
		return l
	}
	return []string{"[yellow]Gone.[-]"}
}

func (c *commandCenter) eventDetail(key string, w int) []string {
	for _, e := range c.snap.Events {
		obj := strings.ToLower(e.Kind) + "/" + e.Name
		if e.NS != "" {
			obj = e.NS + "/" + obj
		}
		if "e/"+obj+"/"+e.Reason == key {
			l := []string{
				kv("OBJECT", tview.Escape(obj)),
				kv("REASON", "[yellow]"+tview.Escape(e.Reason)+"[-]"),
				kv("WHEN", fmtAge(e.Time)+" ago"+map[bool]string{true: fmt.Sprintf(" · %d times", e.Count), false: ""}[e.Count > 1]),
				"",
			}
			return append(l, wrapText(e.Message, w)...)
		}
	}
	return []string{"[gray]This event has expired.[-]"}
}

// ---------------------------------------------------------------------------
// Pod logs
// ---------------------------------------------------------------------------

type ccLogs struct {
	c          *commandCenter
	view       *logView
	header     *tview.TextView
	page       *tview.Flex
	ns, pod    string
	containers []string
	container  int
	previous   bool
	stop       chan struct{}
}

func newCCLogs(c *commandCenter) *ccLogs {
	l := &ccLogs{c: c, view: newLogView(c.app), header: tview.NewTextView().SetDynamicColors(true)}
	l.view.clickFocus = func() tview.Primitive { return l.view }
	l.view.onCopy = func(text string) {
		if copyToClipboard(text) {
			l.header.SetText(l.headerText() + "  [green]copied[-]")
		}
	}
	body := frame("POD LOGS")
	body.AddItem(l.header, 1, 0, false).AddItem(l.view, 0, 1, true)
	l.page = tview.NewFlex().SetDirection(tview.FlexRow).AddItem(body, 0, 1, true).AddItem(c.footer, 1, 0, false)
	return l
}

func (l *ccLogs) headerText() string {
	ct := ""
	if len(l.containers) > 0 {
		ct = " · container [yellow]" + tview.Escape(l.containers[l.container]) + "[-]"
		if len(l.containers) > 1 {
			ct += fmt.Sprintf(" [gray](%d/%d)[-]", l.container+1, len(l.containers))
		}
	}
	prev := ""
	if l.previous {
		prev = " · [orange]previous run (before the last restart)[-]"
	}
	follow := " · [green]following[-]"
	if !l.view.Following() {
		follow = " · [gray]scrolled (END follows)[-]"
	}
	return " [::b]" + tview.Escape(l.ns+"/"+l.pod) + "[::-]" + ct + prev + follow
}

func (l *ccLogs) open(ns, pod string) {
	l.ns, l.pod, l.container, l.previous = ns, pod, 0, false
	l.containers = nil
	if p := l.c.snap.pod(ns, pod); p != nil {
		for _, ct := range p.Containers {
			l.containers = append(l.containers, ct.Name)
		}
	}
	l.view.Reset()
	l.view.SetLines([]logLine{styledLine("loading…", baseLogStyle())}, 0)
	l.c.pages.AddAndSwitchToPage("cclogs", l.page, true)
	l.c.footer.SetText(" [aqua::b]↑↓/wheel[-::-] Scroll  [aqua::b]END[-::-] Follow  [aqua::b]C[-::-] Next container  [aqua::b]P[-::-] Previous run  [aqua::b]drag[-::-] Copy  [aqua::b]ESC[-::-] Back")
	l.c.app.SetFocus(l.view)
	l.header.SetText(l.headerText())
	l.startPolling()
}

func (l *ccLogs) path() string {
	q := url.Values{"tailLines": {"1000"}}
	if len(l.containers) > 0 {
		q.Set("container", l.containers[l.container])
	}
	if l.previous {
		q.Set("previous", "true")
	}
	return "/api/v1/namespaces/" + url.PathEscape(l.ns) + "/pods/" + url.PathEscape(l.pod) + "/log?" + q.Encode()
}

func (l *ccLogs) startPolling() {
	l.stopPolling()
	stop, src, path := make(chan struct{}), l.c.src, l.path()
	l.stop = stop
	demo := false
	if _, ok := src.(*demoCCSource); ok {
		demo = true
	}
	pod := l.pod
	go func() {
		for {
			var data []byte
			var err error
			if demo {
				data = []byte(demoLogs(pod))
			} else {
				data, err = ccGet(src, path)
			}
			l.c.app.QueueUpdateDraw(func() {
				if l.stop != stop {
					return
				}
				var lines []logLine
				if err != nil {
					lines = []logLine{styledLine("Can't read the logs: "+err.Error(), baseLogStyle().Foreground(tcell.ColorRed))}
				} else {
					st := baseLogStyle()
					for _, raw := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
						var line logLine
						line, st = parseANSI(raw, st)
						lines = append(lines, line)
					}
					if len(lines) == 1 && len(lines[0]) == 0 {
						lines = []logLine{styledLine("(no output)", baseLogStyle().Foreground(tcell.ColorGray))}
					}
				}
				l.view.SetLines(lines, 0)
				l.header.SetText(l.headerText())
			})
			select {
			case <-stop:
				return
			case <-time.After(2 * time.Second):
			}
		}
	}()
}

func (l *ccLogs) stopPolling() {
	if l.stop != nil {
		close(l.stop)
		l.stop = nil
	}
}

func (l *ccLogs) HandleKey(ev *tcell.EventKey) *tcell.EventKey {
	switch ev.Key() {
	case tcell.KeyEscape:
		l.stopPolling()
		l.c.show()
		return nil
	case tcell.KeyUp:
		l.view.ScrollBy(-1)
	case tcell.KeyDown:
		l.view.ScrollBy(1)
	case tcell.KeyPgUp:
		l.view.ScrollBy(-20)
	case tcell.KeyPgDn:
		l.view.ScrollBy(20)
	case tcell.KeyHome:
		l.view.ScrollToBeginning()
	case tcell.KeyEnd:
		l.view.ScrollToEnd()
	case tcell.KeyRune:
		switch ev.Rune() {
		case 'c', 'C':
			if len(l.containers) > 1 {
				l.container = (l.container + 1) % len(l.containers)
				l.view.Reset()
				l.startPolling()
			}
		case 'p', 'P':
			l.previous = !l.previous
			l.view.Reset()
			l.startPolling()
		case 'q', 'Q':
			l.stopPolling()
			l.c.show()
		}
	}
	l.header.SetText(l.headerText())
	return nil
}
