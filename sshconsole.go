package main

// SSH Console: pick a cluster node (or a saved host) and get a live shell in
// the embedded terminal. "K" installs this machine's SSH key on the node once,
// after which connections need no password.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// ---------------------------------------------------------------------------
// Saved hosts (~/.config/kubestui/ssh-hosts.json). No passwords are stored.
// ---------------------------------------------------------------------------

type hostEntry struct {
	Name     string `json:"name,omitempty"`
	Host     string `json:"host"`
	User     string `json:"user,omitempty"`
	Port     int    `json:"port,omitempty"`
	KeyLogin bool   `json:"keyLogin,omitempty"`
	Custom   bool   `json:"custom,omitempty"` // added by hand, not a cluster node
}

func (h *hostEntry) portOr22() int {
	if h.Port > 0 {
		return h.Port
	}
	return 22
}

type hostStore struct {
	Hosts []hostEntry `json:"hosts"`
	Last  *hostEntry  `json:"last,omitempty"` // last remote-join target
	path  string
}

func hostStorePath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		dir = filepath.Join(os.Getenv("HOME"), ".config")
	}
	return filepath.Join(dir, "kubestui", "ssh-hosts.json")
}

func loadHostStore() *hostStore {
	s := &hostStore{path: hostStorePath()}
	if data, err := os.ReadFile(s.path); err == nil {
		_ = json.Unmarshal(data, s)
	}
	return s
}

func (s *hostStore) save() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0o600)
}

func (s *hostStore) find(host string) *hostEntry {
	for i := range s.Hosts {
		if s.Hosts[i].Host == host {
			return &s.Hosts[i]
		}
	}
	return nil
}

// upsert stores the user/port for host, keeping other fields.
func (s *hostStore) upsert(e hostEntry) *hostEntry {
	if cur := s.find(e.Host); cur != nil {
		if e.Name != "" {
			cur.Name = e.Name
		}
		if e.User != "" {
			cur.User = e.User
		}
		if e.Port > 0 {
			cur.Port = e.Port
		}
		cur.Custom = cur.Custom || e.Custom
		return cur
	}
	s.Hosts = append(s.Hosts, e)
	return &s.Hosts[len(s.Hosts)-1]
}

func (s *hostStore) remember(e hostEntry) {
	s.upsert(e)
	last := e
	s.Last = &last
}

func (s *hostStore) remove(host string) {
	out := s.Hosts[:0]
	for _, h := range s.Hosts {
		if h.Host != host {
			out = append(out, h)
		}
	}
	s.Hosts = out
}

// ---------------------------------------------------------------------------
// Cluster nodes
// ---------------------------------------------------------------------------

type nodeRow struct {
	name   string
	host   string
	role   string
	status string // Ready / NotReady / "" for saved hosts
	custom bool
}

func clusterNodes() ([]nodeRow, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "kubectl", "get", "nodes", "-o", "json").Output()
	if err != nil {
		return nil, err
	}
	return parseNodes(out)
}

// kubeNodeList is the part of `kubectl get nodes -o json` we use.
type kubeNodeList struct {
	Items []struct {
		Metadata struct {
			Name   string            `json:"name"`
			Labels map[string]string `json:"labels"`
		} `json:"metadata"`
		Status struct {
			Addresses []struct {
				Type    string `json:"type"`
				Address string `json:"address"`
			} `json:"addresses"`
			Conditions []struct {
				Type   string `json:"type"`
				Status string `json:"status"`
			} `json:"conditions"`
		} `json:"status"`
	} `json:"items"`
}

func (list kubeNodeList) rows() []nodeRow {
	var rows []nodeRow
	for _, n := range list.Items {
		r := nodeRow{name: n.Metadata.Name, status: "NotReady"}
		for _, a := range n.Status.Addresses {
			if a.Type == "InternalIP" {
				r.host = a.Address
			}
		}
		for _, c := range n.Status.Conditions {
			if c.Type == "Ready" && c.Status == "True" {
				r.status = "Ready"
			}
		}
		var roles []string
		for k := range n.Metadata.Labels {
			if role, ok := strings.CutPrefix(k, "node-role.kubernetes.io/"); ok && role != "" {
				roles = append(roles, role)
			}
		}
		sort.Strings(roles)
		r.role = strings.Join(roles, ",")
		if r.role == "" {
			r.role = "-"
		}
		if r.host != "" {
			rows = append(rows, r)
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].name < rows[j].name })
	return rows
}

// ---------------------------------------------------------------------------
// Screen
// ---------------------------------------------------------------------------

type sshConsole struct {
	app    *tview.Application
	pages  *tview.Pages
	footer *tview.TextView
	onBack func()

	screen *tview.Flex
	intro  *tview.TextView
	table  *tview.Table
	note   *tview.TextView

	store *hostStore
	rows  []nodeRow

	// Swappable for workstation mode (see workstation.go).
	nodesFn     func() ([]nodeRow, error)
	connectFn   func(e hostEntry)
	keyFn       func(e hostEntry)
	defaultUser func() string
	keyLoginFn  func(host string) bool // extra "key ✓" source (demo)
	demo        bool                   // demo: don't change saved hosts
}

var sshPage *sshConsole

func newSSHConsole(app *tview.Application, pages *tview.Pages, footer *tview.TextView, onBack func()) *sshConsole {
	c := &sshConsole{app: app, pages: pages, footer: footer, onBack: onBack}
	c.nodesFn = clusterNodes
	c.connectFn = c.connect
	c.keyFn = c.setupKey
	c.defaultUser = defaultSSHUser

	c.intro = tview.NewTextView().SetDynamicColors(true).SetText(
		"\n  [yellow::b]SSH CONSOLE[-::-]\n" +
			"  Open a shell on any node right here. Press [aqua::b]K[-::-] once per node to install\n" +
			"  this machine's SSH key, and every later connection is password-free.\n")

	c.table = tview.NewTable().
		SetSelectable(true, false).
		SetFixed(1, 0).
		SetSelectedStyle(tcell.StyleDefault.Background(tcell.ColorAqua).Foreground(tcell.ColorBlack))
	c.table.SetBorderPadding(0, 0, 1, 1)
	c.table.SetSelectedFunc(func(row, _ int) { c.activate(row) })

	c.note = tview.NewTextView().SetDynamicColors(true)

	body := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(c.intro, 5, 0, false).
		AddItem(c.table, 0, 1, true).
		AddItem(c.note, 2, 0, false)
	body.SetBorder(true).SetTitle(" HOMELAB KUBERNETES PLATFORM ").SetTitleAlign(tview.AlignLeft)

	c.screen = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(body, 0, 1, true).
		AddItem(footer, 1, 0, false)

	return c
}

func (c *sshConsole) footerText() string {
	return " [aqua::b]ENTER[-::-] Connect    [aqua::b]K[-::-] Key login    [aqua::b]U[-::-] User    [aqua::b]A[-::-] Add host    [aqua::b]D[-::-] Remove    [aqua::b]R[-::-] Refresh    [aqua::b]ESC[-::-] Back"
}

func (c *sshConsole) Show() {
	c.pages.AddAndSwitchToPage("ssh", c.screen, true)
	c.footer.SetText(c.footerText())
	c.refresh()
	c.app.SetFocus(c.table)
}

func (c *sshConsole) refresh() {
	c.store = loadHostStore()

	nodes, err := c.nodesFn()
	if err != nil {
		c.note.SetText("  [yellow]Cluster nodes unavailable (kubectl: " + tview.Escape(strings.TrimSpace(err.Error())) + "). Showing saved hosts.[-]")
	} else {
		path := c.store.path
		if home, err := os.UserHomeDir(); err == nil && strings.HasPrefix(path, home+"/") {
			path = "~" + strings.TrimPrefix(path, home)
		}
		c.note.SetText(fmt.Sprintf("  [gray]%d cluster node(s). Saved logins: %s[-]", len(nodes), tview.Escape(path)))
	}

	seen := map[string]bool{}
	c.rows = nil
	for _, n := range nodes {
		seen[n.host] = true
		c.rows = append(c.rows, n)
	}
	for _, h := range c.store.Hosts {
		if h.Custom && !seen[h.Host] {
			name := h.Name
			if name == "" {
				name = h.Host
			}
			c.rows = append(c.rows, nodeRow{name: name, host: h.Host, role: "saved", custom: true})
		}
	}

	selected, _ := c.table.GetSelection()
	c.table.Clear()

	headers := []string{"NODE", "ADDRESS", "ROLE", "STATUS", "LOGIN AS", "AUTH"}
	for i, h := range headers {
		c.table.SetCell(0, i, tview.NewTableCell(" "+h+" ").
			SetTextColor(tcell.ColorYellow).
			SetAttributes(tcell.AttrBold).
			SetSelectable(false).
			SetExpansion(1))
	}

	for i, r := range c.rows {
		entry := c.store.find(r.host)
		user, auth, authColor := c.defaultUser(), "password", tcell.ColorYellow
		port := 22
		if entry != nil {
			if entry.User != "" {
				user = entry.User
			}
			port = entry.portOr22()
			if entry.KeyLogin {
				auth, authColor = "key ✓", tcell.ColorGreen
			}
		}
		if c.keyLoginFn != nil && c.keyLoginFn(r.host) {
			auth, authColor = "key ✓", tcell.ColorGreen
		}

		status, statusColor := r.status, tcell.ColorGreen
		switch r.status {
		case "NotReady":
			statusColor = tcell.ColorRed
		case "":
			status, statusColor = "-", tcell.ColorGray
		}

		addr := r.host
		if port != 22 {
			addr += ":" + strconv.Itoa(port)
		}

		row := i + 1
		c.table.SetCell(row, 0, tview.NewTableCell(" "+r.name+" ").SetTextColor(tcell.ColorWhite).SetAttributes(tcell.AttrBold).SetExpansion(1))
		c.table.SetCell(row, 1, tview.NewTableCell(" "+addr+" ").SetTextColor(tcell.ColorWhite).SetExpansion(1))
		c.table.SetCell(row, 2, tview.NewTableCell(" "+r.role+" ").SetTextColor(tcell.ColorAqua).SetExpansion(1))
		c.table.SetCell(row, 3, tview.NewTableCell(" "+status+" ").SetTextColor(statusColor).SetExpansion(1))
		c.table.SetCell(row, 4, tview.NewTableCell(" "+user+" ").SetTextColor(tcell.ColorWhite).SetExpansion(1))
		c.table.SetCell(row, 5, tview.NewTableCell(" "+auth+" ").SetTextColor(authColor).SetExpansion(1))
	}

	addRow := len(c.rows) + 1
	c.table.SetCell(addRow, 0, tview.NewTableCell(" + Add a host…").SetTextColor(tcell.ColorAqua).SetExpansion(1))
	for col := 1; col < len(headers); col++ {
		c.table.SetCell(addRow, col, tview.NewTableCell(""))
	}

	if selected < 1 || selected > addRow {
		selected = 1
	}
	c.table.Select(selected, 0)
}

// current returns the selected host row, or nil for the "Add a host" row.
func (c *sshConsole) current() *nodeRow {
	row, _ := c.table.GetSelection()
	if row >= 1 && row <= len(c.rows) {
		return &c.rows[row-1]
	}
	return nil
}

func (c *sshConsole) entryFor(r *nodeRow) hostEntry {
	e := hostEntry{Name: r.name, Host: r.host, User: c.defaultUser(), Custom: r.custom}
	if saved := c.store.find(r.host); saved != nil {
		e = *saved
		if e.User == "" {
			e.User = c.defaultUser()
		}
		if e.Name == "" {
			e.Name = r.name
		}
	}
	return e
}

func (c *sshConsole) activate(row int) {
	if row == len(c.rows)+1 && c.demo {
		c.note.SetText("  [yellow]Adding hosts is turned off in the demo.[-]")
		return
	}
	if row == len(c.rows)+1 {
		c.addHostForm()
		return
	}
	if r := c.current(); r != nil {
		c.connectFn(c.entryFor(r))
	}
}

func sshArgs(e hostEntry) []string {
	return []string{
		"-p", strconv.Itoa(e.portOr22()),
		"-o", "StrictHostKeyChecking=accept-new",
		// A device that goes away ends the session within ~30s
		// instead of leaving it frozen.
		"-o", "ConnectTimeout=15",
		"-o", "ServerAliveInterval=10",
		"-o", "ServerAliveCountMax=3",
		e.User + "@" + e.Host,
	}
}

func termEnv() []string {
	env := []string{}
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "TERM=") {
			env = append(env, kv)
		}
	}
	return append(env, "TERM=xterm-256color")
}

func (c *sshConsole) back() {
	c.Show()
}

func (c *sshConsole) connect(e hostEntry) {
	if _, err := exec.LookPath("ssh"); err != nil {
		c.note.SetText("  [red]The ssh client is not installed on this machine.[-]")
		return
	}
	name := e.Name
	if name == "" {
		name = e.Host
	}
	termPage.Open(termLaunch{
		title:  fmt.Sprintf("SSH  %s@%s", e.User, name),
		target: fmt.Sprintf("%s@%s:%d", e.User, e.Host, e.portOr22()),
		name:   "ssh",
		args:   sshArgs(e),
		env:    termEnv(),
	}, c.back)
}

// keyPath returns this machine's SSH key, creating an ed25519 key if needed.
func ensureSSHKey() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	for _, name := range []string{"id_ed25519", "id_ecdsa", "id_rsa"} {
		p := filepath.Join(home, ".ssh", name)
		if _, err := os.Stat(p + ".pub"); err == nil {
			return p, nil
		}
	}
	p := filepath.Join(home, ".ssh", "id_ed25519")
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return "", err
	}
	host, _ := os.Hostname()
	out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "kubestui@"+host, "-f", p).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("ssh-keygen: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return p, nil
}

func (c *sshConsole) setupKey(e hostEntry) {
	if _, err := exec.LookPath("ssh-copy-id"); err != nil {
		c.note.SetText("  [red]ssh-copy-id is not installed on this machine (package openssh-client).[-]")
		return
	}
	key, err := ensureSSHKey()
	if err != nil {
		c.note.SetText("  [red]" + tview.Escape(err.Error()) + "[-]")
		return
	}

	termPage.Open(termLaunch{
		title:  fmt.Sprintf("KEY LOGIN SETUP  %s@%s", e.User, e.Host),
		target: fmt.Sprintf("%s@%s:%d  key %s.pub", e.User, e.Host, e.portOr22(), filepath.Base(key)),
		name:   "ssh-copy-id",
		args: []string{
			"-i", key + ".pub",
			"-p", strconv.Itoa(e.portOr22()),
			"-o", "StrictHostKeyChecking=accept-new",
			"-o", "ConnectTimeout=15",
			e.User + "@" + e.Host,
		},
		env:    termEnv(),
		okText: "KEY INSTALLED",
		onFinish: func(code int) {
			if code == 0 {
				store := loadHostStore()
				saved := store.upsert(e)
				saved.KeyLogin = true
				_ = store.save()
			}
		},
	}, c.back)
}

// ---------------------------------------------------------------------------
// Dialogs
// ---------------------------------------------------------------------------

func (c *sshConsole) showDialog(form *tview.Form, title string, height int) {
	styleForm(form)
	form.SetTitle(" " + title + " ")
	closeDialog := func() {
		c.pages.RemovePage("sshform")
		c.footer.SetText(c.footerText())
		c.app.SetFocus(c.table)
	}
	form.SetCancelFunc(closeDialog)
	form.AddButton("Cancel", closeDialog)
	c.pages.AddPage("sshform", centered(form, 64, height), true, true)
	c.footer.SetText(" [aqua::b]TAB[-::-] Next field    [aqua::b]ENTER[-::-] Select    [aqua::b]ESC[-::-] Cancel")
	c.app.SetFocus(form)
}

func (c *sshConsole) closeDialogAndRefresh() {
	c.pages.RemovePage("sshform")
	c.footer.SetText(c.footerText())
	c.refresh()
	c.app.SetFocus(c.table)
}

func (c *sshConsole) userForm(r *nodeRow) {
	e := c.entryFor(r)
	form := tview.NewForm().
		AddInputField("SSH user", e.User, 30, nil, nil).
		AddInputField("SSH port", strconv.Itoa(e.portOr22()), 6, tview.InputFieldInteger, nil)
	form.AddButton("Save", func() {
		user := strings.TrimSpace(form.GetFormItemByLabel("SSH user").(*tview.InputField).GetText())
		port, _ := strconv.Atoi(form.GetFormItemByLabel("SSH port").(*tview.InputField).GetText())
		if user == "" || port < 1 || port > 65535 {
			return
		}
		c.store.upsert(hostEntry{Name: r.name, Host: r.host, User: user, Port: port, Custom: r.custom})
		_ = c.store.save()
		c.closeDialogAndRefresh()
	})
	c.showDialog(form, "LOGIN FOR "+strings.ToUpper(r.name), 10)
}

func (c *sshConsole) addHostForm() {
	form := tview.NewForm().
		AddInputField("Name", "", 30, nil, nil).
		AddInputField("IP / hostname", "", 30, nil, nil).
		AddInputField("SSH user", c.defaultUser(), 30, nil, nil).
		AddInputField("SSH port", "22", 6, tview.InputFieldInteger, nil)
	form.AddButton("Add", func() {
		get := func(label string) string {
			return strings.TrimSpace(form.GetFormItemByLabel(label).(*tview.InputField).GetText())
		}
		host, user := get("IP / hostname"), get("SSH user")
		port, _ := strconv.Atoi(get("SSH port"))
		if host == "" || user == "" || port < 1 || port > 65535 {
			return
		}
		c.store.upsert(hostEntry{Name: get("Name"), Host: host, User: user, Port: port, Custom: true})
		_ = c.store.save()
		c.closeDialogAndRefresh()
	})
	c.showDialog(form, "ADD A HOST", 14)
}

// HandleKey is the input capture for the "ssh" page.
func (c *sshConsole) HandleKey(ev *tcell.EventKey) *tcell.EventKey {
	switch ev.Key() {
	case tcell.KeyEscape:
		c.onBack()
		return nil
	case tcell.KeyRune:
		r := c.current()
		if c.demo {
			switch ev.Rune() {
			case 'u', 'U', 'a', 'A', 'd', 'D':
				c.note.SetText("  [yellow]Changing saved logins is turned off in the demo.[-]")
				return nil
			}
		}
		switch ev.Rune() {
		case 'k', 'K':
			if r != nil {
				c.keyFn(c.entryFor(r))
			}
			return nil
		case 'u', 'U':
			if r != nil {
				c.userForm(r)
			}
			return nil
		case 'a', 'A':
			c.addHostForm()
			return nil
		case 'd', 'D':
			if r != nil && r.custom {
				c.store.remove(r.host)
				_ = c.store.save()
				c.refresh()
			} else if r != nil {
				c.note.SetText("  [yellow]Cluster nodes can't be removed here; only hosts you added.[-]")
			}
			return nil
		case 'r', 'R':
			c.refresh()
			return nil
		case 'q', 'Q':
			c.app.Stop()
			return nil
		}
	}
	return ev
}
