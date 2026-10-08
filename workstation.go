package main

// Workstation mode: KubesTUI on a computer that is not part of the cluster
// (Windows, macOS or Linux). It pairs with a control plane over SSH once
// (installs a per-computer key, fetches a kubeconfig), then runs homelabCD
// operations on that control plane and opens SSH sessions to nodes, all in
// the built-in terminal. Everything is stored under ~/.kubestui.

import (
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"golang.org/x/crypto/ssh"
)

// nodeMode is true when KubesTUI was launched by homelabCD's install.sh on a
// cluster node; otherwise it runs as a workstation.
func nodeMode() bool { return os.Getenv("HOMELABCD_INSTALL") != "" }

type workstation struct {
	app    *tview.Application
	pages  *tview.Pages
	footer *tview.TextView

	// Home: list of paired clusters.
	home      *tview.Flex
	homeTable *tview.Table
	homeNote  *tview.TextView
	profiles  []*clusterProfile

	// Cluster page.
	cluster     *tview.Flex
	clusterInfo *tview.TextView
	clusterList *tview.List
	clusterNote *tview.TextView
	current     *clusterProfile

	// Pairing log.
	pairView *tview.TextView
	pairDone bool
	pairOK   bool

	nodeCache []nodeRow
	nodeErr   error

	demoKeys map[string]bool // demo: nodes with "installed" keys

	vpn          *vpnPage
	reachChecked map[string]bool // clusters already checked this session
}

// demoActive is true while the demo cluster is open (see demo.go).
var demoActive bool

func currentUsername() string {
	if u, err := user.Current(); err == nil {
		name := u.Username
		if i := strings.LastIndexAny(name, `\/`); i >= 0 {
			name = name[i+1:] // Windows: DOMAIN\user
		}
		return name
	}
	return "root"
}

func runWorkstation(app *tview.Application) error {
	setupWorkstation(app)
	return app.Run()
}

// setupWorkstation builds the workstation UI and makes it the app's root.
func setupWorkstation(app *tview.Application) *workstation {
	w := &workstation{app: app, pages: tview.NewPages(), footer: tview.NewTextView().SetDynamicColors(true),
		reachChecked: map[string]bool{}}
	uiPages = w.pages

	termPage = newTermScreen(app, w.pages, w.footer)
	sshPage = newSSHConsole(app, w.pages, w.footer, w.showCluster)
	sshPage.nodesFn = func() ([]nodeRow, error) { return w.nodeCache, w.nodeErr }
	sshPage.connectFn = w.connectNode
	sshPage.keyFn = w.installKeyOnNode
	sshPage.keyLoginFn = func(host string) bool { return w.current != nil && w.current.demo && w.demoKeys[host] }
	sshPage.defaultUser = func() string {
		if w.current != nil {
			return w.current.User // the account used to pair this cluster
		}
		return currentUsername()
	}

	w.buildHome()
	w.buildCluster()
	w.showHome()

	app.SetInputCapture(w.capture)
	app.SetRoot(w.pages, true).EnableMouse(true).EnablePaste(true)
	return w
}

func (w *workstation) capture(ev *tcell.EventKey) *tcell.EventKey {
	name, _ := w.pages.GetFrontPage()
	switch name {
	case "term":
		return termPage.HandleKey(ev)
	case "ssh":
		return sshPage.HandleKey(ev)
	case "vpn":
		return w.vpnScreen().HandleKey(ev)
	case "ask", "pair", "sshform", "rjform", "vpnimport", "composeform":
		return ev
	case "pairlog":
		if w.pairDone {
			switch ev.Key() {
			case tcell.KeyEnter:
				if w.pairOK {
					w.showCluster()
				} else {
					w.showHome()
				}
			case tcell.KeyEscape:
				w.showHome()
			}
		}
		return nil
	case "home":
		switch ev.Key() {
		case tcell.KeyRune:
			switch ev.Rune() {
			case 'n', 'N':
				w.showPairForm()
				return nil
			case 'd', 'D':
				w.removeSelected()
				return nil
			case 'q', 'Q':
				w.app.Stop()
				return nil
			}
		}
	case "cluster":
		switch ev.Key() {
		case tcell.KeyEscape:
			w.showHome()
			return nil
		case tcell.KeyRune:
			if ev.Rune() == 'q' || ev.Rune() == 'Q' {
				w.app.Stop()
				return nil
			}
		}
	}
	return ev
}

func frame(title string) *tview.Flex {
	f := tview.NewFlex().SetDirection(tview.FlexRow)
	f.SetBorder(true).SetTitle(" " + title + " ").SetTitleAlign(tview.AlignLeft)
	return f
}

// ---------------------------------------------------------------------------
// Home: clusters
// ---------------------------------------------------------------------------

func (w *workstation) buildHome() {
	intro := tview.NewTextView().SetDynamicColors(true).SetText(fmt.Sprintf(
		"\n  [yellow::b]KUBESTUI WORKSTATION[-::-]   [gray]%s · %s/%s[-]\n"+
			"  Control your homelab clusters from this computer over SSH.\n"+
			"  Pair once with a control plane; after that no passwords are needed.\n",
		version, runtime.GOOS, runtime.GOARCH))

	w.homeTable = tview.NewTable().
		SetSelectable(true, false).
		SetFixed(1, 0).
		SetSelectedStyle(tcell.StyleDefault.Background(tcell.ColorAqua).Foreground(tcell.ColorBlack))
	w.homeTable.SetBorderPadding(0, 0, 1, 1)
	w.homeTable.SetSelectedFunc(func(row, _ int) {
		if row >= 1 && row <= len(w.profiles) {
			w.current = w.profiles[row-1]
			w.showCluster()
		} else if row == len(w.profiles)+1 {
			w.showPairForm()
		} else if row == len(w.profiles)+2 {
			w.openDemo()
		}
	})

	w.homeNote = tview.NewTextView().SetDynamicColors(true)

	body := frame("HOMELAB KUBERNETES PLATFORM")
	body.AddItem(intro, 5, 0, false).
		AddItem(w.homeTable, 0, 1, true).
		AddItem(w.homeNote, 2, 0, false)

	w.home = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(body, 0, 1, true).
		AddItem(w.footer, 1, 0, false)
}

func (w *workstation) showHome() {
	demoActive = false
	w.profiles = listProfiles()
	t := w.homeTable
	t.Clear()

	headers := []string{"CLUSTER", "CONTROL PLANE", "LOGIN AS", "KUBECTL", "LAST USED"}
	for i, h := range headers {
		t.SetCell(0, i, tview.NewTableCell(" "+h+" ").
			SetTextColor(tcell.ColorYellow).SetAttributes(tcell.AttrBold).
			SetSelectable(false).SetExpansion(1))
	}
	for i, p := range w.profiles {
		kube, kubeColor := "ready", tcell.ColorGreen
		if !p.HasKube {
			kube, kubeColor = "-", tcell.ColorGray
		}
		last := "never"
		if !p.LastUsed.IsZero() {
			last = p.LastUsed.Local().Format("2006-01-02 15:04")
		}
		row := i + 1
		t.SetCell(row, 0, tview.NewTableCell(" "+p.Name+" ").SetAttributes(tcell.AttrBold).SetExpansion(1))
		t.SetCell(row, 1, tview.NewTableCell(fmt.Sprintf(" %s:%d ", p.Host, p.port())).SetExpansion(1))
		t.SetCell(row, 2, tview.NewTableCell(" "+p.User+" ").SetExpansion(1))
		t.SetCell(row, 3, tview.NewTableCell(" "+kube+" ").SetTextColor(kubeColor).SetExpansion(1))
		t.SetCell(row, 4, tview.NewTableCell(" "+last+" ").SetTextColor(tcell.ColorGray).SetExpansion(1))
	}
	addRow := len(w.profiles) + 1
	t.SetCell(addRow, 0, tview.NewTableCell(" + Connect a new cluster…").SetTextColor(tcell.ColorAqua).SetExpansion(1))
	for c := 1; c < len(headers); c++ {
		t.SetCell(addRow, c, tview.NewTableCell(""))
	}
	t.SetCell(addRow+1, 0, tview.NewTableCell(" ▶ Explore a demo cluster").SetTextColor(tcell.ColorYellow).SetExpansion(1))
	t.SetCell(addRow+1, 1, tview.NewTableCell(" [gray]simulated: try every screen, nothing is real").SetExpansion(1))
	for c := 2; c < len(headers); c++ {
		t.SetCell(addRow+1, c, tview.NewTableCell(""))
	}
	t.Select(1, 0)

	if len(w.profiles) == 0 {
		w.homeNote.SetText("  [gray]No clusters yet: connect one with a control plane's IP and SSH login, or try the demo.[-]")
	} else {
		w.homeNote.SetText("  [gray]Profiles and keys: " + tview.Escape(shortPath(kubestuiDir())) + "[-]")
	}

	w.pages.AddAndSwitchToPage("home", w.home, true)
	w.footer.SetText(" [aqua::b]ENTER[-::-] Open    [aqua::b]N[-::-] New cluster    [aqua::b]D[-::-] Remove    [aqua::b]Q[-::-] Quit")
	w.app.SetFocus(w.homeTable)
}

func (w *workstation) removeSelected() {
	row, _ := w.homeTable.GetSelection()
	if row < 1 || row > len(w.profiles) {
		return
	}
	p := w.profiles[row-1]
	sshNote := fmt.Sprintf("Its SSH key stays authorized until you delete the kubestui@ line in %s@%s:~/.ssh/authorized_keys.", p.User, p.Host)

	if p.Credential == "" {
		showConfirm("REMOVE CLUSTER",
			fmt.Sprintf("Remove %q from this computer?\n\nDeletes its profile, key and kubeconfig here.\n%s", p.Name, sshNote),
			"Remove", "Cancel", func(ok bool) {
				if ok {
					_ = p.remove()
					w.showHome()
				}
			})
		return
	}

	showChoice("REMOVE CLUSTER",
		fmt.Sprintf("Remove %q from this computer?\n\nRevoke also deletes this computer's cluster credential (%s), "+
			"so its kubeconfig stops working everywhere.\n%s", p.Name, p.Credential, sshNote),
		[]string{"Revoke and remove", "Remove only", "Cancel"}, func(label string) {
			switch label {
			case "Remove only":
				_ = p.remove()
				w.showHome()
			case "Revoke and remove":
				w.homeNote.SetText("  [aqua]Revoking " + tview.Escape(p.Credential) + "…[-]")
				go func() {
					err := revokeCredential(p)
					w.app.QueueUpdateDraw(func() {
						if err != nil {
							w.homeNote.SetText("  [red]Revoke failed, nothing removed: " + tview.Escape(err.Error()) + "[-]")
							return
						}
						_ = p.remove()
						w.showHome()
						w.homeNote.SetText("  [green]Revoked " + tview.Escape(p.Credential) + " and removed " + tview.Escape(p.Name) + ".[-]")
					})
				}()
			}
		})
}

// ---------------------------------------------------------------------------
// Pairing
// ---------------------------------------------------------------------------

func (w *workstation) showPairForm() {
	name := "homelab"
	for i := 2; ; i++ {
		taken := false
		for _, p := range listProfiles() {
			if profileSlug(p.Name) == profileSlug(name) {
				taken = true
			}
		}
		if !taken {
			break
		}
		name = "homelab-" + strconv.Itoa(i)
	}

	errText := tview.NewTextView().SetDynamicColors(true)
	form := tview.NewForm().
		AddInputField("Cluster name", name, 30, nil, nil).
		AddInputField("Control plane IP", "", 30, nil, nil).
		AddInputField("SSH port", "22", 6, tview.InputFieldInteger, nil).
		AddInputField("SSH user", currentUsername(), 30, nil, nil).
		AddPasswordField("Password", "", 30, '*', nil)

	get := func(label string) string {
		return strings.TrimSpace(form.GetFormItemByLabel(label).(*tview.InputField).GetText())
	}
	cancel := func() {
		w.pages.RemovePage("pair")
		w.showHome()
	}
	form.AddButton("Connect", func() {
		port, err := strconv.Atoi(get("SSH port"))
		switch {
		case get("Cluster name") == "":
			errText.SetText("  [red]Give the cluster a name.[-]")
			return
		case get("Control plane IP") == "":
			errText.SetText("  [red]Enter a control plane's IP address or hostname.[-]")
			return
		case err != nil || port < 1 || port > 65535:
			errText.SetText("  [red]SSH port must be 1-65535.[-]")
			return
		case get("SSH user") == "":
			errText.SetText("  [red]Enter the SSH user.[-]")
			return
		}
		p := newProfile(get("Cluster name"))
		p.Host, p.Port, p.User = get("Control plane IP"), port, get("SSH user")
		password := form.GetFormItemByLabel("Password").(*tview.InputField).GetText()
		w.pages.RemovePage("pair")
		w.startPairing(p, password)
	})
	form.AddButton("Cancel", cancel)
	form.SetCancelFunc(cancel)
	styleForm(form)
	form.SetBorder(false)

	intro := tview.NewTextView().SetDynamicColors(true).SetText(
		"\n  [yellow::b]Connect a cluster[-::-]\n" +
			"  Use any control plane and an account that can sudo there.\n" +
			"  The password is used once to install this computer's key\n" +
			"  and copy the kubeconfig. It is never saved.\n")

	panel := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(intro, 6, 0, false).
		AddItem(form, 0, 1, true).
		AddItem(errText, 1, 0, false)
	panel.SetBorder(true).SetTitle(" CONNECT A CLUSTER ").SetTitleAlign(tview.AlignLeft)

	w.pages.AddPage("pair", centered(panel, 70, 24), true, true)
	w.footer.SetText(" [aqua::b]TAB[-::-] Next field    [aqua::b]ENTER[-::-] Select    [aqua::b]ESC[-::-] Cancel")
	w.app.SetFocus(form)
}

func (w *workstation) startPairing(p *clusterProfile, password string) {
	w.pairView = tview.NewTextView().SetDynamicColors(true).SetScrollable(true)
	w.pairView.SetBorderPadding(1, 0, 2, 1)
	w.pairDone, w.pairOK = false, false

	body := frame(fmt.Sprintf("CONNECTING  %s → %s@%s", p.Name, p.User, p.Host))
	body.AddItem(w.pairView, 0, 1, true)
	screen := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(body, 0, 1, true).
		AddItem(w.footer, 1, 0, false)

	w.pages.AddAndSwitchToPage("pairlog", screen, true)
	w.footer.SetText(" [gray]Working…[-]")
	w.app.SetFocus(w.pairView)

	logf := func(format string, args ...any) {
		line := fmt.Sprintf(format, args...)
		w.app.QueueUpdateDraw(func() {
			fmt.Fprintln(w.pairView, line)
			w.pairView.ScrollToEnd()
		})
	}
	ok := func(s string) { logf("[green::b] OK [-::-]  %s", tview.Escape(s)) }
	warn := func(s string) { logf("[yellow::b]WARN[-::-]  %s", tview.Escape(s)) }
	fail := func(s string) { logf("[red::b]FAIL[-::-]  %s", tview.Escape(s)) }
	info := func(s string) { logf("[aqua]  ··[-]  %s", tview.Escape(s)) }

	finish := func(success bool) {
		w.app.QueueUpdateDraw(func() {
			w.pairDone, w.pairOK = true, success
			if success {
				w.current = p
				fmt.Fprintln(w.pairView, "\n[green::b]Connected.[-::-] Press ENTER to open "+tview.Escape(p.Name)+".")
				w.footer.SetText(" [aqua::b]ENTER[-::-] Open cluster    [aqua::b]ESC[-::-] Clusters")
			} else {
				fmt.Fprintln(w.pairView, "\n[red::b]Not connected.[-::-] Nothing was saved. Press ESC to go back.")
				w.footer.SetText(" [aqua::b]ESC[-::-] Back")
			}
			w.pairView.ScrollToEnd()
		})
	}

	go func() {
		target := fmt.Sprintf("%s@%s:%d", p.User, p.Host, p.port())
		info("Connecting to " + target + "…")
		client, err := dialSSH(dialTarget{Host: p.Host, Port: p.port(), User: p.User, Password: password, Prompt: password == ""})
		if err != nil {
			fail("SSH: " + err.Error())
			finish(false)
			return
		}
		defer client.Close()
		ok("Connected over SSH")

		// Where homelabCD lives on the node (the kbtui launcher records it).
		out, _ := runRemote(client,
			`sed -n 's#.*bash "\(.*\)/install.sh".*#\1#p' /usr/local/bin/kbtui 2>/dev/null | head -n1; `+
				`for d in /opt/homelabCD "$HOME/homelabCD"; do [ -f "$d/install.sh" ] && echo "$d"; done`, "")
		for _, line := range strings.Split(out, "\n") {
			if line = strings.TrimSpace(line); line != "" {
				p.HomelabRoot = line
				break
			}
		}
		if p.HomelabRoot != "" {
			ok("homelabCD found at " + p.HomelabRoot)
		} else {
			warn("homelabCD not found on this node; cluster operations will be unavailable (SSH and kubectl still work)")
		}

		// Per-computer key, so it can be revoked on its own.
		host, _ := os.Hostname()
		comment := "kubestui@" + host
		pub, err := publicKeyLine(p.keyPath())
		if err != nil {
			pub, err = generateKey(p.keyPath(), comment)
			if err != nil {
				fail("Could not create a key: " + err.Error())
				finish(false)
				return
			}
			ok("Created a key for this computer (" + comment + ")")
		}
		if err := authorizeKey(client, pub); err != nil {
			fail("Could not install the key on the node: " + err.Error())
			_ = p.remove()
			finish(false)
			return
		}
		ok("Installed the key for " + p.User + " on " + p.Host)

		// This computer's own cluster credential (revocable on its own).
		cred := credentialName()
		info("Creating this computer's cluster credential " + cred + "…")
		if kc, err := createCredential(client, p.User, password, cred); err != nil {
			warn("No kubeconfig (needs sudo and kubectl on the node): " + err.Error())
		} else if err := os.WriteFile(p.kubeconfigPath(), []byte(kc), 0o600); err != nil {
			warn("Could not save kubeconfig: " + err.Error())
		} else {
			p.HasKube, p.Credential = true, cred
			ok("Created credential " + cred + " (cluster-admin, revocable) → " + shortPath(p.kubeconfigPath()))
		}

		// Prove the key works on its own.
		if c2, err := dialSSH(dialTarget{Host: p.Host, Port: p.port(), User: p.User, Keys: []string{p.keyPath()}}); err != nil {
			warn("Key login test failed (you may be asked for a password later): " + err.Error())
		} else {
			c2.Close()
			ok("Key login works; no password needed from now on")
		}

		p.Created = time.Now()
		if err := p.save(); err != nil {
			fail("Could not save the profile: " + err.Error())
			finish(false)
			return
		}
		ok("Saved profile " + shortPath(p.dir))
		finish(true)
	}()
}

// ---------------------------------------------------------------------------
// Cluster page
// ---------------------------------------------------------------------------

type wsAction struct {
	title, desc string
	op          string // install.sh --run operation, if any
	confirm     bool   // changes something: ask first
	run         func()
}

func (w *workstation) buildCluster() {
	w.clusterInfo = tview.NewTextView().SetDynamicColors(true)
	w.clusterNote = tview.NewTextView().SetDynamicColors(true)

	w.clusterList = tview.NewList().
		ShowSecondaryText(true).
		SetHighlightFullLine(true).
		SetMainTextColor(tcell.ColorWhite).
		SetSecondaryTextColor(tcell.ColorGray).
		SetSelectedTextColor(tcell.ColorBlack).
		SetSelectedBackgroundColor(tcell.ColorAqua)

	header := tview.NewTextView().SetDynamicColors(true).SetText("\n  [yellow::b]OPERATIONS[-::-]")

	body := frame("HOMELAB KUBERNETES PLATFORM")
	body.AddItem(nil, 1, 0, false).
		AddItem(w.clusterInfo, 7, 0, false).
		AddItem(header, 2, 0, false).
		AddItem(w.clusterList, 0, 1, true).
		AddItem(w.clusterNote, 2, 0, false)

	w.cluster = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(body, 0, 1, true).
		AddItem(w.footer, 1, 0, false)
}

func (w *workstation) actions() []wsAction {
	return []wsAction{
		{title: "Cluster Health Check", desc: "Nodes, control plane, networking, DNS, Argo CD, storage, certificates", op: "health"},
		{title: "Cluster Configuration", desc: "config/cluster.yaml and the live kubeadm configuration", op: "config"},
		{title: "Generate Join Commands", desc: "Fresh join commands for new nodes", op: "join-commands"},
		{title: "Remote Join Worker", desc: "Add a new worker over SSH; runs on " + w.current.Host, run: func() { w.remoteJoin("remote-worker", "Remote Join Worker") }},
		{title: "Remote Join Control Plane", desc: "Add a new control plane over SSH; runs on " + w.current.Host, run: func() { w.remoteJoin("remote-controlplane", "Remote Join Control Plane") }},
		{title: "Move Node to Dedicated Longhorn Disk", desc: "Format a spare disk and move a node's Longhorn data onto it", op: "longhorn-disk", confirm: true},
		{title: "Repair Control Plane Node", desc: "Restart containerd and kubelet on " + w.current.Host, op: "repair", confirm: true},
		{title: "Import Docker Compose App", desc: "Deploy a docker-compose.yml from this computer into the cluster through GitOps", run: w.importCompose},
		{title: "Remove Imported App", desc: "Remove an app imported from Docker Compose (and its data)", op: "compose-remove", confirm: true},
		{title: "VPN", desc: w.vpnSummary(), run: func() { w.vpnScreen().Show() }},
		{title: "Open Shell on Control Plane", desc: "A terminal on " + w.current.Host, run: w.openShell},
		{title: "SSH Console", desc: "Shell on any node; set up key login per node", run: w.openSSHConsole},
		{title: "Use kubectl from This Computer", desc: "kubeconfig location and commands for kubectl, k9s or Lens", run: w.showKubectl},
		{title: "Back to Clusters", desc: "", run: w.showHome},
	}
}

func (w *workstation) showCluster() {
	p := w.current
	if p == nil {
		w.showHome()
		return
	}

	row := func(k, v string) string { return fmt.Sprintf("  [yellow::b]%-13s[-::-] %s\n", k, v) }
	kube := "[gray]not available[-]"
	switch {
	case p.HasKube && p.Credential != "":
		kube = tview.Escape(shortPath(p.kubeconfigPath())) + "  [gray](own credential " + tview.Escape(p.Credential) + ")[-]"
	case p.HasKube:
		kube = tview.Escape(shortPath(p.kubeconfigPath())) + "  [yellow](shared admin.conf: remove and re-pair for a revocable one)[-]"
	}
	root := "[yellow]not found on node[-]"
	if p.HomelabRoot != "" {
		root = tview.Escape(p.HomelabRoot)
	}
	w.clusterInfo.SetText(
		row("CLUSTER", tview.Escape(p.Name)) +
			row("CONTROL PLANE", fmt.Sprintf("%s:%d", tview.Escape(p.Host), p.port())) +
			row("LOGIN", tview.Escape(p.User)+" [gray](key)[-]") +
			row("HOMELABCD", root) +
			row("KUBECONFIG", kube) +
			row("MODE", w.modeText()))

	selected := w.clusterList.GetCurrentItem()
	w.clusterList.Clear()
	for _, a := range w.actions() {
		a := a
		w.clusterList.AddItem("  "+a.title, "    "+a.desc, 0, func() { w.runAction(a) })
	}
	if selected >= 0 && selected < w.clusterList.GetItemCount() {
		w.clusterList.SetCurrentItem(selected)
	}
	w.clusterNote.SetText("")

	w.pages.AddAndSwitchToPage("cluster", w.cluster, true)
	w.footer.SetText(" [aqua::b]UP/DOWN[-::-] Navigate    [aqua::b]ENTER[-::-] Select    [aqua::b]ESC[-::-] Clusters    [aqua::b]Q[-::-] Quit")
	w.app.SetFocus(w.clusterList)
	w.checkReachable()
}

// dialer returns a connect function for the current cluster's control plane.
func (w *workstation) dialer(p *clusterProfile) func() (*ssh.Client, error) {
	return func() (*ssh.Client, error) {
		c, err := dialSSH(dialTarget{Host: p.Host, Port: p.port(), User: p.User, Keys: []string{p.keyPath()}, Prompt: true})
		if err == nil {
			p.LastUsed = time.Now()
			_ = p.save()
		}
		return c, err
	}
}

func remoteInstallCommand(p *clusterProfile, op string) string {
	cmd := "bash " + shellQuote(p.HomelabRoot+"/install.sh") + " --run " + shellQuote(op)
	if p.User != "root" {
		cmd = "sudo -p '[sudo] password for %u: ' " + cmd
	}
	return cmd
}

func (w *workstation) runAction(a wsAction) {
	if a.run != nil {
		a.run()
		return
	}
	p := w.current
	if p.HomelabRoot == "" {
		w.clusterNote.SetText("  [yellow]homelabCD wasn't found on " + tview.Escape(p.Host) + ", so operations can't run there. Re-pair with a node that ran the bootstrapper.[-]")
		return
	}
	launch := func() {
		termPage.Open(termLaunch{
			title:      fmt.Sprintf("%s  ·  %s", strings.ToUpper(a.title), p.Name),
			target:     fmt.Sprintf("%s@%s:%d  %s", p.User, p.Host, p.port(), a.op),
			okText:     "COMPLETED",
			sshConnect: w.dialer(p),
			command:    remoteInstallCommand(p, a.op),
		}, w.showCluster)
	}
	if p.demo {
		launch = func() {
			termPage.Open(termLaunch{
				title:  fmt.Sprintf("DEMO · %s  ·  %s", strings.ToUpper(a.title), p.Name),
				target: fmt.Sprintf("%s@%s:%d  %s", p.User, p.Host, p.port(), a.op),
				okText: "COMPLETED",
				demo:   demoScriptFor(a.op),
			}, w.showCluster)
		}
	}
	if !a.confirm {
		launch()
		return
	}
	showConfirm("RUN ON "+strings.ToUpper(p.Name),
		fmt.Sprintf("%s\n\nRuns on %s and can change the cluster. Continue?", a.title, p.Host),
		"Run", "Cancel", func(ok bool) {
			if ok {
				launch()
			}
		})
}

func (w *workstation) openShell() {
	p := w.current
	if p.demo {
		termPage.Open(termLaunch{
			title:  "DEMO · SSH  admin@cp1  ·  " + p.Name,
			target: fmt.Sprintf("%s@%s:%d", p.User, p.Host, p.port()),
			demo:   demoShell("cp1"),
		}, w.showCluster)
		return
	}
	termPage.Open(termLaunch{
		title:      fmt.Sprintf("SSH  %s@%s  ·  %s", p.User, p.Host, p.Name),
		target:     fmt.Sprintf("%s@%s:%d", p.User, p.Host, p.port()),
		sshConnect: w.dialer(p),
	}, w.showCluster)
}

func (w *workstation) showKubectl() {
	p := w.current
	if !p.HasKube {
		showConfirm("KUBECTL", "No kubeconfig was saved when this cluster was paired "+
			"(the account couldn't sudo). Remove the cluster and pair again with an account that can.",
			"OK", "Close", func(bool) {})
		return
	}
	path := p.kubeconfigPath()
	ps := fmt.Sprintf(`$env:KUBECONFIG = "%s"`, path)
	sh := fmt.Sprintf(`export KUBECONFIG="%s"`, path)
	cmd := sh
	if runtime.GOOS == "windows" {
		cmd = ps
	}
	text := fmt.Sprintf("Kubeconfig (cluster-admin):\n%s\n\nPowerShell:\n%s\n\nmacOS / Linux:\n%s\n\n"+
		"Then: kubectl get nodes\nThe API is at your VIP, so this computer must be on the same network.",
		path, ps, sh)
	showConfirm("USE KUBECTL FROM THIS COMPUTER", text, "Copy command", "Close", func(ok bool) {
		if ok && copyToClipboard(cmd) {
			w.clusterNote.SetText("  [green]Copied:[-] " + tview.Escape(cmd))
		}
	})
}

// ---------------------------------------------------------------------------
// SSH console (workstation flavour)
// ---------------------------------------------------------------------------

func (w *workstation) openSSHConsole() {
	p := w.current
	sshPage.demo = p.demo
	if p.demo {
		w.nodeCache, w.nodeErr = demoNodes, nil
		sshPage.Show()
		sshPage.note.SetText("  [black:yellow:b] DEMO [-:-:-] [gray] Simulated nodes. ENTER opens a demo shell, K simulates key setup.[-]")
		return
	}
	w.nodeCache, w.nodeErr = nil, fmt.Errorf("loading nodes from %s…", p.Host)
	sshPage.Show()

	go func() {
		var rows []nodeRow
		client, err := w.dialer(p)()
		if err == nil {
			var out string
			out, err = runRemote(client,
				"kubectl get nodes -o json 2>/dev/null || sudo -n kubectl --kubeconfig /etc/kubernetes/admin.conf get nodes -o json", "")
			client.Close()
			if err == nil {
				rows, err = parseNodes([]byte(out))
			}
		}
		w.app.QueueUpdateDraw(func() {
			w.nodeCache, w.nodeErr = rows, err
			if name, _ := w.pages.GetFrontPage(); name == "ssh" {
				sshPage.refresh()
			}
		})
	}()
}

func (w *workstation) connectNode(e hostEntry) {
	p := w.current
	name := e.Name
	if name == "" {
		name = e.Host
	}
	if p.demo {
		termPage.Open(termLaunch{
			title:  fmt.Sprintf("DEMO · SSH  %s@%s", e.User, name),
			target: fmt.Sprintf("%s@%s:%d", e.User, e.Host, e.portOr22()),
			demo:   demoShell(name),
		}, sshPage.back)
		return
	}
	termPage.Open(termLaunch{
		title:  fmt.Sprintf("SSH  %s@%s", e.User, name),
		target: fmt.Sprintf("%s@%s:%d", e.User, e.Host, e.portOr22()),
		sshConnect: func() (*ssh.Client, error) {
			return dialSSH(dialTarget{Host: e.Host, Port: e.portOr22(), User: e.User, Keys: []string{p.keyPath()}, Prompt: true})
		},
	}, sshPage.back)
}

func (w *workstation) installKeyOnNode(e hostEntry) {
	p := w.current
	if p.demo {
		termPage.Open(termLaunch{
			title:  fmt.Sprintf("DEMO · KEY LOGIN SETUP  %s@%s", e.User, e.Host),
			target: fmt.Sprintf("%s@%s:%d", e.User, e.Host, e.portOr22()),
			okText: "KEY INSTALLED",
			demo:   demoKeySetup,
			onFinish: func(code int) {
				if code == 0 {
					w.demoKeys[e.Host] = true
				}
			},
		}, sshPage.back)
		return
	}
	sshPage.note.SetText("  [aqua]Installing this computer's key on " + tview.Escape(e.Host) + "…[-]")
	go func() {
		pub, err := publicKeyLine(p.keyPath())
		if err == nil {
			var client *ssh.Client
			client, err = dialSSH(dialTarget{Host: e.Host, Port: e.portOr22(), User: e.User, Keys: []string{p.keyPath()}, Prompt: true})
			if err == nil {
				err = authorizeKey(client, pub)
				client.Close()
			}
		}
		w.app.QueueUpdateDraw(func() {
			if err != nil {
				sshPage.note.SetText("  [red]Key setup failed: " + tview.Escape(err.Error()) + "[-]")
				return
			}
			store := loadHostStore()
			saved := store.upsert(e)
			saved.KeyLogin = true
			_ = store.save()
			sshPage.refresh()
			sshPage.note.SetText("  [green]Key installed on " + tview.Escape(e.Host) + "; future connections need no password.[-]")
		})
	}()
}

// parseNodes reads `kubectl get nodes -o json`.
func parseNodes(out []byte) ([]nodeRow, error) {
	var list kubeNodeList
	if err := json.Unmarshal(out, &list); err != nil {
		return nil, err
	}
	return list.rows(), nil
}

// ---------------------------------------------------------------------------
// Remote joins, driven from this computer but run on the control plane
// ---------------------------------------------------------------------------

// remoteJoin shows the join form; the join itself runs on the control plane,
// which has homelabCD, the bootstrap secrets and can create join tokens.
func (w *workstation) remoteJoin(op, title string) {
	if w.current.HomelabRoot == "" {
		w.clusterNote.SetText("  [yellow]homelabCD wasn't found on " + tview.Escape(w.current.Host) + "; remote joins run there.[-]")
		return
	}
	showRemoteJoinForm(w.app, w.pages, w.footer, operation{Title: title, Op: op}, w.showCluster, w.launchRemoteJoin)
}

func (w *workstation) launchRemoteJoin(op operation, pre remotePrefill, role string) error {
	p := w.current
	if p.demo {
		termPage.Open(termLaunch{
			title:  fmt.Sprintf("DEMO · REMOTE JOIN  %s → %s@%s  via %s", role, pre.User, pre.Host, p.Name),
			target: fmt.Sprintf("%s@%s:%d  (%s, run on %s)", pre.User, pre.Host, pre.Port, role, p.Host),
			okText: "JOINED",
			demo:   demoRemoteJoin(pre, role),
		}, w.showCluster)
		return nil
	}
	termPage.Open(termLaunch{
		title:      fmt.Sprintf("REMOTE JOIN  %s → %s@%s  via %s", role, pre.User, pre.Host, p.Name),
		target:     fmt.Sprintf("%s@%s:%d  (%s, run on %s)", pre.User, pre.Host, pre.Port, role, p.Host),
		okText:     "JOINED",
		sshConnect: w.dialer(p),
		prepare: func(client *ssh.Client) (string, error) {
			// Hand the form values over as a private temp file; the join
			// reads and deletes it at once. The password never appears in a
			// command line or environment.
			data, err := json.Marshal(pre)
			if err != nil {
				return "", err
			}
			out, err := runRemote(client,
				`umask 077; f=$(mktemp /tmp/kubestui-join.XXXXXX) && cat > "$f" && echo "$f"`, string(data))
			path := strings.TrimSpace(out)
			if err != nil || !strings.HasPrefix(path, "/tmp/kubestui-join.") {
				return "", fmt.Errorf("could not stage the join on %s: %v", p.Host, err)
			}
			root := p.HomelabRoot
			cmd := "env " + remoteOpEnv + "=" + shellQuote(op.Op) +
				" " + prefillFileEnv + "=" + shellQuote(path) +
				" HOMELABCD_INSTALL=" + shellQuote(root+"/install.sh") +
				" HOMELABCD_ROOT=" + shellQuote(root) +
				" " + shellQuote(root+"/bin/kubestui")
			if p.User != "root" {
				cmd = "sudo -p '[sudo] password for %u: ' " + cmd
			}
			// Remove the file even if the join never started.
			return cmd + "; rc=$?; rm -f " + shellQuote(path) + "; exit $rc", nil
		},
	}, w.showCluster)
	return nil
}

// ---------------------------------------------------------------------------
// Demo cluster
// ---------------------------------------------------------------------------

func (w *workstation) openDemo() {
	demoActive = true
	if w.demoKeys == nil {
		w.demoKeys = map[string]bool{}
	}
	w.current = demoProfile()
	w.showCluster()
	w.clusterNote.SetText("  [black:yellow:b] DEMO [-:-:-] [gray] A simulated cluster: try any operation. Nothing is sent anywhere or saved.[-]")
}

func (w *workstation) modeText() string {
	if w.current != nil && w.current.demo {
		return "[aqua::b]WORKSTATION[-::-]  [black:yellow:b] DEMO [-:-:-] [gray]nothing here is real[-]"
	}
	return "[aqua::b]WORKSTATION[-::-]"
}

// vpnSummary is the VPN menu item's one-line state.
func (w *workstation) vpnSummary() string {
	p := w.current
	switch {
	case p.demo && w.vpn != nil && w.vpn.demoUp:
		return "[green]● Connected[-] (demo)"
	case p.demo:
		return "WireGuard: configured, not connected (demo)"
	case tunnelFor(p) != nil:
		return "[green]● Connected[-] through WireGuard"
	case p.hasVPN():
		return "WireGuard: configured, not connected"
	}
	return "Not set up: import a WireGuard config for when you're away"
}

func removeFile(path string) error { return os.Remove(path) }
