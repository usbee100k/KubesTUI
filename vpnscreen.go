package main

// VPN screen (workstation cluster menu): import a WireGuard config, connect
// the built-in tunnel, and watch its health. Also offers the VPN when a
// cluster isn't reachable directly (away from home).

import (
	"fmt"
	"net/netip"
	"runtime"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

type vpnPage struct {
	w      *workstation
	screen *tview.Flex
	view   *tview.TextView
	note   string

	connecting bool
	lastErr    string
	probeMs    time.Duration
	probeErr   string
	probedAt   time.Time
	stop       chan struct{}

	// demo state
	demoUp    bool
	demoSince time.Time
}

func (w *workstation) vpnScreen() *vpnPage {
	if w.vpn != nil {
		return w.vpn
	}
	v := &vpnPage{w: w}
	v.view = tview.NewTextView().SetDynamicColors(true).SetWrap(true)
	v.view.SetBorderPadding(1, 0, 2, 1)
	body := frame("VPN · WIREGUARD")
	body.AddItem(v.view, 0, 1, true)
	v.screen = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(body, 0, 1, true).
		AddItem(w.footer, 1, 0, false)
	w.vpn = v
	return v
}

func (v *vpnPage) Show() {
	w := v.w
	v.note = ""
	w.pages.AddAndSwitchToPage("vpn", v.screen, true)
	w.app.SetFocus(v.view)
	v.render()

	if v.stop != nil {
		close(v.stop)
	}
	stop := make(chan struct{})
	v.stop = stop
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				w.app.QueueUpdateDraw(func() {
					if name, _ := w.pages.GetFrontPage(); name == "vpn" {
						v.render()
					}
				})
			}
		}
	}()
}

func (v *vpnPage) leave() {
	if v.stop != nil {
		close(v.stop)
		v.stop = nil
	}
	v.w.showCluster()
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func (v *vpnPage) render() {
	w := v.w
	p := w.current
	row := func(k, val string) string { return fmt.Sprintf("  [yellow::b]%-14s[-::-] %s\n", k, val) }
	var b strings.Builder

	// Config section.
	var conf *wgConfig
	if p.demo {
		conf = &wgConfig{
			Endpoint:   "demo-vpn.duckdns.org:51820",
			Addresses:  []netip.Prefix{netip.MustParsePrefix("10.8.0.2/24")},
			AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.99.0.0/24")},
		}
	} else if p.hasVPN() {
		c, err := p.loadVPNConf()
		if err != nil {
			b.WriteString("  [red]The saved config can't be read: " + tview.Escape(err.Error()) + "[-]\n\n")
		}
		conf = c
	}

	tun := tunnelFor(p)
	up := tun != nil || (p.demo && v.demoUp)

	var badge string
	switch {
	case v.connecting:
		badge = "[black:yellow:b] ◌ CONNECTING [-:-:-]"
	case up:
		badge = "[black:green:b] ● CONNECTED [-:-:-]"
	case conf == nil:
		badge = "[black:gray:b] ■ NOT SET UP [-:-:-]"
	default:
		badge = "[white:red:b] ■ DISCONNECTED [-:-:-]"
	}
	fmt.Fprintf(&b, "  %s   [white::b]%s[-::-]", badge, tview.Escape(p.Name))
	if p.demo {
		b.WriteString("   [black:yellow:b] DEMO [-:-:-]")
	}
	b.WriteString("\n\n")

	if conf == nil {
		b.WriteString("  No WireGuard config for this cluster yet.\n\n" +
			"  1. On your home network, open the wg-easy web UI (https://wg.<your domain>)\n" +
			"     or ask whoever runs the VPN, and create a client for this computer.\n" +
			"  2. Download its .conf file.\n" +
			"  3. Press [aqua::b]I[-::-] here and give the file's path. KubesTUI keeps a private copy,\n" +
			"     so you can delete the download afterwards.\n\n" +
			"  [gray]No VPN on the cluster yet? Run Set Up VPN in the node menu (kbtui).[-]\n")
	} else {
		path := shortPath(p.vpnConfPath())
		if p.demo {
			path = "~/.kubestui/clusters/demo-homelab/wg.conf  [gray](demo)[-]"
		}
		var addrs []string
		for _, a := range conf.Addresses {
			addrs = append(addrs, a.Addr().String())
		}
		b.WriteString(row("CONFIG", path))
		b.WriteString(row("SERVER", tview.Escape(conf.Endpoint)))
		b.WriteString(row("THIS DEVICE", strings.Join(addrs, ", ")))
		b.WriteString(row("REACHES", prefixList(conf.AllowedIPs)))
		if conf.routesEverything() {
			b.WriteString("  [yellow]This config routes everything (0.0.0.0/0). KubesTUI only sends cluster traffic\n  through it; the rest of this computer is unaffected.[-]\n")
		}
		b.WriteString("\n")

		// Live health.
		switch {
		case p.demo && v.demoUp:
			since := time.Since(v.demoSince)
			hs := int(since.Seconds()) % 120
			b.WriteString(row("HANDSHAKE", fmt.Sprintf("[green]%ds ago (healthy)[-]", hs)))
			b.WriteString(row("TRAFFIC", fmt.Sprintf("rx %s   tx %s", humanBytes(int64(since.Seconds())*41000+1200000), humanBytes(int64(since.Seconds())*9000+300000))))
			b.WriteString(row("UP FOR", formatElapsed(since)))
			b.WriteString(row("CONTROL PLANE", fmt.Sprintf("[green]%s:%d reachable through the VPN (%d ms)[-]", p.Host, p.port(), 31+int(since.Seconds())%9)))
			b.WriteString(row("KUBECTL", "export KUBECONFIG=~/.kubestui/clusters/demo-homelab/kubeconfig-vpn  [gray](demo)[-]"))
		case tun != nil:
			s := tun.stats()
			switch {
			case s.lastHandshake.IsZero():
				b.WriteString(row("HANDSHAKE", "[yellow]none yet[-]"))
			case time.Since(s.lastHandshake) < 3*time.Minute:
				b.WriteString(row("HANDSHAKE", fmt.Sprintf("[green]%ds ago (healthy)[-]", int(time.Since(s.lastHandshake).Seconds()))))
			default:
				b.WriteString(row("HANDSHAKE", fmt.Sprintf("[red]%s ago: the server stopped answering[-]", formatElapsed(time.Since(s.lastHandshake)))))
			}
			b.WriteString(row("TRAFFIC", fmt.Sprintf("rx %s   tx %s", humanBytes(s.rx), humanBytes(s.tx))))
			b.WriteString(row("UP FOR", formatElapsed(time.Since(tun.started))))
			if v.probeErr != "" {
				b.WriteString(row("CONTROL PLANE", "[red]not reachable: "+tview.Escape(v.probeErr)+"[-]"))
			} else if !v.probedAt.IsZero() {
				b.WriteString(row("CONTROL PLANE", fmt.Sprintf("[green]%s:%d reachable through the VPN (%d ms)[-]  [gray]tested %s ago[-]",
					p.Host, p.port(), v.probeMs.Milliseconds(), formatElapsed(time.Since(v.probedAt)))))
			}
			if tun.apiLocal != "" {
				kc := p.kubeconfigVPNPath()
				cmd := fmt.Sprintf(`export KUBECONFIG="%s"`, kc)
				if runtime.GOOS == "windows" {
					cmd = fmt.Sprintf(`$env:KUBECONFIG = "%s"`, kc)
				}
				b.WriteString(row("KUBECTL", tview.Escape(cmd)+"  [gray](while connected)[-]"))
			}
		default:
			b.WriteString("  [gray]Not connected. Press C to connect.[-]\n")
		}
	}

	if v.lastErr != "" {
		b.WriteString("\n  [red]" + tview.Escape(v.lastErr) + "[-]\n")
	}
	if v.note != "" {
		b.WriteString("\n  [yellow]" + tview.Escape(v.note) + "[-]\n")
	}

	v.view.SetText(b.String())

	keys := " [aqua::b]I[-::-] Import config    [aqua::b]ESC[-::-] Back"
	if conf != nil {
		action := "Connect"
		if up {
			action = "Disconnect"
		}
		keys = fmt.Sprintf(" [aqua::b]C[-::-] %s    [aqua::b]T[-::-] Test    [aqua::b]S[-::-] Server status    [aqua::b]I[-::-] Replace config    [aqua::b]D[-::-] Delete config    [aqua::b]ESC[-::-] Back", action)
	}
	w.footer.SetText(keys)
}

func (v *vpnPage) connect() {
	w, p := v.w, v.w.current
	if p.demo {
		v.connecting = true
		v.render()
		go func() {
			time.Sleep(1200 * time.Millisecond)
			w.app.QueueUpdateDraw(func() {
				v.connecting, v.demoUp, v.demoSince = false, true, time.Now()
				v.note = "Demo: connected (simulated)."
				v.render()
			})
		}()
		return
	}
	v.connecting, v.lastErr = true, ""
	v.render()
	go func() {
		start := time.Now()
		t, err := startTunnel(p)
		w.app.QueueUpdateDraw(func() {
			v.connecting = false
			if err != nil {
				v.lastErr = err.Error()
			} else {
				v.probeMs, v.probeErr, v.probedAt = time.Since(start), "", time.Now()
				if t.apiLocal == "" && p.HasKube {
					v.note = "Connected. (The local kubectl forward couldn't start.)"
				} else {
					v.note = "Connected."
				}
			}
			v.render()
		})
	}()
}

func (v *vpnPage) disconnect() {
	p := v.w.current
	if p.demo {
		v.demoUp = false
	} else {
		stopTunnel(p)
	}
	v.probedAt, v.probeErr = time.Time{}, ""
	v.note = "Disconnected."
	v.render()
}

func (v *vpnPage) test() {
	w, p := v.w, v.w.current
	t := tunnelFor(p)
	if t == nil {
		v.note = "Not connected."
		v.render()
		return
	}
	v.note = "Testing…"
	v.render()
	go func() {
		d, err := t.probe(p.Host, p.port(), 8*time.Second)
		w.app.QueueUpdateDraw(func() {
			v.probedAt, v.probeMs, v.probeErr, v.note = time.Now(), d, "", ""
			if err != nil {
				v.probeErr = err.Error()
			}
			v.render()
		})
	}()
}

func (v *vpnPage) importForm() {
	w, p := v.w, v.w.current
	if p.demo {
		v.note = "Importing is turned off in the demo."
		v.render()
		return
	}
	errText := tview.NewTextView().SetDynamicColors(true)
	form := tview.NewForm().AddInputField("Path to .conf", "", 50, nil, nil)
	closeForm := func() {
		w.pages.RemovePage("vpnimport")
		w.app.SetFocus(v.view)
		v.render()
	}
	form.AddButton("Import", func() {
		path := form.GetFormItem(0).(*tview.InputField).GetText()
		c, err := importVPNConf(p, path)
		if err != nil {
			errText.SetText("  [red]" + tview.Escape(err.Error()) + "[-]")
			return
		}
		if tunnelFor(p) != nil {
			stopTunnel(p) // reconnect with the new config
		}
		v.note = fmt.Sprintf("Imported (server %s). You can delete the original file now.", c.Endpoint)
		closeForm()
	})
	form.AddButton("Cancel", closeForm)
	form.SetCancelFunc(closeForm)
	styleForm(form)
	form.SetBorder(false)

	hint := "  e.g. C:\\Users\\you\\Downloads\\laptop.conf  (quotes are fine)"
	if runtime.GOOS != "windows" {
		hint = "  e.g. ~/Downloads/laptop.conf"
	}
	panel := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(tview.NewTextView().SetDynamicColors(true).SetText(
			"\n  [yellow::b]Import a WireGuard config[-::-]\n  The client .conf from wg-easy for this computer.\n[gray]"+tview.Escape(hint)+"[-]"), 4, 0, false).
		AddItem(form, 0, 1, true).
		AddItem(errText, 1, 0, false)
	panel.SetBorder(true).SetTitle(" VPN CONFIG ").SetTitleAlign(tview.AlignLeft)
	w.pages.AddPage("vpnimport", centered(panel, 74, 14), true, true)
	w.footer.SetText(" [aqua::b]ENTER[-::-] Import    [aqua::b]ESC[-::-] Cancel")
	w.app.SetFocus(form)
}

func (v *vpnPage) deleteConf() {
	w, p := v.w, v.w.current
	if p.demo {
		v.note = "Deleting is turned off in the demo."
		v.render()
		return
	}
	showConfirm("DELETE VPN CONFIG", "Delete this cluster's WireGuard config from this computer?\n\n"+
		"Disconnects first. To also revoke it, delete the client in the wg-easy web UI.",
		"Delete", "Cancel", func(ok bool) {
			if ok {
				stopTunnel(p)
				_ = removeFile(p.vpnConfPath())
				v.note = "VPN config deleted."
			}
			w.app.SetFocus(v.view)
			v.render()
		})
}

// HandleKey is the input capture for the "vpn" page.
func (v *vpnPage) HandleKey(ev *tcell.EventKey) *tcell.EventKey {
	w, p := v.w, v.w.current
	if ev.Key() == tcell.KeyEscape {
		v.leave()
		return nil
	}
	if ev.Key() != tcell.KeyRune || v.connecting {
		return ev
	}
	hasConf := p.hasVPN()
	switch ev.Rune() {
	case 'i', 'I':
		v.importForm()
	case 'c', 'C':
		if !hasConf {
			break
		}
		if tunnelFor(p) != nil || (p.demo && v.demoUp) {
			v.disconnect()
		} else {
			v.connect()
		}
	case 't', 'T':
		if p.demo {
			v.note = "Demo: reachable (simulated)."
			v.render()
		} else {
			v.test()
		}
	case 'd', 'D':
		if hasConf {
			v.deleteConf()
		}
	case 's', 'S':
		if hasConf {
			w.runAction(wsAction{title: "VPN Server Status", op: "vpn-status"})
		}
	case 'q', 'Q':
		w.app.Stop()
	}
	return nil
}

// checkReachable runs once per cluster per session: if the control plane
// can't be reached directly, offer the VPN.
func (w *workstation) checkReachable() {
	p := w.current
	if p == nil || p.demo || tunnelFor(p) != nil {
		return
	}
	key := profileSlug(p.Name)
	if w.reachChecked[key] {
		return
	}
	w.reachChecked[key] = true

	go func() {
		if reachableDirect(p.Host, p.port()) {
			return
		}
		w.app.QueueUpdateDraw(func() {
			if w.current != p {
				return
			}
			if name, _ := w.pages.GetFrontPage(); name != "cluster" {
				return
			}
			if !p.hasVPN() {
				w.clusterNote.SetText("  [yellow]Can't reach " + tview.Escape(p.Host) + ". Away from home? Import your WireGuard config under VPN.[-]")
				return
			}
			showChoice("NOT ON THE CLUSTER'S NETWORK",
				fmt.Sprintf("Can't reach %s directly.\n\nConnect through the VPN?", p.Host),
				[]string{"Connect VPN", "Not now"}, func(label string) {
					if label == "Connect VPN" {
						v := w.vpnScreen()
						v.Show()
						v.connect()
					}
				})
		})
	}()
}
