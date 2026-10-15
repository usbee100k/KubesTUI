package main

// The SOC console's NET page (N in the zoomed alerts panel): the whole
// network as the computer running KubesTUI sees it (netsensor.go), next
// to the cluster. Network problems also go into the SOC incident queue.

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// netRisk: ports that are a finding when open on a LAN device.
var netRisk = map[int]struct {
	sev        socSev
	tech, why  string
	tactic     string
	suggestion string
}{
	23:    {sevHigh, "T1021", "telnet: logins in clear text, often default passwords (IoT)", "Lateral Movement", "Turn telnet off in the device's settings or update its firmware; block it on the router."},
	2375:  {sevCrit, "T1610", "Docker API without TLS: anyone on the LAN can run containers as root", "Execution", "Bind the Docker API to a socket or 2376 with TLS client certificates."},
	21:    {sevMed, "T1040", "FTP: passwords in clear text", "Credential Access", "Use SFTP (ssh) instead."},
	3389:  {sevMed, "T1021", "Remote Desktop open on the LAN", "Lateral Movement", "Allow it only from your own computers (Windows firewall), use Network Level Authentication."},
	5900:  {sevMed, "T1021", "VNC: often weak or no password", "Lateral Movement", "Require a password, tunnel it over SSH, or turn it off."},
	6379:  {sevMed, "T1190", "Redis: no password by default", "Initial Access", "Set requirepass and bind it to localhost."},
	27017: {sevMed, "T1190", "MongoDB open on the LAN", "Initial Access", "Enable authentication; bind to localhost."},
	9200:  {sevMed, "T1190", "Elasticsearch open on the LAN", "Initial Access", "Enable security (users, TLS)."},
	445:   {sevLow, "T1021", "SMB file sharing", "Lateral Movement", "Keep SMBv1 off; share only what's needed, with passwords."},
	1883:  {sevLow, "T1040", "MQTT without TLS", "Credential Access", "Use 8883 (TLS) and passwords."},
	5432:  {sevLow, "T1190", "PostgreSQL open on the LAN", "Initial Access", "Allow only the hosts that need it (pg_hba.conf)."},
	3306:  {sevLow, "T1190", "MySQL open on the LAN", "Initial Access", "Allow only the hosts that need it."},
}

func init() {
	socTechniques["T1557"] = "Adversary-in-the-Middle (ARP Cache Poisoning)"
	socTechniques["T1200"] = "Hardware Additions"
	socTechniques["T1021"] = "Remote Services"
	socTechniques["T1610"] = "Deploy Container"
	// socTactics (with the network and DNS tactics) is set in cc_dns.go.
}

func (c *commandCenter) netStart() {
	if c.net != nil || c.src == nil {
		return
	}
	_, demo := c.src.(ccNoProbe)
	app := c.app
	c.net = newNetSensor(demo, func() { app.QueueUpdateDraw(func() {}) })
	if c.snap != nil {
		c.net.setTargets(c.snap)
	}
	c.net.Start()
}

func (c *commandCenter) netStop() {
	if c.net != nil {
		c.net.Stop()
		c.net = nil
	}
}

func (c *commandCenter) netPage() bool { return c.socMode() && c.socPage == 1 && c.net != nil }

// netFindings: network problems for the SOC queue.
func (c *commandCenter) netFindings() []socFinding {
	if c.net == nil {
		return nil
	}
	v := c.net.view()
	var out []socFinding
	add := func(f socFinding) { out = append(out, f) }

	inet, inetOK := 0, 0
	for _, p := range v.Probes {
		if len(p.RTT.v) == 0 {
			continue
		}
		switch p.Kind {
		case "internet":
			inet++
			if p.OK {
				inetOK++
			}
		case "gateway":
			if !p.OK {
				add(socFinding{Key: "net/gw-down", Incident: true, Sev: sevCrit, Category: "Network", Tactic: "Impact",
					Object: "gateway " + p.Addr, Title: "the gateway doesn't answer",
					Response: []string{"Check the router is on and this computer's cable or Wi-Fi.", "Every device loses the internet while it's down."}})
			} else if p.Fails >= 5 {
				add(socFinding{Key: "net/gw-loss", Incident: true, Sev: sevMed, Category: "Network", Tactic: "Impact",
					Object: "gateway " + p.Addr, Title: fmt.Sprintf("%d%% of probes to the gateway failed (last 20)", p.Fails*5),
					Response: []string{"Look for a bad cable, Wi-Fi interference or an overloaded router."}})
			}
		case "vip":
			if !p.OK {
				add(socFinding{Key: "net/vip-down", Incident: true, Sev: sevHigh, Category: "Network", Tactic: "Impact",
					Object: "API " + p.Addr, Title: "the cluster API address doesn't answer",
					Response: []string{"kube-vip holds this address on a control plane: check kube-vip pods and that a control plane is up."}})
			}
		}
	}
	if inet > 0 && inetOK == 0 {
		add(socFinding{Key: "net/wan-down", Incident: true, Sev: sevCrit, Category: "Network", Tactic: "Impact",
			Object: "internet", Title: "the internet is unreachable (1.1.1.1 and 8.8.8.8)",
			Response: []string{"Check the modem and the router's WAN status.", "The cluster keeps running on the LAN; image pulls and certificates renewals fail meanwhile."}})
	}
	dnsOK, dnsN := 0, 0
	for _, d := range v.DNS {
		if d.Took == 0 && d.Err == "" {
			continue
		}
		dnsN++
		if d.OK {
			dnsOK++
		}
	}
	switch {
	case dnsN > 0 && dnsOK == 0:
		add(socFinding{Key: "net/dns-down", Incident: true, Sev: sevHigh, Category: "Network", Tactic: "Impact", Object: "DNS",
			Title: "no DNS server answers", Response: []string{"Check the DNS servers set on this computer (router, Pi-hole, AdGuard)."}})
	case dnsOK < dnsN:
		var bad []string
		for _, d := range v.DNS {
			if !d.OK && (d.Took > 0 || d.Err != "") {
				bad = append(bad, d.Server+" ("+d.Err+")")
			}
		}
		add(socFinding{Key: "net/dns-some", Incident: true, Sev: sevLow, Category: "Network", Tactic: "Impact", Object: "DNS",
			Title: "a DNS server doesn't answer: " + strings.Join(bad, ", "), Evidence: bad})
	}
	if len(v.Spoof) > 0 {
		add(socFinding{Key: "net/spoof", Incident: true, Sev: sevHigh, Category: "Network", Tactic: "Credential Access", Technique: "T1557",
			Object: "gateway " + v.Gateway, Title: "the gateway's MAC also answers for " + strings.Join(v.Spoof, ", ") + " (possible ARP spoofing)",
			Evidence: append([]string{"in this computer's ARP table one MAC claims several addresses"}, v.Spoof...),
			Response: []string{"Find the device with that MAC (switch/router client list).", "If it isn't the router itself, disconnect it: traffic through it can be read or changed."}})
	}
	for _, d := range v.Devices {
		obj := d.IP
		if d.Name != "" {
			obj += " " + d.Name
		}
		if d.OldMAC != "" && !d.Known {
			sev := sevMed
			if d.IP == v.Gateway {
				sev = sevHigh
			}
			add(socFinding{Key: "net/macchange/" + d.IP + "/" + d.MAC, Incident: true, Sev: sev, Category: "Network", Tactic: "Credential Access",
				Technique: "T1557", Object: obj, Title: "this address moved to a new MAC " + d.MAC + " (was " + d.OldMAC + ")",
				Evidence: []string{"vendor now: " + orDefault(d.Vendor, "unknown"), "a new device took the address (DHCP), or something impersonates it"},
				Response: []string{"If you replaced the device or it changed Wi-Fi MAC: K on the NET page marks it known.", "Otherwise find who owns that MAC."},
				Target:   ccTarget{Kind: "Device", Name: d.MAC}})
		} else if !d.Known && d.Online {
			add(socFinding{Key: "net/new/" + d.MAC, Incident: true, Sev: sevMed, Category: "Network", Tactic: "Initial Access", Technique: "T1200",
				Object: obj, Title: "new device on the LAN (" + orDefault(d.Vendor, "unknown vendor") + ")", Since: d.First,
				Evidence: []string{"MAC " + d.MAC, "open ports: " + portList(d.Ports)},
				Response: []string{"Check it's yours (router client list, the vendor).", "K on the NET page marks it known."},
				Target:   ccTarget{Kind: "Device", Name: d.MAC}})
		}
		if !d.Online {
			continue
		}
		for _, p := range d.Ports {
			r, ok := netRisk[p]
			if !ok || (p == 445 && d.Role == "THIS HOST") {
				continue
			}
			add(socFinding{Key: fmt.Sprintf("net/port/%s/%d", d.MAC, p), Sev: r.sev, Category: "Exposure", Tactic: r.tactic, Technique: r.tech,
				Object: obj, Title: fmt.Sprintf("port %d open: %s", p, r.why),
				Evidence: []string{"MAC " + d.MAC + " " + orDefault(d.Vendor, ""), "open: " + portList(d.Ports)},
				Response: []string{r.suggestion}, Target: ccTarget{Kind: "Device", Name: d.MAC}})
		}
	}
	untrusted := map[string][]string{} // issuer -> hosts
	for _, sv := range v.Services {
		obj := "https://" + sv.Host
		switch {
		case sv.Err != "":
			add(socFinding{Key: "net/site/" + sv.Host, Incident: true, Sev: sevMed, Category: "Service", Tactic: "Impact",
				Object: obj, Title: "site check failed: " + sv.Err,
				Response: []string{"Check the ingress, its service and pods; and that " + sv.Host + " resolves to " + orDefault(sv.Want, "the ingress IP") + "."}})
		case sv.Status >= 500:
			add(socFinding{Key: "net/site/" + sv.Host, Incident: true, Sev: sevMed, Category: "Service", Tactic: "Impact",
				Object: obj, Title: fmt.Sprintf("answers HTTP %d", sv.Status),
				Response: []string{"The app behind it is down or starting: check its pods."}})
		}
		if sv.Got != "" && !sv.DNSOK {
			add(socFinding{Key: "net/sitedns/" + sv.Host, Incident: true, Sev: sevMed, Category: "Network", Tactic: "Impact",
				Object: sv.Host, Title: "resolves to " + sv.Got + ", the ingress is " + sv.Want,
				Response: []string{"Fix the DNS record (router, Pi-hole or public DNS) to point at " + sv.Want + "."}})
		}
		if sv.Status > 0 && sv.TLSIssuer != "" {
			switch {
			case sv.TLSDays < 14:
				add(socFinding{Key: "net/tls/" + sv.Host, Sev: sevMed, Category: "Crypto", Tactic: "Operations", Object: obj,
					Title: fmt.Sprintf("certificate expires in %d days", sv.TLSDays), Response: []string{"Check cert-manager renews it (kubectl get certificate -A)."}})
			case !sv.TLSTrusted:
				untrusted[sv.TLSIssuer] = append(untrusted[sv.TLSIssuer], sv.Host)
			}
		}
	}
	for issuer, hosts := range untrusted {
		add(socFinding{Key: "net/tlsuntrusted/" + issuer, Sev: sevLow, Category: "Crypto", Tactic: "Credential Access", Technique: "T1557",
			Object: socCount(len(hosts), "site"), Title: "certificate this computer doesn't trust (issuer " + issuer + ")", Evidence: hosts,
			Response: []string{"If it's your own CA: Command Center tab → Trust Cluster Certificates installs it on this computer (S there saves it for phones).",
				"Otherwise users learn to click through certificate warnings, which is exactly what a man in the middle needs."}})
	}
	for _, l := range v.Listening {
		port := l.Local[strings.LastIndex(l.Local, ":")+1:]
		p, _ := strconv.Atoi(port)
		host := l.Local[:strings.LastIndex(l.Local, ":")]
		if host != "0.0.0.0" && host != "[::]" {
			continue
		}
		if r, ok := netRisk[p]; ok && p != 445 && p != 3389 {
			add(socFinding{Key: "net/listen/" + port, Sev: r.sev, Category: "Exposure", Tactic: r.tactic, Technique: r.tech,
				Object: "this computer :" + port, Title: "listening on all interfaces: " + r.why + " (" + orDefault(l.Process, "?") + ")",
				Response: []string{r.suggestion}})
		}
	}
	return append(out, c.dnsFindings()...)
}

func portList(ports []int) string {
	if len(ports) == 0 {
		return "none"
	}
	var parts []string
	for _, p := range ports {
		parts = append(parts, strconv.Itoa(p))
	}
	return strings.Join(parts, " ")
}

func netClass(ip string, v netView, t map[string]string) string {
	p := net.ParseIP(ip)
	switch {
	case p == nil:
		return "?"
	case p.IsLoopback():
		return "local"
	case t[ip] != "":
		return "node"
	case inSubnets(ip, v.Subnets):
		return "LAN"
	case p.IsPrivate():
		return "private"
	}
	return "internet"
}

// ---------------------------------------------------------------------------
// Drawing
// ---------------------------------------------------------------------------

func fmtMS(d time.Duration) string {
	if d <= 0 {
		return "-"
	}
	ms := float64(d.Microseconds()) / 1000
	if ms < 10 {
		return fmt.Sprintf("%.1fms", ms)
	}
	return fmt.Sprintf("%.0fms", ms)
}

func (c *commandCenter) drawNet(screen tcell.Screen, in ccRect) int {
	v := c.net.view()
	s := c.snap

	// Line 1: WAN, gateway, DNS, this host.
	inetOK, inetN := 0, 0
	gw := "[gray]?[-]"
	for _, p := range v.Probes {
		switch p.Kind {
		case "internet":
			if len(p.RTT.v) > 0 {
				inetN++
				if p.OK {
					inetOK++
				}
			}
		case "gateway":
			if len(p.RTT.v) > 0 {
				gw = map[bool]string{true: "[green]" + fmtMS(p.Last) + "[-]", false: "[red]DOWN[-]"}[p.OK]
			}
		}
	}
	wan := "[gray]checking[-]"
	switch {
	case inetN > 0 && inetOK == inetN:
		wan = "[green::b]● UP[-::-]"
	case inetN > 0 && inetOK > 0:
		wan = "[yellow::b]● DEGRADED[-::-]"
	case inetN > 0:
		wan = "[red::b]● DOWN[-::-]"
	}
	pub := "[gray]…[-]"
	if v.PublicIP != "" {
		pub = fmt.Sprintf("[::b]%s[::-] [gray](%s %s)[-]", v.PublicIP, v.Colo, v.Loc)
	} else if v.WANErr != "" {
		pub = "[gray]" + tview.Escape(v.WANErr) + "[-]"
	}
	var dns []string
	for _, d := range v.DNS {
		col, mark := "gray", "…"
		if d.Took > 0 || d.Err != "" {
			col, mark = map[bool]string{true: "green", false: "red"}[d.OK], fmtMS(d.Took)
			if !d.OK {
				mark = d.Err
			}
		}
		dns = append(dns, fmt.Sprintf("%s [%s]%s[-]", d.Server, col, tview.Escape(mark)))
	}
	put(screen, fmt.Sprintf(" [gray]WAN[-] %s  [gray]public[-] %s  [gray]│ GATEWAY[-] %s %s  [gray]│ DNS[-] %s  [gray]│ THIS HOST[-] %s [gray]%s[-]",
		wan, pub, orDefault(v.Gateway, "?"), gw, orDefault(strings.Join(dns, "  "), "[gray]?[-]"), orDefault(v.HostIP, "?"), tview.Escape(v.HostIface)), in.x, in.y, in.w)

	// Line 2: LAN, sweep, traffic.
	online, newN, total := 0, 0, len(v.Devices)
	for _, d := range v.Devices {
		if d.Online {
			online++
			if !d.Known {
				newN++
			}
		}
	}
	sweep := "[gray]first sweep soon[-]"
	switch {
	case v.Sweeping:
		sweep = fmt.Sprintf("[aqua]sweeping %d%%[-]", v.SweepDone*100/max(1, v.SweepTotal))
	case !v.SweepAt.IsZero():
		sweep = fmt.Sprintf("[gray]swept %s ago · next in %s · U now[-]", fmtAge(v.SweepAt), fmtDur(time.Until(v.NextSweep)))
	}
	rxTop := 1.0
	for _, x := range append(append([]float64{}, v.Rx.v...), v.Tx.v...) {
		rxTop = max(rxTop, x)
	}
	put(screen, fmt.Sprintf(" [gray]LAN[-] %s  [::b]%d[::-] online · [aqua::b]%d[-::-] new [gray]· of %d[-]  %s  [gray]│ THIS HOST ↓[-]%s/s %s [gray]↑[-]%s/s %s  [gray]│ CONN[-] %d est · %d listening",
		strings.Join(v.Subnets, " "), online, newN, total, sweep, fmtBytes(int64(v.RxRate)), spark(v.Rx.v, 14, rxTop), fmtBytes(int64(v.TxRate)), spark(v.Tx.v, 14, rxTop),
		len(v.Conns), len(v.Listening)), in.x, in.y+1, in.w)

	body := ccRect{in.x, in.y + 2, in.w, in.h - 2}
	rightW := 0
	if body.w >= 120 {
		rightW = max(46, min(76, body.w*40/100))
	}
	q := ccRect{body.x, body.y, body.w - rightW, body.h}
	socTitle(screen, q, fmt.Sprintf("LAN DEVICES · %d online of %d", online, total))
	rowsY := c.drawTable(screen, pAlerts, q.inner())
	c.hits = append(c.hits, ccHit{r: q, panel: pAlerts, rowsY: rowsY})
	if rightW == 0 {
		return rowsY
	}
	r := ccRect{body.x + q.w, body.y, rightW, body.h}

	// Latency (and, for nodes, their traffic from the kubelet).
	lh := min(len(v.Probes)+2, r.h/2)
	lb := ccRect{r.x, r.y, r.w, lh}
	socTitle(screen, lb, "LATENCY · TCP connect, last 20")
	var lines []string
	for _, p := range v.Probes {
		col := "green"
		if !p.OK {
			col = "red"
		} else if p.Fails > 0 {
			col = "yellow"
		}
		top := 1.0
		var vals []float64
		for _, x := range p.RTT.v {
			top = max(top, x)
			vals = append(vals, max(0, x))
		}
		extra := ""
		if p.Kind == "node" && s != nil {
			if n := s.node(p.Name); n != nil && n.HasStats {
				extra = fmt.Sprintf(" [gray]↓%s ↑%s[-]", fmtBytes(int64(n.RxRate)), fmtBytes(int64(n.TxRate)))
			}
		}
		last := fmtMS(p.Last)
		if !p.OK {
			last = "DOWN"
		}
		lines = append(lines, fmt.Sprintf("[%s]●[-] %-10s %s [%s]%7s[-] [gray]loss %3d%%[-]%s",
			col, fit(p.Name, 10, false), spark(vals, 16, top), col, last, p.Fails*5, extra))
	}
	socLines(screen, lb.inner(), lines, "probing…")

	rest := r.h - lh
	sh := rest / 2
	sb := ccRect{r.x, r.y + lh, r.w, sh}
	socTitle(screen, sb, fmt.Sprintf("SITES · %d ingress hosts", len(v.Services)))
	lines = nil
	for _, sv := range v.Services {
		col, what := "green", fmt.Sprintf("%d", sv.Status)
		switch {
		case sv.Err != "":
			col, what = "red", sv.Err
		case sv.Status >= 500:
			col = "red"
		case sv.Status >= 400:
			col = "yellow"
		}
		tlsS := "[gray]http[-]"
		if sv.TLSIssuer != "" {
			tc := "green"
			if !sv.TLSTrusted {
				tc = "yellow"
			}
			if sv.TLSDays < 14 {
				tc = "red"
			}
			tlsS = fmt.Sprintf("[%s]TLS %dd[-] [gray]%s[-]", tc, sv.TLSDays, tview.Escape(fit(sv.TLSIssuer, 10, false)))
		}
		dnsS := "[green]dns[-]"
		if !sv.DNSOK {
			dnsS = "[red]dns→" + orDefault(sv.Got, "none") + "[-]"
		}
		lines = append(lines, fmt.Sprintf("[%s]●[-] %-26s [%s]%-5s[-] %6s %s %s", col, fit(sv.Host, 26, false), col, tview.Escape(fit(what, 5, false)), fmtMS(sv.Took), dnsS, tlsS))
	}
	socLines(screen, sb.inner(), lines, "checking…")

	cb := ccRect{r.x, r.y + lh + sh, r.w, rest - sh}
	socTitle(screen, cb, "THIS HOST · top talkers · listening")
	type talker struct {
		ip, proc string
		n        int
	}
	byIP := map[string]*talker{}
	for _, cn := range v.Conns {
		host, _, err := net.SplitHostPort(cn.Remote)
		if err != nil {
			continue
		}
		t := byIP[host]
		if t == nil {
			t = &talker{ip: host, proc: cn.Process}
			byIP[host] = t
		}
		t.n++
	}
	var ts []*talker
	for _, t := range byIP {
		ts = append(ts, t)
	}
	sort.Slice(ts, func(i, j int) bool {
		if ts[i].n != ts[j].n {
			return ts[i].n > ts[j].n
		}
		return ts[i].ip < ts[j].ip
	})
	nodes := map[string]string{}
	if s != nil {
		for _, n := range s.Nodes {
			nodes[n.IP] = n.Name
		}
	}
	names := map[string]string{}
	for _, d := range v.Devices {
		names[d.IP] = orDefault(d.Name, d.Role)
	}
	lines = nil
	for _, t := range ts {
		class := netClass(t.ip, v, nodes)
		col := map[string]string{"internet": "#ff8700", "LAN": "aqua", "node": "green"}[class]
		label := orDefault(nodes[t.ip], names[t.ip])
		lines = append(lines, fmt.Sprintf("[%s]%-8s[-] %-15s %3d× [gray]%s %s[-]", orDefault(col, "gray"), class, t.ip, t.n, tview.Escape(fit(t.proc, 14, false)), tview.Escape(label)))
	}
	var listen []string
	for _, l := range v.Listening {
		if strings.HasPrefix(l.Local, "0.0.0.0:") || strings.HasPrefix(l.Local, "[::]:") {
			port := l.Local[strings.LastIndex(l.Local, ":")+1:]
			if !contains(listen, port) {
				listen = append(listen, port)
			}
		}
	}
	sort.Slice(listen, func(i, j int) bool { a, _ := strconv.Atoi(listen[i]); b, _ := strconv.Atoi(listen[j]); return a < b })
	if len(listen) > 0 {
		lines = append([]string{"[yellow]open to the LAN:[-] " + strings.Join(listen, " ")}, lines...)
	}
	socLines(screen, cb.inner(), lines, "no connections")
	return rowsY
}

// netTable: the LAN devices.
func (c *commandCenter) netTable() *ccTable {
	v := c.net.view()
	t := &ccTable{
		cols: []ccCol{
			{title: "", width: 1},
			{title: "IP", width: 15},
			{title: "MAC", width: 17, drop: 3},
			{title: "VENDOR", width: 16, drop: 2},
			{title: "NAME", min: 14},
			{title: "ROLE", width: 14, drop: 1},
			{title: "OPEN PORTS", min: 16},
			{title: "SEEN", width: 5, right: true, drop: 4},
		},
		empty: "no devices yet: the first sweep runs a few seconds after opening (U runs it now)",
	}
	sort.SliceStable(v.Devices, func(i, j int) bool {
		if v.Devices[i].Online != v.Devices[j].Online {
			return v.Devices[i].Online
		}
		return ipLess(v.Devices[i].IP, v.Devices[j].IP)
	})
	for _, d := range v.Devices {
		col := "green"
		switch {
		case !d.Online:
			col = "gray"
		case d.OldMAC != "" && !d.Known:
			col = "red"
		case !d.Known:
			col = "aqua"
		}
		portCol := ""
		for _, p := range d.Ports {
			if r, ok := netRisk[p]; ok && r.sev >= sevMed {
				portCol = "#ff8700"
			}
		}
		name := d.Name
		if name == "" {
			if cl := c.net.ph.client(d.IP); cl != nil {
				name = cl.Name // the Pi-hole's name for it
			}
		}
		if !d.Known && d.Online {
			name = "NEW " + name
		}
		roleCol := "#48dbfb"
		if d.Role == "" {
			roleCol = "gray"
		}
		seen := "now"
		if !d.Online {
			seen = fmtAge(d.Last)
		}
		textCol := ""
		if !d.Online {
			textCol = "gray"
		}
		t.rows = append(t.rows, ccRow{key: "d/" + d.MAC, dim: !d.Online, cells: []ccCell{
			{text: "●", color: col}, {text: d.IP, color: textCol}, {text: d.MAC, color: "gray"}, {text: d.Vendor, color: "gray"},
			{text: name, color: map[bool]string{true: "aqua", false: textCol}[!d.Known && d.Online]}, {text: d.Role, color: roleCol},
			{text: portList(d.Ports), color: portCol}, {text: seen, color: "gray"},
		}})
	}
	return t
}

// netDeviceDetail: one device (ENTER on the NET page).
func (c *commandCenter) netDeviceDetail(mac string, w int) []string {
	if c.net == nil {
		return []string{"[gray]The network sensor stopped.[-]"}
	}
	v := c.net.view()
	for _, d := range v.Devices {
		if d.MAC != mac {
			continue
		}
		state := "[green]online[-]"
		if !d.Online {
			state = "[gray]offline · last seen " + fmtAge(d.Last) + " ago[-]"
		}
		known := "[green]known[-]"
		if !d.Known {
			known = "[aqua::b]NEW[-::-] [gray](K marks it known)[-]"
		}
		l := []string{
			kv("ADDRESS", d.IP+"   "+state),
			kv("MAC", d.MAC+"   [gray]"+tview.Escape(orDefault(d.Vendor, "vendor unknown"))+"[-]"),
			kv("NAME", tview.Escape(orDefault(d.Name, "-"))+"   [gray](reverse DNS)[-]"),
			kv("ROLE", orDefault(d.Role, "-")),
			kv("STATUS", known),
			kv("FIRST SEEN", d.First.Local().Format("2006-01-02 15:04")+"   [gray]last[-] "+d.Last.Local().Format("15:04:05")),
		}
		if d.RTT > 0 {
			l = append(l, kv("ANSWERED IN", fmtMS(d.RTT)))
		}
		if d.OldMAC != "" {
			l = append(l, kv("WAS", "[red]"+d.OldMAC+"[-] [gray](this address had another MAC before)[-]"))
		}
		l = append(l, "", section("OPEN PORTS"))
		if len(d.Ports) == 0 {
			l = append(l, "  [gray]none of the checked ports ("+strconv.Itoa(len(netPorts))+") answered[-]")
		}
		for _, p := range d.Ports {
			line := fmt.Sprintf("  [::b]%-6d[::-] %-16s", p, orDefault(netPortNames[p], "?"))
			if r, ok := netRisk[p]; ok {
				line += fmt.Sprintf(" [%s]%s[-] %s", socSevColors[r.sev], socSevNames[r.sev], tview.Escape(r.why))
			}
			l = append(l, line)
			if r, ok := netRisk[p]; ok {
				for _, s := range wrapText(r.suggestion, w-12) {
					l = append(l, "           [gray]"+s+"[-]")
				}
			}
		}
		l = append(l, c.dnsDeviceLines(d.IP)...)
		if strings.HasPrefix(d.Vendor, "random MAC") {
			l = append(l, "", "[gray]A random MAC is what phones and laptops use per Wi-Fi network (private address): the same phone shows up as new on another network, or after a reset.[-]")
		}
		return l
	}
	return []string{"[gray]Gone.[-]"}
}

func (c *commandCenter) openNetDevice(mac string) {
	c.overlay = &ccOverlay{title: "DEVICE " + mac, target: ccTarget{Kind: "Device", Name: mac},
		build: func(w int) []string { return c.netDeviceDetail(mac, w) }}
	c.setFooter()
}
