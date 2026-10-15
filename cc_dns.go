package main

// The SOC console's DNS page (N twice in the zoomed alerts panel): the
// Pi-hole's view of the network (pihole.go). Every device and what it
// looks up, blocked lookups, detections, and whether the Pi-hole answers
// the cluster's sites with the ingress address. Detections also go into
// the SOC incident queue.

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

func init() {
	socTechniques["T1496"] = "Resource Hijacking (cryptomining)"
	socTechniques["T1572"] = "Protocol Tunneling"
	socTechniques["T1219"] = "Remote Access Software"
	socTechniques["T1568.002"] = "Dynamic Resolution: Domain Generation Algorithms"
	socTechniques["T1071.004"] = "Application Layer Protocol: DNS"
	socTechniques["T1562.001"] = "Impair Defenses: Disable or Modify Tools"
	socTactics = []string{"Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
		"Discovery", "Lateral Movement", "Command and Control", "Impact", "Operations"}
}

// What each detection kind means.
var phKinds = map[string]struct {
	flag, title string
	sev         socSev
	tactic      string
	tech        string
	response    []string
}{
	"mining": {"MINING", "looks up crypto-mining pools", sevHigh, "Impact", "T1496", []string{
		"Something on this device mines cryptocurrency (cryptojacking: often a compromised NAS, server or container).",
		"Find the process (top/Task Manager, docker ps), remove it, and change the passwords it could have used.",
		"Pi-hole: add the pool domains to the deny list so it can't reach them again."}},
	"tunnel": {"DNS-TUNNEL", "sends data inside DNS lookups (many long, unique subdomains)", sevHigh, "Command and Control", "T1071.004", []string{
		"DNS tunneling hides traffic in lookups: malware uses it to talk to its server or leak data past firewalls.",
		"Look at the examples: random-looking subdomains of one domain. If it's not software you know, isolate the device.",
		"Pi-hole: deny the base domain."}},
	"dga": {"DGA", "looks up random-looking domains that don't exist", sevMed, "Command and Control", "T1568.002", []string{
		"Malware generates domain names to find its server (domain generation algorithm); most don't exist (NXDOMAIN).",
		"Scan the device (antivirus, or reset an IoT device), and check what runs on it."}},
	"tunnelsvc": {"TUNNEL", "uses a tunnel service that exposes it to the internet", sevMed, "Command and Control", "T1572", []string{
		"ngrok, Cloudflare quick tunnels, Tor and the like publish a device to the internet past your router, or hide its traffic.",
		"Fine if you set it up yourself; otherwise find the program and remove it."}},
	"remote": {"REMOTE", "uses a remote-control tool", sevLow, "Command and Control", "T1219", []string{
		"AnyDesk, TeamViewer and similar let someone control this device from anywhere; scammers and attackers use them too.",
		"Fine if it's yours; otherwise uninstall it and check who connected."}},
	"doh": {"DoH", "can use encrypted DNS, which skips the Pi-hole", sevLow, "Defense Evasion", "T1572", []string{
		"With DNS over HTTPS the browser or device asks Google/Cloudflare directly: no blocking, nothing in this log.",
		"Turn off 'secure DNS' in the browser, or block these resolvers on the Pi-hole (and port 853 on the router)."}},
}

func (c *commandCenter) dnsPage() bool { return c.socMode() && c.socPage == 2 && c.net != nil }

// dnsFindings: the Pi-hole's problems and detections for the SOC queue.
func (c *commandCenter) dnsFindings() []socFinding {
	if c.net == nil {
		return nil
	}
	v := c.net.ph.view()
	if !v.Configured {
		return nil
	}
	var out []socFinding
	add := func(f socFinding) { out = append(out, f) }
	obj := "Pi-hole " + v.URL
	if v.CertChanged {
		add(socFinding{Key: "dns/pin", Incident: true, Sev: sevHigh, Category: "DNS", Tactic: "Credential Access", Technique: "T1557",
			Object: obj, Title: "the Pi-hole's certificate changed: the password wasn't sent",
			Evidence: []string{"the certificate differs from the one seen when it was connected"},
			Response: []string{"If you reinstalled the Pi-hole or renewed its certificate: C on the DNS page connects again.",
				"Otherwise something may be answering in its place (man in the middle): check the device at that address."}})
		return out
	}
	if !v.OK && v.Err != "" {
		add(socFinding{Key: "dns/down", Incident: true, Sev: sevMed, Category: "DNS", Tactic: "Operations", Object: obj,
			Title: "can't read the Pi-hole: " + v.Err, Response: []string{"Check the Pi-hole is up; C on the DNS page changes the address or password."}})
		return out
	}
	if !v.OK {
		return out
	}
	if v.Blocking != "" && v.Blocking != "enabled" {
		add(socFinding{Key: "dns/blocking", Incident: true, Sev: sevHigh, Category: "DNS", Tactic: "Defense Evasion", Technique: "T1562.001",
			Object: obj, Title: "blocking is " + v.Blocking + ": ads, trackers and malware domains get through",
			Response: []string{"Turn it back on in the Pi-hole (or 'pihole enable'). If you didn't turn it off, find out who did: Pi-hole → Settings → API sessions."}})
	}
	if !v.GravityAt.IsZero() && time.Since(v.GravityAt) > 14*24*time.Hour {
		add(socFinding{Key: "dns/gravity", Sev: sevLow, Category: "DNS", Tactic: "Operations", Object: obj,
			Title:    fmt.Sprintf("block lists last updated %s ago", fmtAge(v.GravityAt)),
			Response: []string{"Update them: Pi-hole → Tools → Update Gravity (or 'pihole -g'); it normally runs weekly."}})
	}
	if v.Update != "" {
		add(socFinding{Key: "dns/update", Sev: sevInfo, Category: "DNS", Tactic: "Operations", Object: obj,
			Title:    "Pi-hole update available: " + v.Update + " (running " + orDefault(v.Version, "?") + ")",
			Response: []string{"'pihole -up' on the Pi-hole (or update its container/app)."}})
	}
	for i, m := range v.Messages {
		if i >= 6 {
			break
		}
		sev := sevLow
		if strings.Contains(m, "RATE_LIMIT") || strings.Contains(strings.ToLower(m), "rate-limit") {
			sev = sevMed
		}
		add(socFinding{Key: "dns/msg/" + m, Incident: true, Sev: sev, Category: "DNS", Tactic: "Operations", Object: obj,
			Title: m, Response: []string{"Pi-hole's own diagnosis: Pi-hole → Tools → Pi-hole diagnosis (dismiss it there once handled)."}})
	}
	var wrong []string
	for _, h := range v.Hosts {
		if h.Got == h.Want {
			continue
		}
		why := "no local record: the Pi-hole forwards it to public DNS"
		if h.Record != "" {
			why = "local record: " + h.Record
		}
		got := orDefault(h.Got, h.Err)
		wrong = append(wrong, fmt.Sprintf("%s → %s, the ingress is %s (%s)", h.Host, got, h.Want, why))
	}
	if len(wrong) > 0 {
		add(socFinding{Key: "dns/hosts", Incident: true, Sev: sevMed, Category: "DNS", Tactic: "Impact", Object: socCount(len(wrong), "site"),
			Title: "the Pi-hole answers a cluster site with the wrong address", Evidence: wrong,
			Response: []string{"A on the DNS page fixes the Pi-hole's local records (asks first).",
				"Devices on the LAN then reach the site directly; they may need to flush their DNS cache (ipconfig /flushdns)."}})
	}
	for _, d := range v.Detections {
		k := phKinds[d.Kind]
		who := d.Client
		if d.Name != "" {
			who += " " + d.Name
		}
		title := k.title
		if d.Domain != "" {
			title += ": " + d.Domain
		}
		first := fmt.Sprintf("%d lookups in the last hour, last %s ago", d.Count, fmtAge(d.Last))
		if d.Blocked > 0 {
			first += fmt.Sprintf(" (%d blocked by the Pi-hole)", d.Blocked)
		}
		ev := append([]string{first}, d.Examples...)
		add(socFinding{Key: "dns/det/" + d.Kind + "/" + d.Client + "/" + d.Domain, Incident: k.sev >= sevMed, Sev: k.sev, Category: "DNS",
			Tactic: k.tactic, Technique: k.tech, Object: who, Title: title, Evidence: ev, Response: k.response, Since: d.Last,
			Target: ccTarget{Kind: "DNSClient", Name: d.Client}})
	}
	for _, cl := range v.Clients {
		who := cl.IP
		if cl.Name != "" {
			who += " " + cl.Name
		}
		if cl.Hour >= 200 && cl.HourBlocked*2 >= cl.Hour {
			add(socFinding{Key: "dns/blockheavy/" + cl.IP, Sev: sevLow, Category: "DNS", Tactic: "Operations", Object: who,
				Title:    fmt.Sprintf("%d%% of its lookups are blocked (%d of %d in the last hour)", cl.HourBlocked*100/cl.Hour, cl.HourBlocked, cl.Hour),
				Evidence: phCountLines(cl.BlockedDomains, 6),
				Response: []string{"Usually ads and telemetry (smart TVs, apps). If it's something else, look at the blocked domains."},
				Target:   ccTarget{Kind: "DNSClient", Name: cl.IP}})
		}
		if cl.NX >= 300 && cl.NX*2 >= cl.Hour {
			add(socFinding{Key: "dns/nx/" + cl.IP, Sev: sevLow, Category: "DNS", Tactic: "Operations", Object: who,
				Title:    fmt.Sprintf("%d lookups of names that don't exist in the last hour", cl.NX),
				Response: []string{"A misconfigured program, or malware searching for its server: the device's recent lookups show which."},
				Target:   ccTarget{Kind: "DNSClient", Name: cl.IP}})
		}
	}
	if len(v.NoDNS) > 0 {
		nv := c.net.view()
		var ev []string
		for _, ip := range v.NoDNS {
			name := ""
			for _, d := range nv.Devices {
				if d.IP == ip {
					name = strings.TrimSpace(d.Name + " " + d.Role)
				}
			}
			ev = append(ev, strings.TrimSpace(ip+" "+name))
		}
		add(socFinding{Key: "dns/nodns", Sev: sevInfo, Category: "DNS", Tactic: "Defense Evasion", Object: socCount(len(ev), "device"),
			Title: "online on the LAN, but never asked the Pi-hole (another DNS, or hard-coded)", Evidence: ev,
			Response: []string{"Fine for the router and for nodes with their own DNS settings.",
				"For anything else: set its DNS to the Pi-hole, or force it on the router (redirect port 53 to the Pi-hole)."}})
	}
	return out
}

func phCountLines(l []phCount, n int) []string {
	var out []string
	for i, x := range l {
		if i >= n {
			break
		}
		out = append(out, fmt.Sprintf("%5d× %s", x.Count, x.Name))
	}
	return out
}

// phFlags: the detection kinds of each client.
func phFlags(v phView) map[string][]string {
	out := map[string][]string{}
	for _, d := range v.Detections {
		f := phKinds[d.Kind].flag
		if !contains(out[d.Client], f) {
			out[d.Client] = append(out[d.Client], f)
		}
	}
	for _, f := range out {
		sort.Strings(f)
	}
	return out
}

func phWorst(v phView) map[string]socSev {
	out := map[string]socSev{}
	for _, d := range v.Detections {
		if s := phKinds[d.Kind].sev; s > out[d.Client] {
			out[d.Client] = s
		}
	}
	return out
}

func phStatusColor(q phQuery) string {
	switch {
	case phBlocked(q.Status):
		return "red"
	case q.Reply.Type == "NXDOMAIN":
		return "yellow"
	case q.Status == "CACHE" || q.Status == "CACHE_STALE":
		return "#5f87af"
	}
	return "green"
}

func phStatusShort(q phQuery) string {
	switch {
	case phBlocked(q.Status):
		return "BLOCK"
	case q.Reply.Type == "NXDOMAIN":
		return "NX"
	case q.Status == "CACHE" || q.Status == "CACHE_STALE":
		return "cache"
	case q.Status == "FORWARDED":
		return "fwd"
	}
	return strings.ToLower(fit(q.Status, 5, false))
}

// ---------------------------------------------------------------------------
// Drawing
// ---------------------------------------------------------------------------

func (c *commandCenter) drawDNS(screen tcell.Screen, in ccRect) int {
	v := c.net.ph.view()
	if !v.Configured || (!v.OK && v.At.IsZero()) || v.CertChanged {
		lines := []string{"", "[#48dbfb::b]  PI-HOLE · DNS of the whole network[-::-]", ""}
		switch {
		case v.CertChanged:
			lines = append(lines, "  [red::b]The Pi-hole's certificate changed since it was connected, so the password wasn't sent.[-::-]",
				"  [gray]If you reinstalled it or renewed its certificate, press[-] [aqua::b]C[-::-] [gray]to connect again. Otherwise check the device at "+tview.Escape(v.URL)+".[-]")
		case v.Configured && v.Err != "":
			lines = append(lines, "  [red]"+tview.Escape(v.Err)+"[-]", "", "  [aqua::b]C[-::-] [gray]changes the address or password.[-]")
		case v.Configured:
			lines = append(lines, "  [gray]Connecting to "+tview.Escape(v.URL)+"…[-]")
		default:
			if v.Found != "" {
				lines = append(lines, "  [green]Found a Pi-hole at[-] [::b]"+tview.Escape(v.Found)+"[::-] [gray](one of this computer's DNS servers)[-]", "")
			}
			lines = append(lines,
				"  Press [aqua::b]C[-::-] to connect it: every device on the network and what it looks up, blocked",
				"  lookups, malware-like lookups (mining pools, random domains, DNS tunnels, remote-control",
				"  and tunnel tools, encrypted DNS) in the incident queue, and the cluster's site records.",
				"",
				"  [yellow]Use an app password:[-] Pi-hole → Settings → Web interface / API → [::b]Configure app password[::-]",
				"  [gray](turn on Expert mode at the top right). It reads everything here but can't change settings[-]",
				"  [gray]unless 'webserver.api.app_sudo' is on, and it can be revoked any time.[-]",
				"",
				"  [gray]Saved in ~/.kubestui/network/pihole.json, readable only by you. The Pi-hole's certificate is[-]",
				"  [gray]remembered on the first connect; if it ever changes, the password isn't sent.[-]")
		}
		for i, l := range lines {
			if i >= in.h {
				break
			}
			put(screen, l, in.x, in.y+i, in.w)
		}
		return in.y + in.h
	}

	blocking := "[gray]?[-]"
	switch v.Blocking {
	case "enabled":
		blocking = "[green::b]● BLOCKING[-::-]"
	case "":
	default:
		blocking = "[red::b]● BLOCKING " + strings.ToUpper(v.Blocking) + "[-::-]"
	}
	state := ""
	if !v.OK {
		state = " [red]" + tview.Escape(v.Err) + "[-]"
	} else if v.Err != "" {
		state = " [yellow]" + tview.Escape(fit(v.Err, 50, false)) + "[-]"
	}
	grav := ""
	if v.Gravity > 0 {
		grav = fmt.Sprintf("  [gray]│ LISTS[-] %s domains", fmtCount(v.Gravity))
		if !v.GravityAt.IsZero() {
			grav += " [gray]· updated " + fmtAge(v.GravityAt) + " ago[-]"
		}
	}
	ver := ""
	if v.Version != "" {
		ver = " [gray]" + tview.Escape(v.Version) + "[-]"
		if v.Update != "" {
			ver += " [yellow]→ " + tview.Escape(v.Update) + "[-]"
		}
	}
	put(screen, fmt.Sprintf(" [gray]PI-HOLE[-] %s%s %s  [gray]│ 24H[-] [::b]%s[::-] queries · [red]%s blocked (%.1f%%)[-] [gray]· %s cached · %s forwarded · %.1f/s[-]  [gray]│ CLIENTS[-] %d active [gray]of %d[-]%s%s",
		tview.Escape(v.URL), ver, blocking, fmtCount(v.Total), fmtCount(v.Blocked), v.Percent, fmtCount(v.Cached), fmtCount(v.Forwarded), v.Freq,
		v.ClientsActive, v.ClientsTotal, grav, state), in.x, in.y, in.w)

	top := 1.0
	for _, x := range v.QPM.v {
		top = max(top, x)
	}
	var ups []string
	for i, u := range v.Upstreams {
		if i >= 3 {
			break
		}
		ups = append(ups, fmt.Sprintf("%s [gray]%d[-]", tview.Escape(u.Name), u.Count))
	}
	worst := sevInfo
	for _, d := range v.Detections {
		worst = max(worst, phKinds[d.Kind].sev)
	}
	detS := "[green]0 detections[-]"
	if n := len(v.Detections); n > 0 {
		detS = fmt.Sprintf("[%s::b]%d detection%s[-::-]", socSevColors[worst], n, map[bool]string{true: "", false: "s"}[n == 1])
	}
	put(screen, fmt.Sprintf(" [gray]LAST HOUR[-] %s queries · [red]%s blocked[-] %s [gray]per minute[-]  %s  [gray]│ UPSTREAM[-] %s  [gray]│ LOCAL RECORDS[-] %d",
		fmtCount(v.HourQueries), fmtCount(v.HourBlocked), spark(v.QPM.v, 30, top), detS, orDefault(strings.Join(ups, "  "), "[gray]-[-]"), len(v.LocalRecords)), in.x, in.y+1, in.w)

	body := ccRect{in.x, in.y + 2, in.w, in.h - 2}
	rightW := 0
	if body.w >= 120 {
		rightW = max(50, min(84, body.w*42/100))
	}
	q := ccRect{body.x, body.y, body.w - rightW, body.h}
	socTitle(screen, q, fmt.Sprintf("DEVICES ON THE PI-HOLE · %d", len(v.Clients)))
	rowsY := c.drawTable(screen, pAlerts, q.inner())
	c.hits = append(c.hits, ccHit{r: q, panel: pAlerts, rowsY: rowsY})
	if rightW == 0 {
		return rowsY
	}
	r := ccRect{body.x + q.w, body.y, rightW, body.h}
	names := map[string]string{}
	for _, cl := range v.Clients {
		names[cl.IP] = cl.Name
	}

	// Detections, then sites, then top domains, then the live stream.
	var det []string
	for _, d := range v.Detections {
		k := phKinds[d.Kind]
		what := d.Domain
		if what == "" && len(d.Examples) > 0 {
			what = d.Examples[0]
		}
		det = append(det, fmt.Sprintf("[%s]%-4s[-] [::b]%-10s[::-] %-15s %s [gray]%d×[-]", socSevColors[k.sev], socSevNames[k.sev], k.flag,
			fit(orDefault(d.Name, d.Client), 15, false), tview.Escape(what), d.Count))
	}
	for _, h := range v.Hosts {
		if h.Got != h.Want {
			det = append(det, fmt.Sprintf("[yellow]MED [-] [::b]%-10s[::-] %s [red]→ %s[-] [gray](A fixes)[-]", "SITE DNS", tview.Escape(h.Host), tview.Escape(orDefault(h.Got, h.Err))))
		}
	}
	dh := min(max(len(det), 1)+2, r.h/4+1)
	db := ccRect{r.x, r.y, r.w, dh}
	socTitle(screen, db, "DETECTIONS · last hour")
	socLines(screen, db.inner(), det, "[green]nothing suspicious in the lookups[-]")

	rest := r.h - dh
	th := min(rest/2, 14)
	tb := ccRect{r.x, r.y + dh, r.w, th}
	socTitle(screen, tb, "TOP 24H · allowed │ blocked")
	half := (tb.inner().w - 3) / 2
	var lines []string
	for i := 0; i < max(len(v.TopDomains), len(v.TopBlocked)); i++ {
		a, b := "", ""
		if i < len(v.TopDomains) {
			a = fmt.Sprintf("%6s %s", fmtCount(v.TopDomains[i].Count), fit(v.TopDomains[i].Name, half-8, false))
		}
		if i < len(v.TopBlocked) {
			b = fmt.Sprintf("[red]%6s[-] %s", fmtCount(v.TopBlocked[i].Count), tview.Escape(fit(v.TopBlocked[i].Name, half-8, false)))
		}
		lines = append(lines, fmt.Sprintf("%-*s [gray]│[-] %s", half, tview.Escape(a), b))
	}
	socLines(screen, tb.inner(), lines, "no queries yet")

	sb := ccRect{r.x, r.y + dh + th, r.w, rest - th}
	socTitle(screen, sb, "LIVE LOOKUPS")
	lines = nil
	for _, qq := range v.Recent {
		who := orDefault(names[qq.Client.IP], qq.Client.IP)
		lines = append(lines, fmt.Sprintf("[gray]%s[-] [%s]%-5s[-] %-14s [gray]%-5s[-] %s", qq.at().Local().Format("15:04:05"), phStatusColor(qq), phStatusShort(qq),
			tview.Escape(fit(who, 14, false)), tview.Escape(fit(qq.Type, 5, false)), tview.Escape(qq.Domain)))
	}
	socLines(screen, sb.inner(), lines, "waiting for lookups…")
	return rowsY
}

func fmtCount(n int) string {
	switch {
	case n >= 10_000_000:
		return fmt.Sprintf("%.0fM", float64(n)/1e6)
	case n >= 1_000_000:
		return fmt.Sprintf("%.1fM", float64(n)/1e6)
	case n >= 100_000:
		return fmt.Sprintf("%.0fk", float64(n)/1e3)
	case n >= 10_000:
		return fmt.Sprintf("%.1fk", float64(n)/1e3)
	}
	return fmt.Sprint(n)
}

// dnsTable: the Pi-hole's clients.
func (c *commandCenter) dnsTable() *ccTable {
	v := c.net.ph.view()
	t := &ccTable{
		cols: []ccCol{
			{title: "", width: 1},
			{title: "IP", width: 15},
			{title: "NAME", min: 14},
			{title: "VENDOR", width: 14, drop: 3},
			{title: "24H", width: 6, right: true},
			{title: "BLOCKED", width: 7, right: true, drop: 1},
			{title: "%", width: 3, right: true, drop: 2},
			{title: "1H", width: 5, right: true, drop: 4},
			{title: "LAST", width: 5, right: true, drop: 5},
			{title: "FLAGS", min: 8},
		},
		empty: "no lookups yet",
	}
	if !v.Configured || !v.OK && v.At.IsZero() {
		t.empty = ""
		return t
	}
	flags, worst := phFlags(v), phWorst(v)
	dnsSortClients(v.Clients, worst)
	devName := map[string]string{}
	for _, d := range c.net.view().Devices {
		devName[d.IP] = orDefault(d.Name, d.Role)
	}
	for _, cl := range v.Clients {
		col := "green"
		if s, ok := worst[cl.IP]; ok {
			col = socSevColors[s]
		}
		if cl.Hour == 0 {
			col = "gray"
		}
		pct := ""
		if cl.Total > 0 {
			pct = fmt.Sprint(cl.Blocked * 100 / cl.Total)
		}
		last := "-"
		if !cl.Last.IsZero() {
			last = fmtAge(cl.Last)
		}
		vendor := cl.Vendor
		if vendor == "" && cl.MAC != "" {
			vendor = macVendor(cl.MAC)
		}
		t.rows = append(t.rows, ccRow{key: "c/" + cl.IP, dim: cl.Hour == 0, cells: []ccCell{
			{text: "●", color: col}, {text: cl.IP}, {text: orDefault(cl.Name, devName[cl.IP])}, {text: vendor, color: "gray"},
			{text: fmtCount(cl.Total)}, {text: fmtCount(cl.Blocked), color: "red"}, {text: pct, color: "gray"},
			{text: fmtCount(cl.Hour), color: "gray"}, {text: last, color: "gray"},
			{text: strings.Join(flags[cl.IP], " "), color: map[bool]string{true: socSevColors[worst[cl.IP]], false: ""}[len(flags[cl.IP]) > 0]},
		}})
	}
	return t
}

// dnsClientDetail: one device as the Pi-hole sees it (ENTER on the DNS page).
func (c *commandCenter) dnsClientDetail(ip string, w int) []string {
	if c.net == nil {
		return []string{"[gray]The network sensor stopped.[-]"}
	}
	ph := c.net.ph
	cl := ph.client(ip)
	if cl == nil {
		return []string{"[gray]The Pi-hole hasn't seen " + ip + " lately.[-]"}
	}
	v := ph.view()
	l := []string{
		kv("ADDRESS", cl.IP),
		kv("NAME", tview.Escape(orDefault(cl.Name, "-"))),
	}
	if cl.MAC != "" {
		l = append(l, kv("MAC", cl.MAC+"   [gray]"+tview.Escape(orDefault(cl.Vendor, macVendor(cl.MAC)))+"[-]"))
	}
	pct := 0
	if cl.Total > 0 {
		pct = cl.Blocked * 100 / cl.Total
	}
	l = append(l,
		kv("24 HOURS", fmt.Sprintf("%s lookups · [red]%s blocked[-] (%d%%)", fmtCount(cl.Total), fmtCount(cl.Blocked), pct)),
		kv("LAST HOUR", fmt.Sprintf("%d lookups · [red]%d blocked[-] · [yellow]%d don't exist (NXDOMAIN)[-]", cl.Hour, cl.HourBlocked, cl.NX)))
	if !cl.Last.IsZero() {
		l = append(l, kv("LAST LOOKUP", cl.Last.Local().Format("15:04:05")+" [gray]("+fmtAge(cl.Last)+" ago)[-]"))
	}
	for _, d := range v.Detections {
		if d.Client != ip {
			continue
		}
		k := phKinds[d.Kind]
		blk := ""
		if d.Blocked > 0 {
			blk = fmt.Sprintf(", %d blocked", d.Blocked)
		}
		l = append(l, "", fmt.Sprintf("[%s::b]%s %s[-::-] %s%s [gray](%d×%s · ATT&CK %s %s)[-]", socSevColors[k.sev], socSevNames[k.sev], k.flag,
			tview.Escape(k.title), map[bool]string{true: ": " + tview.Escape(d.Domain), false: ""}[d.Domain != ""], d.Count, blk, k.tech, tview.Escape(socTechniques[k.tech])))
		for _, e := range d.Examples {
			l = append(l, "    [gray]"+tview.Escape(e)+"[-]")
		}
		for _, r := range k.response {
			for _, s := range wrapText(r, w-6) {
				l = append(l, "    "+tview.Escape(s))
			}
		}
	}
	if c.net != nil {
		for _, d := range c.net.view().Devices {
			if d.IP == ip {
				l = append(l, "", section("ON THE LAN"), kv("DEVICE", d.MAC+" "+tview.Escape(orDefault(d.Vendor, ""))+" "+tview.Escape(d.Role)),
					kv("OPEN PORTS", portList(d.Ports)))
			}
		}
	}
	two := func(title string, a []phCount, col string) {
		l = append(l, "", section(title))
		if len(a) == 0 {
			l = append(l, "  [gray]none[-]")
		}
		for _, x := range a {
			l = append(l, fmt.Sprintf("  [%s]%5d×[-] %s", col, x.Count, tview.Escape(x.Name)))
		}
	}
	two("MOST LOOKED UP · last hour", cl.Domains, "white")
	two("BLOCKED · last hour", cl.BlockedDomains, "red")
	l = append(l, "", section("RECENT LOOKUPS"))
	qs := ph.queriesFor(ip, 60)
	if len(qs) == 0 {
		l = append(l, "  [gray]none in the last hour[-]")
	}
	for _, q := range qs {
		l = append(l, fmt.Sprintf("  [gray]%s[-] [%s]%-5s[-] [gray]%-5s[-] %s", q.at().Local().Format("15:04:05"), phStatusColor(q), phStatusShort(q),
			tview.Escape(fit(q.Type, 5, false)), tview.Escape(q.Domain)))
	}
	return l
}

func (c *commandCenter) openDNSClient(ip string) {
	c.overlay = &ccOverlay{title: "DNS · " + ip, target: ccTarget{Kind: "DNSClient", Name: ip},
		build: func(w int) []string { return c.dnsClientDetail(ip, w) }}
	c.setFooter()
}

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

// dnsConnect (C): connect a Pi-hole, or change/forget the saved one.
func (c *commandCenter) dnsConnect() {
	ph := c.net.ph
	v := ph.view()
	if ph.demo {
		c.flash("[yellow]The demo's Pi-hole is made up: on a real cluster C asks for the Pi-hole's address and password.[-]")
		return
	}
	if v.Configured {
		showChoice("Pi-hole", "Connected to "+v.URL+".\n\nChange the address or password, or forget it (deletes the saved password)?",
			[]string{"Change", "Forget", "Cancel"}, func(label string) {
				switch label {
				case "Change":
					c.dnsForm(v.URL)
				case "Forget":
					go func() {
						ph.Forget()
						c.app.QueueUpdateDraw(func() { c.flash("[green]Pi-hole forgotten: its saved password is deleted.[-]") })
					}()
				}
			})
		return
	}
	c.dnsForm(orDefault(v.Found, ""))
}

func (c *commandCenter) dnsForm(addr string) {
	ph := c.net.ph
	prev := uiApp.GetFocus()
	form := tview.NewForm().
		AddInputField("Pi-hole address", addr, 40, nil, nil).
		AddPasswordField("App password", "", 40, '*', nil)
	closeForm := func() {
		uiPages.RemovePage("ask")
		if prev != nil {
			uiApp.SetFocus(prev)
		}
	}
	form.AddButton("Connect", func() {
		base := form.GetFormItem(0).(*tview.InputField).GetText()
		pw := form.GetFormItem(1).(*tview.InputField).GetText()
		closeForm()
		c.flash("[aqua]Connecting to the Pi-hole…[-]")
		go func() {
			err := ph.Connect(base, pw)
			c.app.QueueUpdateDraw(func() {
				if err != nil {
					c.flash("[red]Pi-hole: " + tview.Escape(err.Error()) + "[-]")
				} else {
					c.flash("[green]Pi-hole connected: reading its query log.[-]")
				}
			})
		}()
	})
	form.AddButton("Cancel", closeForm)
	form.SetCancelFunc(closeForm)
	styleForm(form)
	form.SetTitle(" Connect Pi-hole ")
	uiPages.AddPage("ask", centered(form, 64, 9), true, true)
	uiApp.SetFocus(form)
}

// dnsFix (A): make the Pi-hole answer every cluster site with its ingress.
func (c *commandCenter) dnsFix() {
	ph := c.net.ph
	v := ph.view()
	var fix []phHost
	var plan []string
	for _, h := range v.Hosts {
		if h.Got == h.Want {
			continue
		}
		fix = append(fix, h)
		if h.Record != "" {
			plan = append(plan, "remove  "+h.Record)
		}
		plan = append(plan, "add     "+h.Want+" "+h.Host)
	}
	if len(fix) == 0 {
		if len(v.Hosts) == 0 {
			c.flash("[gray]No cluster sites checked on the Pi-hole yet.[-]")
		} else {
			c.flash("[green]The Pi-hole answers every cluster site with its ingress address.[-]")
		}
		return
	}
	showConfirm("Fix site records on the Pi-hole", "Pi-hole Local DNS records:\n\n"+strings.Join(plan, "\n")+"\n\nOther records aren't touched.", "Fix", "Cancel", func(ok bool) {
		if !ok {
			return
		}
		go func() {
			done, err := ph.FixHosts(fix)
			c.app.QueueUpdateDraw(func() {
				if err != nil {
					c.flash("[red]" + tview.Escape(err.Error()) + "[-]")
					return
				}
				c.flash("[green]Pi-hole: " + tview.Escape(strings.Join(done, "; ")) + ". Flush DNS on devices that cached the old address (ipconfig /flushdns).[-]")
			})
		}()
	})
}

// dnsDeviceLines: the Pi-hole's summary of a LAN device (device detail).
func (c *commandCenter) dnsDeviceLines(ip string) []string {
	if c.net == nil {
		return nil
	}
	cl := c.net.ph.client(ip)
	if cl == nil {
		return nil
	}
	l := []string{"", section("DNS (PI-HOLE)") + " [gray]· ENTER on it on the DNS page for everything[-]",
		kv("LOOKUPS", fmt.Sprintf("%s in 24h · [red]%s blocked[-] · %d last hour", fmtCount(cl.Total), fmtCount(cl.Blocked), cl.Hour))}
	var top []string
	for i, d := range cl.Domains {
		if i >= 6 {
			break
		}
		top = append(top, d.Name)
	}
	if len(top) > 0 {
		l = append(l, kv("LOOKS UP", tview.Escape(strings.Join(top, ", "))))
	}
	for _, f := range phFlags(c.net.ph.view())[ip] {
		l = append(l, kv("DETECTION", "[#ff8700::b]"+f+"[-::-]"))
	}
	return l
}

// dnsSortClients keeps detections on top.
func dnsSortClients(cl []*phClient, worst map[string]socSev) {
	sort.SliceStable(cl, func(i, j int) bool { return worst[cl[i].IP] > worst[cl[j].IP] })
}
