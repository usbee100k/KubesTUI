package main

// The DNS page in the demo: a made-up Pi-hole (10.99.0.61) for the demo
// network, with a NAS reaching for a mining pool, a new device looking up
// random domains, and a site record pointing at the public address.

import (
	"fmt"
	"math/rand"
	"strings"
	"time"
)

type phDemoClient struct {
	ip, name, mac string
	perHour       int
	allowed       []string
	blocked       []string
	blockShare    float64
	special       func(r *rand.Rand) (domain, status, reply string, ok bool)
}

func phDemoClients() []phDemoClient {
	consonants := "bcdfghjklmnpqrstvwxz0123456789"
	randomName := func(r *rand.Rand) string {
		var b strings.Builder
		for i := 0; i < 14+r.Intn(6); i++ {
			b.WriteByte(consonants[r.Intn(len(consonants))])
		}
		return b.String() + []string{".com", ".net", ".info", ".biz"}[r.Intn(4)]
	}
	nodes := []string{"registry-1.docker.io", "production.cloudflare.docker.com", "ghcr.io", "pkg-containers.githubusercontent.com",
		"quay.io", "api.github.com", "acme-v02.api.letsencrypt.org", "www.duckdns.org", "ntp.ubuntu.com", "archive.ubuntu.com"}
	return []phDemoClient{
		{ip: "10.99.0.50", name: "desktop.lan", mac: "3c:97:0e:4a:10:22", perHour: 900,
			allowed: []string{"github.com", "api.github.com", "www.google.com", "discord.com", "gateway.discord.gg", "outlook.office365.com",
				"login.microsoftonline.com", "onedrive.live.com", "www.youtube.com", "i.ytimg.com", "argocd.homelab.example", "rancher.homelab.example",
				"cdn.discordapp.com", "www.reddit.com", "objects.githubusercontent.com"},
			blocked: []string{"googleads.g.doubleclick.net", "v10.events.data.microsoft.com", "browser.events.data.microsoft.com", "www.google-analytics.com"}, blockShare: 0.12,
			special: func(r *rand.Rand) (string, string, string, bool) {
				switch r.Intn(60) {
				case 0:
					return fmt.Sprintf("relay-%x.net.anydesk.com", r.Intn(0xffff)), "FORWARDED", "IP", true
				case 1:
					return "use-application-dns.net", "SPECIAL_DOMAIN", "NXDOMAIN", true
				}
				return "", "", "", false
			}},
		{ip: "10.99.0.74", name: "living-room-tv.lan", mac: "f4:f5:d8:12:34:56", perHour: 620,
			allowed: []string{"clients3.google.com", "android.googleapis.com", "www.netflix.com", "occ-0-1-2.1.nflxso.net", "play.googleapis.com", "time.android.com"},
			blocked: []string{"googleads.g.doubleclick.net", "ade.googlesyndication.com", "app-measurement.com", "firebaselogging-pa.googleapis.com",
				"samsungads.com", "logs.netflix.com"}, blockShare: 0.58},
		{ip: "10.99.0.101", name: "iphone.lan", mac: "a6:4f:12:9e:00:31", perHour: 300,
			allowed: []string{"gateway.icloud.com", "mesu.apple.com", "api.apple-cloudkit.com", "graph.instagram.com", "scontent.cdninstagram.com",
				"i.instagram.com", "www.apple.com", "init.itunes.apple.com"},
			blocked: []string{"app-measurement.com", "graph.facebook.com", "iadsdk.apple.com"}, blockShare: 0.18},
		{ip: "10.99.0.5", name: "nas.lan", mac: "00:11:32:aa:bb:cc", perHour: 140,
			allowed: []string{"global.synologydownload.com", "checkip.synology.com", "account.synology.com", "pool.ntp.org"},
			special: func(r *rand.Rand) (string, string, string, bool) {
				if r.Intn(5) == 0 {
					d := []string{"pool.supportxmr.com", "xmr.2miners.com", "gulf.moneroocean.stream"}[r.Intn(3)]
					st := "FORWARDED"
					if r.Intn(2) == 0 {
						st = "GRAVITY"
					}
					return d, st, "IP", true
				}
				return "", "", "", false
			}},
		{ip: "10.99.0.88", name: "hue-bridge.lan", mac: "00:17:88:ab:cd:ef", perHour: 60,
			allowed: []string{"diag.meethue.com", "ws.meethue.com", "time.cloudflare.com"}},
		{ip: "10.99.0.70", name: "", mac: "24:0a:c4:9a:8b:7c", perHour: 40,
			allowed: []string{"a1x2y3abc-ats.iot.us-east-1.amazonaws.com", "pool.ntp.org"}},
		{ip: "10.99.0.117", name: "", mac: "6e:21:9a:44:1b:02", perHour: 90,
			allowed: []string{"connectivitycheck.gstatic.com", "www.google.com"},
			special: func(r *rand.Rand) (string, string, string, bool) {
				switch {
				case r.Intn(3) == 0:
					return randomName(r), "FORWARDED", "NXDOMAIN", true
				case r.Intn(12) == 0:
					return fmt.Sprintf("%x-%d-%d.ngrok-free.app", r.Intn(0xffffff), r.Intn(255), r.Intn(255)), "FORWARDED", "IP", true
				}
				return "", "", "", false
			}},
		{ip: "10.99.0.11", name: "cp1", mac: "52:54:00:00:00:11", perHour: 150, allowed: nodes},
		{ip: "10.99.0.12", name: "cp2", mac: "52:54:00:00:00:12", perHour: 140, allowed: nodes},
		{ip: "10.99.0.13", name: "cp3", mac: "52:54:00:00:00:13", perHour: 130, allowed: nodes},
		{ip: "10.99.0.21", name: "w1", mac: "52:54:00:00:00:21", perHour: 170, allowed: nodes},
		{ip: "10.99.0.8", name: "pve.lan", mac: "bc:24:11:00:00:08", perHour: 40,
			allowed: []string{"enterprise.proxmox.com", "download.proxmox.com", "deb.debian.org", "security.debian.org"}},
	}
}

func (cl phDemoClient) query(r *rand.Rand, id int64, at time.Time) phQuery {
	q := phQuery{ID: id, Time: float64(at.UnixNano()) / 1e9, Type: "A", Status: "FORWARDED", Upstream: "127.0.0.1#5335"}
	q.Client.IP, q.Client.Name = cl.ip, cl.name
	q.Reply.Type, q.Reply.Time = "IP", 4+r.Float64()*30
	if r.Intn(3) == 0 {
		q.Type = "AAAA"
	}
	if cl.special != nil {
		if d, st, rep, ok := cl.special(r); ok {
			q.Domain, q.Status, q.Reply.Type = d, st, rep
			return q
		}
	}
	if len(cl.blocked) > 0 && r.Float64() < cl.blockShare {
		q.Domain, q.Status, q.Upstream = cl.blocked[r.Intn(len(cl.blocked))], "GRAVITY", ""
		return q
	}
	q.Domain = cl.allowed[r.Intn(len(cl.allowed))]
	if r.Intn(5) < 2 {
		q.Status, q.Upstream = "CACHE", ""
	}
	return q
}

func (p *piholeClient) runDemo() {
	r := rand.New(rand.NewSource(7))
	clients := phDemoClients()
	now := time.Now()
	var id int64 = 4_200_000
	p.mu.Lock()
	for _, cl := range clients {
		for i := 0; i < cl.perHour; i++ {
			id++
			at := now.Add(-time.Duration(r.Int63n(int64(time.Hour))))
			p.window[id] = cl.query(r, id, at)
		}
		p.devs[cl.ip] = phDevice{MAC: cl.mac, Vendor: macVendor(cl.mac), Name: cl.name, NumQueries: cl.perHour * 24 * 30, LastQuery: now}
	}
	p.v = phView{Configured: true, OK: true, URL: "https://10.99.0.61", Version: "v6.1.2", Blocking: "enabled",
		Gravity: 1_284_312, GravityAt: now.Add(-3 * 24 * time.Hour), At: now,
		Upstreams: []phCount{{"127.0.0.1#5335 (unbound)", 61_244}, {"9.9.9.9", 312}},
		LocalRecords: []string{"10.99.0.200 argocd.homelab.example", "10.99.0.200 cloud.homelab.example", "203.0.113.47 jellyfin.homelab.example",
			"10.99.0.200 longhorn.homelab.example", "10.99.0.200 n8n.homelab.example", "10.99.0.200 rancher.homelab.example",
			"10.99.0.200 torrent.homelab.example", "10.99.0.200 vpn.homelab.example", "10.99.0.61 pihole.lan"},
		Messages: []string{now.Add(-25*time.Minute).Format("01-02 15:04") + " RATE_LIMIT: Rate-limiting 10.99.0.117 for at least 60 seconds"}}
	p.mu.Unlock()

	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		now := time.Now()
		p.mu.Lock()
		for i := 0; i < 3+r.Intn(5); i++ {
			cl := clients[r.Intn(len(clients))]
			id++
			p.window[id] = cl.query(r, id, now.Add(-time.Duration(r.Intn(2000))*time.Millisecond))
		}
		cut := float64(now.Add(-time.Hour).Unix())
		for k, q := range p.window {
			if q.Time < cut {
				delete(p.window, k)
			}
		}
		// 24-hour counts: the hour's, scaled (with a little history).
		type cnt = struct {
			IP, Name string
			Count    int
		}
		tot, blk := map[string]int{}, map[string]int{}
		dom, bdom := map[string]int{}, map[string]int{}
		for _, q := range p.window {
			tot[q.Client.IP]++
			if phBlocked(q.Status) {
				blk[q.Client.IP]++
				bdom[q.Domain]++
			} else {
				dom[q.Domain]++
			}
		}
		var top, topB []cnt
		total, blocked := 0, 0
		for _, cl := range clients {
			top = append(top, cnt{cl.ip, cl.name, tot[cl.ip] * 21})
			topB = append(topB, cnt{cl.ip, cl.name, blk[cl.ip] * 21})
			total += tot[cl.ip] * 21
			blocked += blk[cl.ip] * 21
		}
		v := &p.v
		v.At = now
		v.Total, v.Blocked = total, blocked
		v.Percent = float64(blocked) * 100 / float64(max(1, total))
		v.Cached, v.Forwarded = total*38/100, total-total*38/100-blocked
		v.Unique, v.Freq = 1834, float64(total)/86400
		v.ClientsActive, v.ClientsTotal = len(clients), len(clients)+3
		v.TopDomains, v.TopBlocked = nil, nil
		for _, x := range topCounts(dom, 15) {
			v.TopDomains = append(v.TopDomains, phCount{x.Name, x.Count * 21})
		}
		for _, x := range topCounts(bdom, 15) {
			v.TopBlocked = append(v.TopBlocked, phCount{x.Name, x.Count * 21})
		}
		p.analyze(top, topB, now)
		records := append([]string(nil), v.LocalRecords...)
		p.mu.Unlock()

		// The site check, answered from the made-up records.
		var hosts []phHost
		if p.sites != nil {
			seen := map[string]bool{}
			for _, ing := range p.sites() {
				if seen[ing.Host] || ing.Address == "" {
					continue
				}
				seen[ing.Host] = true
				h := phHost{Host: ing.Host, Want: ing.Address, Got: ing.Address, Record: phRecordFor(records, ing.Host)}
				if h.Record != "" {
					h.Got = strings.Fields(h.Record)[0]
				}
				hosts = append(hosts, h)
			}
		}
		p.mu.Lock()
		p.v.Hosts = hosts
		p.mu.Unlock()
		if p.redraw != nil {
			p.redraw()
		}
		select {
		case <-p.stop:
			return
		case <-p.kick:
		case <-tick.C:
		}
	}
}

// demoFixHosts: FixHosts on the made-up records.
func (p *piholeClient) demoFixHosts(fix []phHost) []string {
	var done []string
	p.mu.Lock()
	for _, h := range fix {
		var keep []string
		for _, rec := range p.v.LocalRecords {
			if rec == h.Record {
				done = append(done, "removed "+rec)
				continue
			}
			keep = append(keep, rec)
		}
		entry := h.Want + " " + h.Host
		p.v.LocalRecords = append(keep, entry)
		done = append(done, "added "+entry)
	}
	p.mu.Unlock()
	p.Kick()
	return done
}
