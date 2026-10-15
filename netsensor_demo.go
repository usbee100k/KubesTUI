package main

// The NET page in the demo: a made-up home network around the demo
// cluster (10.99.0.0/24), with a new device turning up and a risky one.

import (
	"math"
	"time"
)

func (s *netSensor) runDemo() {
	now := time.Now()
	dev := func(ip, mac, name, role string, ports []int, known bool, age time.Duration) *netDevice {
		return &netDevice{IP: ip, MAC: mac, Vendor: macVendor(mac), Name: name, Role: role, Ports: ports, Online: true,
			Known: known, First: now.Add(-age), Last: now, RTT: time.Duration(1+len(ip)%4) * time.Millisecond}
	}
	s.mu.Lock()
	s.v.HostIP, s.v.HostIface, s.v.HostMAC = "10.99.0.50", "Ethernet", "3c:97:0e:4a:10:22"
	s.v.Gateway, s.v.GatewayMAC = "10.99.0.1", "fc:ec:da:11:22:33"
	s.v.PublicIP, s.v.Loc, s.v.Colo, s.v.WANAt = "203.0.113.47", "US", "LAX", now
	s.v.DNS = []netDNS{{Server: "10.99.0.1", OK: true, Took: 14 * time.Millisecond}, {Server: "1.1.1.1", OK: true, Took: 9 * time.Millisecond}}
	s.v.Subnets = []string{"10.99.0.0/24"}
	for _, d := range []*netDevice{
		dev("10.99.0.1", "fc:ec:da:11:22:33", "unifi.lan", "GATEWAY", []int{22, 53, 80, 443}, true, 400*24*time.Hour),
		dev("10.99.0.5", "00:11:32:aa:bb:cc", "nas.lan", "", []int{22, 80, 139, 443, 445, 5000, 5001}, true, 300*24*time.Hour),
		dev("10.99.0.8", "bc:24:11:00:00:08", "pve.lan", "", []int{22, 8006}, true, 200*24*time.Hour),
		dev("10.99.0.11", "52:54:00:00:00:11", "cp1", "NODE cp1", []int{22, 6443, 10250}, true, 41*24*time.Hour),
		dev("10.99.0.12", "52:54:00:00:00:12", "cp2", "NODE cp2", []int{22, 6443, 10250}, true, 41*24*time.Hour),
		dev("10.99.0.13", "52:54:00:00:00:13", "cp3", "NODE cp3", []int{22, 6443, 10250}, true, 41*24*time.Hour),
		dev("10.99.0.21", "52:54:00:00:00:21", "w1", "NODE w1", []int{22, 10250}, true, 41*24*time.Hour),
		dev("10.99.0.22", "52:54:00:00:00:22", "w2", "NODE w2", nil, true, 41*24*time.Hour),
		dev("10.99.0.50", "3c:97:0e:4a:10:22", "desktop.lan", "THIS HOST", []int{135, 445, 3389}, true, 500*24*time.Hour),
		dev("10.99.0.61", "dc:a6:32:01:02:03", "pihole.lan", "", []int{22, 53, 80}, true, 120*24*time.Hour),
		dev("10.99.0.70", "24:0a:c4:9a:8b:7c", "", "", []int{23, 80}, true, 90*24*time.Hour),
		dev("10.99.0.74", "f4:f5:d8:12:34:56", "living-room-tv.lan", "", []int{8008, 8443}, true, 60*24*time.Hour),
		dev("10.99.0.88", "00:17:88:ab:cd:ef", "hue-bridge.lan", "", []int{80, 443}, true, 30*24*time.Hour),
		dev("10.99.0.101", "a6:4f:12:9e:00:31", "", "", []int{62078}, true, 10*24*time.Hour),
		dev("10.99.0.117", "6e:21:9a:44:1b:02", "", "", nil, false, 4*time.Minute),
	} {
		s.known[d.MAC] = d
	}
	s.known["52:54:00:00:00:22"].Online = false
	for _, p := range []netProbe{
		{Name: "gateway", Addr: "10.99.0.1", Kind: "gateway"}, {Name: "cloudflare", Addr: "1.1.1.1:443", Kind: "internet"},
		{Name: "google dns", Addr: "8.8.8.8:53", Kind: "internet"}, {Name: "API VIP", Addr: "10.99.0.10:6443", Kind: "vip"},
		{Name: "cp1", Addr: "10.99.0.11:10250", Kind: "node"}, {Name: "cp2", Addr: "10.99.0.12:10250", Kind: "node"},
		{Name: "cp3", Addr: "10.99.0.13:10250", Kind: "node"}, {Name: "w1", Addr: "10.99.0.21:10250", Kind: "node"},
		{Name: "w2", Addr: "10.99.0.22:10250", Kind: "node"},
	} {
		p := p
		s.v.Probes = append(s.v.Probes, &p)
	}
	s.v.Conns = []netConn{
		{Proto: "tcp", Local: "10.99.0.50:51022", Remote: "10.99.0.10:6443", State: "ESTABLISHED", Process: "kubestui"},
		{Proto: "tcp", Local: "10.99.0.50:51040", Remote: "10.99.0.11:22", State: "ESTABLISHED", Process: "kubestui"},
		{Proto: "tcp", Local: "10.99.0.50:52110", Remote: "140.82.112.3:443", State: "ESTABLISHED", Process: "git"},
		{Proto: "tcp", Local: "10.99.0.50:52200", Remote: "142.250.72.14:443", State: "ESTABLISHED", Process: "chrome"},
		{Proto: "tcp", Local: "10.99.0.50:52201", Remote: "142.250.72.14:443", State: "ESTABLISHED", Process: "chrome"},
		{Proto: "tcp", Local: "10.99.0.50:52230", Remote: "13.107.42.14:443", State: "ESTABLISHED", Process: "OneDrive"},
		{Proto: "tcp", Local: "10.99.0.50:52300", Remote: "10.99.0.5:445", State: "ESTABLISHED", Process: "System"},
		{Proto: "tcp", Local: "10.99.0.50:52410", Remote: "162.159.135.234:443", State: "ESTABLISHED", Process: "Discord"},
	}
	s.v.Listening = []netConn{
		{Proto: "tcp", Local: "0.0.0.0:135", State: "LISTENING", Process: "svchost"},
		{Proto: "tcp", Local: "0.0.0.0:445", State: "LISTENING", Process: "System"},
		{Proto: "tcp", Local: "0.0.0.0:3389", State: "LISTENING", Process: "svchost"},
		{Proto: "tcp", Local: "127.0.0.1:5939", State: "LISTENING", Process: "TeamViewer"},
	}
	var svcs []netService
	for _, h := range []string{"argocd", "cloud", "jellyfin", "longhorn", "n8n", "rancher", "vpn"} {
		svcs = append(svcs, netService{Host: h + ".homelab.example", Want: "10.99.0.200", Got: "10.99.0.200", DNSOK: true,
			Status: 200, TLSDays: 61, TLSIssuer: "R11", TLSTrusted: true, Took: time.Duration(40+len(h)*9) * time.Millisecond, At: now})
	}
	svcs[0].Status = 307
	svcs = append(svcs, netService{Host: "torrent.homelab.example", Want: "10.99.0.200", Got: "10.99.0.200", DNSOK: true, Status: 503,
		Took: 22 * time.Millisecond, At: now})
	s.v.Services = svcs
	s.v.SweepAt, s.v.NextSweep = now.Add(-70*time.Second), now.Add(230*time.Second)
	s.mu.Unlock()

	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for i := 0; ; i++ {
		t := time.Since(s.v.Started).Seconds()
		s.mu.Lock()
		for j, p := range s.v.Probes {
			base := map[string]float64{"gateway": 0.8, "internet": 11, "vip": 0.6, "node": 0.5}[p.Kind] + float64(j)*0.3
			v := base * (1 + 0.4*math.Sin(t/3+float64(j)))
			ok := !(p.Name == "w2")
			if p.Name == "google dns" && i%9 == 4 {
				ok = false // a dropped probe now and then
			}
			p.OK, p.Last = ok, time.Duration(v*float64(time.Millisecond))
			if ok {
				p.RTT.push(v)
			} else {
				p.RTT.push(-1)
			}
			p.window = append(p.window, ok)
			if len(p.window) > 20 {
				p.window = p.window[1:]
			}
			p.Fails = 0
			for _, w := range p.window {
				if !w {
					p.Fails++
				}
			}
		}
		s.v.RxRate = 2.4e6 * (1 + 0.6*math.Sin(t/5))
		s.v.TxRate = 3.1e5 * (1 + 0.5*math.Sin(t/4+1))
		s.v.Rx.push(s.v.RxRate)
		s.v.Tx.push(s.v.TxRate)
		s.mu.Unlock()
		if s.redraw != nil {
			s.redraw()
		}
		select {
		case <-s.stop:
			return
		case <-s.rescan:
			s.mu.Lock()
			s.v.SweepAt, s.v.NextSweep = time.Now(), time.Now().Add(5*time.Minute)
			s.mu.Unlock()
		case <-tick.C:
		}
	}
}
