package main

// Network sensor for the SOC console's NET page: watches the network from
// the computer KubesTUI runs on (the workstation, or a node in node mode).
// It only uses what an ordinary user can do: TCP connects (no raw packets,
// no admin rights), the system's ARP/route/connection tables, DNS lookups.
//
//   - WAN: internet reachability, public IP (Cloudflare's trace page),
//     gateway and DNS servers with latency.
//   - LAN: the node subnets (and this computer's) swept for devices: ARP,
//     a few TCP ports, then a port scan of each device found. Devices are
//     remembered (~/.kubestui/network/devices.json) so new ones, and an IP
//     whose MAC changes (ARP spoofing), become detections.
//   - Latency history to the gateway, internet, the API VIP and each node.
//   - Every ingress site: DNS, TLS certificate, HTTP status, time.
//   - This computer: connections (and their processes on Windows),
//     listening ports, traffic.
//
// It runs only while the SOC console has been opened, and stops with the
// Command Center.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// netTargets: what the cluster says is on the network (from snapshots).
type netTargets struct {
	Nodes     map[string]string // IP -> node name
	VIP       string            // API address (host)
	LBs       map[string]string // MetalLB IP -> ns/service
	LBPorts   map[string][]int  // MetalLB IP -> TCP ports
	Ingresses []ccIngress
}

type netProbe struct {
	Name, Addr string // label, host:port
	Kind       string // gateway, internet, dns, vip, node
	RTT        ccRing // ms; -1 = failed
	OK         bool
	Last       time.Duration
	Fails      int // of the last 20
	window     []bool
}

type netDevice struct {
	IP, MAC, Vendor, Name string
	Ports                 []int
	Online                bool
	First, Last           time.Time
	Known                 bool   // in the baseline or marked known (K)
	Role                  string // GATEWAY, NODE x, LB x, THIS HOST, VIP
	OldMAC                string // the MAC this IP had before, if it changed
	RTT                   time.Duration
}

type netService struct {
	Host, Want, Got string // ingress host, its address, what DNS says
	DNSOK           bool
	Status          int
	TLSDays         int // days until the certificate expires
	TLSIssuer       string
	TLSTrusted      bool
	Err             string
	Took            time.Duration
	At              time.Time
}

type netConn struct {
	Proto, Local, Remote, State, Process string
	PID                                  int
}

type netDNS struct {
	Server string
	OK     bool
	Took   time.Duration
	Err    string
}

// netView is a copy of the sensor's state for drawing.
type netView struct {
	Started               time.Time
	OS                    string
	HostIP, HostIface     string
	HostMAC               string
	Gateway, GatewayMAC   string
	PublicIP, Loc, Colo   string
	WANAt                 time.Time
	WANErr                string
	DNS                   []netDNS
	Probes                []*netProbe
	Subnets               []string
	Devices               []*netDevice
	SweepAt, NextSweep    time.Time
	Sweeping              bool
	SweepDone, SweepTotal int
	Services              []netService
	Conns                 []netConn
	Listening             []netConn
	RxRate, TxRate        float64
	Rx, Tx                ccRing
	Spoof                 []string // detections from the ARP table
	Baseline              bool     // the first sweep becomes the known baseline
	Err                   string
}

type netSensor struct {
	mu      sync.Mutex
	v       netView
	targets netTargets
	stop    chan struct{}
	rescan  chan struct{}
	known   map[string]*netDevice // by MAC (persisted)
	path    string
	demo    bool
	redraw  func()
	ph      *piholeClient // the DNS page (pihole.go)
	lastCnt struct {
		rx, tx float64
		at     time.Time
	}
}

// Ports checked on every device (name; risky ones become findings).
var netPorts = []int{21, 22, 23, 25, 53, 80, 111, 139, 143, 443, 445, 554, 631, 1883, 2375, 2376, 3000, 3306, 3389,
	5000, 5001, 5432, 5900, 6379, 6443, 8006, 8080, 8123, 8443, 8883, 9000, 9090, 9100, 9200, 10250, 27017, 32400, 51821, 62078}

var netPortNames = map[int]string{21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 111: "rpcbind", 139: "netbios",
	143: "imap", 443: "https", 445: "smb", 554: "rtsp", 631: "ipp", 1883: "mqtt", 2375: "docker", 2376: "docker-tls", 3000: "web",
	3306: "mysql", 3389: "rdp", 5000: "web/upnp", 5001: "synology", 5432: "postgres", 5900: "vnc", 6379: "redis", 6443: "k8s-api",
	8006: "proxmox", 8080: "http-alt", 8123: "home-asst", 8443: "https-alt", 8883: "mqtts", 9000: "web", 9090: "web", 9100: "jetdirect/node-exp",
	9200: "elastic", 10250: "kubelet", 27017: "mongodb", 32400: "plex", 51821: "wg-easy", 62078: "iphone-sync"}

// A few MAC prefixes (OUI) of common homelab devices; a guess only.
var netOUI = map[string]string{
	"B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi", "2C:CF:67": "Raspberry Pi", "D8:3A:DD": "Raspberry Pi",
	"00:50:56": "VMware", "00:0C:29": "VMware", "00:05:69": "VMware", "52:54:00": "QEMU/KVM", "BC:24:11": "Proxmox",
	"00:15:5D": "Hyper-V", "08:00:27": "VirtualBox", "02:42:AC": "Docker",
	"00:11:32": "Synology", "90:09:D0": "Synology", "24:5E:BE": "QNAP",
	"FC:EC:DA": "Ubiquiti", "78:8A:20": "Ubiquiti", "24:5A:4C": "Ubiquiti", "74:83:C2": "Ubiquiti", "E0:63:DA": "Ubiquiti", "68:D7:9A": "Ubiquiti",
	"50:C7:BF": "TP-Link", "98:DA:C4": "TP-Link", "60:A4:B7": "TP-Link", "14:EB:B6": "TP-Link", "3C:52:A1": "TP-Link",
	"04:D9:F5": "ASUS", "2C:FD:A1": "ASUS", "F0:2F:74": "ASUS", "A0:36:BC": "ASUS", "08:BF:B8": "ASUS",
	"A0:40:A0": "Netgear", "9C:3D:CF": "Netgear", "C4:04:15": "Netgear",
	"24:0A:C4": "Espressif (IoT)", "30:AE:A4": "Espressif (IoT)", "84:F3:EB": "Espressif (IoT)", "EC:FA:BC": "Espressif (IoT)", "A4:CF:12": "Espressif (IoT)",
	"F4:F5:D8": "Google", "54:60:09": "Google", "1C:F2:9A": "Google", "44:07:0B": "Google",
	"FC:65:DE": "Amazon", "74:C2:46": "Amazon", "68:54:FD": "Amazon",
	"B0:BE:76": "TP-Link Kasa", "00:17:88": "Philips Hue", "EC:B5:FA": "Philips Hue", "5C:AA:FD": "Sonos", "48:A6:B8": "Sonos",
	"3C:22:FB": "Apple", "F0:18:98": "Apple", "A4:83:E7": "Apple", "AC:BC:32": "Apple", "BC:D0:74": "Apple",
	"00:1B:21": "Intel", "3C:97:0E": "Intel", "A4:BB:6D": "Intel", "8C:16:45": "Intel", "48:21:0B": "Intel",
	"00:E0:4C": "Realtek", "4C:ED:FB": "ASUS", "70:85:C2": "ASRock", "D8:BB:C1": "Micro-Star (MSI)", "18:C0:4D": "Gigabyte",
	"28:6F:B9": "Nokia", "C8:3A:35": "Tenda", "00:1A:11": "Google", "BC:83:85": "Microsoft", "C0:33:5E": "Microsoft",
	"44:65:0D": "Amazon", "00:04:4B": "NVIDIA", "48:B0:2D": "NVIDIA", "00:0D:B9": "PC Engines", "00:08:A2": "ADI Engineering",
	"2C:F0:5D": "Micro-Star (MSI)", "E8:9C:25": "ASUS", "74:56:3C": "Giga-Byte", "B4:2E:99": "Giga-Byte",
}

func macVendor(mac string) string {
	m := strings.ToUpper(strings.ReplaceAll(mac, "-", ":"))
	if len(m) < 8 {
		return ""
	}
	if v, ok := netOUI[m[:8]]; ok {
		return v
	}
	// Second bit of the first byte: a locally administered (random) MAC,
	// what phones and laptops use per Wi-Fi network.
	if b, err := strconv.ParseUint(m[:2], 16, 8); err == nil && b&2 != 0 {
		return "random MAC (phone/laptop privacy)"
	}
	return ""
}

func newNetSensor(demo bool, redraw func()) *netSensor {
	s := &netSensor{stop: make(chan struct{}), rescan: make(chan struct{}, 1), known: map[string]*netDevice{},
		demo: demo, redraw: redraw}
	s.v.Started = time.Now()
	s.v.OS = runtime.GOOS
	if !demo {
		s.path = filepath.Join(kubestuiDir(), "network", "devices.json")
		s.load()
	}
	s.ph = newPiholeClient(demo, redraw)
	s.ph.dnsIPs = dnsServers
	s.ph.sites = func() []ccIngress {
		s.mu.Lock()
		defer s.mu.Unlock()
		return append([]ccIngress(nil), s.targets.Ingresses...)
	}
	s.ph.lan = func() []string {
		s.mu.Lock()
		defer s.mu.Unlock()
		var ips []string
		for _, d := range s.known {
			if d.Online && d.Role != "THIS HOST" {
				ips = append(ips, d.IP)
			}
		}
		return ips
	}
	return s
}

func (s *netSensor) load() {
	data, err := os.ReadFile(s.path)
	if err != nil {
		s.v.Baseline = true // first run: what's there now is the baseline
		return
	}
	var list []*netDevice
	if json.Unmarshal(data, &list) == nil {
		for _, d := range list {
			d.Online = false
			s.known[d.MAC] = d
		}
	}
}

func (s *netSensor) save() {
	if s.path == "" {
		return
	}
	var list []*netDevice
	for _, d := range s.known {
		list = append(list, d)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].MAC < list[j].MAC })
	data, _ := json.MarshalIndent(list, "", "  ")
	_ = os.MkdirAll(filepath.Dir(s.path), 0o700)
	_ = os.WriteFile(s.path, data, 0o600)
}

// setTargets passes what the cluster knows (called on each snapshot).
func (s *netSensor) setTargets(snap *ccSnapshot) {
	t := netTargets{Nodes: map[string]string{}, LBs: map[string]string{}, LBPorts: map[string][]int{}}
	for _, n := range snap.Nodes {
		if n.IP != "" {
			t.Nodes[n.IP] = n.Name
		}
	}
	if h, ok := strings.CutPrefix(snap.Source, "API "); ok {
		if host, _, err := net.SplitHostPort(h); err == nil {
			t.VIP = host
		}
	}
	for _, svc := range snap.Services {
		if svc.Type == "LoadBalancer" && svc.ExternalIP != "" {
			t.LBs[svc.ExternalIP] = svc.NS + "/" + svc.Name
			for _, p := range svc.Ports {
				if n, err := strconv.Atoi(p); err == nil {
					t.LBPorts[svc.ExternalIP] = append(t.LBPorts[svc.ExternalIP], n)
				}
			}
		}
	}
	t.Ingresses = append([]ccIngress(nil), snap.Ingresses...)
	s.mu.Lock()
	s.targets = t
	s.mu.Unlock()
}

// view copies the state for drawing.
func (s *netSensor) view() netView {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.v
	v.Probes = nil
	for _, p := range s.v.Probes {
		cp := *p
		cp.RTT = ccRing{v: append([]float64(nil), p.RTT.v...)}
		v.Probes = append(v.Probes, &cp)
	}
	v.Devices = nil
	for _, d := range s.known {
		cp := *d
		v.Devices = append(v.Devices, &cp)
	}
	sort.Slice(v.Devices, func(i, j int) bool { return ipLess(v.Devices[i].IP, v.Devices[j].IP) })
	v.Services = append([]netService(nil), s.v.Services...)
	v.Conns = append([]netConn(nil), s.v.Conns...)
	v.Listening = append([]netConn(nil), s.v.Listening...)
	v.Rx = ccRing{v: append([]float64(nil), s.v.Rx.v...)}
	v.Tx = ccRing{v: append([]float64(nil), s.v.Tx.v...)}
	return v
}

func ipLess(a, b string) bool {
	pa, pb := net.ParseIP(a).To4(), net.ParseIP(b).To4()
	if pa == nil || pb == nil {
		return a < b
	}
	for i := range pa {
		if pa[i] != pb[i] {
			return pa[i] < pb[i]
		}
	}
	return false
}

// markKnown accepts a device (K): no more "new device" detection.
func (s *netSensor) markKnown(mac string) {
	s.mu.Lock()
	if d := s.known[mac]; d != nil {
		d.Known, d.OldMAC = true, ""
	}
	s.mu.Unlock()
	s.save()
}

func (s *netSensor) Rescan() {
	select {
	case s.rescan <- struct{}{}:
	default:
	}
}

func (s *netSensor) Stop() {
	select {
	case <-s.stop:
	default:
		close(s.stop)
		s.ph.Stop()
	}
}

func (s *netSensor) Start() {
	s.ph.Start()
	if s.demo {
		go s.runDemo()
		return
	}
	go s.loop()
}

func (s *netSensor) loop() {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	n := 0
	s.host()
	s.sweepSoon(3 * time.Second)
	for {
		s.latency()
		s.counters()
		if n%3 == 0 {
			s.host()
			s.connections()
			s.arpCheck()
		}
		if n%6 == 0 {
			s.dnsCheck()
		}
		if n%12 == 0 {
			go s.services()
		}
		if n%60 == 0 {
			go s.wan()
		}
		s.mu.Lock()
		due := !s.v.Sweeping && !s.v.NextSweep.IsZero() && time.Now().After(s.v.NextSweep)
		s.mu.Unlock()
		if due {
			go s.sweep()
		}
		if s.redraw != nil {
			s.redraw()
		}
		n++
		select {
		case <-s.stop:
			return
		case <-s.rescan:
			s.sweepSoon(0)
		case <-tick.C:
		}
	}
}

func (s *netSensor) sweepSoon(d time.Duration) {
	s.mu.Lock()
	s.v.NextSweep = time.Now().Add(d)
	s.mu.Unlock()
}

// ---------------------------------------------------------------------------
// Host: address, gateway, DNS servers
// ---------------------------------------------------------------------------

func runCmd(timeout time.Duration, name string, args ...string) string {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...) // stdin/stderr: the null device, not the TUI
	out, _ := cmd.Output()
	return string(out)
}

func (s *netSensor) host() {
	gw, hostIP, iface := defaultRoute()
	dns := dnsServers()
	mac := ""
	if ifs, err := net.Interfaces(); err == nil {
		for _, i := range ifs {
			addrs, _ := i.Addrs()
			for _, a := range addrs {
				if ipn, ok := a.(*net.IPNet); ok && ipn.IP.String() == hostIP {
					mac, iface = i.HardwareAddr.String(), orDefault(iface, i.Name)
					if iface == "" || runtime.GOOS == "windows" {
						iface = i.Name
					}
				}
			}
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.v.Gateway, s.v.HostIP, s.v.HostIface, s.v.HostMAC = gw, hostIP, iface, mac
	have := map[string]bool{}
	for _, d := range s.v.DNS {
		have[d.Server] = true
	}
	for _, d := range dns {
		if !have[d] {
			s.v.DNS = append(s.v.DNS, netDNS{Server: d})
		}
	}
	// The probe list: gateway, internet, DNS, the API VIP, the nodes.
	want := []netProbe{}
	if gw != "" {
		want = append(want, netProbe{Name: "gateway", Addr: gw, Kind: "gateway"})
	}
	want = append(want, netProbe{Name: "cloudflare", Addr: "1.1.1.1:443", Kind: "internet"},
		netProbe{Name: "google dns", Addr: "8.8.8.8:53", Kind: "internet"})
	if s.targets.VIP != "" {
		want = append(want, netProbe{Name: "API VIP", Addr: net.JoinHostPort(s.targets.VIP, "6443"), Kind: "vip"})
	}
	var nodes []string
	for ip := range s.targets.Nodes {
		nodes = append(nodes, ip)
	}
	sort.Slice(nodes, func(i, j int) bool { return s.targets.Nodes[nodes[i]] < s.targets.Nodes[nodes[j]] })
	for _, ip := range nodes {
		want = append(want, netProbe{Name: s.targets.Nodes[ip], Addr: net.JoinHostPort(ip, "10250"), Kind: "node"})
	}
	old := map[string]*netProbe{}
	for _, p := range s.v.Probes {
		old[p.Kind+p.Addr] = p
	}
	var probes []*netProbe
	for _, w := range want {
		if p := old[w.Kind+w.Addr]; p != nil {
			p.Name = w.Name
			probes = append(probes, p)
		} else {
			w := w
			probes = append(probes, &w)
		}
	}
	s.v.Probes = probes
}

// defaultRoute: gateway, this computer's address on that route, interface.
func defaultRoute() (gw, ip, iface string) {
	switch runtime.GOOS {
	case "windows":
		// "  0.0.0.0  0.0.0.0  192.168.50.1  192.168.50.10  25"
		best := 1 << 30
		for _, l := range strings.Split(runCmd(5*time.Second, "route", "print", "-4", "0.0.0.0"), "\n") {
			f := strings.Fields(l)
			if len(f) == 5 && f[0] == "0.0.0.0" && f[1] == "0.0.0.0" {
				if m, err := strconv.Atoi(f[4]); err == nil && m < best && net.ParseIP(f[2]) != nil {
					best, gw, ip = m, f[2], f[3]
				}
			}
		}
	default:
		data, _ := os.ReadFile("/proc/net/route")
		for _, l := range strings.Split(string(data), "\n")[1:] {
			f := strings.Fields(l)
			if len(f) > 2 && f[1] == "00000000" {
				if v, err := strconv.ParseUint(f[2], 16, 32); err == nil {
					gw = fmt.Sprintf("%d.%d.%d.%d", v&0xff, v>>8&0xff, v>>16&0xff, v>>24)
					iface = f[0]
					break
				}
			}
		}
		if i, err := net.InterfaceByName(iface); err == nil {
			addrs, _ := i.Addrs()
			for _, a := range addrs {
				if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
					ip = ipn.IP.String()
				}
			}
		}
	}
	return gw, ip, iface
}

func dnsServers() []string {
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		s = strings.TrimSpace(strings.Split(s, "%")[0])
		if ip := net.ParseIP(s); ip != nil && ip.To4() != nil && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	switch runtime.GOOS {
	case "windows":
		// ipconfig /all: "DNS Servers . . . : 1.1.1.1" then indented extras.
		in := false
		for _, l := range strings.Split(runCmd(8*time.Second, "ipconfig", "/all"), "\n") {
			l = strings.TrimRight(l, "\r")
			switch {
			case strings.Contains(l, "DNS Servers"):
				in = true
				if _, v, ok := strings.Cut(l, ":"); ok {
					add(v)
				}
			case in && strings.HasPrefix(l, "      ") && !strings.Contains(l, ":"):
				add(l)
			default:
				in = false
			}
		}
	default:
		data, _ := os.ReadFile("/etc/resolv.conf")
		for _, l := range strings.Split(string(data), "\n") {
			if f := strings.Fields(l); len(f) == 2 && f[0] == "nameserver" {
				if f[1] == "127.0.0.53" { // systemd-resolved: ask it for the real ones
					for _, w := range strings.Fields(runCmd(3*time.Second, "resolvectl", "dns")) {
						add(w)
					}
				}
				add(f[1])
			}
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Latency (TCP connect time: no ICMP or admin rights needed)
// ---------------------------------------------------------------------------

// tcpRTT: how long a TCP connect takes. A refused connection still means
// the host answered.
func tcpRTT(addr string, timeout time.Duration) (time.Duration, bool) {
	start := time.Now()
	c, err := net.DialTimeout("tcp", addr, timeout)
	took := time.Since(start)
	if err == nil {
		c.Close()
		return took, true
	}
	if isRefused(err) {
		return took, true
	}
	return took, false
}

func isRefused(err error) bool {
	s := err.Error()
	return strings.Contains(s, "refused") || strings.Contains(s, "actively refused")
}

func (s *netSensor) latency() {
	s.mu.Lock()
	probes := append([]*netProbe(nil), s.v.Probes...)
	s.mu.Unlock()
	type res struct {
		p   *netProbe
		rtt time.Duration
		ok  bool
	}
	ch := make(chan res, len(probes))
	for _, p := range probes {
		go func(p *netProbe) {
			addr := p.Addr
			if p.Kind == "gateway" { // a router answers on one of these
				for _, port := range []string{"53", "80", "443"} {
					if rtt, ok := tcpRTT(net.JoinHostPort(p.Addr, port), 1500*time.Millisecond); ok {
						ch <- res{p, rtt, true}
						return
					}
				}
				ch <- res{p, 0, false}
				return
			}
			rtt, ok := tcpRTT(addr, 1500*time.Millisecond)
			ch <- res{p, rtt, ok}
		}(p)
	}
	results := make([]res, 0, len(probes))
	for range probes {
		results = append(results, <-ch)
	}
	s.mu.Lock()
	for _, r := range results {
		p := r.p
		p.OK, p.Last = r.ok, r.rtt
		if r.ok {
			p.RTT.push(float64(r.rtt.Microseconds()) / 1000)
		} else {
			p.RTT.push(-1)
		}
		p.window = append(p.window, r.ok)
		if len(p.window) > 20 {
			p.window = p.window[1:]
		}
		p.Fails = 0
		for _, ok := range p.window {
			if !ok {
				p.Fails++
			}
		}
	}
	s.mu.Unlock()
}

// ---------------------------------------------------------------------------
// DNS, WAN
// ---------------------------------------------------------------------------

func (s *netSensor) dnsCheck() {
	s.mu.Lock()
	servers := append([]netDNS(nil), s.v.DNS...)
	s.mu.Unlock()
	for i := range servers {
		srv := servers[i].Server
		r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 2 * time.Second}
			return d.DialContext(ctx, "udp", net.JoinHostPort(srv, "53"))
		}}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		start := time.Now()
		_, err := r.LookupHost(ctx, "cloudflare.com")
		cancel()
		servers[i].Took = time.Since(start)
		servers[i].OK = err == nil
		servers[i].Err = ""
		if err != nil {
			servers[i].Err = shortErr(err)
		}
	}
	s.mu.Lock()
	s.v.DNS = servers
	s.mu.Unlock()
}

func shortErr(err error) string {
	var de *net.DNSError
	if errors.As(err, &de) {
		if de.IsTimeout {
			return "timeout"
		}
		if de.IsNotFound {
			return "not found"
		}
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "timeout"), strings.Contains(msg, "deadline"):
		return "timeout"
	case strings.Contains(msg, "refused"):
		return "refused"
	case strings.Contains(msg, "no such host"):
		return "no such host"
	case strings.Contains(msg, "certificate"):
		return "certificate error"
	}
	if len(msg) > 60 {
		msg = msg[len(msg)-60:]
	}
	return msg
}

func (s *netSensor) wan() {
	c := &http.Client{Timeout: 5 * time.Second}
	resp, err := c.Get("https://1.1.1.1/cdn-cgi/trace")
	ip, loc, colo := "", "", ""
	if err == nil {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		for _, l := range strings.Split(string(body), "\n") {
			k, v, _ := strings.Cut(l, "=")
			switch k {
			case "ip":
				ip = v
			case "loc":
				loc = v
			case "colo":
				colo = v
			}
		}
	}
	s.mu.Lock()
	s.v.WANAt = time.Now()
	s.v.WANErr = ""
	if err != nil {
		s.v.WANErr = shortErr(err)
	} else {
		s.v.PublicIP, s.v.Loc, s.v.Colo = ip, loc, colo
	}
	s.mu.Unlock()
}

// ---------------------------------------------------------------------------
// Ingress sites: DNS, TLS, HTTP
// ---------------------------------------------------------------------------

func (s *netSensor) services() {
	s.mu.Lock()
	ings := append([]ccIngress(nil), s.targets.Ingresses...)
	s.mu.Unlock()
	out := make([]netService, len(ings))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 6)
	for i, ing := range ings {
		wg.Add(1)
		go func(i int, ing ccIngress) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			out[i] = checkSite(ing)
		}(i, ing)
	}
	wg.Wait()
	s.mu.Lock()
	s.v.Services = out
	s.mu.Unlock()
}

func checkSite(ing ccIngress) netService {
	r := netService{Host: ing.Host, Want: ing.Address, At: time.Now()}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	addrs, err := net.DefaultResolver.LookupHost(ctx, ing.Host)
	cancel()
	if err == nil && len(addrs) > 0 {
		r.Got = addrs[0]
		r.DNSOK = r.Want == "" || contains(addrs, r.Want)
	}
	target := r.Want
	if target == "" {
		target = r.Got
	}
	if target == "" {
		r.Err = "no DNS name and no ingress address"
		return r
	}
	scheme, port := "https", "443"
	if !ing.TLS {
		scheme, port = "http", "80"
	}
	var state *tls.ConnectionState
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, network, net.JoinHostPort(target, port))
		},
		TLSClientConfig:   &tls.Config{ServerName: ing.Host, InsecureSkipVerify: true}, // checked below
		DisableKeepAlives: true,
	}
	defer tr.CloseIdleConnections()
	c := &http.Client{Transport: tr, Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	start := time.Now()
	resp, err := c.Get(scheme + "://" + ing.Host + "/")
	r.Took = time.Since(start)
	if err != nil {
		r.Err = shortErr(err)
		return r
	}
	resp.Body.Close()
	r.Status = resp.StatusCode
	state = resp.TLS
	if state != nil && len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		r.TLSDays = int(time.Until(cert.NotAfter).Hours() / 24)
		r.TLSIssuer = orDefault(cert.Issuer.CommonName, strings.Join(cert.Issuer.Organization, " "))
		pool := x509.NewCertPool()
		for _, ic := range state.PeerCertificates[1:] {
			pool.AddCert(ic)
		}
		_, verr := cert.Verify(x509.VerifyOptions{DNSName: ing.Host, Intermediates: pool})
		r.TLSTrusted = verr == nil
	}
	return r
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Connections and traffic of this computer
// ---------------------------------------------------------------------------

func (s *netSensor) connections() {
	var conns []netConn
	switch runtime.GOOS {
	case "windows":
		names := map[int]string{}
		for _, l := range strings.Split(runCmd(8*time.Second, "tasklist", "/fo", "csv", "/nh"), "\n") {
			f := strings.Split(strings.TrimSpace(l), "\",\"")
			if len(f) > 2 {
				if pid, err := strconv.Atoi(strings.Trim(f[1], "\"")); err == nil {
					names[pid] = strings.TrimSuffix(strings.Trim(f[0], "\""), ".exe")
				}
			}
		}
		for _, l := range strings.Split(runCmd(8*time.Second, "netstat", "-ano"), "\n") {
			f := strings.Fields(l)
			if len(f) == 5 && f[0] == "TCP" {
				pid, _ := strconv.Atoi(f[4])
				conns = append(conns, netConn{Proto: "tcp", Local: f[1], Remote: f[2], State: f[3], PID: pid, Process: names[pid]})
			} else if len(f) == 4 && f[0] == "UDP" {
				pid, _ := strconv.Atoi(f[3])
				conns = append(conns, netConn{Proto: "udp", Local: f[1], Remote: f[2], State: "LISTENING", PID: pid, Process: names[pid]})
			}
		}
	default:
		states := map[string]string{"01": "ESTABLISHED", "0A": "LISTENING", "06": "TIME_WAIT", "08": "CLOSE_WAIT", "02": "SYN_SENT"}
		for _, file := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
			data, _ := os.ReadFile(file)
			for _, l := range strings.Split(string(data), "\n")[1:] {
				f := strings.Fields(l)
				if len(f) < 4 {
					continue
				}
				st := states[f[3]]
				if st == "" {
					continue
				}
				conns = append(conns, netConn{Proto: "tcp", Local: procAddr(f[1]), Remote: procAddr(f[2]), State: st})
			}
		}
	}
	var est, listen []netConn
	for _, c := range conns {
		switch c.State {
		case "ESTABLISHED":
			est = append(est, c)
		case "LISTENING":
			if c.Proto == "tcp" || strings.HasPrefix(c.Local, "0.0.0.0:") || strings.HasPrefix(c.Local, "[::]:") {
				listen = append(listen, c)
			}
		}
	}
	s.mu.Lock()
	s.v.Conns, s.v.Listening = est, listen
	s.mu.Unlock()
}

// procAddr turns /proc/net/tcp's "0100007F:1F90" into "127.0.0.1:8080".
func procAddr(h string) string {
	ipHex, portHex, ok := strings.Cut(h, ":")
	if !ok {
		return h
	}
	port, _ := strconv.ParseUint(portHex, 16, 16)
	b := make([]byte, len(ipHex)/2)
	for i := range b {
		v, _ := strconv.ParseUint(ipHex[2*i:2*i+2], 16, 8)
		b[i] = byte(v)
	}
	// Stored as 32-bit little-endian words.
	for i := 0; i+4 <= len(b); i += 4 {
		b[i], b[i+1], b[i+2], b[i+3] = b[i+3], b[i+2], b[i+1], b[i]
	}
	ip := net.IP(b)
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(int(port)))
}

func (s *netSensor) counters() {
	var rx, tx float64
	ok := false
	switch runtime.GOOS {
	case "windows":
		// netstat -e: "Bytes    123456    654321"
		for _, l := range strings.Split(runCmd(5*time.Second, "netstat", "-e"), "\n") {
			f := strings.Fields(l)
			if len(f) == 3 && f[0] == "Bytes" {
				rx, _ = strconv.ParseFloat(f[1], 64)
				tx, _ = strconv.ParseFloat(f[2], 64)
				ok = true
			}
		}
	default:
		data, _ := os.ReadFile("/proc/net/dev")
		for _, l := range strings.Split(string(data), "\n")[2:] {
			name, rest, found := strings.Cut(l, ":")
			name = strings.TrimSpace(name)
			if !found || name == "lo" || strings.HasPrefix(name, "lxc") || strings.HasPrefix(name, "cilium") ||
				strings.HasPrefix(name, "veth") || strings.HasPrefix(name, "docker") || strings.HasPrefix(name, "cni") {
				continue
			}
			f := strings.Fields(rest)
			if len(f) >= 9 {
				r, _ := strconv.ParseFloat(f[0], 64)
				t, _ := strconv.ParseFloat(f[8], 64)
				rx, tx, ok = rx+r, tx+t, true
			}
		}
	}
	if !ok {
		return
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if p := s.lastCnt; !p.at.IsZero() {
		if dt := now.Sub(p.at).Seconds(); dt > 0 && rx >= p.rx && tx >= p.tx {
			s.v.RxRate, s.v.TxRate = (rx-p.rx)/dt, (tx-p.tx)/dt
			s.v.Rx.push(s.v.RxRate)
			s.v.Tx.push(s.v.TxRate)
		}
	}
	s.lastCnt.rx, s.lastCnt.tx, s.lastCnt.at = rx, tx, now
}

// ---------------------------------------------------------------------------
// LAN: ARP table, sweep, port scan
// ---------------------------------------------------------------------------

// arpTable: IP -> MAC (aa:bb:cc:dd:ee:ff) of the neighbours this computer
// knows, without broadcast and multicast entries.
func arpTable() map[string]string {
	out := map[string]string{}
	add := func(ip, mac string) {
		mac = strings.ToLower(strings.ReplaceAll(mac, "-", ":"))
		p := net.ParseIP(ip).To4()
		if p == nil || p[0] >= 224 || p[3] == 255 || mac == "ff:ff:ff:ff:ff:ff" || mac == "00:00:00:00:00:00" ||
			strings.HasPrefix(mac, "01:00:5e") || len(mac) != 17 {
			return
		}
		out[ip] = mac
	}
	switch runtime.GOOS {
	case "windows":
		for _, l := range strings.Split(runCmd(5*time.Second, "arp", "-a"), "\n") {
			if f := strings.Fields(l); len(f) == 3 && f[2] == "dynamic" {
				add(f[0], f[1])
			}
		}
	default:
		data, _ := os.ReadFile("/proc/net/arp")
		for _, l := range strings.Split(string(data), "\n")[1:] {
			if f := strings.Fields(l); len(f) >= 4 && f[2] != "0x0" {
				add(f[0], f[3])
			}
		}
	}
	return out
}

// lanSubnets: the /24 of every node and of this computer (private only).
func (s *netSensor) lanSubnets() []string {
	seen := map[string]bool{}
	var out []string
	add := func(ip string) {
		p := net.ParseIP(ip).To4()
		if p == nil || !net.IP(p).IsPrivate() {
			return
		}
		n := fmt.Sprintf("%d.%d.%d.0/24", p[0], p[1], p[2])
		if !seen[n] && len(out) < 4 {
			seen[n] = true
			out = append(out, n)
		}
	}
	s.mu.Lock()
	for ip := range s.targets.Nodes {
		add(ip)
	}
	host := s.v.HostIP
	s.mu.Unlock()
	add(host)
	sort.Strings(out)
	return out
}

// arpCheck refreshes which known devices are online from the ARP table
// between sweeps, and notices an IP changing MAC.
func (s *netSensor) arpCheck() {
	arp := arpTable()
	subnets := s.lanSubnets()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.v.Subnets = subnets
	byIP := map[string]*netDevice{}
	for _, d := range s.known {
		byIP[d.IP] = d
	}
	for ip, mac := range arp {
		if !inSubnets(ip, subnets) {
			continue
		}
		if d := s.known[mac]; d != nil {
			d.Last, d.Online = time.Now(), true
			if d.IP != ip {
				d.IP = ip
			}
		}
		if d := byIP[ip]; d != nil && d.MAC != mac && s.known[mac] == nil {
			s.addDevice(ip, mac, d.MAC)
		}
	}
	s.v.Spoof = spoofCheck(arp, s.v.Gateway, s.targets)
}

func inSubnets(ip string, subnets []string) bool {
	p := net.ParseIP(ip)
	for _, n := range subnets {
		if _, ipn, err := net.ParseCIDR(n); err == nil && ipn.Contains(p) {
			return true
		}
	}
	return false
}

// spoofCheck: the gateway's MAC answering for other addresses is the mark
// of ARP spoofing (a man in the middle). MetalLB addresses legitimately
// share their node's MAC, so they don't count.
func spoofCheck(arp map[string]string, gw string, t netTargets) []string {
	gmac := arp[gw]
	if gmac == "" {
		return nil
	}
	var out []string
	for ip, mac := range arp {
		if ip != gw && mac == gmac && t.LBs[ip] == "" && t.Nodes[ip] == "" && ip != t.VIP {
			out = append(out, ip)
		}
	}
	sort.Slice(out, func(i, j int) bool { return ipLess(out[i], out[j]) })
	return out
}

// addDevice records a device seen for the first time (locked).
func (s *netSensor) addDevice(ip, mac, oldMAC string) *netDevice {
	d := &netDevice{IP: ip, MAC: mac, Vendor: macVendor(mac), First: time.Now(), Last: time.Now(), Online: true,
		Known: s.v.Baseline, OldMAC: oldMAC}
	s.known[mac] = d
	return d
}

// sweep finds the devices on the LAN subnets and scans their ports.
func (s *netSensor) sweep() { s.sweepNets(s.lanSubnets()) }

func (s *netSensor) sweepNets(subnets []string) {
	var ips []string
	for _, n := range subnets {
		_, ipn, err := net.ParseCIDR(n)
		if err != nil {
			continue
		}
		base := ipn.IP.To4()
		for i := 1; i < 255; i++ {
			ips = append(ips, fmt.Sprintf("%d.%d.%d.%d", base[0], base[1], base[2], i))
		}
	}
	s.mu.Lock()
	s.v.Sweeping, s.v.SweepDone, s.v.SweepTotal, s.v.Subnets = true, 0, len(ips)*2, subnets
	self := s.v.HostIP
	s.mu.Unlock()

	// 1. Who's there: a few likely ports (a refusal counts), plus whatever
	//    the ARP table learns from the attempts.
	alive := map[string]time.Duration{}
	var amu sync.Mutex
	sem := make(chan struct{}, 128)
	var wg sync.WaitGroup
	for _, ip := range ips {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			for _, port := range []string{"80", "443", "22", "445", "53", "62078"} {
				if rtt, ok := tcpRTT(net.JoinHostPort(ip, port), 350*time.Millisecond); ok {
					amu.Lock()
					alive[ip] = rtt
					amu.Unlock()
					break
				}
			}
			s.mu.Lock()
			s.v.SweepDone++
			s.mu.Unlock()
		}(ip)
	}
	wg.Wait()
	arp := arpTable()
	for ip := range arp {
		if inSubnets(ip, subnets) {
			if _, ok := alive[ip]; !ok {
				alive[ip] = 0
			}
		}
	}
	if self != "" {
		alive[self] = 0
	}

	// 2. Port scan of each device.
	ports := map[string][]int{}
	var pmu sync.Mutex
	s.mu.Lock()
	s.v.SweepTotal = len(ips) + len(alive)
	s.mu.Unlock()
	for ip := range alive {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			var open []int
			var omu sync.Mutex
			var pw sync.WaitGroup
			for _, p := range netPorts {
				pw.Add(1)
				go func(p int) {
					defer pw.Done()
					sem <- struct{}{}
					defer func() { <-sem }()
					c, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(p)), 600*time.Millisecond)
					if err == nil {
						c.Close()
						omu.Lock()
						open = append(open, p)
						omu.Unlock()
					}
				}(p)
			}
			pw.Wait()
			sort.Ints(open)
			pmu.Lock()
			ports[ip] = open
			pmu.Unlock()
			s.mu.Lock()
			s.v.SweepDone++
			s.mu.Unlock()
		}(ip)
	}
	wg.Wait()

	// 3. Names (reverse DNS).
	names := map[string]string{}
	var nmu sync.Mutex
	for ip := range alive {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if n, err := net.DefaultResolver.LookupAddr(ctx, ip); err == nil && len(n) > 0 {
				nmu.Lock()
				names[ip] = strings.TrimSuffix(n[0], ".")
				nmu.Unlock()
			}
		}(ip)
	}
	wg.Wait()

	now := time.Now()
	s.mu.Lock()
	for _, d := range s.known {
		d.Online = false
	}
	byIP := map[string]*netDevice{}
	for _, d := range s.known {
		byIP[d.IP] = d
	}
	for ip, rtt := range alive {
		mac := arp[ip]
		if ip == self {
			mac = strings.ToLower(s.v.HostMAC)
		}
		key := mac
		if key == "" {
			key = "ip:" + ip // routed or no ARP entry yet
		}
		d := s.known[key]
		if d == nil {
			old := ""
			if prev := byIP[ip]; prev != nil && mac != "" && !strings.HasPrefix(prev.MAC, "ip:") && prev.MAC != mac {
				old = prev.MAC
			}
			d = s.addDevice(ip, key, old)
			if mac == "" {
				d.Vendor = ""
			}
		}
		d.IP, d.Online, d.Last, d.RTT = ip, true, now, rtt
		d.Ports = ports[ip]
		if n := names[ip]; n != "" {
			d.Name = n
		}
	}
	s.roles()
	s.v.Baseline = false
	s.v.Sweeping, s.v.SweepAt, s.v.NextSweep = false, now, now.Add(5*time.Minute)
	s.mu.Unlock()
	s.save()
	if s.redraw != nil {
		s.redraw()
	}
}

// roles tags devices the cluster knows (locked).
func (s *netSensor) roles() {
	for _, d := range s.known {
		d.Role = ""
		switch {
		case d.IP == s.v.Gateway:
			d.Role = "GATEWAY"
		case d.IP == s.v.HostIP:
			d.Role = "THIS HOST"
		case s.targets.Nodes[d.IP] != "":
			d.Role = "NODE " + s.targets.Nodes[d.IP]
		case d.IP == s.targets.VIP:
			d.Role = "API VIP"
		case s.targets.LBs[d.IP] != "":
			d.Role = "LB " + s.targets.LBs[d.IP]
		}
	}
}
