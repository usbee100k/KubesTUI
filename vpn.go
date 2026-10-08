package main

// Built-in WireGuard for workstation mode (option A).
//
// KubesTUI runs WireGuard itself with an in-process network stack
// (wireguard-go + gVisor netstack): no admin rights, no WireGuard app, and the
// computer's own network settings never change. Only KubesTUI's connections
// to addresses inside the config's AllowedIPs (the node subnet) go through the
// tunnel, so a "route everything" config can't take over the computer.
//
// kubectl, k9s and Lens can't see an in-process tunnel, so while it is up
// KubesTUI also listens on 127.0.0.1 and forwards to the API server, and
// writes kubeconfig-vpn pointing there (TLS still checks the real cluster
// certificate via tls-server-name).

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// ---------------------------------------------------------------------------
// wg-quick config
// ---------------------------------------------------------------------------

type wgConfig struct {
	PrivateKey   string // base64
	Addresses    []netip.Prefix
	DNS          []netip.Addr
	MTU          int
	PublicKey    string // peer, base64
	PresharedKey string
	Endpoint     string // host:port
	AllowedIPs   []netip.Prefix
	Keepalive    int
}

func parseWGConfig(data string) (*wgConfig, error) {
	c := &wgConfig{MTU: 1420}
	section := ""
	peers := 0
	sc := bufio.NewScanner(strings.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			section = strings.ToLower(strings.Trim(line, "[] "))
			if section == "peer" {
				peers++
			}
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		list := func() []string {
			var out []string
			for _, s := range strings.Split(v, ",") {
				if s = strings.TrimSpace(s); s != "" {
					out = append(out, s)
				}
			}
			return out
		}
		switch section + "." + k {
		case "interface.privatekey":
			c.PrivateKey = v
		case "interface.address":
			for _, s := range list() {
				if p, err := netip.ParsePrefix(s); err == nil {
					c.Addresses = append(c.Addresses, p)
				} else if a, err := netip.ParseAddr(s); err == nil {
					c.Addresses = append(c.Addresses, netip.PrefixFrom(a, a.BitLen()))
				}
			}
		case "interface.dns":
			for _, s := range list() {
				if a, err := netip.ParseAddr(s); err == nil {
					c.DNS = append(c.DNS, a)
				}
			}
		case "interface.mtu":
			if n, err := strconv.Atoi(v); err == nil && n >= 576 {
				c.MTU = n
			}
		case "peer.publickey":
			c.PublicKey = v
		case "peer.presharedkey":
			c.PresharedKey = v
		case "peer.endpoint":
			c.Endpoint = v
		case "peer.allowedips":
			for _, s := range list() {
				if p, err := netip.ParsePrefix(s); err == nil {
					c.AllowedIPs = append(c.AllowedIPs, p.Masked())
				}
			}
		case "peer.persistentkeepalive":
			c.Keepalive, _ = strconv.Atoi(v)
		}
	}

	var missing []string
	if c.PrivateKey == "" {
		missing = append(missing, "PrivateKey")
	}
	if len(c.Addresses) == 0 {
		missing = append(missing, "Address")
	}
	if c.PublicKey == "" {
		missing = append(missing, "peer PublicKey")
	}
	if c.Endpoint == "" {
		missing = append(missing, "peer Endpoint")
	}
	if len(c.AllowedIPs) == 0 {
		missing = append(missing, "peer AllowedIPs")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("not a WireGuard client config (missing %s)", strings.Join(missing, ", "))
	}
	if peers > 1 {
		return nil, errors.New("configs with more than one [Peer] aren't supported")
	}
	for _, k := range []string{c.PrivateKey, c.PublicKey} {
		if b, err := base64.StdEncoding.DecodeString(k); err != nil || len(b) != 32 {
			return nil, errors.New("a key in the config is not valid")
		}
	}
	return c, nil
}

func keyHex(b64 string) string {
	b, _ := base64.StdEncoding.DecodeString(b64)
	return hex.EncodeToString(b)
}

// routesEverything reports a full-tunnel config (0.0.0.0/0).
func (c *wgConfig) routesEverything() bool {
	for _, p := range c.AllowedIPs {
		if p.Bits() == 0 {
			return true
		}
	}
	return false
}

func (c *wgConfig) allows(ip netip.Addr) bool {
	for _, p := range c.AllowedIPs {
		if p.Contains(ip.Unmap()) {
			return true
		}
	}
	return false
}

func prefixList(ps []netip.Prefix) string {
	var s []string
	for _, p := range ps {
		s = append(s, p.String())
	}
	return strings.Join(s, ", ")
}

// ---------------------------------------------------------------------------
// Tunnels
// ---------------------------------------------------------------------------

type vpnTunnel struct {
	profile string
	conf    *wgConfig
	dev     *device.Device
	net     *netstack.Net
	started time.Time

	apiListener net.Listener // kubectl stand-in
	apiLocal    string       // 127.0.0.1:port
}

var (
	tunnelsMu sync.Mutex
	tunnels   = map[string]*vpnTunnel{} // by profile slug
)

func (p *clusterProfile) vpnConfPath() string { return filepath.Join(p.dir, "wg.conf") }
func (p *clusterProfile) kubeconfigVPNPath() string {
	return filepath.Join(p.dir, "kubeconfig-vpn")
}

func (p *clusterProfile) hasVPN() bool {
	if p.demo {
		return true
	}
	return fileExists(p.vpnConfPath())
}

func (p *clusterProfile) loadVPNConf() (*wgConfig, error) {
	data, err := os.ReadFile(p.vpnConfPath())
	if err != nil {
		return nil, err
	}
	return parseWGConfig(string(data))
}

func tunnelFor(p *clusterProfile) *vpnTunnel {
	tunnelsMu.Lock()
	defer tunnelsMu.Unlock()
	return tunnels[profileSlug(p.Name)]
}

// importVPNConf validates a .conf and stores it privately with the profile.
func importVPNConf(p *clusterProfile, path string) (*wgConfig, error) {
	path = strings.Trim(strings.TrimSpace(path), `"'`) // Windows "Copy as path" adds quotes
	if strings.HasPrefix(path, "~") {
		if home, err := os.UserHomeDir(); err == nil {
			path = filepath.Join(home, strings.TrimPrefix(path, "~"))
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c, err := parseWGConfig(string(data))
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(p.dir, 0o700); err != nil {
		return nil, err
	}
	return c, os.WriteFile(p.vpnConfPath(), data, 0o600)
}

// startTunnel brings the profile's tunnel up and verifies it by reaching the
// control plane's SSH port through it.
func startTunnel(p *clusterProfile) (*vpnTunnel, error) {
	if t := tunnelFor(p); t != nil {
		return t, nil
	}
	c, err := p.loadVPNConf()
	if err != nil {
		return nil, err
	}

	// The endpoint must be an IP for WireGuard; resolve it with the
	// computer's normal DNS (public name -> home public IP).
	host, port, err := net.SplitHostPort(c.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("endpoint %q: %w", c.Endpoint, err)
	}
	ips, err := net.DefaultResolver.LookupNetIP(context.Background(), "ip4", host)
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("can't resolve VPN endpoint %s: %v", host, err)
	}
	endpoint := net.JoinHostPort(ips[0].Unmap().String(), port)

	var local []netip.Addr
	for _, a := range c.Addresses {
		local = append(local, a.Addr())
	}
	tdev, tnet, err := netstack.CreateNetTUN(local, c.DNS, c.MTU)
	if err != nil {
		return nil, err
	}
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))

	keepalive := c.Keepalive
	if keepalive == 0 {
		keepalive = 25 // keep home NAT mappings open
	}
	var uapi strings.Builder
	fmt.Fprintf(&uapi, "private_key=%s\nreplace_peers=true\npublic_key=%s\n", keyHex(c.PrivateKey), keyHex(c.PublicKey))
	if c.PresharedKey != "" {
		fmt.Fprintf(&uapi, "preshared_key=%s\n", keyHex(c.PresharedKey))
	}
	fmt.Fprintf(&uapi, "endpoint=%s\npersistent_keepalive_interval=%d\nreplace_allowed_ips=true\n", endpoint, keepalive)
	for _, a := range c.AllowedIPs {
		fmt.Fprintf(&uapi, "allowed_ip=%s\n", a)
	}
	if err := dev.IpcSet(uapi.String()); err != nil {
		dev.Close()
		return nil, fmt.Errorf("configure WireGuard: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, err
	}

	t := &vpnTunnel{profile: profileSlug(p.Name), conf: c, dev: dev, net: tnet, started: time.Now()}

	// Prove it works (this also triggers the handshake).
	if _, err := t.probe(p.Host, p.port(), 8*time.Second); err != nil {
		dev.Close()
		return nil, fmt.Errorf("tunnel came up but %s isn't reachable through it: %v "+
			"(check the router forwards UDP to the VPN server, and that AllowedIPs covers the node subnet)", p.Host, err)
	}

	tunnelsMu.Lock()
	tunnels[t.profile] = t
	tunnelsMu.Unlock()

	if p.HasKube {
		if err := t.startAPIForward(p); err != nil {
			t.apiLocal = ""
		}
	}
	return t, nil
}

func stopTunnel(p *clusterProfile) {
	tunnelsMu.Lock()
	t := tunnels[profileSlug(p.Name)]
	delete(tunnels, profileSlug(p.Name))
	tunnelsMu.Unlock()
	if t == nil {
		return
	}
	if t.apiListener != nil {
		t.apiListener.Close()
	}
	_ = os.Remove(p.kubeconfigVPNPath())
	t.dev.Close()
}

// probe opens a TCP connection to host:port through the tunnel.
func (t *vpnTunnel) probe(host string, port int, timeout time.Duration) (time.Duration, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	start := time.Now()
	c, err := t.dial(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return 0, err
	}
	c.Close()
	return time.Since(start), nil
}

// dial connects through the tunnel. Names are resolved with the computer's
// DNS first (a split-tunnel config can't reach public resolvers).
func (t *vpnTunnel) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if _, err := netip.ParseAddr(host); err != nil {
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("resolve %s: %v", host, err)
		}
		host = ips[0].Unmap().String()
	}
	return t.net.DialContext(ctx, network, net.JoinHostPort(host, port))
}

type tunnelStats struct {
	endpoint      string
	lastHandshake time.Time
	rx, tx        int64
}

func (t *vpnTunnel) stats() tunnelStats {
	var s tunnelStats
	out, err := t.dev.IpcGet()
	if err != nil {
		return s
	}
	for _, line := range strings.Split(out, "\n") {
		k, v, _ := strings.Cut(line, "=")
		switch k {
		case "endpoint":
			s.endpoint = v
		case "last_handshake_time_sec":
			if n, _ := strconv.ParseInt(v, 10, 64); n > 0 {
				s.lastHandshake = time.Unix(n, 0)
			}
		case "rx_bytes":
			s.rx, _ = strconv.ParseInt(v, 10, 64)
		case "tx_bytes":
			s.tx, _ = strconv.ParseInt(v, 10, 64)
		}
	}
	return s
}

// vpnDial is the dialer used for every cluster connection: through a tunnel
// whose AllowedIPs contain the destination, otherwise directly.
func vpnDial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err == nil {
		ip, perr := netip.ParseAddr(host)
		if perr != nil {
			if ips, lerr := net.DefaultResolver.LookupNetIP(ctx, "ip4", host); lerr == nil && len(ips) > 0 {
				ip, perr = ips[0], nil
			}
		}
		if perr == nil {
			tunnelsMu.Lock()
			var use *vpnTunnel
			for _, t := range tunnels {
				if t.conf.allows(ip) {
					use = t
					break
				}
			}
			tunnelsMu.Unlock()
			if use != nil {
				return use.dial(ctx, network, addr)
			}
		}
	}
	d := net.Dialer{Timeout: 15 * time.Second}
	return d.DialContext(ctx, network, addr)
}

// reachableDirect checks the control plane without any tunnel.
func reachableDirect(host string, port int) bool {
	c, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), 2*time.Second)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// ---------------------------------------------------------------------------
// kubectl stand-in
// ---------------------------------------------------------------------------

var serverLine = regexp.MustCompile(`(?m)^(\s*)server:\s*(\S+)\s*$`)

func (t *vpnTunnel) startAPIForward(p *clusterProfile) error {
	data, err := os.ReadFile(p.kubeconfigPath())
	if err != nil {
		return err
	}
	m := serverLine.FindSubmatch(data)
	if m == nil {
		return errors.New("no server in kubeconfig")
	}
	target := strings.TrimPrefix(string(m[2]), "https://")
	if !strings.Contains(target, ":") {
		target += ":443"
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	t.apiListener = ln
	t.apiLocal = ln.Addr().String()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				r, err := t.dial(ctx, "tcp", target)
				cancel()
				if err != nil {
					return
				}
				defer r.Close()
				go func() { _, _ = io.Copy(r, c) }()
				_, _ = io.Copy(c, r)
			}()
		}
	}()

	// Same credential, pointed at the local forwarder. The API server's
	// certificate always includes "kubernetes", so TLS still verifies.
	vpnCfg := serverLine.ReplaceAll(data, []byte("${1}server: https://"+t.apiLocal+"\n${1}tls-server-name: kubernetes"))
	return os.WriteFile(p.kubeconfigVPNPath(), vpnCfg, 0o600)
}
