package main

// Demo cluster for workstation mode: every screen works against a simulated
// cluster, with no network and nothing saved, so the UI can be previewed on
// any computer (e.g. in PowerShell). Opened from the workstation home screen
// ("Explore a demo cluster") or with `kubestui --demo`.
//
// Demo node addresses are in 10.99.0.0/24 so they never match a real node.

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// ---------------------------------------------------------------------------
// Simulated terminal session
// ---------------------------------------------------------------------------

type demoBackend struct {
	keys chan []byte
	done chan struct{}
	once sync.Once
}

func (d *demoBackend) Write(b []byte) (int, error) {
	c := append([]byte(nil), b...)
	select {
	case d.keys <- c:
	case <-d.done:
	}
	return len(b), nil
}

func (d *demoBackend) Resize(cols, rows int) {}
func (d *demoBackend) Hangup()               { d.once.Do(func() { close(d.done) }) }

// demoTerm is what a demo script talks to. Output needs \r\n (there is no
// terminal driver to translate \n), which Print adds.
type demoTerm struct {
	out         io.Writer
	b           *demoBackend
	view        *termView
	interrupted bool
}

const (
	cReset  = "\x1b[0m"
	cBold   = "\x1b[1m"
	cRed    = "\x1b[0;31m"
	cGreen  = "\x1b[0;32m"
	cYellow = "\x1b[1;33m"
	cBlue   = "\x1b[0;34m"
	cCyan   = "\x1b[0;36m"
	cGray   = "\x1b[0;90m"
)

func (d *demoTerm) raw(s string) { _, _ = io.WriteString(d.out, s) }

func (d *demoTerm) Print(s string) {
	d.raw(strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\n", "\r\n"))
}

func (d *demoTerm) Printf(format string, a ...any) { d.Print(fmt.Sprintf(format, a...)) }

// Sleep waits d; false if the session was closed meanwhile.
func (d *demoTerm) Sleep(t time.Duration) bool {
	select {
	case <-time.After(t):
		return true
	case <-d.b.done:
		return false
	}
}

// Lines prints lines with a short pause between them, like live output.
func (d *demoTerm) Lines(pause time.Duration, lines ...string) bool {
	for _, l := range lines {
		d.Print(l + "\n")
		if !d.Sleep(pause) {
			return false
		}
	}
	return true
}

func (d *demoTerm) Cols() int {
	d.view.mu.Lock()
	defer d.view.mu.Unlock()
	return d.view.cols
}

// ReadKey waits for the next key press (raw bytes). ok is false on hang-up.
func (d *demoTerm) ReadKey() ([]byte, bool) {
	select {
	case k := <-d.b.keys:
		return k, true
	case <-d.b.done:
		return nil, false
	}
}

// ReadLine reads a line like a terminal in cooked mode. echo=false hides the
// input (passwords). ok is false on hang-up or Ctrl+C (then interrupted).
func (d *demoTerm) ReadLine(echo bool) (string, bool) {
	var line []rune
	for {
		k, ok := d.ReadKey()
		if !ok {
			return "", false
		}
		if k[0] == 0x1b {
			continue // arrows etc.: no line editing in the demo
		}
		for _, r := range string(k) {
			switch {
			case r == '\r' || r == '\n':
				d.raw("\r\n")
				return string(line), true
			case r == 0x03:
				d.raw("^C\r\n")
				d.interrupted = true
				return "", false
			case r == 0x7f || r == 0x08:
				if len(line) > 0 {
					line = line[:len(line)-1]
					if echo {
						d.raw("\b \b")
					}
				}
			case r == 0x15: // Ctrl+U
				if echo {
					d.raw(strings.Repeat("\b \b", len(line)))
				}
				line = line[:0]
			case r >= 0x20:
				line = append(line, r)
				if echo {
					buf := make([]byte, utf8.UTFMax)
					d.raw(string(buf[:utf8.EncodeRune(buf, r)]))
				}
			}
		}
	}
}

// exitCode for a script that stopped early.
func (d *demoTerm) exitCode() int {
	if d.interrupted {
		return 130
	}
	return 129
}

// ---------------------------------------------------------------------------
// Demo data
// ---------------------------------------------------------------------------

const demoCredential = "kubestui-demo-pc-x7k2m"

func demoProfile() *clusterProfile {
	return &clusterProfile{
		Name:        "demo-homelab",
		Host:        "10.99.0.11",
		Port:        22,
		User:        "admin",
		HomelabRoot: "/home/admin/homelabCD",
		HasKube:     true,
		Credential:  demoCredential,
		demo:        true,
		dir:         filepath.Join(kubestuiDir(), "clusters", "demo-homelab"), // shown only; never written
	}
}

var demoNodes = []nodeRow{
	{name: "cp1", host: "10.99.0.11", role: "control-plane", status: "Ready"},
	{name: "cp2", host: "10.99.0.12", role: "control-plane", status: "Ready"},
	{name: "cp3", host: "10.99.0.13", role: "control-plane", status: "Ready"},
	{name: "w1", host: "10.99.0.21", role: "worker", status: "Ready"},
	{name: "w2", host: "10.99.0.22", role: "worker", status: "NotReady"},
}

func demoNodesTable(wide bool) string {
	var b strings.Builder
	if wide {
		b.WriteString("NAME   STATUS     ROLES           AGE   VERSION   INTERNAL-IP   OS-IMAGE             CONTAINER-RUNTIME\n")
	} else {
		b.WriteString("NAME   STATUS     ROLES           AGE   VERSION\n")
	}
	for _, n := range demoNodes {
		age := "41d"
		if n.role == "worker" {
			age = "12d"
		}
		if wide {
			fmt.Fprintf(&b, "%-6s %-10s %-15s %-5s %-9s %-13s %-20s %s\n", n.name, n.status, n.role, age, "v1.36.2", n.host, "Ubuntu 24.04.3 LTS", "containerd://2.1.4")
		} else {
			fmt.Fprintf(&b, "%-6s %-10s %-15s %-5s %s\n", n.name, n.status, n.role, age, "v1.36.2")
		}
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// Demo scripts
// ---------------------------------------------------------------------------

func demoSudo(d *demoTerm) bool {
	d.Print("[sudo] password for admin: ")
	if _, ok := d.ReadLine(false); !ok {
		return false
	}
	return d.Sleep(300 * time.Millisecond)
}

func demoScriptFor(op string) func(d *demoTerm) int {
	switch op {
	case "health":
		return demoHealth
	case "config":
		return demoConfig
	case "join-commands":
		return demoJoinCommands
	case "repair":
		return demoRepair
	case "longhorn-disk":
		return demoLonghornDisk
	case "vpn-status":
		return demoVPNStatus
	}
	return func(d *demoTerm) int {
		d.Print("demo: no simulation for " + op + "\n")
		return 0
	}
}

func demoHealth(d *demoTerm) int {
	if !demoSudo(d) {
		return d.exitCode()
	}
	pass := func(s string) string { return "  " + cGreen + "PASS" + cReset + "  " + s }
	warn := func(s string) string { return "  " + cYellow + "WARN" + cReset + "  " + s }
	sec := func(s string) string { return "\n" + cBlue + "== " + s + " ==" + cReset }
	p := 70 * time.Millisecond

	ok := d.Lines(p,
		"",
		"=============================================",
		" Cluster Health Report  ("+time.Now().Format("2006-01-02 15:04:05")+")",
		" Run from: cp1",
		"=============================================",
		sec("API Server"),
		pass("API server ready (https://10.99.0.100:6443)"),
		pass("Control plane VIP 10.99.0.100 answering (kube-vip)"),
		sec("Nodes"),
		warn("4/5 node(s) Ready"),
		"          w2     NotReady   worker   12d   v1.36.2",
		pass("3 node(s) selected for MetalLB announcements"),
		pass("No memory, disk or PID pressure"),
		sec("Control Plane"),
		pass("etcd: 3/3 running"),
		pass("kube-apiserver: 3/3 running"),
		pass("kube-controller-manager: 3/3 running"),
		pass("kube-scheduler: 3/3 running"),
		pass("Control plane certificates valid for 30+ days"),
		sec("Networking"),
		warn("Cilium agents: 4/5 ready"),
		pass("Cilium operator: 2/2 ready"),
		pass("CoreDNS: 2/2 ready"),
		pass("MetalLB pool default-pool: 10.99.0.200-10.99.0.220"),
		pass("ingress-nginx: 2/2 ready"),
		pass("Ingress LoadBalancer IP: 10.99.0.200"),
		sec("DNS (demo.duckdns.org)"),
		pass("demo.duckdns.org -> 10.99.0.200"),
		pass("Last DuckDNS update succeeded (duckdns-updater-29318040)"),
		sec("Argo CD Applications"),
		pass("homelab-root: Synced / Healthy"),
		pass("infrastructure: Synced / Healthy"),
		pass("networking: Synced / Healthy"),
		pass("longhorn: Synced / Healthy"),
		sec("Workloads"),
		pass("All pods Running or Completed"),
		sec("Storage & Certificates"),
		pass("All PersistentVolumeClaims Bound"),
		pass("All cert-manager certificates Ready"),
		"",
		"=============================================",
		" Summary: "+cGreen+"31 passed"+cReset+", "+cYellow+"2 warnings"+cReset+", "+cRed+"0 failed"+cReset,
		"=============================================",
	)
	if !ok {
		return d.exitCode()
	}
	return 0
}

func demoVPNStatus(d *demoTerm) int {
	if !demoSudo(d) {
		return d.exitCode()
	}
	pass := func(s string) string { return "  " + cGreen + "PASS" + cReset + "  " + s }
	d.Lines(90*time.Millisecond,
		"",
		"=============================================",
		" VPN Status (wg-easy)",
		"=============================================",
		"",
		"  Endpoint   demo-vpn.duckdns.org:51820/udp",
		"  Server IP  10.99.0.220   (router: forward UDP 51820 here)",
		"  Clients    reach 10.99.0.0/24",
		"  Web UI     https://wg.demo.duckdns.org  (LAN)",
		"",
		pass("wg-easy is running"),
		pass("VPN listening on 10.99.0.220:51820/udp"),
		pass("demo-vpn.duckdns.org -> 203.0.113.9 (your public IP)"),
		"",
		"  "+cBlue+"Clients"+cReset,
		"    laptop        connected  handshake  12s ago  rx 18M  tx 2.1M",
		"    this-pc       connected  handshake   4s ago  rx 1.4M  tx 310K",
		"    phone         idle       last seen 2026-10-06 21:14",
		"",
		pass("3 client(s), 2 connected now"),
		"",
		"=============================================",
		" Summary: "+cGreen+"4 passed"+cReset+", "+cYellow+"0 warnings"+cReset+", "+cRed+"0 failed"+cReset,
		"=============================================",
	)
	return 0
}

func demoComposeImport(d *demoTerm) int {
	if !demoSudo(d) {
		return d.exitCode()
	}
	d.Lines(120*time.Millisecond,
		cBlue+"[INFO]"+cReset+" Updating the GitOps repository...",
		cGreen+"[ OK ]"+cReset+" GitOps repository up to date",
		"",
		"=============================================",
		" Import a Docker Compose app",
		"=============================================",
		"",
		cGreen+"[ OK ]"+cReset+" Read docker-compose.yml: 1 service(s): jellyfin",
		"",
		cBold+"── jellyfin"+cReset+"  (jellyfin/jellyfin:10.10.7)",
	)
	ask := func(q string) (string, bool) {
		d.Print(q)
		return d.ReadLine(true)
	}
	if _, ok := ask("App name (also its namespace and URL) [jellyfin]: "); !ok {
		return d.exitCode()
	}
	d.Print("  Port 8096->8096/tcp:  web UI (https://…), lan (own IP), or internal\n")
	if _, ok := ask("    use as (web/lan/internal) [web]: "); !ok {
		return d.exitCode()
	}
	if _, ok := ask("    hostname [jellyfin.demo.duckdns.org]: "); !ok {
		return d.exitCode()
	}
	if _, ok := ask("  Folder ./config -> /config: Longhorn volume size [5Gi]: "); !ok {
		return d.exitCode()
	}
	d.Lines(60*time.Millisecond,
		"",
		"=============================================",
		" Plan: jellyfin  ->  apps/applications/jellyfin/",
		"=============================================",
		"  jellyfin",
		"    https://jellyfin.demo.duckdns.org  ->  port 8096",
		"    /config  <- Longhorn volume jellyfin-config (5Gi)",
		"    "+cYellow+"[WARN]"+cReset+" /config starts empty: copy your Docker data from ./config if you need it",
		"",
	)
	if a, ok := ask("Create it and deploy through GitOps (y/n) [y]: "); !ok || strings.HasPrefix(strings.ToLower(a), "n") {
		if ok {
			d.Print(cYellow + "[WARN]" + cReset + " Cancelled. Nothing was written.\n")
			return 1
		}
		return d.exitCode()
	}
	d.Lines(400*time.Millisecond,
		cGreen+"[ OK ]"+cReset+" Wrote apps/applications/jellyfin/",
		cGreen+"[ OK ]"+cReset+" Pushed: Import jellyfin from Docker Compose",
		"",
		cBlue+"[INFO]"+cReset+" Waiting for Argo CD to deploy jellyfin (Ctrl+C stops watching; it keeps deploying)...",
		"  "+time.Now().Format("15:04:05")+"  OutOfSync / Missing",
		"  "+time.Now().Add(4*time.Second).Format("15:04:05")+"  Synced / Progressing",
		"  "+time.Now().Add(31*time.Second).Format("15:04:05")+"  Synced / Healthy",
		cGreen+"[ OK ]"+cReset+" jellyfin is running.",
	)
	return 0
}

func demoConfig(d *demoTerm) int {
	if !demoSudo(d) {
		return d.exitCode()
	}
	d.Lines(15*time.Millisecond,
		"",
		"=============================================",
		" homelabCD Configuration  (/home/admin/homelabCD/config/cluster.yaml)",
		"=============================================",
		"",
		"cluster:",
		"  name: demo-homelab",
		"kubernetes:",
		`  version: "1.36.2"`,
		"network:",
		`  vip: "10.99.0.100"`,
		`  metallbRange: "10.99.0.200-10.99.0.220"`,
		`  podSubnet: "10.0.0.0/16"`,
		`  serviceSubnet: "10.96.0.0/12"`,
		"domains:",
		`  base: "demo.duckdns.org"`,
	)
	return 0
}

func demoJoinCommands(d *demoTerm) int {
	if !demoSudo(d) {
		return d.exitCode()
	}
	d.Lines(60*time.Millisecond,
		cBlue+"[INFO]"+cReset+" Creating join token...",
		cGreen+"[ OK ]"+cReset+" Join commands generated (valid 2 hours).",
		"",
		cYellow+"Worker:"+cReset,
		"kubeadm join 10.99.0.100:6443 --token demo01.0123456789abcdef \\",
		"    --discovery-token-ca-cert-hash sha256:0d3m0...c0ffee",
		"",
		cYellow+"Control plane:"+cReset,
		"kubeadm join 10.99.0.100:6443 --token demo01.0123456789abcdef \\",
		"    --discovery-token-ca-cert-hash sha256:0d3m0...c0ffee \\",
		"    --control-plane --certificate-key 5a1e...d3m0",
	)
	return 0
}

func demoRepair(d *demoTerm) int {
	if !demoSudo(d) {
		return d.exitCode()
	}
	ok := d.Lines(400*time.Millisecond,
		cBlue+"[INFO]"+cReset+" Starting node repair...",
		"",
		cBlue+"[INFO]"+cReset+" Restarting containerd...",
		cGreen+"[ OK ]"+cReset+" containerd is running.",
		"",
		cBlue+"[INFO]"+cReset+" Restarting kubelet...",
		cGreen+"[ OK ]"+cReset+" kubelet is running.",
		"",
		cBlue+"[INFO]"+cReset+" Recent kubelet errors:",
		"  none",
		"",
	)
	if !ok {
		return d.exitCode()
	}
	d.Print(demoNodesTable(true))
	d.Print(cGreen + "[ OK ]" + cReset + " Repair completed.\n")
	return 0
}

func demoLonghornDisk(d *demoTerm) int {
	if !demoSudo(d) {
		return d.exitCode()
	}
	d.Print("\n=============================================\n Move Node to Dedicated Longhorn Disk\n=============================================\n\nLonghorn nodes:\n\n")
	for i, n := range demoNodes[:4] {
		state := "os-disk"
		if n.name == "cp2" {
			state = "dedicated"
		}
		d.Printf("  %d) %-20s %-10s %s\n", i+1, n.name, state, map[bool]string{true: "/mnt/longhorn-disk", false: "/var/lib/longhorn/"}[state == "dedicated"])
	}
	d.Print("\nNode to move to a dedicated disk [1-4]: ")
	choice, ok := d.ReadLine(true)
	if !ok {
		return d.exitCode()
	}
	node := "w1"
	if n := strings.TrimSpace(choice); n >= "1" && n <= "4" && len(n) == 1 {
		node = demoNodes[n[0]-'1'].name
	}
	d.Lines(150*time.Millisecond,
		cBlue+"[INFO]"+cReset+" Checking volume health...",
		cGreen+"[ OK ]"+cReset+" All volumes healthy.",
		"",
		"  Replica data on "+node+":          48GiB (provisioned size)",
		"  Free space on the other nodes:    611GiB",
		"",
	)
	d.Print("Type " + node + " to continue (anything else cancels): ")
	if c, ok := d.ReadLine(true); !ok || strings.TrimSpace(c) != node {
		if !ok {
			return d.exitCode()
		}
		d.Print(cYellow + "[WARN]" + cReset + " Cancelled. Nothing was changed.\n")
		return 0
	}
	d.Print("\n--- Step 1/4: prepare the disk on " + node + " ---\n\n  0) No, use the OS disk\n  1) /dev/sdb          500 GB  SSD   sata   Samsung SSD 870\n\nUse a dedicated disk for Longhorn? [0-1] (default 0): ")
	if c, ok := d.ReadLine(true); !ok || strings.TrimSpace(c) != "1" {
		if !ok {
			return d.exitCode()
		}
		d.Print(cYellow + "[WARN]" + cReset + " No dedicated disk was prepared. Nothing in Longhorn was changed.\n")
		return 1
	}
	d.Print("\n!!! /dev/sdb will be COMPLETELY ERASED !!!\n\nType /dev/sdb to confirm erasing it (anything else cancels): ")
	if c, ok := d.ReadLine(true); !ok || strings.TrimSpace(c) != "/dev/sdb" {
		if !ok {
			return d.exitCode()
		}
		d.Print(cYellow + "[WARN]" + cReset + " Cancelled. Longhorn will use the OS disk on this node.\n")
		return 1
	}
	if !d.Lines(400*time.Millisecond,
		cGreen+"[ OK ]"+cReset+" Longhorn disk ready: /dev/sdb1 -> /mnt/longhorn-disk (458G)",
		"",
		"--- Step 2/4: add the disk to Longhorn ---",
		cGreen+"[ OK ]"+cReset+" New disk is Ready and Schedulable.",
		"",
		"--- Step 3/4 and 4/4: move replicas and remove the old disk ---",
	) {
		return d.exitCode()
	}
	for left := 12; left >= 0; left-- {
		d.raw(fmt.Sprintf("\r  %s  replicas left on old disk: %-6d", time.Now().Format("15:04:05"), left))
		if !d.Sleep(250 * time.Millisecond) {
			return d.exitCode()
		}
	}
	d.Lines(200*time.Millisecond,
		"",
		cGreen+"[ OK ]"+cReset+" All replicas moved off the old disk.",
		cGreen+"[ OK ]"+cReset+" Old disk(s) removed from Longhorn.",
		"",
		cGreen+"[ OK ]"+cReset+" "+node+" now stores Longhorn data on its dedicated disk.",
	)
	return 0
}

func demoRemoteJoin(pre remotePrefill, role string) func(d *demoTerm) int {
	return func(d *demoTerm) int {
		host := pre.Host
		if host == "" {
			host = "10.99.0.23"
		}
		d.Print("[sudo] password for admin: ")
		if _, ok := d.ReadLine(false); !ok {
			return d.exitCode()
		}
		d.Lines(80*time.Millisecond,
			"",
			"==================================================",
			"             REMOTE NODE EXECUTION",
			"==================================================",
			"",
			"SSH user : "+pre.User,
			fmt.Sprintf("Target   : %s:%d", host, pre.Port),
			"Operation: "+role,
			"",
			"[INFO] Reading SSH host fingerprint...",
			"",
			"==================================================",
			"                 SSH FINGERPRINT",
			"==================================================",
			"",
			"Host: "+host,
			"  ssh-ed25519            SHA256:d3m0Fing3rpr1ntN0tR3a1xxxxxxxxxxxxxxxxxxxx",
			"",
		)
		d.Print("Trust this host fingerprint? [y/N]: ")
		answer, ok := d.ReadLine(true)
		if !ok {
			return d.exitCode()
		}
		if a := strings.ToLower(strings.TrimSpace(answer)); a != "y" && a != "yes" {
			d.Print("\nSSH connection cancelled.\n\n" + cRed + "✗ Remote join did not complete." + cReset + "\n")
			return 1
		}
		steps := []string{
			"",
			"[INFO] Connecting to remote node...",
			"[ OK ] SSH connection established.",
			"[INFO] Validating sudo access...",
			"[ OK ] Sudo access confirmed.",
			"[INFO] Creating join token on this machine...",
			"[ OK ] Fresh join token generated (valid 2 hours).",
			"[INFO] Copying homelabCD...",
			"[ OK ] homelabCD copied to remote node.",
			"[INFO] Executing " + role + " on " + host + "...",
			"",
			"[preflight] Running pre-flight checks",
			"[preflight] Reading configuration from the cluster...",
			"[kubelet-start] Writing kubelet configuration to file \"/var/lib/kubelet/config.yaml\"",
			"[kubelet-start] Starting the kubelet",
			"[kubelet-start] Waiting for the kubelet to perform the TLS Bootstrap",
			"",
			"This node has joined the cluster:",
			"* Certificate signing request was sent to apiserver and a response was received.",
			"* The Kubelet was informed of the new secure connection details.",
			"",
			"[ OK ] Remote " + role + " operation completed.",
			"",
			cGreen + "✓ Remote join finished." + cReset,
		}
		if !d.Lines(220*time.Millisecond, steps...) {
			return d.exitCode()
		}
		return 0
	}
}

// demoShell is a small fake bash on a demo node.
func demoShell(node string) func(d *demoTerm) int {
	return func(d *demoTerm) int {
		prompt := func() { d.raw(cGreen + cBold + "admin@" + node + cReset + ":" + cBlue + cBold + "~" + cReset + "$ ") }
		d.Print("Welcome to Ubuntu 24.04.3 LTS (GNU/Linux 6.8.0-71-generic x86_64)\n\n")
		d.Print(cGray + "  This is a KubesTUI demo shell. Nothing here is real. Type " + cReset + cBold + "help" + cReset + cGray + "." + cReset + "\n\n")
		for {
			prompt()
			line, ok := d.ReadLine(true)
			if !ok {
				if d.interrupted {
					d.interrupted = false
					continue // Ctrl+C at the prompt: new prompt, like bash
				}
				return d.exitCode()
			}
			cmd := strings.Fields(line)
			if len(cmd) == 0 {
				continue
			}
			switch strings.Join(cmd, " ") {
			case "help":
				d.Print("Try: kubectl get nodes [-o wide] · kubectl get pods -A · ls · df -h · free -h\n" +
					"     uptime · top (full-screen, q quits) · logs (300 lines: try Shift+PgUp, drag to copy) · clear · exit\n")
			case "kubectl get nodes":
				d.Print(demoNodesTable(false))
			case "kubectl get nodes -o wide":
				d.Print(demoNodesTable(true))
			case "kubectl get pods -A":
				d.Print("NAMESPACE        NAME                                       READY   STATUS    RESTARTS   AGE\n" +
					"argocd           argocd-server-7c9b6d5f8-x2kq4              1/1     Running   0          41d\n" +
					"cert-manager     cert-manager-6d9c8b7f5d-9wq2m              1/1     Running   0          41d\n" +
					"ingress-nginx    ingress-nginx-controller-5f7d8c9b6-k4m8p   1/1     Running   0          41d\n" +
					"kube-system      cilium-4xk8m                               1/1     Running   0          41d\n" +
					"kube-system      coredns-668d6bf9bc-7hjzt                   1/1     Running   0          41d\n" +
					"kube-system      etcd-cp1                                   1/1     Running   0          41d\n" +
					"longhorn-system  longhorn-manager-8q2vx                     2/2     Running   0          12d\n" +
					"metallb-system   metallb-speaker-p9z7c                      4/4     Running   0          41d\n")
			case "ls":
				d.Print(cBlue + cBold + "homelabCD" + cReset + "  " + cBlue + cBold + "kubestui-logs" + cReset + "  notes.txt\n")
			case "df -h":
				d.Print("Filesystem      Size  Used Avail Use% Mounted on\n/dev/sda2       234G   61G  161G  28% /\n/dev/sdb1       458G  112G  346G  25% /mnt/longhorn-disk\n")
			case "free -h":
				d.Print("               total        used        free      shared  buff/cache   available\nMem:            31Gi       9.8Gi        14Gi       3.1Mi       7.6Gi        21Gi\nSwap:             0B          0B          0B\n")
			case "uptime":
				d.Print(" " + time.Now().Format("15:04:05") + " up 41 days,  3:12,  1 user,  load average: 0.42, 0.37, 0.31\n")
			case "hostname":
				d.Print(node + "\n")
			case "whoami":
				d.Print("admin\n")
			case "clear":
				d.raw("\x1b[H\x1b[2J")
			case "logs":
				for i := 1; i <= 300; i++ {
					level := cGreen + "INFO" + cReset
					if i%37 == 0 {
						level = cYellow + "WARN" + cReset
					}
					d.Printf("%s %s demo-app[%d]: processed request %d in %dms\n",
						time.Now().Add(time.Duration(i-300)*time.Second).Format("15:04:05"), level, 4000+i%7, i, 5+i%40)
				}
			case "top", "htop":
				if !demoTop(d, node) {
					return d.exitCode()
				}
			case "exit", "logout":
				d.Print("logout\n")
				return 0
			default:
				d.Print(cmd[0] + ": command not found " + cGray + "(demo shell: type help)" + cReset + "\n")
			}
		}
	}
}

// demoTop shows a full-screen view on the alternate screen until q.
func demoTop(d *demoTerm, node string) bool {
	d.raw("\x1b[?1049h\x1b[?25l") // alternate screen, hide cursor
	defer d.raw("\x1b[?25h\x1b[?1049l")
	procs := []string{"kube-apiserver", "etcd", "kubelet", "cilium-agent", "containerd", "longhorn-manager", "coredns", "kube-controller", "argocd-server", "ingress-nginx"}
	for tick := 0; ; tick++ {
		var b strings.Builder
		b.WriteString("\x1b[H\x1b[2J")
		fmt.Fprintf(&b, "top - %s up 41 days,  load average: 0.%d2, 0.37, 0.31   %s(demo, press q to quit)%s\r\n",
			time.Now().Format("15:04:05"), 3+tick%5, cGray, cReset)
		b.WriteString("Tasks: 312 total,   1 running, 311 sleeping\r\n")
		fmt.Fprintf(&b, "%%Cpu(s): %2d.1 us,  2.3 sy,  0.0 ni, %2d.4 id\r\n", 6+tick%4, 90-tick%4)
		b.WriteString("MiB Mem :  31842.1 total,  14211.0 free,  10031.4 used,   7599.7 buff/cache\r\n\r\n")
		b.WriteString("\x1b[7m    PID USER      %CPU  %MEM     TIME+ COMMAND                              \x1b[0m\r\n")
		for i, p := range procs {
			cpu := float64((i*7+tick*3)%23) / 2.0
			fmt.Fprintf(&b, "%7d root    %5.1f  %4.1f  %3d:%02d.%02d %s\r\n", 1000+i*37, cpu, 0.4+float64(i)/3, 40-i, (tick+i)%60, i*11%100, p)
		}
		d.raw(b.String())
		select {
		case k := <-d.b.keys:
			if len(k) > 0 && (k[0] == 'q' || k[0] == 'Q' || k[0] == 0x03) {
				return true
			}
		case <-time.After(time.Second):
		case <-d.b.done:
			return false
		}
	}
}

func demoKeySetup(d *demoTerm) int {
	d.Lines(150*time.Millisecond,
		"/usr/bin/ssh-copy-id: INFO: Source of key(s) to be installed: ~/.kubestui/clusters/demo-homelab/id_ed25519.pub",
	)
	d.Print("admin@10.99.0.21's password: ")
	if _, ok := d.ReadLine(false); !ok {
		return d.exitCode()
	}
	d.Lines(150*time.Millisecond, "", "Number of key(s) added: 1", "", "Now try logging into the machine. (demo: nothing was changed)")
	return 0
}
