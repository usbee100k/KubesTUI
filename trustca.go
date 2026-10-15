package main

// Trust Cluster Certificates (workstation, Command Center tab): the
// cluster's own certificate authorities, found from cert-manager's CA
// issuers (homelabCD's "Homelab Root CA", Rancher's, any added later),
// installed as trusted roots on this computer so browsers stop warning on
// its sites; or saved as files for phones and other computers.
//
// Only the public certificate (tls.crt / ca.crt) of each CA is used. On
// Windows it goes into the current user's Root store (certutil -user,
// Windows asks to confirm; no admin rights); on Linux into
// /usr/local/share/ca-certificates (sudo); on macOS into the login
// keychain.

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

type clusterCA struct {
	cert    *x509.Certificate
	pem     []byte
	sources []string // "ClusterIssuer homelab-ca"
	trusted bool
	mark    bool
}

func (c *clusterCA) name() string {
	return orDefault(c.cert.Subject.CommonName, strings.Join(c.cert.Subject.Organization, " "))
}

// fileName: "Homelab Root CA" -> "homelab-root-ca".
func (c *clusterCA) fileName() string {
	n := strings.Trim(regexp.MustCompile(`[^a-z0-9]+`).ReplaceAllString(strings.ToLower(c.name()), "-"), "-")
	return orDefault(n, "cluster-ca")
}

func (c *clusterCA) sha256() string {
	sum := sha256.Sum256(c.cert.Raw)
	return colonHex(sum[:])
}

func (c *clusterCA) sha1() string {
	sum := sha1.Sum(c.cert.Raw)
	return hex.EncodeToString(sum[:])
}

func colonHex(b []byte) string {
	parts := make([]string, len(b))
	for i, x := range b {
		parts[i] = fmt.Sprintf("%02X", x)
	}
	return strings.Join(parts, ":")
}

type trustPage struct {
	w       *workstation
	view    *tview.TextView
	screen  *tview.Flex
	cas     []*clusterCA
	sel     int
	note    string
	loading bool
	busy    bool
	err     string
	demo    map[string]bool // demo: trusted fingerprints
}

func (w *workstation) openTrustCA() {
	t := &trustPage{w: w, demo: map[string]bool{}}
	t.view = tview.NewTextView().SetDynamicColors(true).SetWrap(true)
	t.view.SetBorderPadding(1, 0, 2, 1)
	body := frame("TRUST CLUSTER CERTIFICATES")
	body.AddItem(t.view, 0, 1, true)
	t.screen = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(body, 0, 1, true).
		AddItem(w.footer, 1, 0, false)
	t.view.SetInputCapture(t.key)
	w.pages.AddAndSwitchToPage("trust-ca", t.screen, true)
	w.app.SetFocus(t.view)
	w.footer.SetText(" [aqua::b]↑/↓[-::-] Select   [aqua::b]SPACE[-::-] Mark   [aqua::b]T[-::-] Trust   [aqua::b]A[-::-] Trust all   " +
		"[aqua::b]R[-::-] Remove trust   [aqua::b]S[-::-] Save files (phones)   [aqua::b]F5[-::-] Reload   [aqua::b]ESC[-::-] Back")
	t.load()
}

func (t *trustPage) load() {
	t.loading, t.err = true, ""
	t.render()
	p := t.w.current
	go func() {
		var cas []*clusterCA
		var err error
		if p.demo {
			cas = demoClusterCAs()
		} else {
			cas, err = fetchClusterCAs(p)
		}
		t.w.app.QueueUpdateDraw(func() {
			t.loading = false
			if err != nil {
				t.err = err.Error()
			}
			t.cas = cas
			t.refreshTrust()
			t.render()
		})
	}()
}

// fetchClusterCAs reads cert-manager's CA issuers and their certificates.
func fetchClusterCAs(p *clusterProfile) ([]*clusterCA, error) {
	src, err := workstationCCSource(p)
	if err != nil {
		return nil, err
	}
	defer src.Close()
	res := src.GetMany([]string{"/apis/cert-manager.io/v1/clusterissuers", "/apis/cert-manager.io/v1/issuers"})
	type issuer struct {
		Metadata kMeta `json:"metadata"`
		Spec     struct {
			CA *struct {
				SecretName string `json:"secretName"`
			} `json:"ca"`
		} `json:"spec"`
	}
	type ref struct{ ns, secret, source string }
	var refs []ref
	for i, r := range res {
		if r.err != nil {
			if i == 0 {
				return nil, fmt.Errorf("can't list cert-manager issuers: %v", r.err)
			}
			continue
		}
		var list struct {
			Items []issuer `json:"items"`
		}
		_ = json.Unmarshal(r.data, &list)
		for _, it := range list.Items {
			if it.Spec.CA == nil || it.Spec.CA.SecretName == "" {
				continue
			}
			if i == 0 { // a ClusterIssuer's secret lives in cert-manager's namespace
				refs = append(refs, ref{"cert-manager", it.Spec.CA.SecretName, "ClusterIssuer " + it.Metadata.Name})
			} else {
				refs = append(refs, ref{it.Metadata.Namespace, it.Spec.CA.SecretName, "Issuer " + it.Metadata.Namespace + "/" + it.Metadata.Name})
			}
		}
	}
	var paths []string
	for _, r := range refs {
		paths = append(paths, "/api/v1/namespaces/"+r.ns+"/secrets/"+r.secret)
	}
	byFP := map[string]*clusterCA{}
	var out []*clusterCA
	for i, r := range src.GetMany(paths) {
		if r.err != nil {
			continue
		}
		// Only the public parts are kept; the key in the secret is ignored.
		var sec struct {
			Data map[string]string `json:"data"`
		}
		_ = json.Unmarshal(r.data, &sec)
		for _, k := range []string{"tls.crt", "ca.crt"} {
			raw, err := base64.StdEncoding.DecodeString(sec.Data[k])
			if err != nil {
				continue
			}
			for rest := raw; ; {
				var b *pem.Block
				b, rest = pem.Decode(rest)
				if b == nil {
					break
				}
				cert, err := x509.ParseCertificate(b.Bytes)
				if err != nil || !cert.IsCA {
					continue
				}
				ca := &clusterCA{cert: cert, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})}
				if old := byFP[ca.sha256()]; old != nil {
					if !contains(old.sources, refs[i].source) {
						old.sources = append(old.sources, refs[i].source)
					}
					continue
				}
				ca.sources = []string{refs[i].source}
				byFP[ca.sha256()] = ca
				out = append(out, ca)
			}
		}
	}
	if len(refs) == 0 {
		return nil, fmt.Errorf("no CA issuers in cert-manager (the cluster's sites may use Let's Encrypt, which every computer trusts already)")
	}
	return out, nil
}

// refreshTrust checks which CAs this computer trusts now.
func (t *trustPage) refreshTrust() {
	for _, c := range t.cas {
		if t.w.current.demo {
			c.trusted = t.demo[c.sha256()]
		} else {
			c.trusted = systemTrusts(c.cert)
		}
	}
}

func systemTrusts(cert *x509.Certificate) bool {
	if runtime.GOOS == "linux" {
		// Go caches the system pool, so read the bundle fresh.
		data, err := os.ReadFile("/etc/ssl/certs/ca-certificates.crt")
		if err != nil {
			return false
		}
		for rest := data; ; {
			var b *pem.Block
			b, rest = pem.Decode(rest)
			if b == nil {
				return false
			}
			if string(b.Bytes) == string(cert.Raw) {
				return true
			}
		}
	}
	_, err := cert.Verify(x509.VerifyOptions{KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	return err == nil
}

func (t *trustPage) render() {
	p := t.w.current
	var b strings.Builder
	fmt.Fprintf(&b, "  [white::b]%s[-::-]", tview.Escape(p.Name))
	if p.demo {
		b.WriteString("   [black:yellow:b] DEMO [-:-:-]")
	}
	b.WriteString("\n\n  [gray]Your cluster signs its own sites with these certificate authorities. Trusting them on this\n" +
		"  computer makes browsers accept those sites without warnings. Check each fingerprint before you\n" +
		"  trust it: anyone holding a trusted CA's key can impersonate any website to this computer.[-]\n\n")
	switch {
	case t.loading:
		b.WriteString("  [aqua]Reading the cluster's certificate authorities…[-]\n")
	case t.err != "" && len(t.cas) == 0:
		b.WriteString("  [yellow]" + tview.Escape(t.err) + "[-]\n")
	}
	for i, c := range t.cas {
		cur := "  "
		if i == t.sel {
			cur = "[aqua::b]▶[-::-] "
		}
		box := "[ ]"
		if c.mark {
			box = "[aqua][x][-]"
		}
		state := "[red::b]NOT TRUSTED[-::-]"
		if c.trusted {
			state = "[green::b]TRUSTED HERE[-::-]"
		}
		days := int(time.Until(c.cert.NotAfter).Hours() / 24)
		exp := fmt.Sprintf("valid until %s (%d days)", c.cert.NotAfter.Local().Format("2006-01-02"), days)
		if days < 30 {
			exp = "[yellow]" + exp + "[-]"
		}
		fmt.Fprintf(&b, "%s%s [white::b]%s[-::-]   %s\n", cur, tview.Escape(box), tview.Escape(c.name()), state)
		fmt.Fprintf(&b, "        [gray]from[-]        %s\n", tview.Escape(strings.Join(c.sources, ", ")))
		fmt.Fprintf(&b, "        [gray]validity[-]    %s\n", exp)
		fmt.Fprintf(&b, "        [gray]SHA-256[-]     %s\n", c.sha256())
		if days < 120 {
			b.WriteString("        [yellow]Short-lived: when cert-manager renews it, trust it again here (T). homelabCD's\n" +
				"        templates now make the Homelab Root CA last 10 years and keep its key: run Update GitOps Templates.[-]\n")
		}
		b.WriteString("\n")
	}
	if !t.loading && len(t.cas) > 0 {
		b.WriteString("  [gray]T trusts the selected (or marked) ones, A all of them. " + trustHow() + "[-]\n")
		b.WriteString("  [gray]S saves them as .crt files for phones and other computers (Downloads).[-]\n")
	}
	if t.busy {
		b.WriteString("\n  [aqua]Working… " + map[bool]string{true: "answer Windows' security dialog (Yes) to continue.", false: ""}[runtime.GOOS == "windows" && !p.demo] + "[-]\n")
	}
	if t.note != "" {
		b.WriteString("\n" + t.note + "\n")
	}
	t.view.SetText(b.String())
}

func trustHow() string {
	switch runtime.GOOS {
	case "windows":
		return "Windows asks you to confirm each one; it goes into your user's trusted roots (no admin needed; Edge, Chrome and Firefox use it)."
	case "darwin":
		return "macOS asks for your password; it goes into your login keychain."
	}
	return "It's added to the system's trusted CAs with sudo."
}

func (t *trustPage) key(ev *tcell.EventKey) *tcell.EventKey {
	if t.busy {
		return nil
	}
	switch ev.Key() {
	case tcell.KeyEscape:
		t.w.showCluster()
		return nil
	case tcell.KeyUp:
		t.sel = max(0, t.sel-1)
	case tcell.KeyDown:
		t.sel = min(max(0, len(t.cas)-1), t.sel+1)
	case tcell.KeyF5:
		t.load()
		return nil
	case tcell.KeyEnter:
		t.trust(t.chosen())
	case tcell.KeyRune:
		switch ev.Rune() {
		case ' ':
			if t.sel < len(t.cas) {
				t.cas[t.sel].mark = !t.cas[t.sel].mark
			}
		case 't', 'T':
			t.trust(t.chosen())
		case 'a', 'A':
			t.trust(t.cas)
		case 'r', 'R':
			t.untrust(t.chosen())
		case 's', 'S':
			t.save()
		case 'q', 'Q':
			t.w.showCluster()
			return nil
		}
	}
	t.render()
	return nil
}

// chosen: the marked CAs, else the selected one.
func (t *trustPage) chosen() []*clusterCA {
	var out []*clusterCA
	for _, c := range t.cas {
		if c.mark {
			out = append(out, c)
		}
	}
	if len(out) == 0 && t.sel < len(t.cas) {
		out = append(out, t.cas[t.sel])
	}
	return out
}

func (t *trustPage) trust(list []*clusterCA) {
	var todo []*clusterCA
	for _, c := range list {
		if !c.trusted {
			todo = append(todo, c)
		}
	}
	if len(todo) == 0 {
		t.note = "  [green]Already trusted.[-]"
		t.render()
		return
	}
	t.run(todo, true)
}

func (t *trustPage) untrust(list []*clusterCA) {
	var todo []*clusterCA
	for _, c := range list {
		if c.trusted {
			todo = append(todo, c)
		}
	}
	if len(todo) == 0 {
		t.note = "  [gray]Not trusted here, nothing to remove.[-]"
		t.render()
		return
	}
	t.run(todo, false)
}

// run installs (or removes) the CAs, one at a time.
func (t *trustPage) run(list []*clusterCA, add bool) {
	p := t.w.current
	t.busy, t.note = true, ""
	t.render()
	finish := func(lines []string) {
		t.busy = false
		t.refreshTrust()
		for _, c := range t.cas {
			c.mark = false
		}
		t.note = strings.Join(lines, "\n")
		t.render()
	}
	if p.demo {
		var lines []string
		for _, c := range list {
			t.demo[c.sha256()] = add
			lines = append(lines, "  [green]"+map[bool]string{true: "Trusted ", false: "Removed "}[add]+tview.Escape(c.name())+" (demo: nothing was installed).[-]")
		}
		finish(lines)
		return
	}
	if runtime.GOOS != "windows" {
		// sudo and macOS prompts need the terminal.
		var lines []string
		t.w.app.Suspend(func() {
			for _, c := range list {
				lines = append(lines, trustInTerminal(c, add))
			}
			fmt.Print("\nPress Enter to go back to KubesTUI…")
			fmt.Scanln()
		})
		finish(lines)
		return
	}
	go func() {
		var lines []string
		for _, c := range list {
			lines = append(lines, trustWindows(c, add))
		}
		t.w.app.QueueUpdateDraw(func() { finish(lines) })
	}()
}

func trustWindows(c *clusterCA, add bool) string {
	var out []byte
	var err error
	if add {
		f, ferr := os.CreateTemp("", c.fileName()+"-*.crt")
		if ferr != nil {
			return "  [red]" + tview.Escape(ferr.Error()) + "[-]"
		}
		_, _ = f.Write(c.pem)
		f.Close()
		defer os.Remove(f.Name())
		out, err = exec.Command("certutil", "-user", "-addstore", "Root", f.Name()).CombinedOutput()
	} else {
		out, err = exec.Command("certutil", "-user", "-delstore", "Root", c.sha1()).CombinedOutput()
	}
	verb := map[bool]string{true: "Trusted", false: "Removed"}[add]
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if strings.Contains(msg, "canceled") || strings.Contains(msg, "cancelled") || strings.Contains(msg, "0x800704c7") {
			return "  [yellow]" + tview.Escape(c.name()) + ": cancelled in the Windows dialog.[-]"
		}
		lines := strings.Split(msg, "\n")
		return "  [red]" + tview.Escape(c.name()) + ": " + tview.Escape(strings.TrimSpace(lines[len(lines)-1])) + "[-]"
	}
	return "  [green]" + verb + " " + tview.Escape(c.name()) + ". Restart the browser if it was open.[-]"
}

func trustInTerminal(c *clusterCA, add bool) string {
	name := "kubestui-" + c.fileName()
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		kc := filepath.Join(os.Getenv("HOME"), "Library", "Keychains", "login.keychain-db")
		if add {
			f, err := os.CreateTemp("", name+"-*.crt")
			if err != nil {
				return "  [red]" + tview.Escape(err.Error()) + "[-]"
			}
			_, _ = f.Write(c.pem)
			f.Close()
			defer os.Remove(f.Name())
			cmd = exec.Command("security", "add-trusted-cert", "-r", "trustRoot", "-k", kc, f.Name())
		} else {
			cmd = exec.Command("security", "delete-certificate", "-Z", strings.ToUpper(c.sha1()), kc)
		}
	default:
		dest := "/usr/local/share/ca-certificates/" + name + ".crt"
		script := "set -e; printf '%s' \"$1\" > \"$2\"; update-ca-certificates"
		args := []string{"sh", "-c", script, "sh", string(c.pem), dest}
		if !add {
			args = []string{"sh", "-c", "rm -f \"$1\"; update-ca-certificates --fresh", "sh", dest}
		}
		if os.Geteuid() != 0 {
			args = append([]string{"sudo"}, args...)
		}
		cmd = exec.Command(args[0], args[1:]...)
	}
	fmt.Printf("\n%s %s…\n", map[bool]string{true: "Trusting", false: "Removing"}[add], c.name())
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return "  [red]" + tview.Escape(c.name()) + ": " + tview.Escape(err.Error()) + "[-]"
	}
	return "  [green]" + map[bool]string{true: "Trusted ", false: "Removed "}[add] + tview.Escape(c.name()) + ". Restart the browser if it was open.[-]"
}

// save writes the CAs as .crt files for other devices.
func (t *trustPage) save() {
	if len(t.cas) == 0 {
		return
	}
	home, _ := os.UserHomeDir()
	dir := filepath.Join(home, "Downloads", t.w.current.Name+"-certificates")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.note = "  [red]" + tview.Escape(err.Error()) + "[-]"
		return
	}
	var names []string
	for _, c := range t.cas {
		f := filepath.Join(dir, c.fileName()+".crt")
		if err := os.WriteFile(f, c.pem, 0o644); err != nil {
			t.note = "  [red]" + tview.Escape(err.Error()) + "[-]"
			return
		}
		names = append(names, filepath.Base(f))
	}
	t.note = "  [green]Saved " + strings.Join(names, ", ") + " in " + tview.Escape(dir) + "[-]\n" +
		"  [gray]iPhone/iPad: send the file to it (AirDrop, mail), install the profile in Settings, then turn it on in\n" +
		"  Settings → General → About → Certificate Trust Settings. Android: Settings → Security → Encryption &\n" +
		"  credentials → Install a certificate → CA certificate.[-]"
}

// demoClusterCAs: two made-up CAs for the demo.
func demoClusterCAs() []*clusterCA {
	mk := func(cn, org string, days int, source string) *clusterCA {
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn, Organization: []string{org}},
			NotBefore: time.Now().Add(-40 * 24 * time.Hour), NotAfter: time.Now().Add(time.Duration(days) * 24 * time.Hour),
			IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
		der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
		cert, _ := x509.ParseCertificate(der)
		return &clusterCA{cert: cert, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), sources: []string{source}}
	}
	return []*clusterCA{
		mk("Homelab Root CA", "homelab", 3610, "ClusterIssuer homelab-ca"),
		mk("dynamiclistener-ca", "dynamiclistener-org", 3600, "Issuer cattle-system/rancher"),
	}
}
