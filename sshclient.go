package main

// Cross-platform SSH for workstation mode: cluster profiles, host key
// verification against ~/.kubestui/known_hosts (trust on first use, with the
// fingerprint shown), key generation/authorization, and UI prompts that
// background goroutines can use.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// uiApp / uiPages are set in main so background work can show prompts.
var (
	uiApp   *tview.Application
	uiPages *tview.Pages
)

// ---------------------------------------------------------------------------
// Prompts usable from background goroutines (never from the UI goroutine).
// ---------------------------------------------------------------------------

var askMu sync.Mutex // one prompt at a time

// showConfirm shows a yes/no dialog. UI goroutine only.
func showConfirm(title, text, yes, no string, done func(ok bool)) {
	showChoice(title, text, []string{yes, no}, func(label string) { done(label == yes) })
}

// showChoice shows a dialog with several buttons; done gets the label
// pressed ("" on ESC). UI goroutine only.
func showChoice(title, text string, buttons []string, done func(label string)) {
	prev := uiApp.GetFocus()
	modal := tview.NewModal().
		SetText(text).
		AddButtons(buttons).
		SetBackgroundColor(tcell.ColorDarkSlateGray).
		SetTextColor(tcell.ColorWhite).
		SetButtonBackgroundColor(tcell.ColorAqua).
		SetButtonTextColor(tcell.ColorBlack)
	modal.SetBorder(true).SetTitle(" " + title + " ")
	modal.SetDoneFunc(func(_ int, label string) {
		uiPages.RemovePage("ask")
		if prev != nil {
			uiApp.SetFocus(prev)
		}
		done(label)
	})
	uiPages.AddPage("ask", modal, true, true)
	uiApp.SetFocus(modal)
}

func askYesNo(title, text, yes, no string) bool {
	askMu.Lock()
	defer askMu.Unlock()
	ch := make(chan bool, 1)
	uiApp.QueueUpdateDraw(func() {
		showConfirm(title, text, yes, no, func(ok bool) { ch <- ok })
	})
	return <-ch
}

// askSecret asks for a password. ok is false if cancelled.
func askSecret(title, label string) (string, bool) {
	askMu.Lock()
	defer askMu.Unlock()
	type answer struct {
		text string
		ok   bool
	}
	ch := make(chan answer, 1)
	uiApp.QueueUpdateDraw(func() {
		prev := uiApp.GetFocus()
		form := tview.NewForm().AddPasswordField(label, "", 30, '*', nil)
		finish := func(a answer) {
			uiPages.RemovePage("ask")
			if prev != nil {
				uiApp.SetFocus(prev)
			}
			ch <- a
		}
		form.AddButton("OK", func() {
			finish(answer{form.GetFormItem(0).(*tview.InputField).GetText(), true})
		})
		form.AddButton("Cancel", func() { finish(answer{}) })
		form.SetCancelFunc(func() { finish(answer{}) })
		styleForm(form)
		form.SetTitle(" " + title + " ")
		uiPages.AddPage("ask", centered(form, 60, 9), true, true)
		uiApp.SetFocus(form)
	})
	a := <-ch
	return a.text, a.ok
}

// ---------------------------------------------------------------------------
// Files under ~/.kubestui
// ---------------------------------------------------------------------------

func kubestuiDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".kubestui")
}

func knownHostsPath() string { return filepath.Join(kubestuiDir(), "known_hosts") }

type clusterProfile struct {
	Name        string    `json:"name"`
	Host        string    `json:"host"`
	Port        int       `json:"port"`
	User        string    `json:"user"`
	HomelabRoot string    `json:"homelabRoot,omitempty"` // homelabCD path on the node
	HasKube     bool      `json:"hasKubeconfig"`
	Credential  string    `json:"credential,omitempty"` // this computer's ServiceAccount; empty = legacy admin.conf
	Created     time.Time `json:"created"`
	LastUsed    time.Time `json:"lastUsed,omitempty"`

	dir  string
	demo bool // the built-in demo cluster (demo.go): simulated, never saved
}

var profileNameChars = regexp.MustCompile(`[^a-z0-9-]+`)

func profileSlug(name string) string {
	s := strings.Trim(profileNameChars.ReplaceAllString(strings.ToLower(name), "-"), "-")
	if s == "" {
		s = "cluster"
	}
	return s
}

func newProfile(name string) *clusterProfile {
	return &clusterProfile{
		Name: name,
		dir:  filepath.Join(kubestuiDir(), "clusters", profileSlug(name)),
	}
}

func (p *clusterProfile) keyPath() string        { return filepath.Join(p.dir, "id_ed25519") }
func (p *clusterProfile) kubeconfigPath() string { return filepath.Join(p.dir, "kubeconfig") }
func (p *clusterProfile) port() int {
	if p.Port > 0 {
		return p.Port
	}
	return 22
}

func (p *clusterProfile) save() error {
	if err := os.MkdirAll(p.dir, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(p.dir, "profile.json"), data, 0o600)
}

func (p *clusterProfile) remove() error { return os.RemoveAll(p.dir) }

func listProfiles() []*clusterProfile {
	dirs, _ := filepath.Glob(filepath.Join(kubestuiDir(), "clusters", "*", "profile.json"))
	var out []*clusterProfile
	for _, f := range dirs {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		p := &clusterProfile{}
		if json.Unmarshal(data, p) != nil {
			continue
		}
		p.dir = filepath.Dir(f)
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

// generateKey writes an ed25519 key pair (path, path.pub) and returns the
// authorized_keys line.
func generateKey(path, comment string) (string, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	block, err := ssh.MarshalPrivateKey(priv, comment)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		return "", err
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return "", err
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))) + " " + comment
	return line, os.WriteFile(path+".pub", []byte(line+"\n"), 0o644)
}

// publicKeyLine returns the authorized_keys line for an existing key.
func publicKeyLine(path string) (string, error) {
	data, err := os.ReadFile(path + ".pub")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// loadSigners returns signers for the given private keys plus the user's
// default ~/.ssh keys. Passphrase-protected keys are skipped.
func loadSigners(paths ...string) []ssh.Signer {
	if home, err := os.UserHomeDir(); err == nil {
		for _, n := range []string{"id_ed25519", "id_ecdsa", "id_rsa"} {
			paths = append(paths, filepath.Join(home, ".ssh", n))
		}
	}
	var signers []ssh.Signer
	seen := map[string]bool{}
	for _, p := range paths {
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if s, err := ssh.ParsePrivateKey(data); err == nil {
			signers = append(signers, s)
		}
	}
	return signers
}

// ---------------------------------------------------------------------------
// Dialing
// ---------------------------------------------------------------------------

type dialTarget struct {
	Host     string
	Port     int
	User     string
	Keys     []string // private key files to try first
	Password string   // used if set
	Prompt   bool     // ask for a password if keys fail and Password is empty
}

// hostKeyCallback verifies against ~/.kubestui/known_hosts, asking the user
// to trust unknown hosts and refusing changed keys.
func hostKeyCallback() (ssh.HostKeyCallback, error) {
	path := knownHostsPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if f, err := os.OpenFile(path, os.O_CREATE|os.O_RDONLY, 0o600); err == nil {
		f.Close()
	}
	check, err := knownhosts.New(path)
	if err != nil {
		return nil, err
	}

	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := check(hostname, remote, key)
		if err == nil {
			return nil
		}
		var keyErr *knownhosts.KeyError
		if !errors.As(err, &keyErr) {
			return err
		}
		if len(keyErr.Want) > 0 {
			return fmt.Errorf("HOST KEY CHANGED for %s (now %s). This can mean the node was "+
				"reinstalled, or that someone is intercepting the connection. If the node was "+
				"reinstalled, delete its line from %s and connect again",
				hostname, ssh.FingerprintSHA256(key), path)
		}

		text := fmt.Sprintf("First connection to %s\n\n%s\n%s\n\nOnly trust it if this is your node.",
			hostname, key.Type(), ssh.FingerprintSHA256(key))
		if !askYesNo("NEW HOST", text, "Trust", "Cancel") {
			return errors.New("host not trusted")
		}

		line := knownhosts.Line([]string{knownhosts.Normalize(hostname)}, key)
		f, ferr := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
		if ferr != nil {
			return ferr
		}
		defer f.Close()
		_, ferr = f.WriteString(line + "\n")
		return ferr
	}, nil
}

func dialSSH(t dialTarget) (*ssh.Client, error) {
	hkc, err := hostKeyCallback()
	if err != nil {
		return nil, err
	}

	var auth []ssh.AuthMethod
	if signers := loadSigners(t.Keys...); len(signers) > 0 {
		auth = append(auth, ssh.PublicKeys(signers...))
	}

	password := t.Password
	var pwOnce sync.Once
	getPassword := func() (string, error) {
		var err error
		pwOnce.Do(func() {
			if password == "" && t.Prompt {
				pw, ok := askSecret("PASSWORD", fmt.Sprintf("%s@%s", t.User, t.Host))
				if !ok {
					err = errors.New("cancelled")
					return
				}
				password = pw
			}
		})
		if err == nil && password == "" {
			err = errors.New("no password")
		}
		return password, err
	}
	if t.Password != "" || t.Prompt {
		auth = append(auth,
			ssh.PasswordCallback(getPassword),
			ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range questions {
					pw, err := getPassword()
					if err != nil {
						return nil, err
					}
					answers[i] = pw
				}
				return answers, nil
			}),
		)
	}

	port := t.Port
	if port <= 0 {
		port = 22
	}
	cfg := &ssh.ClientConfig{
		User:            t.User,
		Auth:            auth,
		HostKeyCallback: hkc,
		Timeout:         15 * time.Second,
	}
	// Through the built-in VPN when the node is behind it (vpn.go).
	addr := net.JoinHostPort(t.Host, strconv.Itoa(port))
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()
	c, err := vpnDial(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	// A server that accepts the connection but never answers must not
	// hang the handshake.
	_ = c.SetDeadline(time.Now().Add(cfg.Timeout))
	sc, chans, reqs, err := ssh.NewClientConn(c, addr, cfg)
	if err != nil {
		c.Close()
		return nil, err
	}
	_ = c.SetDeadline(time.Time{})
	return ssh.NewClient(sc, chans, reqs), nil
}

// runRemote runs a command and returns its stdout. stdin may be empty.
func runRemote(client *ssh.Client, command, stdin string) (string, error) {
	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()
	var out, errOut bytes.Buffer
	session.Stdout = &out
	session.Stderr = &errOut
	if stdin != "" {
		session.Stdin = strings.NewReader(stdin)
	}
	if err := session.Run(command); err != nil {
		msg := strings.TrimSpace(errOut.String())
		if msg == "" {
			msg = strings.TrimSpace(out.String())
		}
		if msg != "" {
			return out.String(), fmt.Errorf("%w: %s", err, msg)
		}
		return out.String(), err
	}
	return out.String(), nil
}

// authorizeKey adds pubLine to the remote user's authorized_keys (once).
func authorizeKey(client *ssh.Client, pubLine string) error {
	q := shellQuote(pubLine)
	_, err := runRemote(client,
		"umask 077; mkdir -p ~/.ssh && touch ~/.ssh/authorized_keys && "+
			"(grep -qxF "+q+" ~/.ssh/authorized_keys || echo "+q+" >> ~/.ssh/authorized_keys)", "")
	return err
}
