package main

// Command Center data access. The Command Center reads the Kubernetes API
// the cheapest way available:
//
//   - HTTP with the kubeconfig's own credential (token or client
//     certificate), through the built-in VPN when away. Workstations with
//     their own credential, and control planes (admin.conf).
//   - kubectl on this machine, when the kubeconfig can't be used directly.
//   - kubectl on the control plane over SSH (key login only, never a
//     prompt), for workstation profiles paired with the shared admin.conf.

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"go.yaml.in/yaml/v3"
	"golang.org/x/crypto/ssh"
)

// ccSource reads (and, for the few actions, changes) the cluster.
type ccSource interface {
	// GetMany fetches API paths; results are in the same order.
	GetMany(paths []string) []ccResult
	// Do runs a change: an HTTP request, or the kubectl arguments where
	// the source has no HTTP access.
	Do(r ccRequest) error
	// Label says how the cluster is reached, for the status line.
	Label() string
	Close()
}

type ccResult struct {
	data []byte
	err  error
}

type ccRequest struct {
	Method, Path, Body, ContentType string
	Kubectl                         []string // the same change as kubectl arguments
}

func ccGet(s ccSource, path string) ([]byte, error) {
	r := s.GetMany([]string{path})[0]
	return r.data, r.err
}

// ---------------------------------------------------------------------------
// Kubeconfig credentials
// ---------------------------------------------------------------------------

type kubeCreds struct {
	Server    string
	CA        []byte
	Token     string
	Cert, Key []byte
	Insecure  bool
}

// loadKubeCreds reads the current context's server and credential.
func loadKubeCreds(path string) (*kubeCreds, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var kc struct {
		CurrentContext string `yaml:"current-context"`
		Clusters       []struct {
			Name    string `yaml:"name"`
			Cluster struct {
				Server   string `yaml:"server"`
				CAData   string `yaml:"certificate-authority-data"`
				CAFile   string `yaml:"certificate-authority"`
				Insecure bool   `yaml:"insecure-skip-tls-verify"`
			} `yaml:"cluster"`
		} `yaml:"clusters"`
		Contexts []struct {
			Name    string `yaml:"name"`
			Context struct {
				Cluster string `yaml:"cluster"`
				User    string `yaml:"user"`
			} `yaml:"context"`
		} `yaml:"contexts"`
		Users []struct {
			Name string `yaml:"name"`
			User struct {
				Token     string `yaml:"token"`
				TokenFile string `yaml:"tokenFile"`
				CertData  string `yaml:"client-certificate-data"`
				KeyData   string `yaml:"client-key-data"`
				CertFile  string `yaml:"client-certificate"`
				KeyFile   string `yaml:"client-key"`
			} `yaml:"user"`
		} `yaml:"users"`
	}
	if err := yaml.Unmarshal(data, &kc); err != nil {
		return nil, err
	}

	clusterName, userName := "", ""
	for _, c := range kc.Contexts {
		if c.Name == kc.CurrentContext || (kc.CurrentContext == "" && len(kc.Contexts) == 1) {
			clusterName, userName = c.Context.Cluster, c.Context.User
		}
	}
	if clusterName == "" && len(kc.Clusters) == 1 && len(kc.Users) == 1 {
		clusterName, userName = kc.Clusters[0].Name, kc.Users[0].Name
	}

	base := filepath.Dir(path)
	file := func(p string) ([]byte, error) {
		if !filepath.IsAbs(p) {
			p = filepath.Join(base, p)
		}
		return os.ReadFile(p)
	}
	decode := func(inline, path string) ([]byte, error) {
		if inline != "" {
			return base64.StdEncoding.DecodeString(strings.TrimSpace(inline))
		}
		if path != "" {
			return file(path)
		}
		return nil, nil
	}

	c := &kubeCreds{}
	for _, cl := range kc.Clusters {
		if cl.Name != clusterName {
			continue
		}
		c.Server = strings.TrimRight(cl.Cluster.Server, "/")
		c.Insecure = cl.Cluster.Insecure
		if c.CA, err = decode(cl.Cluster.CAData, cl.Cluster.CAFile); err != nil {
			return nil, fmt.Errorf("cluster CA: %w", err)
		}
	}
	for _, u := range kc.Users {
		if u.Name != userName {
			continue
		}
		c.Token = u.User.Token
		if c.Token == "" && u.User.TokenFile != "" {
			t, err := file(u.User.TokenFile)
			if err != nil {
				return nil, err
			}
			c.Token = strings.TrimSpace(string(t))
		}
		if c.Cert, err = decode(u.User.CertData, u.User.CertFile); err != nil {
			return nil, fmt.Errorf("client certificate: %w", err)
		}
		if c.Key, err = decode(u.User.KeyData, u.User.KeyFile); err != nil {
			return nil, fmt.Errorf("client key: %w", err)
		}
	}
	switch {
	case c.Server == "":
		return nil, errors.New("kubeconfig has no server for its current context")
	case c.Token == "" && (len(c.Cert) == 0 || len(c.Key) == 0):
		return nil, errors.New("kubeconfig has no token or client certificate (exec/auth plugins aren't supported)")
	}
	return c, nil
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

type httpSource struct {
	client *http.Client
	server string
	token  string
	label  string
}

func newHTTPSource(c *kubeCreds, label string) (*httpSource, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: c.Insecure}
	if len(c.CA) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(c.CA) {
			return nil, errors.New("invalid cluster CA in kubeconfig")
		}
		tc.RootCAs = pool
	}
	if len(c.Cert) > 0 {
		pair, err := tls.X509KeyPair(c.Cert, c.Key)
		if err != nil {
			return nil, fmt.Errorf("client certificate: %w", err)
		}
		tc.Certificates = []tls.Certificate{pair}
	}
	return &httpSource{
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig:     tc,
				DialContext:         vpnDial, // through the built-in VPN when away
				MaxIdleConnsPerHost: 8,
			},
		},
		server: c.Server,
		token:  c.Token,
		label:  label,
	}, nil
}

func (s *httpSource) request(method, path, body, contentType string) ([]byte, error) {
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, s.server+path, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json, */*")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if s.token != "" {
		req.Header.Set("Authorization", "Bearer "+s.token)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		return nil, apiError(resp.StatusCode, data)
	}
	return data, nil
}

// apiError keeps the API's own message ("pods is forbidden: …").
func apiError(code int, body []byte) error {
	var st struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &st) == nil && st.Message != "" {
		return fmt.Errorf("%d: %s", code, st.Message)
	}
	msg := strings.TrimSpace(string(body))
	if len(msg) > 120 {
		msg = msg[:120]
	}
	if msg == "" {
		msg = http.StatusText(code)
	}
	return fmt.Errorf("%d: %s", code, msg)
}

func (s *httpSource) GetMany(paths []string) []ccResult {
	out := make([]ccResult, len(paths))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 6)
	for i, p := range paths {
		wg.Add(1)
		go func(i int, p string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			out[i].data, out[i].err = s.request(http.MethodGet, p, "", "")
		}(i, p)
	}
	wg.Wait()
	return out
}

func (s *httpSource) Do(r ccRequest) error {
	_, err := s.request(r.Method, r.Path, r.Body, r.ContentType)
	return err
}

func (s *httpSource) Label() string { return s.label }
func (s *httpSource) Close()        { s.client.CloseIdleConnections() }

// ---------------------------------------------------------------------------
// kubectl on this machine
// ---------------------------------------------------------------------------

type kubectlSource struct{}

func (kubectlSource) GetMany(paths []string) []ccResult {
	out := make([]ccResult, len(paths))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)
	for i, p := range paths {
		wg.Add(1)
		go func(i int, p string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			out[i].data, out[i].err = runKubectl("get", "--raw", p)
		}(i, p)
	}
	wg.Wait()
	return out
}

func runKubectl(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "kubectl", args...)
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return nil, errors.New(strings.TrimPrefix(msg, "Error from server "))
		}
		return nil, err
	}
	return out, nil
}

func (kubectlSource) Do(r ccRequest) error {
	args := r.Kubectl
	if len(args) == 0 {
		switch r.Method {
		case http.MethodDelete:
			args = []string{"delete", "--raw", r.Path}
		default:
			return errors.New("not supported through kubectl")
		}
	}
	_, err := runKubectl(args...)
	return err
}

func (kubectlSource) Label() string { return "kubectl on this node" }
func (kubectlSource) Close()        {}

// ---------------------------------------------------------------------------
// kubectl on the control plane over SSH
// ---------------------------------------------------------------------------

type sshKubeSource struct {
	p      *clusterProfile
	mu     sync.Mutex
	client *ssh.Client
}

// ccMarker separates the outputs of one batched SSH command.
const ccMarker = "@@KUBESTUI-CC "

const sshKubectl = `K=kubectl; kubectl version --request-timeout=5s >/dev/null 2>&1 || K="sudo -n kubectl --kubeconfig /etc/kubernetes/admin.conf"; `

func (s *sshKubeSource) dial() (*ssh.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.client != nil {
		return s.client, nil
	}
	c, err := dialSSH(dialTarget{Host: s.p.Host, Port: s.p.port(), User: s.p.User, Keys: []string{s.p.keyPath()}})
	if err != nil {
		return nil, err
	}
	s.client = c
	return c, nil
}

func (s *sshKubeSource) drop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.client != nil {
		s.client.Close()
		s.client = nil
	}
}

// GetMany runs every path in one SSH command, each output after a marker
// line with its exit code.
func (s *sshKubeSource) GetMany(paths []string) []ccResult {
	out := make([]ccResult, len(paths))
	fail := func(err error) []ccResult {
		for i := range out {
			out[i].err = err
		}
		return out
	}
	client, err := s.dial()
	if err != nil {
		return fail(err)
	}
	var script strings.Builder
	script.WriteString(sshKubectl)
	for i, p := range paths {
		fmt.Fprintf(&script, `o=$($K get --raw %s 2>&1); printf '%s%d %%d\n%%s\n' "$?" "$o"; `, shellQuote(p), ccMarker, i)
	}
	script.WriteString("true")
	raw, err := runRemote(client, script.String(), "")
	if err != nil {
		s.drop()
		return fail(err)
	}
	return parseBatch(raw, len(paths))
}

// parseBatch splits the batched command's output back into results.
func parseBatch(raw string, n int) []ccResult {
	out := make([]ccResult, n)
	cur := -1
	var buf strings.Builder
	codes := make([]int, n)
	for i := range codes {
		codes[i] = -1
	}
	for _, line := range strings.SplitAfter(raw, "\n") {
		if rest, ok := strings.CutPrefix(line, ccMarker); ok {
			if cur >= 0 {
				out[cur].data = []byte(buf.String())
			}
			buf.Reset()
			var idx, code int
			if _, err := fmt.Sscanf(rest, "%d %d", &idx, &code); err == nil && idx >= 0 && idx < n {
				cur, codes[idx] = idx, code
			} else {
				cur = -1
			}
			continue
		}
		if cur >= 0 {
			buf.WriteString(line)
		}
	}
	if cur >= 0 {
		out[cur].data = []byte(buf.String())
	}
	for i := range out {
		switch {
		case codes[i] == -1:
			out[i] = ccResult{err: errors.New("no output from the control plane")}
		case codes[i] != 0:
			msg := strings.TrimSpace(string(out[i].data))
			out[i] = ccResult{err: errors.New(strings.TrimPrefix(msg, "Error from server "))}
		default:
			out[i].data = bytes.TrimSuffix(out[i].data, []byte("\n"))
		}
	}
	return out
}

func (s *sshKubeSource) Do(r ccRequest) error {
	client, err := s.dial()
	if err != nil {
		return err
	}
	args := r.Kubectl
	if len(args) == 0 {
		if r.Method != http.MethodDelete {
			return errors.New("not supported over SSH")
		}
		args = []string{"delete", "--raw", r.Path}
	}
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = shellQuote(a)
	}
	_, err = runRemote(client, sshKubectl+"$K "+strings.Join(quoted, " "), "")
	if err != nil {
		s.drop()
	}
	return err
}

func (s *sshKubeSource) Label() string { return "kubectl on " + s.p.Host + " over SSH" }
func (s *sshKubeSource) Close()        { s.drop() }

// ---------------------------------------------------------------------------
// Choosing a source
// ---------------------------------------------------------------------------

// nodeCCSource: on a cluster node, the API with the kubeconfig in use
// (install.sh sets admin.conf on control planes), else kubectl.
func nodeCCSource() ccSource {
	var candidates []string
	if kc := os.Getenv("KUBECONFIG"); kc != "" {
		candidates = append(candidates, filepath.SplitList(kc)[0])
	}
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates, filepath.Join(home, ".kube", "config"))
	}
	candidates = append(candidates, "/etc/kubernetes/admin.conf")
	for _, path := range candidates {
		c, err := loadKubeCreds(path)
		if err != nil {
			continue
		}
		if s, err := newHTTPSource(c, "API "+apiHost(c.Server)); err == nil {
			return s
		}
	}
	return kubectlSource{}
}

// workstationCCSource: the cluster API with this computer's credential,
// else kubectl on the control plane over SSH.
func workstationCCSource(p *clusterProfile) (ccSource, error) {
	if p.demo {
		return newDemoCCSource(), nil
	}
	if !p.HasKube {
		return nil, errors.New("no kubeconfig for this cluster: remove it and pair again with an account that can sudo")
	}
	c, err := loadKubeCreds(p.kubeconfigPath())
	if err == nil {
		label := "API " + apiHost(c.Server)
		if tunnelFor(p) != nil {
			label += " via VPN"
		}
		return newHTTPSource(c, label)
	}
	return &sshKubeSource{p: p}, nil
}

func apiHost(server string) string {
	if u, err := url.Parse(server); err == nil && u.Host != "" {
		return u.Host
	}
	return server
}
