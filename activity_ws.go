package main

// Node list for the workstation's live activity panel. It asks the cluster
// API directly with this computer's own credential (no kubectl needed on
// Windows), through the built-in VPN when away. Profiles paired with the
// shared admin.conf have no token: those ask the control plane over SSH,
// key login only, so a background poll never prompts for a password.

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

func workstationNodeSource(p *clusterProfile) func() ([]nodeRow, error) {
	if p.demo {
		return func() ([]nodeRow, error) { return demoNodes, nil }
	}
	if !p.HasKube {
		return func() ([]nodeRow, error) { return nil, errors.New("no kubeconfig for this cluster") }
	}

	server, ca, token, err := kubeconfigFields(p.kubeconfigPath())
	if err != nil {
		return func() ([]nodeRow, error) { return sshNodes(p) }
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return func() ([]nodeRow, error) { return nil, errors.New("invalid cluster CA in kubeconfig") }
	}
	client := &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
			DialContext:     vpnDial, // through the built-in VPN when away
		},
	}
	url := strings.TrimRight(server, "/") + "/api/v1/nodes"

	return func() ([]nodeRow, error) {
		req, _ := http.NewRequest(http.MethodGet, url, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("cluster API: %s", resp.Status)
		}
		return parseNodes(body)
	}
}

// sshNodes reads the node list on the control plane (admin.conf profiles).
func sshNodes(p *clusterProfile) ([]nodeRow, error) {
	client, err := dialSSH(dialTarget{Host: p.Host, Port: p.port(), User: p.User, Keys: []string{p.keyPath()}})
	if err != nil {
		return nil, err
	}
	defer client.Close()
	out, err := runRemote(client,
		"kubectl get nodes -o json 2>/dev/null || sudo -n kubectl --kubeconfig /etc/kubernetes/admin.conf get nodes -o json", "")
	if err != nil {
		return nil, err
	}
	return parseNodes([]byte(out))
}

// workstationHint explains a failed poll in one short line.
func workstationHint(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "401"), strings.Contains(msg, "403"):
		return "credential rejected: remove and re-pair this cluster"
	case strings.Contains(msg, "certificate"):
		return "TLS check failed: " + msg
	case strings.Contains(msg, "timeout"), strings.Contains(msg, "refused"), strings.Contains(msg, "no route"):
		return "can't reach the API from here (away? connect the VPN); retrying"
	}
	if len(msg) > 70 {
		msg = msg[:69] + "…"
	}
	return msg
}
