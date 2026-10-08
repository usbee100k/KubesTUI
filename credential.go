package main

// Per-computer cluster credential for workstation mode.
//
// Instead of copying the shared /etc/kubernetes/admin.conf, pairing creates
// a ServiceAccount for this computer (kube-system/kubestui-<pc>-<rand>) bound
// to cluster-admin, with a long-lived token. Revoking deletes the
// ClusterRoleBinding and then the ServiceAccount, which invalidates the token
// immediately without affecting anything else.
//
// The ServiceAccount may delete itself (a Role limited to its own name), so
// a workstation can revoke its own access. That Role, its RoleBinding and the
// token Secret are cleaned up by Kubernetes when the ServiceAccount goes.
//
// List or revoke from a node:
//   kubectl get sa,clusterrolebinding -A -l app.kubernetes.io/managed-by=kubestui
//   kubectl delete clusterrolebinding <name>; kubectl -n kube-system delete sa <name>

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const credentialNamespace = "kube-system"

// credentialName returns a ServiceAccount name for this computer.
func credentialName() string {
	host, _ := os.Hostname()
	slug := profileSlug(host)
	if len(slug) > 40 {
		slug = strings.Trim(slug[:40], "-")
	}
	return "kubestui-" + slug + "-" + randomCode(5)
}

// credentialScript creates the ServiceAccount, bindings and token, then
// prints: API server, CA data, cluster name, base64 token (one per line).
// It runs as root on a control plane.
func credentialScript(name, computer string) string {
	return `set -e
export KUBECONFIG=/etc/kubernetes/admin.conf
n=` + shellQuote(name) + `
pc=` + shellQuote(computer) + `
ns=` + credentialNamespace + `
kubectl -n "$ns" create serviceaccount "$n" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n "$ns" label serviceaccount "$n" app.kubernetes.io/managed-by=kubestui "kubestui.io/computer=$pc" --overwrite >/dev/null
uid=$(kubectl -n "$ns" get serviceaccount "$n" -o jsonpath='{.metadata.uid}')
kubectl apply -f - >/dev/null <<YAML
apiVersion: v1
kind: Secret
metadata:
  name: $n-token
  namespace: $ns
  labels: {app.kubernetes.io/managed-by: kubestui}
  annotations: {kubernetes.io/service-account.name: $n}
type: kubernetes.io/service-account-token
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: $n
  labels: {app.kubernetes.io/managed-by: kubestui, kubestui.io/computer: $pc}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: cluster-admin}
subjects: [{kind: ServiceAccount, name: $n, namespace: $ns}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: $n-self
  namespace: $ns
  labels: {app.kubernetes.io/managed-by: kubestui}
  ownerReferences: [{apiVersion: v1, kind: ServiceAccount, name: $n, uid: $uid}]
rules: [{apiGroups: [""], resources: [serviceaccounts], resourceNames: [$n], verbs: [delete]}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: $n-self
  namespace: $ns
  labels: {app.kubernetes.io/managed-by: kubestui}
  ownerReferences: [{apiVersion: v1, kind: ServiceAccount, name: $n, uid: $uid}]
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: $n-self}
subjects: [{kind: ServiceAccount, name: $n, namespace: $ns}]
YAML
t=""
for i in $(seq 1 30); do
  t=$(kubectl -n "$ns" get secret "$n-token" -o jsonpath='{.data.token}')
  [ -n "$t" ] && break
  sleep 1
done
[ -n "$t" ] || { echo "the token was not issued" >&2; exit 1; }
kubectl config view --raw -o jsonpath='{.clusters[0].cluster.server}{"\n"}{.clusters[0].cluster.certificate-authority-data}{"\n"}{.clusters[0].name}{"\n"}'
echo "$t"
`
}

// runAsRoot runs a bash script as root on the node: directly for root,
// otherwise through sudo (without a password if allowed, else with it).
func runAsRoot(client *ssh.Client, user, password, script string) (string, error) {
	cmd := "bash -c " + shellQuote(script)
	if user == "root" {
		return runRemote(client, cmd, "")
	}
	out, err := runRemote(client, "sudo -n "+cmd, "")
	if err != nil && password != "" {
		out, err = runRemote(client, "sudo -S -p '' "+cmd, password+"\n")
	}
	return out, err
}

// createCredential sets up this computer's credential and returns the
// kubeconfig for it.
func createCredential(client *ssh.Client, user, password, name string) (string, error) {
	host, _ := os.Hostname()
	computer := profileSlug(host)
	if len(computer) > 63 {
		computer = strings.Trim(computer[:63], "-")
	}

	out, err := runAsRoot(client, user, password, credentialScript(name, computer))
	if err != nil {
		return "", err
	}

	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) < 4 {
		return "", errors.New("unexpected output while creating the credential")
	}
	server, ca, cluster := strings.TrimSpace(lines[0]), strings.TrimSpace(lines[1]), strings.TrimSpace(lines[2])
	token, err := base64.StdEncoding.DecodeString(strings.TrimSpace(lines[3]))
	if err != nil || server == "" || ca == "" {
		return "", errors.New("could not read the cluster address, CA or token")
	}
	if cluster == "" {
		cluster = "kubernetes"
	}
	return buildKubeconfig(server, ca, cluster, name, string(token)), nil
}

func buildKubeconfig(server, caData, cluster, user, token string) string {
	ctx := user + "@" + cluster
	return fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: %[3]s
  cluster:
    server: %[1]s
    certificate-authority-data: %[2]s
users:
- name: %[4]s
  user:
    token: %[5]s
contexts:
- name: %[6]s
  context:
    cluster: %[3]s
    user: %[4]s
current-context: %[6]s
`, server, caData, cluster, user, token, ctx)
}

// kubeconfigFields reads server, CA and token from a kubeconfig written by
// buildKubeconfig.
func kubeconfigFields(path string) (server string, ca []byte, token string, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", nil, "", err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case strings.HasPrefix(line, "server:"):
			server = strings.TrimSpace(strings.TrimPrefix(line, "server:"))
		case strings.HasPrefix(line, "certificate-authority-data:"):
			ca, _ = base64.StdEncoding.DecodeString(strings.TrimSpace(strings.TrimPrefix(line, "certificate-authority-data:")))
		case strings.HasPrefix(line, "token:"):
			token = strings.TrimSpace(strings.TrimPrefix(line, "token:"))
		}
	}
	if server == "" || len(ca) == 0 || token == "" {
		return "", nil, "", errors.New("kubeconfig has no token credential")
	}
	return server, ca, token, sc.Err()
}

// revokeCredential deletes this computer's ClusterRoleBinding and then its
// ServiceAccount, using the credential itself. Missing objects are fine.
func revokeCredential(p *clusterProfile) error {
	if p.Credential == "" {
		return errors.New("this profile uses the shared admin.conf, which can't be revoked per computer")
	}
	server, ca, token, err := kubeconfigFields(p.kubeconfigPath())
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return errors.New("invalid cluster CA in kubeconfig")
	}
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
			DialContext:     vpnDial, // through the built-in VPN when away
		},
	}

	del := func(path string) error {
		req, _ := http.NewRequest(http.MethodDelete, strings.TrimRight(server, "/")+path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound || resp.StatusCode/100 == 2 {
			return nil
		}
		return fmt.Errorf("DELETE %s: %s", path, resp.Status)
	}

	// Binding first (cluster-admin goes), then the account (token dies).
	if err := del("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/" + p.Credential); err != nil {
		return err
	}
	return del("/api/v1/namespaces/" + credentialNamespace + "/serviceaccounts/" + p.Credential)
}
