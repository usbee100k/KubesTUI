package main

// The SOC console: zooming the alerts panel (8, then Z) turns it into a
// blue-team security operations view. It isn't advertised anywhere, and
// the normal alerts panel is unchanged.
//
//   - Threat level, severity counts, open/new/resolved incidents, MTTR,
//     trends of open findings and warning events, posture score.
//   - Incident queue: every alert (incidents) plus security findings read
//     from the cluster's own settings (posture): privileged or host-level
//     pods, node folders mounted, added capabilities, cluster-admin
//     bindings, tokens of admin service accounts, unencrypted ingresses,
//     namespaces without network policies, mutable image tags, ... Each
//     has an ID, severity, first seen and dwell time, category, MITRE
//     ATT&CK for Containers mapping, evidence and response steps (ENTER).
//     Findings expected for system components are suppressed (baseline).
//   - ATT&CK tactics, attack surface (LAN IPs, NodePorts, web hosts),
//     assets (nodes) and a live stream of warning events and detections.

import (
	"fmt"
	"hash/fnv"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

type socSev int

const (
	sevInfo socSev = iota
	sevLow
	sevMed
	sevHigh
	sevCrit
)

var (
	socSevNames  = [...]string{"INFO", "LOW", "MED", "HIGH", "CRIT"}
	socSevColors = [...]string{"#5f87af", "#87afaf", "yellow", "#ff8700", "red"}
	socWeights   = [...]float64{0, 1, 4, 12, 30}
)

// ATT&CK for Containers techniques the findings map to.
var socTechniques = map[string]string{
	"T1611": "Escape to Host",
	"T1078": "Valid Accounts",
	"T1528": "Steal Application Access Token",
	"T1190": "Exploit Public-Facing Application",
	"T1040": "Network Sniffing",
	"T1525": "Implant Internal Image",
	"T1499": "Endpoint Denial of Service",
	"T1046": "Network Service Discovery",
}

// Kill-chain order for the tactics panel ("Operations" isn't ATT&CK:
// outages and drift).
var socTactics = []string{"Initial Access", "Persistence", "Privilege Escalation", "Credential Access",
	"Discovery", "Lateral Movement", "Impact", "Operations"}

type socFinding struct {
	Key        string
	Incident   bool // from an alert (something is wrong now), else posture
	Sev        socSev
	Category   string
	Tactic     string
	Technique  string // "T1611" or ""
	Object     string
	Title      string
	Evidence   []string
	Response   []string
	Since      time.Time
	Target     ccTarget
	Suppressed bool // expected for a system component (baseline)
}

func (f socFinding) id() string {
	h := fnv.New32a()
	h.Write([]byte(f.Key))
	prefix := "POS"
	if f.Incident {
		prefix = "INC"
	}
	return fmt.Sprintf("%s-%04X", prefix, h.Sum32()&0xffff)
}

func socCount(n int, what string) string {
	if n == 1 {
		return "1 " + what
	}
	return fmt.Sprintf("%d %ss", n, what)
}

func socUnique(l []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range l {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

func socSystemNS(ns string) bool {
	switch ns {
	case "kube-system", "kube-public", "kube-node-lease", "longhorn-system", "metallb-system", "ingress-nginx",
		"cert-manager", "node-feature-discovery", "kubestui", "cilium", "cilium-secrets":
		return true
	}
	return strings.HasPrefix(ns, "cattle-") || strings.HasPrefix(ns, "fleet-") || strings.HasPrefix(ns, "rancher-")
}

// socWorkload names a pod's workload: its controller, with a
// ReplicaSet's hash removed.
func socWorkload(p *ccPod) (kind, name string) {
	kind, name, ok := strings.Cut(p.Owner, "/")
	if !ok {
		return "pod", p.Name
	}
	if kind == "Node" { // a static pod (kube-apiserver, etcd)
		return "pod", p.Name
	}
	if kind == "Job" { // a CronJob's run: name-<minutes>
		if i := strings.LastIndex(name, "-"); i > 0 && strings.Trim(name[i+1:], "0123456789") == "" {
			return "cronjob", name[:i]
		}
	}
	if kind == "ReplicaSet" {
		if i := strings.LastIndex(name, "-"); i > 0 {
			name = name[:i]
		}
		kind = "Deployment"
	}
	return strings.ToLower(kind), name
}

var socDigits = strings.NewReplacer("0", "", "1", "", "2", "", "3", "", "4", "", "5", "", "6", "", "7", "", "8", "", "9", "")

// socFindings derives everything the queue shows from a snapshot.
func socFindings(s *ccSnapshot) []socFinding {
	var out []socFinding
	add := func(f socFinding) { out = append(out, f) }

	// Incidents: the alerts, classified; pods of one workload with the
	// same problem are one incident.
	grouped := map[string]int{} // key -> index in out
	for _, a := range s.Alerts {
		obj, pods := a.Object, ""
		if a.Target.Kind == "Pod" {
			if p := s.pod(a.Target.NS, a.Target.Name); p != nil {
				kind, name := socWorkload(p)
				obj, pods = p.NS+"/"+kind+"/"+name, p.Name
			}
		}
		key := "inc/" + obj + "/" + socDigits.Replace(a.Message)
		if i, ok := grouped[key]; ok && pods != "" {
			out[i].Evidence = append(out[i].Evidence, "pod "+pods+": "+a.Message)
			out[i].Title = fmt.Sprintf("%s (%d pods)", strings.SplitN(out[i].Title, " (", 2)[0], len(out[i].Evidence))
			if !a.Since.IsZero() && (out[i].Since.IsZero() || a.Since.Before(out[i].Since)) {
				out[i].Since = a.Since
			}
			continue
		}
		f := socFinding{Key: key, Incident: true,
			Sev: sevMed, Category: "Workload", Tactic: "Operations", Object: obj, Title: a.Message,
			Since: a.Since, Target: a.Target}
		if pods != "" {
			f.Evidence = []string{"pod " + pods + ": " + a.Message}
		}
		if a.Level == 2 {
			f.Sev = sevHigh
		}
		switch a.Target.Kind {
		case "API":
			f.Sev, f.Category = sevCrit, "Control plane"
			f.Response = []string{"Check the API server and etcd pods on each control plane (kube-system).", "Check the VIP (kube-vip) answers on the API address."}
		case "Node":
			f.Category = "Asset"
			if a.Level == 2 {
				f.Sev, f.Tactic = sevCrit, "Impact"
			}
			f.Response = []string{"Check the node is powered and on the network (ping, console).", "If it's up: systemctl status kubelet containerd; journalctl -u kubelet.", "Workloads on it move after ~5 minutes; volumes need Longhorn copies elsewhere."}
		case "Pod", "Deployment", "StatefulSet", "DaemonSet":
			f.Response = []string{"Read the logs (L on the pod) and its events.", "Look for a changed image, config, Secret or volume since it last ran."}
		case "App":
			f.Category = "Integrity"
			if strings.Contains(a.Message, "OutOfSync") {
				f.Title += " (live state differs from Git)"
				f.Response = []string{"Compare the live objects with Git in Argo CD (diff).", "A change nobody made through Git is a manual edit, or tampering: find who and revert by syncing."}
			} else {
				f.Response = []string{"Open the app in Argo CD and check which resource is unhealthy."}
			}
		case "Volume":
			f.Category = "Storage"
			if strings.Contains(a.Message, "faulted") {
				f.Sev, f.Tactic = sevCrit, "Impact"
			}
			f.Response = []string{"Check the volume in the Longhorn UI (replicas, events).", "Spread Storage Across Nodes keeps a copy on each node."}
		case "Certificate":
			f.Category = "Crypto"
			f.Response = []string{"kubectl describe certificate; check the cert-manager logs and the issuer."}
		}
		grouped[key] = len(out)
		add(f)
	}

	// Posture: per workload, from the pods' specs.
	type wl struct {
		ns, kind, name string
		sec            ccPodSec
		pod            *ccPod
	}
	seen := map[string]*wl{}
	var wls []*wl
	for i := range s.Pods {
		p := &s.Pods[i]
		if p.Status == "Completed" {
			continue
		}
		kind, name := socWorkload(p)
		k := p.NS + "/" + kind + "/" + name
		if seen[k] == nil {
			seen[k] = &wl{ns: p.NS, kind: kind, name: name, sec: p.Sec, pod: p}
			wls = append(wls, seen[k])
		}
	}
	adminSA := map[string]string{} // ns/name -> binding
	for _, b := range s.AdminBindings {
		for _, sub := range b.Subjects {
			if n, ok := strings.CutPrefix(sub, "ServiceAccount:"); ok {
				adminSA[n] = b.Name
			}
		}
	}
	var mayRoot, mutable, noLimit, privEsc []string
	for _, w := range wls {
		obj := w.ns + "/" + w.kind + "/" + w.name
		sys := socSystemNS(w.ns)
		target := ccTarget{Kind: "Pod", NS: w.pod.NS, Name: w.pod.Name}
		sec := w.sec
		sec.Caps = socUnique(sec.Caps)
		if len(sec.Privileged) > 0 {
			add(socFinding{Key: "pos/priv/" + obj, Sev: sevHigh, Category: "Privilege", Tactic: "Privilege Escalation", Technique: "T1611",
				Object: obj, Title: "privileged container: full access to the node (" + strings.Join(sec.Privileged, ", ") + ")",
				Evidence: []string{"securityContext.privileged: true in " + strings.Join(sec.Privileged, ", ")},
				Response: []string{"Remove privileged; add only the capabilities it needs.", "If it must stay (a system agent), pin its image and restrict who can change it."},
				Target:   target, Suppressed: sys})
		}
		if len(sec.HostNS) > 0 {
			sev := sevMed
			if strings.Contains(strings.Join(sec.HostNS, ","), "pid") || strings.Contains(strings.Join(sec.HostNS, ","), "ipc") {
				sev = sevHigh
			}
			add(socFinding{Key: "pos/hostns/" + obj, Sev: sev, Category: "Privilege", Tactic: "Privilege Escalation", Technique: "T1611",
				Object: obj, Title: "shares the node's " + strings.Join(sec.HostNS, ", ") + " namespace",
				Evidence: []string{"spec.host" + strings.Join(sec.HostNS, ", spec.host") + ": true"},
				Response: []string{"Use a Service or MetalLB IP instead of hostNetwork where possible.", "hostPID/hostIPC let it see and signal every process on the node: remove unless required."},
				Target:   target, Suppressed: sys})
		}
		if len(sec.HostPaths) > 0 {
			sev := sevMed
			for _, hp := range sec.HostPaths {
				for _, bad := range []string{"/", "/etc", "/root", "/proc", "/sys", "/dev", "/var/run", "/run", "/var/lib/kubelet", "/var/lib/containerd", "/run/containerd"} {
					if hp == bad || strings.HasSuffix(hp, ".sock") || (bad != "/" && strings.HasPrefix(hp, bad+"/")) {
						sev = sevHigh
					}
				}
			}
			add(socFinding{Key: "pos/hostpath/" + obj, Sev: sev, Category: "Privilege", Tactic: "Privilege Escalation", Technique: "T1611",
				Object: obj, Title: "mounts node folders: " + strings.Join(sec.HostPaths, " "),
				Evidence: []string{"hostPath volumes: " + strings.Join(sec.HostPaths, ", ")},
				Response: []string{"Mount read-only (readOnly: true) or move the data to a Longhorn volume.", "Never mount /, /etc, the container runtime socket or kubelet folders into an app."},
				Target:   target, Suppressed: sys})
		}
		if len(sec.Caps) > 0 {
			sev := sevLow
			for _, cp := range sec.Caps {
				switch cp {
				case "SYS_ADMIN", "SYS_MODULE", "SYS_PTRACE", "ALL", "BPF", "DAC_READ_SEARCH", "SYS_RAWIO":
					sev = sevHigh
				case "NET_ADMIN", "NET_RAW":
					sev = max(sev, sevMed)
				}
			}
			add(socFinding{Key: "pos/caps/" + obj, Sev: sev, Category: "Privilege", Tactic: "Privilege Escalation", Technique: "T1611",
				Object: obj, Title: "added capabilities: " + strings.Join(sec.Caps, " "),
				Evidence: []string{"securityContext.capabilities.add: " + strings.Join(sec.Caps, ", ")},
				Response: []string{"Keep only what it needs (a VPN needs NET_ADMIN; few apps need SYS_ADMIN or SYS_MODULE).", "Load kernel modules on the node instead of granting SYS_MODULE."},
				Target:   target, Suppressed: sys})
		}
		if b, ok := adminSA[w.ns+"/"+sec.SA]; ok && sec.Token {
			add(socFinding{Key: "pos/admintoken/" + obj, Sev: sevCrit, Category: "Identity", Tactic: "Credential Access", Technique: "T1528",
				Object: obj, Title: "runs with a cluster-admin token (service account " + sec.SA + ")",
				Evidence: []string{"ClusterRoleBinding " + b + " gives ServiceAccount " + w.ns + "/" + sec.SA + " cluster-admin", "the token is mounted (automountServiceAccountToken not false)"},
				Response: []string{"Anyone who gets a shell in this app owns the cluster.", "Bind a Role with only the permissions it needs, or set automountServiceAccountToken: false."},
				Target:   target, Suppressed: sys})
		}
		if sys {
			continue
		}
		if len(sec.MayRoot) > 0 {
			mayRoot = append(mayRoot, obj)
		}
		if len(sec.PrivEsc) > 0 {
			privEsc = append(privEsc, obj)
		}
		for _, img := range sec.Mutable {
			mutable = append(mutable, obj+"  "+img)
		}
		if len(sec.NoMemLimit) > 0 {
			noLimit = append(noLimit, obj)
		}
	}
	if len(mayRoot) > 0 {
		add(socFinding{Key: "pos/root", Sev: sevLow, Category: "Hardening", Tactic: "Privilege Escalation", Technique: "T1611",
			Object: socCount(len(mayRoot), "workload"), Title: "not forced to run as non-root",
			Evidence: mayRoot, Response: []string{"Set runAsNonRoot: true (and runAsUser) where the image supports it.", "linuxserver images: use PUID/PGID; they drop root after start."}})
	}
	if len(privEsc) > 0 {
		add(socFinding{Key: "pos/privesc", Sev: sevInfo, Category: "Hardening", Tactic: "Privilege Escalation", Technique: "T1611",
			Object: socCount(len(privEsc), "workload"), Title: "allowPrivilegeEscalation not disabled",
			Evidence: privEsc, Response: []string{"Set allowPrivilegeEscalation: false so setuid binaries can't raise privileges."}})
	}
	if len(mutable) > 0 {
		add(socFinding{Key: "pos/mutable", Sev: sevLow, Category: "Supply chain", Tactic: "Persistence", Technique: "T1525",
			Object: socCount(len(mutable), "image"), Title: "mutable image tags (:latest or none)",
			Evidence: mutable, Response: []string{"Pin a version tag (or a digest) so a pushed image can't silently replace it."}})
	}
	if len(noLimit) > 0 {
		add(socFinding{Key: "pos/nolimit", Sev: sevLow, Category: "Resilience", Tactic: "Impact", Technique: "T1499",
			Object: socCount(len(noLimit), "workload"), Title: "no memory limit: one runaway app can starve its node",
			Evidence: noLimit, Response: []string{"Set resources.limits.memory on each container."}})
	}

	// Identity: who holds cluster-admin.
	for _, b := range s.AdminBindings {
		var risky []string
		for _, sub := range b.Subjects {
			switch {
			case sub == "Group:system:masters", sub == "Group:kubeadm:cluster-admins":
			case strings.HasPrefix(sub, "ServiceAccount:"):
				ns, _, _ := strings.Cut(strings.TrimPrefix(sub, "ServiceAccount:"), "/")
				if !socSystemNS(ns) && ns != "argocd" {
					risky = append(risky, sub)
				}
			default:
				risky = append(risky, sub)
			}
		}
		sev := sevMed // people (Users, Groups): review
		for _, r := range risky {
			if strings.HasPrefix(r, "ServiceAccount:") {
				sev = sevHigh // a workload's identity: stealable token
			}
		}
		f := socFinding{Key: "pos/rbac/" + b.Name, Sev: sev, Category: "Identity", Tactic: "Privilege Escalation", Technique: "T1078",
			Object: "clusterrolebinding/" + b.Name, Title: "cluster-admin for " + strings.Join(b.Subjects, ", "),
			Evidence:   append([]string{"roleRef: ClusterRole/cluster-admin"}, b.Subjects...),
			Response:   []string{"Check each subject still needs full control of the cluster.", "Replace with a narrower ClusterRole; remove unused bindings."},
			Suppressed: len(risky) == 0}
		add(f)
	}

	// Exposure.
	var lan, nodePorts []string
	for _, svc := range s.Services {
		switch svc.Type {
		case "LoadBalancer":
			lan = append(lan, fmt.Sprintf("%s :%s  %s/%s", orDefault(svc.ExternalIP, "pending"), strings.Join(svc.Ports, ","), svc.NS, svc.Name))
		case "NodePort":
			nodePorts = append(nodePorts, fmt.Sprintf("*:%s  %s/%s", strings.Join(svc.Ports, ","), svc.NS, svc.Name))
		}
	}
	if len(lan) > 0 {
		add(socFinding{Key: "pos/lan", Sev: sevInfo, Category: "Exposure", Tactic: "Initial Access", Technique: "T1190",
			Object: socCount(len(lan), "service"), Title: "reachable on LAN IPs (MetalLB)", Evidence: lan,
			Response: []string{"Forward only the VPN port on the router; keep the rest LAN-only.", "Keep exposed apps patched and behind a login."}})
	}
	if len(nodePorts) > 0 {
		add(socFinding{Key: "pos/nodeport", Sev: sevLow, Category: "Exposure", Tactic: "Initial Access", Technique: "T1190",
			Object: socCount(len(nodePorts), "service"), Title: "open on every node's IP (NodePort)", Evidence: nodePorts,
			Response: []string{"Prefer an ingress host or a MetalLB IP; NodePorts open the port on all nodes."}})
	}
	for _, ing := range s.Ingresses {
		if !ing.TLS {
			add(socFinding{Key: "pos/notls/" + ing.Host, Sev: sevMed, Category: "Crypto", Tactic: "Credential Access", Technique: "T1040",
				Object: ing.NS + "/ingress/" + ing.Name, Title: "http://" + ing.Host + " without TLS: logins cross the network in clear text",
				Evidence: []string{"no spec.tls entry for " + ing.Host},
				Response: []string{"Add a tls section (cert-manager issues the certificate)."}})
		}
	}

	// Segmentation: namespaces with apps and no network policy.
	if s.HasPolicies {
		var flat []string
		nsSeen := map[string]bool{}
		for _, w := range wls {
			if !socSystemNS(w.ns) && !s.PolicyNS[w.ns] && !nsSeen[w.ns] {
				nsSeen[w.ns] = true
				flat = append(flat, w.ns)
			}
		}
		sort.Strings(flat)
		if len(flat) > 0 {
			add(socFinding{Key: "pos/flatnet", Sev: sevMed, Category: "Network", Tactic: "Lateral Movement", Technique: "T1046",
				Object: socCount(len(flat), "namespace"), Title: "no network policy: any pod can reach these apps",
				Evidence: flat, Response: []string{"Add a default-deny NetworkPolicy per namespace, then allow what each app needs (ingress-nginx, its database).", "A compromised app can otherwise scan and reach every other app."}})
		}
	}

	// Resilience and assets.
	cps, versions := 0, map[string][]string{}
	for _, n := range s.Nodes {
		if strings.Contains(n.Roles, "control-plane") {
			cps++
		}
		versions[n.Kubelet] = append(versions[n.Kubelet], n.Name)
	}
	if cps == 2 {
		add(socFinding{Key: "pos/quorum", Sev: sevMed, Category: "Resilience", Tactic: "Impact", Object: "etcd",
			Title:    "2 control planes: losing either one stops the cluster (etcd quorum)",
			Evidence: []string{"etcd needs a majority: 2 of 2"}, Response: []string{"Add a third control plane (Remote Join Control Plane)."}})
	}
	if len(versions) > 1 {
		var ev []string
		for v, ns := range versions {
			ev = append(ev, v+": "+strings.Join(ns, " "))
		}
		sort.Strings(ev)
		add(socFinding{Key: "pos/skew", Sev: sevLow, Category: "Patching", Tactic: "Operations", Object: socCount(len(s.Nodes), "node"),
			Title: "kubelet versions differ between nodes", Evidence: ev, Response: []string{"Upgrade the older nodes to the cluster's version."}})
	}
	for _, c := range s.Certs {
		if c.Ready && !c.NotAfter.IsZero() && time.Until(c.NotAfter) < 30*24*time.Hour && time.Until(c.NotAfter) >= 7*24*time.Hour {
			add(socFinding{Key: "pos/cert/" + c.NS + "/" + c.Name, Sev: sevLow, Category: "Crypto", Tactic: "Operations",
				Object: c.NS + "/certificate/" + c.Name, Title: "expires " + c.NotAfter.Local().Format("2006-01-02"),
				Response: []string{"cert-manager renews 30 days before expiry; if it hasn't, check the issuer."}})
		}
	}

	sortFindings(out)
	return out
}

func sortFindings(out []socFinding) {
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Suppressed != b.Suppressed {
			return !a.Suppressed
		}
		if a.Sev != b.Sev {
			return a.Sev > b.Sev
		}
		if a.Incident != b.Incident {
			return a.Incident
		}
		return a.Key < b.Key
	})
}

// ---------------------------------------------------------------------------
// Tracking over time
// ---------------------------------------------------------------------------

type socResolved struct {
	f           socFinding
	first, gone time.Time
}

type socFeedLine struct {
	t     time.Time
	color string
	text  string
}

type socState struct {
	at       time.Time
	started  time.Time
	first    map[string]time.Time
	findings []socFinding
	resolved []socResolved
	feed     []socFeedLine
	open     ccRing // open (unsuppressed) findings
	threat   ccRing
}

func newSOCState() *socState { return &socState{first: map[string]time.Time{}} }

func (st *socState) observe(s *ccSnapshot, extra []socFinding) {
	if s == nil || s.Time.Equal(st.at) || s.Errs["api"] != "" {
		return
	}
	baseline := st.at.IsZero()
	st.at = s.Time
	if baseline {
		st.started = s.Time
	}
	fs := append(socFindings(s), extra...)
	sortFindings(fs)
	now := s.Time
	cur := map[string]bool{}
	for _, f := range fs {
		cur[f.Key] = true
		if _, ok := st.first[f.Key]; ok {
			continue
		}
		t := now
		if !f.Since.IsZero() && f.Since.Before(now) {
			t = f.Since
		}
		st.first[f.Key] = t
		if !baseline && !f.Suppressed {
			st.feed = append(st.feed, socFeedLine{now, socSevColors[f.Sev], fmt.Sprintf("DETECT %s %-4s %s: %s", f.id(), socSevNames[f.Sev], f.Object, f.Title)})
		}
	}
	for _, f := range st.findings {
		if cur[f.Key] {
			continue
		}
		first := st.first[f.Key]
		delete(st.first, f.Key)
		st.resolved = append(st.resolved, socResolved{f: f, first: first, gone: now})
		if !f.Suppressed {
			st.feed = append(st.feed, socFeedLine{now, "green", fmt.Sprintf("RESOLVED %s %s after %s: %s", f.id(), f.Object, fmtDur(now.Sub(first)), f.Title)})
		}
	}
	if baseline {
		open := 0
		for _, f := range fs {
			if !f.Suppressed {
				open++
			}
		}
		st.feed = append(st.feed, socFeedLine{now, "aqua", fmt.Sprintf("SOC online: baseline of %d open findings, %d suppressed", open, len(fs)-open)})
	}
	st.findings = fs
	for len(st.resolved) > 0 && now.Sub(st.resolved[0].gone) > time.Hour {
		st.resolved = st.resolved[1:]
	}
	if len(st.feed) > 300 {
		st.feed = st.feed[len(st.feed)-300:]
	}
	threat, _, counts := st.scores()
	n := 0
	for _, c := range counts {
		n += c
	}
	st.open.push(float64(n))
	st.threat.push(threat)
}

// scores: threat level (incidents count fully, posture half), posture
// score (100 = nothing found), unsuppressed findings per severity.
func (st *socState) scores() (threat, posture float64, counts [5]int) {
	var pw float64
	for _, f := range st.findings {
		if f.Suppressed {
			continue
		}
		counts[f.Sev]++
		if f.Incident {
			threat += socWeights[f.Sev]
		} else {
			threat += socWeights[f.Sev] / 2
			pw += socWeights[f.Sev]
		}
	}
	// Both saturate smoothly: a few serious problems already read HIGH.
	return 100 * (1 - math.Exp(-threat/120)), 100 * math.Exp(-pw/80), counts
}

func socLevel(threat float64) (string, string) {
	switch {
	case threat >= 80:
		return "SEVERE", "red"
	case threat >= 55:
		return "HIGH", "#ff8700"
	case threat >= 30:
		return "ELEVATED", "yellow"
	case threat >= 10:
		return "GUARDED", "aqua"
	}
	return "LOW", "green"
}

func (c *commandCenter) socMode() bool { return c.zoom && c.focus == pAlerts && c.soc != nil }

// ---------------------------------------------------------------------------
// Drawing
// ---------------------------------------------------------------------------

func socTitle(screen tcell.Screen, r ccRect, title string) {
	drawBox(screen, r, tcell.NewRGBColor(0x2e, 0x5f, 0x8a))
	put(screen, "┤[#48dbfb::b]"+title+"[-::-]├", r.x+2, r.y, r.w-4)
}

// drawSOC draws the console into the zoomed alerts panel. Returns the
// screen row of the queue's first row (for the mouse).
func (c *commandCenter) drawSOC(screen tcell.Screen, in ccRect) int {
	s, st := c.snap, c.soc
	if s == nil || in.h < 8 || in.w < 40 {
		return c.drawTable(screen, pAlerts, in)
	}
	threat, posture, counts := st.scores()
	level, lcol := socLevel(threat)
	open, newN := 0, 0
	for _, f := range st.findings {
		if f.Suppressed {
			continue
		}
		open++
		if t, ok := st.first[f.Key]; ok && s.Time.Sub(t) < 15*time.Minute && t.After(st.started) {
			newN++
		}
	}
	var mttr time.Duration
	nInc := 0
	for _, r := range st.resolved {
		if r.f.Incident && !r.f.Suppressed {
			mttr += r.gone.Sub(r.first)
			nInc++
		}
	}
	mttrS := "-"
	if nInc > 0 {
		mttrS = fmtDur(mttr / time.Duration(nInc))
	}
	sevs := ""
	for i := sevCrit; i >= sevInfo; i-- {
		col := socSevColors[i]
		if counts[i] == 0 {
			col = "gray"
		}
		sevs += fmt.Sprintf("[%s]●[-] %s [%s::b]%d[-::-]  ", col, socSevNames[i], col, counts[i])
	}
	put(screen, fmt.Sprintf(" [gray]THREAT[-] %s [%s::b]%3.0f %s[-::-]  [gray]│[-]  %s[gray]│[-]  OPEN [::b]%d[::-]  NEW·15m [aqua::b]%d[-::-]  RESOLVED·1h [green::b]%d[-::-]  MTTR %s  [gray]│ SUPPRESSED %d[-]",
		meter(threat, 16), lcol, threat, level, sevs, open, newN, len(st.resolved), mttrS, len(st.findings)-open), in.x, in.y, in.w)

	// Warning events per minute over the last 30 minutes.
	perMin := make([]float64, 30)
	for _, e := range s.Events {
		if age := s.Time.Sub(e.Time); age >= 0 && age < 30*time.Minute {
			perMin[29-int(age/time.Minute)]++
		}
	}
	top := 1.0
	for _, v := range perMin {
		top = max(top, v)
	}
	openTop := 1.0
	for _, v := range st.open.v {
		openTop = max(openTop, v)
	}
	ready := 0
	for _, n := range s.Nodes {
		if n.Ready && !n.Unreachable {
			ready++
		}
	}
	api := "[green]ok[-]"
	if s.Readyz != "" && s.Readyz != "ok" {
		api = "[red]" + tview.Escape(s.Readyz) + "[-]"
	}
	put(screen, fmt.Sprintf(" [gray]POSTURE[-] %s [::b]%.0f[::-]/100  [gray]FINDINGS[-] %s  [gray]EVENTS/MIN[-] %s  [gray]│[-]  ASSETS %d/%d up · %d pods · API %s %dms  [gray]│ %sZ · on watch %s[-]",
		meter(posture, 10), posture, spark(st.open.v, 16, openTop), spark(perMin, 30, top),
		ready, len(s.Nodes), len(s.Pods), api, s.APIRTT.Milliseconds(), s.Time.UTC().Format("15:04:05"), fmtDur(s.Time.Sub(st.started))), in.x, in.y+1, in.w)

	body := ccRect{in.x, in.y + 2, in.w, in.h - 2}
	streamH := 0
	if body.h >= 20 {
		streamH = max(6, min(14, body.h/4))
	}
	midH := body.h - streamH
	rightW := 0
	if body.w >= 120 {
		rightW = max(40, min(70, body.w*34/100))
	}
	q := ccRect{body.x, body.y, body.w - rightW, midH}
	socTitle(screen, q, fmt.Sprintf("INCIDENT QUEUE · %d", len(st.findings)))
	rowsY := c.drawTable(screen, pAlerts, q.inner())
	c.hits = append(c.hits, ccHit{r: q, panel: pAlerts, rowsY: rowsY})

	if rightW > 0 {
		c.drawSOCRight(screen, ccRect{body.x + q.w, body.y, rightW, midH})
	}
	if streamH > 0 {
		c.drawSOCStream(screen, ccRect{body.x, body.y + midH, body.w, streamH})
	}
	return rowsY
}

func (c *commandCenter) drawSOCRight(screen tcell.Screen, r ccRect) {
	s, st := c.snap, c.soc

	// ATT&CK tactics.
	byTactic := map[string]int{}
	worst := map[string]socSev{}
	for _, f := range st.findings {
		if !f.Suppressed {
			byTactic[f.Tactic]++
			worst[f.Tactic] = max(worst[f.Tactic], f.Sev)
		}
	}
	tacticsH := min(len(socTactics)+2, r.h/3+2)
	tb := ccRect{r.x, r.y, r.w, tacticsH}
	socTitle(screen, tb, "ATT&CK TACTICS")
	in := tb.inner()
	most := 1
	for _, n := range byTactic {
		most = max(most, n)
	}
	for i, t := range socTactics {
		if i >= in.h {
			break
		}
		n := byTactic[t]
		bw := max(0, in.w-25)
		bar := strings.Repeat("■", (n*bw+most-1)/most)
		col := "#3a3a3a"
		if n > 0 {
			col = socSevColors[worst[t]]
		}
		put(screen, fmt.Sprintf("%-21s[%s]%s[-] [::b]%d[::-]", t, col, bar, n), in.x+1, in.y+i, in.w-1)
	}

	rest := r.h - tacticsH
	surfH := rest / 2
	sb := ccRect{r.x, r.y + tacticsH, r.w, surfH}
	socTitle(screen, sb, "ATTACK SURFACE · ways in from the LAN")
	var lines []string
	for _, svc := range s.Services {
		switch svc.Type {
		case "LoadBalancer":
			lines = append(lines, fmt.Sprintf("[#ff8700]LAN[-] %-15s [gray]:%s[-] %s/%s", orDefault(svc.ExternalIP, "pending"), strings.Join(svc.Ports, ","), svc.NS, svc.Name))
		case "NodePort":
			lines = append(lines, fmt.Sprintf("[yellow]NP [-] %-15s [gray]:%s[-] %s/%s", "every node", strings.Join(svc.Ports, ","), svc.NS, svc.Name))
		}
	}
	for _, ing := range s.Ingresses {
		if ing.TLS {
			lines = append(lines, "[green]TLS[-] https://"+ing.Host)
		} else {
			lines = append(lines, "[red]PLN[-] http://"+ing.Host+" [red]no TLS[-]")
		}
	}
	socLines(screen, sb.inner(), lines, "nothing exposed")

	ab := ccRect{r.x, r.y + tacticsH + surfH, r.w, rest - surfH}
	socTitle(screen, ab, "ASSETS")
	lines = nil
	for _, n := range s.Nodes {
		col := "green"
		switch {
		case n.Unreachable || !n.Ready:
			col = "red"
		case len(n.Pressure) > 0 || n.Unschedulable:
			col = "yellow"
		}
		role := "wk"
		if strings.Contains(n.Roles, "control-plane") {
			role = "cp"
		}
		up := "-"
		if !n.KubeletUp.IsZero() {
			up = fmtAge(n.KubeletUp)
		}
		kern := n.Kernel
		if i := strings.Index(kern, "-"); i > 0 {
			kern = kern[:i]
		}
		lines = append(lines, fmt.Sprintf("[%s]●[-] %-9s %s [%s]%-11s[-] [gray]%s k%s up %s · %dp[-]",
			col, fit(n.Name, 9, false), role, col, n.status(), n.Kubelet, kern, up, n.Pods))
	}
	socLines(screen, ab.inner(), lines, "no nodes")
}

func socLines(screen tcell.Screen, in ccRect, lines []string, empty string) {
	if len(lines) == 0 {
		put(screen, "[gray] "+empty+"[-]", in.x, in.y, in.w)
		return
	}
	for i, l := range lines {
		if i >= in.h {
			break
		}
		if i == in.h-1 && len(lines) > in.h {
			put(screen, fmt.Sprintf("[gray] … %d more[-]", len(lines)-i), in.x, in.y+i, in.w)
			break
		}
		put(screen, " "+l, in.x, in.y+i, in.w)
	}
}

// socEventColor: how loud a warning event is in the stream.
func socEventColor(reason string) string {
	switch reason {
	case "OOMKilling", "SystemOOM", "NodeNotReady", "Evicted", "FailedMount", "FailedAttachVolume", "Rebooted", "NodeHasDiskPressure", "FreeDiskSpaceFailed":
		return "#ff8700"
	case "BackOff", "Unhealthy", "FailedScheduling", "Failed", "FailedCreatePodSandBox", "ProbeWarning":
		return "yellow"
	}
	return "gray"
}

func (c *commandCenter) drawSOCStream(screen tcell.Screen, r ccRect) {
	s, st := c.snap, c.soc
	type line struct {
		t    time.Time
		text string
	}
	var lines []line
	for _, e := range s.Events {
		obj := strings.ToLower(e.Kind) + "/" + e.Name
		if e.NS != "" {
			obj = e.NS + "/" + obj
		}
		count := ""
		if e.Count > 1 {
			count = fmt.Sprintf(" [gray]×%d[-]", e.Count)
		}
		col := socEventColor(e.Reason)
		lines = append(lines, line{e.Time, fmt.Sprintf("[gray]%s[-] [%s]EVENT  %-20s[-] %-44s %s%s",
			e.Time.Local().Format("15:04:05"), col, fit(e.Reason, 20, false), tview.Escape(fit(obj, 44, false)), tview.Escape(e.Message), count)})
	}
	for _, f := range st.feed {
		lines = append(lines, line{f.t, fmt.Sprintf("[gray]%s[-] [%s::b]%s[-::-]", f.t.Local().Format("15:04:05"), f.color, tview.Escape(f.text))})
	}
	sort.SliceStable(lines, func(i, j int) bool { return lines[i].t.After(lines[j].t) })
	socTitle(screen, r, fmt.Sprintf("LIVE STREAM · warning events + detections · %d", len(lines)))
	in := r.inner()
	for i, l := range lines {
		if i >= in.h {
			break
		}
		put(screen, " "+l.text, in.x, in.y+i, in.w)
	}
	if len(lines) == 0 {
		put(screen, "[gray] quiet: no warning events[-]", in.x, in.y, in.w)
	}
}

// socTable is the incident queue.
func (c *commandCenter) socTable() *ccTable {
	st := c.soc
	t := &ccTable{
		cols: []ccCol{
			{title: "SEV", width: 4},
			{title: "ID", width: 8},
			{title: "STATE", width: 5},
			{title: "DWELL", width: 5, right: true, drop: 3},
			{title: "CATEGORY", width: 12, drop: 2},
			{title: "ATT&CK", width: 6, drop: 1},
			{title: "OBJECT", min: 18},
			{title: "FINDING", min: 24},
		},
		empty: "no findings: all clear",
	}
	base := 0
	for _, f := range st.findings {
		if f.Suppressed && !c.socShowBase {
			base++
			continue
		}
		state, scol := "OPEN", "white"
		first := st.first[f.Key]
		switch {
		case f.Suppressed:
			state, scol = "BASE", "gray"
		case first.After(st.started) && st.at.Sub(first) < 15*time.Minute:
			state, scol = "NEW", "aqua"
		}
		tech := orDefault(f.Technique, "—")
		col := socSevColors[f.Sev]
		objCol, msgCol := "", ""
		if f.Suppressed {
			col, objCol, msgCol = "#4a4a4a", "gray", "gray"
		}
		t.rows = append(t.rows, ccRow{key: "s/" + f.Key, dim: f.Suppressed, cells: []ccCell{
			{text: socSevNames[f.Sev], color: col}, {text: f.id(), color: "gray"}, {text: state, color: scol},
			{text: fmtAge(first), color: "gray"}, {text: f.Category, color: "#48dbfb"}, {text: tech, color: "gray"},
			{text: f.Object, color: objCol}, {text: f.Title, color: msgCol},
		}})
	}
	if base > 0 {
		t.rows = append(t.rows, ccRow{key: "base", dim: true, cells: []ccCell{
			{text: "····", color: "#4a4a4a"}, {text: "BASELINE", color: "gray"}, {text: "BASE", color: "gray"},
			{text: "", color: "gray"}, {text: "System", color: "gray"}, {text: "", color: "gray"},
			{text: fmt.Sprintf("%d findings", base), color: "gray"},
			{text: "expected on system components (Cilium, Longhorn, kube-system, ...): V shows them", color: "gray"},
		}})
	}
	for i := len(st.resolved) - 1; i >= 0; i-- {
		r := st.resolved[i]
		if r.f.Suppressed {
			continue
		}
		t.rows = append(t.rows, ccRow{key: "r/" + r.f.Key + "/" + r.gone.Format(time.RFC3339Nano), dim: true, cells: []ccCell{
			{text: socSevNames[r.f.Sev], color: "#4a4a4a"}, {text: r.f.id(), color: "gray"}, {text: "DONE", color: "green"},
			{text: fmtDur(r.gone.Sub(r.first)), color: "gray"}, {text: r.f.Category, color: "gray"}, {text: orDefault(r.f.Technique, "—"), color: "gray"},
			{text: r.f.Object, color: "gray"}, {text: r.f.Title, color: "gray"},
		}})
	}
	return t
}

// socDetail is the case file of one finding (ENTER in the queue).
func (c *commandCenter) socDetail(key string, w int) []string {
	st := c.soc
	var f *socFinding
	first, gone := time.Time{}, time.Time{}
	for i := range st.findings {
		if "s/"+st.findings[i].Key == key {
			f, first = &st.findings[i], st.first[st.findings[i].Key]
		}
	}
	if f == nil {
		for i := range st.resolved {
			r := &st.resolved[i]
			if "r/"+r.f.Key+"/"+r.gone.Format(time.RFC3339Nano) == key {
				f, first, gone = &r.f, r.first, r.gone
			}
		}
	}
	if f == nil {
		return []string{"[green]Resolved and aged out.[-]"}
	}
	status := "[white::b]OPEN[-::-]"
	switch {
	case !gone.IsZero():
		status = "[green::b]RESOLVED[-::-] " + gone.Local().Format("15:04:05") + " after " + fmtDur(gone.Sub(first))
	case f.Suppressed:
		status = "[gray]BASELINE: expected for a system component (suppressed)[-]"
	}
	kind := "Posture finding (how the cluster is set up)"
	if f.Incident {
		kind = "Incident (something is wrong now)"
	}
	attack := "[gray]— (operational, not an ATT&CK technique)[-]"
	if f.Technique != "" {
		attack = fmt.Sprintf("%s · [::b]%s[::-] %s   [gray]attack.mitre.org/techniques/%s[-]", f.Tactic, f.Technique, socTechniques[f.Technique], f.Technique)
	}
	l := []string{
		kv("CASE", fmt.Sprintf("[::b]%s[::-]   [%s::b]%s[-::-]", f.id(), socSevColors[f.Sev], socSevNames[f.Sev])),
		kv("STATUS", status),
		kv("TYPE", kind),
		kv("OBJECT", tview.Escape(f.Object)),
		kv("CATEGORY", f.Category),
		kv("ATT&CK", attack),
		kv("FIRST SEEN", first.Local().Format("2006-01-02 15:04:05")+"   [gray]dwell[-] "+fmtAge(first)),
		"",
	}
	for _, line := range wrapText(f.Title, w-2) {
		l = append(l, "[::b]"+line+"[::-]")
	}
	if len(f.Evidence) > 0 {
		l = append(l, "", section("EVIDENCE"))
		for _, e := range f.Evidence {
			for i, line := range wrapText(e, w-4) {
				p := "  • "
				if i > 0 {
					p = "    "
				}
				l = append(l, p+line)
			}
		}
	}
	if len(f.Response) > 0 {
		l = append(l, "", section("RESPONSE"))
		for n, r := range f.Response {
			for i, line := range wrapText(r, w-5) {
				p := fmt.Sprintf("  %d. ", n+1)
				if i > 0 {
					p = "     "
				}
				l = append(l, p+line)
			}
		}
	}
	switch f.Target.Kind {
	case "Pod":
		if c.snap.pod(f.Target.NS, f.Target.Name) != nil {
			l = append(l, "", section("LIVE: POD "+f.Target.NS+"/"+f.Target.Name), "[gray]L logs · X restart[-]")
			l = append(l, c.podDetail(f.Target.NS, f.Target.Name, w)...)
		}
	case "Node":
		l = append(l, "", section("LIVE: NODE "+f.Target.Name), "[gray]C cordon/uncordon[-]")
		l = append(l, c.nodeDetail(f.Target.Name, w)...)
	case "Device":
		l = append(l, "", section("LIVE: DEVICE"), "[gray]K marks it known[-]")
		l = append(l, c.netDeviceDetail(f.Target.Name, w)...)
	case "DNSClient":
		l = append(l, "", section("LIVE: DNS OF "+f.Target.Name))
		l = append(l, c.dnsClientDetail(f.Target.Name, w)...)
	case "App":
		l = append(l, "", section("LIVE: ARGO CD APP "+f.Target.Name))
		l = append(l, c.appDetail(f.Target.Name, w)...)
	}
	return l
}

// openSOCCase opens a finding's case file; the overlay's target is the
// finding's pod or node, so L, X and C work on it.
func (c *commandCenter) openSOCCase(key string) {
	o := &ccOverlay{title: "SOC CASE", build: func(w int) []string { return c.socDetail(key, w) }}
	for _, f := range c.soc.findings {
		if "s/"+f.Key == key {
			o.title = "SOC CASE " + f.id()
			if f.Target.Kind == "Pod" || f.Target.Kind == "Node" || f.Target.Kind == "Device" {
				o.target = f.Target
			}
		}
	}
	c.overlay = o
	c.setFooter()
}
