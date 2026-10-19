package main

// Command Center data: one snapshot of the cluster per refresh, built from
// the Kubernetes API (nodes, metrics-server usage, pods, kubelet stats) and
// the add-ons homelabCD installs (Argo CD, Longhorn, MetalLB, cert-manager).
// Fast-changing parts are read every refresh, the rest every few.

import (
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Snapshot
// ---------------------------------------------------------------------------

type ccNode struct {
	Name, IP, Roles, Kubelet, OS, Kernel, Runtime, Arch string
	Ready, Unschedulable, Unreachable                   bool
	Pressure                                            []string // MemoryPressure, …
	Conditions                                          [][3]string
	Taints, Labels                                      []string
	Created                                             time.Time

	CPUCap, CPUAlloc int64 // millicores
	MemCap, MemAlloc int64 // bytes
	PodCap           int

	HasUsage       bool
	CPUUse, MemUse int64
	CPUReq, MemReq int64 // sum of pod requests
	CPULim, MemLim int64
	Pods           int

	HasStats       bool
	FSUsed, FSCap  int64
	RxRate, TxRate float64 // bytes/s
	KubeletUp      time.Time
}

func (n *ccNode) cpuPct() float64 { return pct(n.CPUUse, n.CPUAlloc) }
func (n *ccNode) memPct() float64 { return pct(n.MemUse, n.MemAlloc) }

func (n *ccNode) status() string {
	switch {
	case n.Unreachable:
		return "unreachable"
	case !n.Ready:
		return "NotReady"
	case len(n.Pressure) > 0:
		return strings.Join(n.Pressure, ",")
	case n.Unschedulable:
		return "cordoned"
	}
	return "Ready"
}

type ccContainer struct {
	Name, Image, State, Reason, LastReason string
	Ready                                  bool
	Restarts                               int
	ExitCode                               int
	CPUReq, MemReq, CPULim, MemLim         int64
	CPUUse, MemUse                         int64
}

type ccPod struct {
	Name, NS, Node, IP, Phase, Status, Owner, QoS string
	Ready, Total, Restarts                        int
	Created, LastRestart                          time.Time
	CPUUse, MemUse                                int64
	HasUsage                                      bool
	CPUReq, MemReq, CPULim, MemLim                int64
	Containers                                    []ccContainer
	Sec                                           ccPodSec
}

// ccPodSec: what a pod may do on its node (for the SOC view).
type ccPodSec struct {
	Privileged []string // containers
	HostNS     []string // network, pid, ipc
	HostPaths  []string
	Caps       []string // added capabilities
	MayRoot    []string // containers not forced to run as non-root
	PrivEsc    []string // containers allowed to gain privileges
	Mutable    []string // images without a fixed tag (:latest or none)
	NoMemLimit []string // containers
	SA         string
	Token      bool // service account token mounted
}

// podSecurity reads a pod's security-relevant settings.
func podSecurity(hostNet, hostPID, hostIPC bool, podCtx *kSecurityContext, sa string, automount *bool, cs []kContainer) ccPodSec {
	sec := ccPodSec{SA: orDefault(sa, "default"), Token: automount == nil || *automount}
	for n, on := range map[string]bool{"network": hostNet, "pid": hostPID, "ipc": hostIPC} {
		if on {
			sec.HostNS = append(sec.HostNS, n)
		}
	}
	sort.Strings(sec.HostNS)
	podNonRoot := podCtx != nil && ((podCtx.RunAsNonRoot != nil && *podCtx.RunAsNonRoot) || (podCtx.RunAsUser != nil && *podCtx.RunAsUser > 0))
	for _, c := range cs {
		sc := c.SecurityContext
		if sc == nil {
			sc = &kSecurityContext{}
		}
		if sc.Privileged != nil && *sc.Privileged {
			sec.Privileged = append(sec.Privileged, c.Name)
		}
		if sc.Capabilities != nil {
			for _, cp := range sc.Capabilities.Add {
				sec.Caps = append(sec.Caps, strings.TrimPrefix(strings.ToUpper(cp), "CAP_"))
			}
		}
		nonRoot := podNonRoot
		if sc.RunAsNonRoot != nil {
			nonRoot = *sc.RunAsNonRoot
		}
		if sc.RunAsUser != nil {
			nonRoot = *sc.RunAsUser > 0
		}
		if !nonRoot {
			sec.MayRoot = append(sec.MayRoot, c.Name)
		}
		if sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation {
			sec.PrivEsc = append(sec.PrivEsc, c.Name)
		}
		img := c.Image
		if i := strings.LastIndex(img, "/"); i >= 0 {
			img = img[i+1:]
		}
		if !strings.Contains(c.Image, "@sha256:") && (!strings.Contains(img, ":") || strings.HasSuffix(img, ":latest")) {
			sec.Mutable = append(sec.Mutable, c.Image)
		}
		if c.Resources.Limits["memory"] == "" {
			sec.NoMemLimit = append(sec.NoMemLimit, c.Name)
		}
	}
	return sec
}

func (p *ccPod) key() string { return p.NS + "/" + p.Name }

// problem: anything a person should look at.
func (p *ccPod) problem() bool {
	switch p.Status {
	case "Running":
		return p.Ready < p.Total
	case "Succeeded", "Completed":
		return false
	}
	return true
}

type ccNamespace struct {
	Name, Phase             string
	Pods, Running, Problems int
	CPUUse, MemUse          int64
	CPUReq, MemReq          int64
	Created                 time.Time
}

type ccService struct {
	NS, Name, Type, ClusterIP, ExternalIP string
	Ports                                 []string
}

type ccIngress struct {
	NS, Name, Host, Backend, Address string
	TLS                              bool
}

type ccApp struct {
	Name, NS, Dest, Sync, Health, Phase, Message, Repo, Path, Revision string
}

type ccEvent struct {
	Time                         time.Time
	Type, NS, Kind, Name, Reason string
	Message                      string
	Count                        int
}

type ccVolume struct {
	Name, PVC, NS, State, Robustness, Node string
	Size, Actual                           int64
	Replicas                               int
	Longhorn                               bool
	Copies                                 []string // node of each replica (Longhorn)
}

// copiesOn says where a volume's copies are ("toji×2 gojo") and on how
// many different nodes.
func (v ccVolume) copiesOn() (string, int) {
	count := map[string]int{}
	var order []string
	for _, n := range v.Copies {
		if count[n] == 0 {
			order = append(order, n)
		}
		count[n]++
	}
	sort.Strings(order)
	var parts []string
	for _, n := range order {
		if count[n] > 1 {
			n += fmt.Sprintf("×%d", count[n])
		}
		parts = append(parts, n)
	}
	return strings.Join(parts, " "), len(order)
}

type ccDisk struct {
	Node             string
	Available, Total int64
}

type ccWorkload struct {
	Kind, NS, Name string
	Ready, Want    int
}

type ccCert struct {
	NS, Name, Reason string
	Ready            bool
	NotAfter         time.Time
}

type ccBinding struct {
	Name     string
	Subjects []string // Kind:namespace/name
}

type ccAlert struct {
	Level   int // 2 critical, 1 warning
	Object  string
	Message string
	Since   time.Time
	Target  ccTarget // where Enter goes
}

// ccTarget names something the Command Center can show in detail.
type ccTarget struct {
	Kind, NS, Name string
}

type ccSnapshot struct {
	Time    time.Time
	Took    time.Duration
	Source  string
	Version string
	Server  string
	Readyz  string // "ok" or the failure
	APIRTT  time.Duration

	Nodes      []ccNode
	Pods       []ccPod
	Namespaces []ccNamespace
	Services   []ccService
	Ingresses  []ccIngress
	Apps       []ccApp
	Events     []ccEvent
	Volumes    []ccVolume
	Disks      []ccDisk
	Workloads  []ccWorkload
	Certs      []ccCert
	Pools      []string
	Alerts     []ccAlert

	HasMetrics, HasApps, HasLonghorn, HasCerts bool

	// Ready nodes with a Longhorn disk where its engine doesn't run, so no
	// copies can be kept there (control planes without the toleration).
	NoEngine []string

	// For the SOC view: who is bound to cluster-admin, and which
	// namespaces have a network policy (HasPolicies: the API answered).
	AdminBindings []ccBinding
	PolicyNS      map[string]bool
	HasPolicies   bool

	// Section errors, shown in the panels ("metrics-server not installed").
	Errs map[string]string
}

func (s *ccSnapshot) node(name string) *ccNode {
	for i := range s.Nodes {
		if s.Nodes[i].Name == name {
			return &s.Nodes[i]
		}
	}
	return nil
}

func (s *ccSnapshot) pod(ns, name string) *ccPod {
	for i := range s.Pods {
		if s.Pods[i].NS == ns && s.Pods[i].Name == name {
			return &s.Pods[i]
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Collector
// ---------------------------------------------------------------------------

const (
	ccSlowEvery  = 5 // refreshes between reads of slow-changing parts
	ccStatsEvery = 2 // refreshes between kubelet stats reads
)

// ccNoProbe marks sources whose nodes can't be probed (the demo).
type ccNoProbe interface{ noProbe() }

type ccCollector struct {
	src  ccSource
	tick int
	prev *ccSnapshot

	// Network counters from the last kubelet stats read, per node.
	netPrev map[string]ccNetSample
	mu      sync.Mutex
}

type ccNetSample struct {
	at     time.Time
	rx, tx float64
}

func newCCCollector(src ccSource) *ccCollector {
	return &ccCollector{src: src, netPrev: map[string]ccNetSample{}}
}

// Paths read every refresh.
var ccFastPaths = []string{
	"/api/v1/nodes",
	"/apis/metrics.k8s.io/v1beta1/nodes",
	"/api/v1/pods",
	"/apis/metrics.k8s.io/v1beta1/pods",
	"/readyz",
}

// Paths read every ccSlowEvery refreshes (and the first time).
var ccSlowPaths = []string{
	"/version",
	"/api/v1/namespaces",
	"/api/v1/services",
	"/apis/networking.k8s.io/v1/ingresses",
	"/apis/argoproj.io/v1alpha1/applications",
	"/api/v1/events?fieldSelector=" + url.QueryEscape("type=Warning"),
	"/apis/longhorn.io/v1beta2/volumes",
	"/apis/longhorn.io/v1beta2/nodes",
	"/apis/longhorn.io/v1beta2/replicas",
	"/apis/longhorn.io/v1beta2/engineimages",
	"/api/v1/persistentvolumeclaims",
	"/apis/apps/v1/deployments",
	"/apis/apps/v1/statefulsets",
	"/apis/apps/v1/daemonsets",
	"/apis/metallb.io/v1beta1/ipaddresspools",
	"/apis/cert-manager.io/v1/certificates",
	"/apis/rbac.authorization.k8s.io/v1/clusterrolebindings",
	"/apis/networking.k8s.io/v1/networkpolicies",
	"/apis/cilium.io/v2/ciliumnetworkpolicies",
}

func statsPath(node string) string {
	return "/api/v1/nodes/" + url.PathEscape(node) + "/proxy/stats/summary"
}

// Collect reads the cluster once. Never returns nil.
func (c *ccCollector) Collect() *ccSnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()

	start := time.Now()
	s := &ccSnapshot{Time: start, Source: c.src.Label(), Errs: map[string]string{}}
	slow := c.prev == nil || c.tick%ccSlowEvery == 0
	stats := c.tick <= 2 || c.tick%ccStatsEvery == 0 // first two reads give the first rate
	c.tick++

	paths := append([]string{}, ccFastPaths...)
	if slow {
		paths = append(paths, ccSlowPaths...)
	}
	var statNodes []string
	if stats && c.prev != nil {
		for _, n := range c.prev.Nodes {
			if n.Ready && !n.Unreachable {
				statNodes = append(statNodes, n.Name)
				paths = append(paths, statsPath(n.Name))
			}
		}
	}

	// Knock on every known node's kubelet meanwhile: Kubernetes needs ~40s
	// to notice a node that lost power, this a second.
	var down map[string]bool
	probed := make(chan struct{})
	go func() {
		defer close(probed)
		if _, skip := c.src.(ccNoProbe); skip || c.prev == nil {
			return
		}
		rows := make([]nodeRow, 0, len(c.prev.Nodes))
		for _, n := range c.prev.Nodes {
			if n.IP != "" {
				rows = append(rows, nodeRow{name: n.Name, host: n.IP})
			}
		}
		probeNodes(rows)
		down = map[string]bool{}
		for _, r := range rows {
			down[r.name] = r.unreachable
		}
	}()

	res := c.src.GetMany(paths)
	<-probed
	got := map[string]ccResult{}
	for i, p := range paths {
		got[p] = res[i]
	}
	s.APIRTT = time.Since(start)

	// Nodes are the core: without them there's nothing to show.
	if r := got["/api/v1/nodes"]; r.err != nil {
		s.Errs["api"] = r.err.Error()
		s.Took = time.Since(start)
		if c.prev != nil { // keep the last picture, marked stale by the error
			keep := *c.prev
			keep.Errs = s.Errs
			keep.Time, keep.Took, keep.Source = s.Time, s.Took, s.Source
			return &keep
		}
		return s
	} else {
		s.Nodes = parseCCNodes(r.data)
		for i := range s.Nodes {
			s.Nodes[i].Unreachable = down[s.Nodes[i].Name]
		}
	}

	if r := got["/readyz"]; r.err != nil {
		s.Readyz = r.err.Error()
	} else {
		s.Readyz = strings.TrimSpace(string(r.data))
	}

	if r := got["/apis/metrics.k8s.io/v1beta1/nodes"]; r.err == nil {
		s.HasMetrics = true
		applyNodeMetrics(s.Nodes, r.data)
	} else {
		s.Errs["metrics"] = ccErr(r.err, "metrics-server")
	}

	if r := got["/api/v1/pods"]; r.err == nil {
		s.Pods = parseCCPods(r.data)
	} else {
		s.Errs["pods"] = r.err.Error()
	}
	if r := got["/apis/metrics.k8s.io/v1beta1/pods"]; r.err == nil {
		applyPodMetrics(s.Pods, r.data)
	}

	if slow {
		c.readSlow(s, got)
	} else if c.prev != nil {
		p := c.prev
		s.Version, s.Server = p.Version, p.Server
		s.Namespaces, s.Services, s.Ingresses = p.Namespaces, p.Services, p.Ingresses
		s.Apps, s.Events, s.Volumes, s.Disks = p.Apps, p.Events, p.Volumes, p.Disks
		s.Workloads, s.Certs, s.Pools = p.Workloads, p.Certs, p.Pools
		s.HasApps, s.HasLonghorn, s.HasCerts = p.HasApps, p.HasLonghorn, p.HasCerts
		s.NoEngine = p.NoEngine
		s.AdminBindings, s.PolicyNS, s.HasPolicies = p.AdminBindings, p.PolicyNS, p.HasPolicies
		for _, k := range []string{"apps", "storage", "network", "events", "certs"} {
			if e, ok := p.Errs[k]; ok {
				s.Errs[k] = e
			}
		}
	}

	// Kubelet stats: disk and network per node. Between reads, keep the
	// last values.
	statsGot := map[string]bool{}
	for _, name := range statNodes {
		if r := got[statsPath(name)]; r.err == nil {
			if n := s.node(name); n != nil {
				c.applyStats(n, r.data)
				statsGot[name] = true
			}
		}
	}
	if c.prev != nil {
		for i := range s.Nodes {
			n := &s.Nodes[i]
			if statsGot[n.Name] {
				continue
			}
			if old := c.prev.node(n.Name); old != nil && old.HasStats {
				n.HasStats, n.FSUsed, n.FSCap = true, old.FSUsed, old.FSCap
				n.RxRate, n.TxRate, n.KubeletUp = old.RxRate, old.TxRate, old.KubeletUp
			}
		}
	}

	summarize(s)
	s.Took = time.Since(start)
	c.prev = s
	return s
}

func (c *ccCollector) readSlow(s *ccSnapshot, got map[string]ccResult) {
	if r := got["/version"]; r.err == nil {
		var v struct {
			GitVersion string `json:"gitVersion"`
		}
		_ = json.Unmarshal(r.data, &v)
		s.Version = v.GitVersion
	}
	if r := got["/api/v1/namespaces"]; r.err == nil {
		s.Namespaces = parseCCNamespaces(r.data)
	}
	if r := got["/api/v1/services"]; r.err == nil {
		s.Services = parseCCServices(r.data)
	} else {
		s.Errs["network"] = r.err.Error()
	}
	if r := got["/apis/networking.k8s.io/v1/ingresses"]; r.err == nil {
		s.Ingresses = parseCCIngresses(r.data)
	}
	if r := got["/apis/argoproj.io/v1alpha1/applications"]; r.err == nil {
		s.HasApps = true
		s.Apps = parseCCApps(r.data)
	} else {
		s.Errs["apps"] = ccErr(r.err, "Argo CD")
	}
	if r := got["/api/v1/events?fieldSelector="+url.QueryEscape("type=Warning")]; r.err == nil {
		s.Events = parseCCEvents(r.data)
	} else {
		s.Errs["events"] = r.err.Error()
	}
	if r := got["/apis/longhorn.io/v1beta2/volumes"]; r.err == nil {
		s.HasLonghorn = true
		s.Volumes = parseLonghornVolumes(r.data)
		if r := got["/apis/longhorn.io/v1beta2/nodes"]; r.err == nil {
			s.Disks = parseLonghornDisks(r.data)
		}
		if r := got["/apis/longhorn.io/v1beta2/replicas"]; r.err == nil {
			applyLonghornReplicas(s.Volumes, r.data)
		}
		if r := got["/apis/longhorn.io/v1beta2/engineimages"]; r.err == nil {
			s.NoEngine = longhornNoEngine(r.data, s.Disks, s.Nodes)
		}
	}
	if r := got["/apis/rbac.authorization.k8s.io/v1/clusterrolebindings"]; r.err == nil {
		s.AdminBindings = parseAdminBindings(r.data)
	}
	s.PolicyNS = map[string]bool{}
	for _, path := range []string{"/apis/networking.k8s.io/v1/networkpolicies", "/apis/cilium.io/v2/ciliumnetworkpolicies"} {
		if r := got[path]; r.err == nil {
			s.HasPolicies = true
			var list struct {
				Items []struct {
					Metadata kMeta `json:"metadata"`
				} `json:"items"`
			}
			_ = json.Unmarshal(r.data, &list)
			for _, it := range list.Items {
				s.PolicyNS[it.Metadata.Namespace] = true
			}
		}
	}
	if r := got["/api/v1/persistentvolumeclaims"]; r.err == nil {
		s.Volumes = mergePVCs(s.Volumes, r.data)
	} else if !s.HasLonghorn {
		s.Errs["storage"] = r.err.Error()
	}
	for _, k := range []string{"deployments", "statefulsets", "daemonsets"} {
		if r := got["/apis/apps/v1/"+k]; r.err == nil {
			s.Workloads = append(s.Workloads, parseCCWorkloads(k, r.data)...)
		}
	}
	if r := got["/apis/metallb.io/v1beta1/ipaddresspools"]; r.err == nil {
		s.Pools = parseMetalLBPools(r.data)
	}
	if r := got["/apis/cert-manager.io/v1/certificates"]; r.err == nil {
		s.HasCerts = true
		s.Certs = parseCCCerts(r.data)
	}
}

// ccErr turns "404: the server could not find the requested resource" for
// an add-on into "<what> not installed".
func ccErr(err error, what string) string {
	if strings.HasPrefix(err.Error(), "404") || strings.Contains(err.Error(), "NotFound") ||
		strings.Contains(err.Error(), "the server could not find") {
		return what + " not installed"
	}
	return err.Error()
}

// ---------------------------------------------------------------------------
// Quantities
// ---------------------------------------------------------------------------

var quantitySuffix = map[string]float64{
	"n": 1e-9, "u": 1e-6, "m": 1e-3, "": 1,
	"k": 1e3, "M": 1e6, "G": 1e9, "T": 1e12, "P": 1e15, "E": 1e18,
	"Ki": 1 << 10, "Mi": 1 << 20, "Gi": 1 << 30, "Ti": 1 << 40, "Pi": 1 << 50, "Ei": 1 << 60,
}

// parseQuantity reads a Kubernetes quantity ("250m", "16Gi", "1e3").
func parseQuantity(s string) float64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	i := len(s)
	for i > 0 && (s[i-1] < '0' || s[i-1] > '9') && s[i-1] != '.' {
		i--
	}
	num, suf := s[:i], s[i:]
	if strings.ContainsAny(suf, "eE") && !strings.HasSuffix(suf, "i") && len(suf) > 1 {
		// exponent form: 1e3
		if f, err := strconv.ParseFloat(s, 64); err == nil {
			return f
		}
	}
	f, err := strconv.ParseFloat(num, 64)
	if err != nil {
		return 0
	}
	if m, ok := quantitySuffix[suf]; ok {
		return f * m
	}
	return f
}

func cpuMilli(s string) int64 { return int64(math.Round(parseQuantity(s) * 1000)) }
func memBytes(s string) int64 { return int64(parseQuantity(s)) }

func pct(a, b int64) float64 {
	if b <= 0 {
		return 0
	}
	return math.Min(100, float64(a)*100/float64(b))
}

// ---------------------------------------------------------------------------
// Parsers
// ---------------------------------------------------------------------------

type kMeta struct {
	Name              string            `json:"name"`
	Namespace         string            `json:"namespace"`
	CreationTimestamp time.Time         `json:"creationTimestamp"`
	DeletionTimestamp *time.Time        `json:"deletionTimestamp"`
	Labels            map[string]string `json:"labels"`
	OwnerReferences   []struct {
		Kind string `json:"kind"`
		Name string `json:"name"`
	} `json:"ownerReferences"`
}

func parseCCNodes(data []byte) []ccNode {
	var list struct {
		Items []struct {
			Metadata kMeta `json:"metadata"`
			Spec     struct {
				Unschedulable bool `json:"unschedulable"`
				Taints        []struct {
					Key, Value, Effect string
				} `json:"taints"`
			} `json:"spec"`
			Status struct {
				Capacity    map[string]string `json:"capacity"`
				Allocatable map[string]string `json:"allocatable"`
				Addresses   []struct {
					Type    string `json:"type"`
					Address string `json:"address"`
				} `json:"addresses"`
				Conditions []struct {
					Type, Status, Reason, Message string
				} `json:"conditions"`
				NodeInfo struct {
					KubeletVersion          string `json:"kubeletVersion"`
					OSImage                 string `json:"osImage"`
					KernelVersion           string `json:"kernelVersion"`
					ContainerRuntimeVersion string `json:"containerRuntimeVersion"`
					Architecture            string `json:"architecture"`
				} `json:"nodeInfo"`
			} `json:"status"`
		} `json:"items"`
	}
	_ = json.Unmarshal(data, &list)
	var out []ccNode
	for _, it := range list.Items {
		n := ccNode{
			Name:          it.Metadata.Name,
			Created:       it.Metadata.CreationTimestamp,
			Unschedulable: it.Spec.Unschedulable,
			Kubelet:       it.Status.NodeInfo.KubeletVersion,
			OS:            it.Status.NodeInfo.OSImage,
			Kernel:        it.Status.NodeInfo.KernelVersion,
			Runtime:       it.Status.NodeInfo.ContainerRuntimeVersion,
			Arch:          it.Status.NodeInfo.Architecture,
			CPUCap:        cpuMilli(it.Status.Capacity["cpu"]),
			CPUAlloc:      cpuMilli(it.Status.Allocatable["cpu"]),
			MemCap:        memBytes(it.Status.Capacity["memory"]),
			MemAlloc:      memBytes(it.Status.Allocatable["memory"]),
		}
		n.PodCap, _ = strconv.Atoi(it.Status.Allocatable["pods"])
		for _, a := range it.Status.Addresses {
			if a.Type == "InternalIP" && n.IP == "" {
				n.IP = a.Address
			}
		}
		var roles []string
		for k, v := range it.Metadata.Labels {
			if role, ok := strings.CutPrefix(k, "node-role.kubernetes.io/"); ok && role != "" {
				roles = append(roles, role)
			}
			if strings.HasPrefix(k, "kubernetes.io/") || strings.HasPrefix(k, "beta.kubernetes.io/") ||
				strings.HasPrefix(k, "feature.node.kubernetes.io/") {
				continue // standard or NFD noise
			}
			n.Labels = append(n.Labels, k+"="+v)
		}
		sort.Strings(roles)
		sort.Strings(n.Labels)
		n.Roles = strings.Join(roles, ",")
		if n.Roles == "" {
			n.Roles = "worker"
		}
		for _, t := range it.Spec.Taints {
			s := t.Key
			if t.Value != "" {
				s += "=" + t.Value
			}
			n.Taints = append(n.Taints, s+":"+t.Effect)
		}
		for _, c := range it.Status.Conditions {
			n.Conditions = append(n.Conditions, [3]string{c.Type, c.Status, strings.TrimSpace(c.Reason + " " + c.Message)})
			switch {
			case c.Type == "Ready":
				n.Ready = c.Status == "True"
			case c.Status == "True" && strings.HasSuffix(c.Type, "Pressure"):
				n.Pressure = append(n.Pressure, c.Type)
			}
		}
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

type kMetricsList struct {
	Items []struct {
		Metadata   kMeta             `json:"metadata"`
		Usage      map[string]string `json:"usage"`
		Containers []struct {
			Name  string            `json:"name"`
			Usage map[string]string `json:"usage"`
		} `json:"containers"`
	} `json:"items"`
}

func applyNodeMetrics(nodes []ccNode, data []byte) {
	var list kMetricsList
	_ = json.Unmarshal(data, &list)
	for _, it := range list.Items {
		for i := range nodes {
			if nodes[i].Name == it.Metadata.Name {
				nodes[i].HasUsage = true
				nodes[i].CPUUse = cpuMilli(it.Usage["cpu"])
				nodes[i].MemUse = memBytes(it.Usage["memory"])
			}
		}
	}
}

func applyPodMetrics(pods []ccPod, data []byte) {
	var list kMetricsList
	_ = json.Unmarshal(data, &list)
	idx := map[string]*ccPod{}
	for i := range pods {
		idx[pods[i].key()] = &pods[i]
	}
	for _, it := range list.Items {
		p := idx[it.Metadata.Namespace+"/"+it.Metadata.Name]
		if p == nil {
			continue
		}
		p.HasUsage = true
		for _, c := range it.Containers {
			cpu, mem := cpuMilli(c.Usage["cpu"]), memBytes(c.Usage["memory"])
			p.CPUUse += cpu
			p.MemUse += mem
			for k := range p.Containers {
				if p.Containers[k].Name == c.Name {
					p.Containers[k].CPUUse, p.Containers[k].MemUse = cpu, mem
				}
			}
		}
	}
}

type kContainerStatus struct {
	Name         string `json:"name"`
	Ready        bool   `json:"ready"`
	RestartCount int    `json:"restartCount"`
	State        kState `json:"state"`
	LastState    kState `json:"lastTerminationState"`
}

type kState struct {
	Waiting *struct {
		Reason string `json:"reason"`
	} `json:"waiting"`
	Running *struct {
		StartedAt time.Time `json:"startedAt"`
	} `json:"running"`
	Terminated *struct {
		Reason     string    `json:"reason"`
		ExitCode   int       `json:"exitCode"`
		FinishedAt time.Time `json:"finishedAt"`
	} `json:"terminated"`
}

type kContainer struct {
	Name      string `json:"name"`
	Image     string `json:"image"`
	Resources struct {
		Requests map[string]string `json:"requests"`
		Limits   map[string]string `json:"limits"`
	} `json:"resources"`
	SecurityContext *kSecurityContext `json:"securityContext"`
}

type kSecurityContext struct {
	Privileged               *bool  `json:"privileged"`
	RunAsNonRoot             *bool  `json:"runAsNonRoot"`
	RunAsUser                *int64 `json:"runAsUser"`
	AllowPrivilegeEscalation *bool  `json:"allowPrivilegeEscalation"`
	Capabilities             *struct {
		Add []string `json:"add"`
	} `json:"capabilities"`
}

func parseCCPods(data []byte) []ccPod {
	var list struct {
		Items []struct {
			Metadata kMeta `json:"metadata"`
			Spec     struct {
				NodeName        string            `json:"nodeName"`
				Containers      []kContainer      `json:"containers"`
				InitContainers  []kContainer      `json:"initContainers"`
				HostNetwork     bool              `json:"hostNetwork"`
				HostPID         bool              `json:"hostPID"`
				HostIPC         bool              `json:"hostIPC"`
				SecurityContext *kSecurityContext `json:"securityContext"`
				ServiceAccount  string            `json:"serviceAccountName"`
				AutomountToken  *bool             `json:"automountServiceAccountToken"`
				Volumes         []struct {
					Name     string `json:"name"`
					HostPath *struct {
						Path string `json:"path"`
					} `json:"hostPath"`
				} `json:"volumes"`
			} `json:"spec"`
			Status struct {
				Phase             string             `json:"phase"`
				Reason            string             `json:"reason"`
				PodIP             string             `json:"podIP"`
				QOSClass          string             `json:"qosClass"`
				ContainerStatuses []kContainerStatus `json:"containerStatuses"`
				InitStatuses      []kContainerStatus `json:"initContainerStatuses"`
			} `json:"status"`
		} `json:"items"`
	}
	_ = json.Unmarshal(data, &list)
	out := make([]ccPod, 0, len(list.Items))
	for _, it := range list.Items {
		p := ccPod{
			Name: it.Metadata.Name, NS: it.Metadata.Namespace, Node: it.Spec.NodeName,
			IP: it.Status.PodIP, Phase: it.Status.Phase, QoS: it.Status.QOSClass,
			Created: it.Metadata.CreationTimestamp, Total: len(it.Spec.Containers),
		}
		if len(it.Metadata.OwnerReferences) > 0 {
			o := it.Metadata.OwnerReferences[0]
			p.Owner = o.Kind + "/" + o.Name
		}
		p.Sec = podSecurity(it.Spec.HostNetwork, it.Spec.HostPID, it.Spec.HostIPC, it.Spec.SecurityContext,
			it.Spec.ServiceAccount, it.Spec.AutomountToken, append(append([]kContainer{}, it.Spec.InitContainers...), it.Spec.Containers...))
		for _, v := range it.Spec.Volumes {
			if v.HostPath != nil {
				p.Sec.HostPaths = append(p.Sec.HostPaths, v.HostPath.Path)
			}
		}
		status := map[string]kContainerStatus{}
		for _, cs := range it.Status.ContainerStatuses {
			status[cs.Name] = cs
		}
		for _, c := range it.Spec.Containers {
			cc := ccContainer{
				Name: c.Name, Image: c.Image,
				CPUReq: cpuMilli(c.Resources.Requests["cpu"]), MemReq: memBytes(c.Resources.Requests["memory"]),
				CPULim: cpuMilli(c.Resources.Limits["cpu"]), MemLim: memBytes(c.Resources.Limits["memory"]),
			}
			p.CPUReq += cc.CPUReq
			p.MemReq += cc.MemReq
			p.CPULim += cc.CPULim
			p.MemLim += cc.MemLim
			if cs, ok := status[c.Name]; ok {
				cc.Ready, cc.Restarts = cs.Ready, cs.RestartCount
				cc.State, cc.Reason, cc.ExitCode = describeState(cs.State)
				if t := cs.LastState.Terminated; t != nil {
					cc.LastReason = fmt.Sprintf("%s (exit %d)", t.Reason, t.ExitCode)
					if t.FinishedAt.After(p.LastRestart) {
						p.LastRestart = t.FinishedAt
					}
				}
				if cs.Ready {
					p.Ready++
				}
				p.Restarts += cs.RestartCount
			} else {
				cc.State = "waiting"
			}
			p.Containers = append(p.Containers, cc)
		}

		// STATUS like kubectl's: the most telling reason.
		p.Status = it.Status.Phase
		if it.Status.Reason != "" {
			p.Status = it.Status.Reason // Evicted, …
		}
		for i, cs := range it.Status.InitStatuses {
			if t := cs.State.Terminated; t != nil && t.ExitCode == 0 {
				continue
			}
			switch {
			case cs.State.Waiting != nil && cs.State.Waiting.Reason != "" && cs.State.Waiting.Reason != "PodInitializing":
				p.Status = "Init:" + cs.State.Waiting.Reason
			case cs.State.Terminated != nil:
				p.Status = "Init:" + cs.State.Terminated.Reason
			default:
				p.Status = fmt.Sprintf("Init:%d/%d", i, len(it.Spec.InitContainers))
			}
			break
		}
		if !strings.HasPrefix(p.Status, "Init:") {
			for _, cs := range it.Status.ContainerStatuses {
				if w := cs.State.Waiting; w != nil && w.Reason != "" {
					p.Status = w.Reason
					break
				}
				if t := cs.State.Terminated; t != nil && t.Reason != "" && p.Phase != "Succeeded" {
					p.Status = t.Reason
				}
			}
		}
		if p.Phase == "Succeeded" {
			p.Status = "Completed"
		}
		if it.Metadata.DeletionTimestamp != nil {
			p.Status = "Terminating"
		}
		out = append(out, p)
	}
	return out
}

func describeState(s kState) (state, reason string, exit int) {
	switch {
	case s.Running != nil:
		return "running", "", 0
	case s.Waiting != nil:
		return "waiting", s.Waiting.Reason, 0
	case s.Terminated != nil:
		return "terminated", s.Terminated.Reason, s.Terminated.ExitCode
	}
	return "unknown", "", 0
}

func parseCCNamespaces(data []byte) []ccNamespace {
	var list struct {
		Items []struct {
			Metadata kMeta `json:"metadata"`
			Status   struct {
				Phase string `json:"phase"`
			} `json:"status"`
		} `json:"items"`
	}
	_ = json.Unmarshal(data, &list)
	var out []ccNamespace
	for _, it := range list.Items {
		out = append(out, ccNamespace{Name: it.Metadata.Name, Phase: it.Status.Phase, Created: it.Metadata.CreationTimestamp})
	}
	return out
}

func parseCCServices(data []byte) []ccService {
	var list struct {
		Items []struct {
			Metadata kMeta `json:"metadata"`
			Spec     struct {
				Type      string `json:"type"`
				ClusterIP string `json:"clusterIP"`
				Ports     []struct {
					Port     int    `json:"port"`
					NodePort int    `json:"nodePort"`
					Protocol string `json:"protocol"`
				} `json:"ports"`
			} `json:"spec"`
			Status struct {
				LoadBalancer struct {
					Ingress []struct {
						IP       string `json:"ip"`
						Hostname string `json:"hostname"`
					} `json:"ingress"`
				} `json:"loadBalancer"`
			} `json:"status"`
		} `json:"items"`
	}
	_ = json.Unmarshal(data, &list)
	var out []ccService
	for _, it := range list.Items {
		s := ccService{NS: it.Metadata.Namespace, Name: it.Metadata.Name, Type: it.Spec.Type, ClusterIP: it.Spec.ClusterIP}
		for _, ing := range it.Status.LoadBalancer.Ingress {
			s.ExternalIP = orDefault(ing.IP, ing.Hostname)
		}
		for _, p := range it.Spec.Ports {
			port := strconv.Itoa(p.Port)
			if s.Type == "NodePort" && p.NodePort > 0 {
				port = strconv.Itoa(p.NodePort)
			}
			if p.Protocol != "" && p.Protocol != "TCP" {
				port += "/" + strings.ToLower(p.Protocol)
			}
			s.Ports = append(s.Ports, port)
		}
		out = append(out, s)
	}
	return out
}

func parseCCIngresses(data []byte) []ccIngress {
	var list struct {
		Items []struct {
			Metadata kMeta `json:"metadata"`
			Spec     struct {
				TLS []struct {
					Hosts []string `json:"hosts"`
				} `json:"tls"`
				Rules []struct {
					Host string `json:"host"`
					HTTP struct {
						Paths []struct {
							Backend struct {
								Service struct {
									Name string `json:"name"`
									Port struct {
										Number int    `json:"number"`
										Name   string `json:"name"`
									} `json:"port"`
								} `json:"service"`
							} `json:"backend"`
						} `json:"paths"`
					} `json:"http"`
				} `json:"rules"`
			} `json:"spec"`
			Status struct {
				LoadBalancer struct {
					Ingress []struct {
						IP string `json:"ip"`
					} `json:"ingress"`
				} `json:"loadBalancer"`
			} `json:"status"`
		} `json:"items"`
	}
	_ = json.Unmarshal(data, &list)
	var out []ccIngress
	for _, it := range list.Items {
		tls := map[string]bool{}
		for _, t := range it.Spec.TLS {
			for _, h := range t.Hosts {
				tls[h] = true
			}
		}
		addr := ""
		for _, i := range it.Status.LoadBalancer.Ingress {
			addr = i.IP
		}
		for _, r := range it.Spec.Rules {
			ing := ccIngress{NS: it.Metadata.Namespace, Name: it.Metadata.Name, Host: orDefault(r.Host, "*"), TLS: tls[r.Host], Address: addr}
			if len(r.HTTP.Paths) > 0 {
				svc := r.HTTP.Paths[0].Backend.Service
				port := svc.Port.Name
				if svc.Port.Number > 0 {
					port = strconv.Itoa(svc.Port.Number)
				}
				ing.Backend = svc.Name + ":" + port
			}
			out = append(out, ing)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out
}

func parseCCApps(data []byte) []ccApp {
	var list struct {
		Items []struct {
			Metadata kMeta `json:"metadata"`
			Spec     struct {
				Destination struct {
					Namespace string `json:"namespace"`
				} `json:"destination"`
				Source *struct {
					RepoURL string `json:"repoURL"`
					Path    string `json:"path"`
					Chart   string `json:"chart"`
				} `json:"source"`
				Sources []struct {
					RepoURL string `json:"repoURL"`
					Path    string `json:"path"`
					Chart   string `json:"chart"`
				} `json:"sources"`
			} `json:"spec"`
			Status struct {
				Sync struct {
					Status   string `json:"status"`
					Revision string `json:"revision"`
				} `json:"sync"`
				Health struct {
					Status  string `json:"status"`
					Message string `json:"message"`
				} `json:"health"`
				OperationState *struct {
					Phase   string `json:"phase"`
					Message string `json:"message"`
				} `json:"operationState"`
				Conditions []struct {
					Type    string `json:"type"`
					Message string `json:"message"`
				} `json:"conditions"`
			} `json:"status"`
		} `json:"items"`
	}
	_ = json.Unmarshal(data, &list)
	var out []ccApp
	for _, it := range list.Items {
		a := ccApp{
			Name: it.Metadata.Name, NS: orDefault(it.Metadata.Namespace, "argocd"), Dest: it.Spec.Destination.Namespace,
			Sync: orDefault(it.Status.Sync.Status, "Unknown"), Health: orDefault(it.Status.Health.Status, "Unknown"),
			Revision: it.Status.Sync.Revision, Message: it.Status.Health.Message,
		}
		if len(a.Revision) > 8 {
			a.Revision = a.Revision[:8]
		}
		src := it.Spec.Source
		if src == nil && len(it.Spec.Sources) > 0 {
			src = &it.Spec.Sources[0]
		}
		if src != nil {
			a.Repo, a.Path = src.RepoURL, orDefault(src.Path, src.Chart)
		}
		if op := it.Status.OperationState; op != nil {
			a.Phase = op.Phase
			if a.Message == "" && op.Phase != "Succeeded" {
				a.Message = op.Message
			}
		}
		for _, c := range it.Status.Conditions {
			if a.Message == "" {
				a.Message = c.Type + ": " + c.Message
			}
		}
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func parseCCEvents(data []byte) []ccEvent {
	var list struct {
		Items []struct {
			Metadata       kMeta `json:"metadata"`
			InvolvedObject struct {
				Kind      string `json:"kind"`
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"involvedObject"`
			Reason        string     `json:"reason"`
			Message       string     `json:"message"`
			Type          string     `json:"type"`
			Count         int        `json:"count"`
			LastTimestamp *time.Time `json:"lastTimestamp"`
			EventTime     *time.Time `json:"eventTime"`
			Series        *struct {
				Count            int        `json:"count"`
				LastObservedTime *time.Time `json:"lastObservedTime"`
			} `json:"series"`
		} `json:"items"`
	}
	_ = json.Unmarshal(data, &list)
	var out []ccEvent
	for _, it := range list.Items {
		e := ccEvent{
			Type: it.Type, NS: it.InvolvedObject.Namespace, Kind: it.InvolvedObject.Kind,
			Name: it.InvolvedObject.Name, Reason: it.Reason, Count: max(it.Count, 1),
			Message: strings.Join(strings.Fields(it.Message), " "),
			Time:    it.Metadata.CreationTimestamp,
		}
		switch {
		case it.Series != nil && it.Series.LastObservedTime != nil:
			e.Time, e.Count = *it.Series.LastObservedTime, max(it.Series.Count, 1)
		case it.LastTimestamp != nil && !it.LastTimestamp.IsZero():
			e.Time = *it.LastTimestamp
		case it.EventTime != nil && !it.EventTime.IsZero():
			e.Time = *it.EventTime
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Time.After(out[j].Time) })
	if len(out) > 200 {
		out = out[:200]
	}
	return out
}

func parseLonghornVolumes(data []byte) []ccVolume {
	var list struct {
		Items []struct {
			Metadata kMeta `json:"metadata"`
			Spec     struct {
				Size             string `json:"size"`
				NumberOfReplicas int    `json:"numberOfReplicas"`
			} `json:"spec"`
			Status struct {
				State            string `json:"state"`
				Robustness       string `json:"robustness"`
				CurrentNodeID    string `json:"currentNodeID"`
				ActualSize       int64  `json:"actualSize"`
				KubernetesStatus struct {
					PVCName   string `json:"pvcName"`
					Namespace string `json:"namespace"`
				} `json:"kubernetesStatus"`
			} `json:"status"`
		} `json:"items"`
	}
	_ = json.Unmarshal(data, &list)
	var out []ccVolume
	for _, it := range list.Items {
		v := ccVolume{
			Name: it.Metadata.Name, Longhorn: true,
			PVC: it.Status.KubernetesStatus.PVCName, NS: it.Status.KubernetesStatus.Namespace,
			State: it.Status.State, Robustness: it.Status.Robustness, Node: it.Status.CurrentNodeID,
			Size: memBytes(it.Spec.Size), Actual: it.Status.ActualSize, Replicas: it.Spec.NumberOfReplicas,
		}
		out = append(out, v)
	}
	return out
}

func parseLonghornDisks(data []byte) []ccDisk {
	var list struct {
		Items []struct {
			Metadata kMeta `json:"metadata"`
			Status   struct {
				DiskStatus map[string]struct {
					StorageAvailable int64 `json:"storageAvailable"`
					StorageMaximum   int64 `json:"storageMaximum"`
				} `json:"diskStatus"`
			} `json:"status"`
		} `json:"items"`
	}
	_ = json.Unmarshal(data, &list)
	var out []ccDisk
	for _, it := range list.Items {
		d := ccDisk{Node: it.Metadata.Name}
		for _, ds := range it.Status.DiskStatus {
			d.Available += ds.StorageAvailable
			d.Total += ds.StorageMaximum
		}
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Node < out[j].Node })
	return out
}

// parseAdminBindings: ClusterRoleBindings to cluster-admin.
func parseAdminBindings(data []byte) []ccBinding {
	var list struct {
		Items []struct {
			Metadata kMeta `json:"metadata"`
			RoleRef  struct {
				Kind string `json:"kind"`
				Name string `json:"name"`
			} `json:"roleRef"`
			Subjects []struct {
				Kind      string `json:"kind"`
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"subjects"`
		} `json:"items"`
	}
	_ = json.Unmarshal(data, &list)
	var out []ccBinding
	for _, it := range list.Items {
		if it.RoleRef.Kind != "ClusterRole" || it.RoleRef.Name != "cluster-admin" {
			continue
		}
		b := ccBinding{Name: it.Metadata.Name}
		for _, sub := range it.Subjects {
			n := sub.Name
			if sub.Namespace != "" {
				n = sub.Namespace + "/" + n
			}
			b.Subjects = append(b.Subjects, sub.Kind+":"+n)
		}
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// applyLonghornReplicas fills in which nodes hold each volume's copies.
func applyLonghornReplicas(vols []ccVolume, data []byte) {
	var list struct {
		Items []struct {
			Spec struct {
				VolumeName string `json:"volumeName"`
				NodeID     string `json:"nodeID"`
			} `json:"spec"`
		} `json:"items"`
	}
	_ = json.Unmarshal(data, &list)
	on := map[string][]string{}
	for _, it := range list.Items {
		if it.Spec.NodeID != "" {
			on[it.Spec.VolumeName] = append(on[it.Spec.VolumeName], it.Spec.NodeID)
		}
	}
	for i := range vols {
		vols[i].Copies = on[vols[i].Name]
	}
}

// longhornNoEngine: Ready nodes with a Longhorn disk where no engine image
// is deployed (Longhorn keeps no copies there).
func longhornNoEngine(data []byte, disks []ccDisk, nodes []ccNode) []string {
	var list struct {
		Items []struct {
			Status struct {
				State             string          `json:"state"`
				NodeDeploymentMap map[string]bool `json:"nodeDeploymentMap"`
			} `json:"status"`
		} `json:"items"`
	}
	if json.Unmarshal(data, &list) != nil || len(list.Items) == 0 {
		return nil
	}
	ready := map[string]bool{}
	for _, n := range nodes {
		ready[n.Name] = n.Ready && !n.Unreachable
	}
	var out []string
	for _, d := range disks {
		if !ready[d.Node] {
			continue
		}
		ok := false
		for _, it := range list.Items {
			if it.Status.State == "deployed" && it.Status.NodeDeploymentMap[d.Node] {
				ok = true
			}
		}
		if !ok {
			out = append(out, d.Node)
		}
	}
	return out
}

// mergePVCs adds claims Longhorn doesn't know (other storage classes) and
// fills in claim names for Longhorn volumes.
func mergePVCs(vols []ccVolume, data []byte) []ccVolume {
	var list struct {
		Items []struct {
			Metadata kMeta `json:"metadata"`
			Spec     struct {
				VolumeName       string `json:"volumeName"`
				StorageClassName string `json:"storageClassName"`
				Resources        struct {
					Requests map[string]string `json:"requests"`
				} `json:"resources"`
			} `json:"spec"`
			Status struct {
				Phase    string            `json:"phase"`
				Capacity map[string]string `json:"capacity"`
			} `json:"status"`
		} `json:"items"`
	}
	_ = json.Unmarshal(data, &list)
	byVolume := map[string]int{}
	for i, v := range vols {
		byVolume[v.Name] = i
	}
	for _, it := range list.Items {
		if i, ok := byVolume[it.Spec.VolumeName]; ok {
			vols[i].PVC, vols[i].NS = it.Metadata.Name, it.Metadata.Namespace
			continue
		}
		size := memBytes(it.Status.Capacity["storage"])
		if size == 0 {
			size = memBytes(it.Spec.Resources.Requests["storage"])
		}
		state := strings.ToLower(it.Status.Phase)
		vols = append(vols, ccVolume{
			Name: orDefault(it.Spec.VolumeName, "-"), PVC: it.Metadata.Name, NS: it.Metadata.Namespace,
			State: state, Robustness: orDefault(it.Spec.StorageClassName, "-"), Size: size,
		})
	}
	sort.Slice(vols, func(i, j int) bool {
		if vols[i].NS != vols[j].NS {
			return vols[i].NS < vols[j].NS
		}
		return vols[i].PVC+vols[i].Name < vols[j].PVC+vols[j].Name
	})
	return vols
}

func parseCCWorkloads(kind string, data []byte) []ccWorkload {
	var list struct {
		Items []struct {
			Metadata kMeta `json:"metadata"`
			Spec     struct {
				Replicas *int `json:"replicas"`
			} `json:"spec"`
			Status struct {
				ReadyReplicas          int `json:"readyReplicas"`
				NumberReady            int `json:"numberReady"`
				DesiredNumberScheduled int `json:"desiredNumberScheduled"`
			} `json:"status"`
		} `json:"items"`
	}
	_ = json.Unmarshal(data, &list)
	k := map[string]string{"deployments": "Deployment", "statefulsets": "StatefulSet", "daemonsets": "DaemonSet"}[kind]
	var out []ccWorkload
	for _, it := range list.Items {
		w := ccWorkload{Kind: k, NS: it.Metadata.Namespace, Name: it.Metadata.Name}
		if kind == "daemonsets" {
			w.Ready, w.Want = it.Status.NumberReady, it.Status.DesiredNumberScheduled
		} else {
			w.Ready, w.Want = it.Status.ReadyReplicas, 1
			if it.Spec.Replicas != nil {
				w.Want = *it.Spec.Replicas
			}
		}
		out = append(out, w)
	}
	return out
}

func parseMetalLBPools(data []byte) []string {
	var list struct {
		Items []struct {
			Spec struct {
				Addresses []string `json:"addresses"`
			} `json:"spec"`
		} `json:"items"`
	}
	_ = json.Unmarshal(data, &list)
	var out []string
	for _, it := range list.Items {
		out = append(out, it.Spec.Addresses...)
	}
	return out
}

func parseCCCerts(data []byte) []ccCert {
	var list struct {
		Items []struct {
			Metadata kMeta `json:"metadata"`
			Status   struct {
				NotAfter   *time.Time `json:"notAfter"`
				Conditions []struct {
					Type, Status, Reason, Message string
				} `json:"conditions"`
			} `json:"status"`
		} `json:"items"`
	}
	_ = json.Unmarshal(data, &list)
	var out []ccCert
	for _, it := range list.Items {
		c := ccCert{NS: it.Metadata.Namespace, Name: it.Metadata.Name}
		if it.Status.NotAfter != nil {
			c.NotAfter = *it.Status.NotAfter
		}
		for _, cond := range it.Status.Conditions {
			if cond.Type == "Ready" {
				c.Ready = cond.Status == "True"
				if !c.Ready {
					c.Reason = orDefault(cond.Message, cond.Reason)
				}
			}
		}
		out = append(out, c)
	}
	return out
}

// applyStats reads disk and network use from the kubelet's stats summary.
func (c *ccCollector) applyStats(n *ccNode, data []byte) {
	var sum struct {
		Node struct {
			StartTime time.Time `json:"startTime"`
			Fs        struct {
				CapacityBytes int64 `json:"capacityBytes"`
				UsedBytes     int64 `json:"usedBytes"`
			} `json:"fs"`
			Network struct {
				Time       time.Time `json:"time"`
				Interfaces []struct {
					Name    string  `json:"name"`
					RxBytes float64 `json:"rxBytes"`
					TxBytes float64 `json:"txBytes"`
				} `json:"interfaces"`
				RxBytes float64 `json:"rxBytes"`
				TxBytes float64 `json:"txBytes"`
			} `json:"network"`
		} `json:"node"`
	}
	if json.Unmarshal(data, &sum) != nil {
		return
	}
	n.HasStats = true
	n.FSUsed, n.FSCap = sum.Node.Fs.UsedBytes, sum.Node.Fs.CapacityBytes
	n.KubeletUp = sum.Node.StartTime

	// All physical interfaces (not the CNI's own lxc/cilium ones).
	var rx, tx float64
	for _, i := range sum.Node.Network.Interfaces {
		if strings.HasPrefix(i.Name, "lxc") || strings.HasPrefix(i.Name, "cilium") || i.Name == "lo" {
			continue
		}
		rx += i.RxBytes
		tx += i.TxBytes
	}
	if len(sum.Node.Network.Interfaces) == 0 {
		rx, tx = sum.Node.Network.RxBytes, sum.Node.Network.TxBytes
	}
	at := sum.Node.Network.Time
	if at.IsZero() {
		at = time.Now()
	}
	if prev, ok := c.netPrev[n.Name]; ok {
		if dt := at.Sub(prev.at).Seconds(); dt > 0 && rx >= prev.rx && tx >= prev.tx {
			n.RxRate, n.TxRate = (rx-prev.rx)/dt, (tx-prev.tx)/dt
		}
	}
	c.netPrev[n.Name] = ccNetSample{at: at, rx: rx, tx: tx}
}

// ---------------------------------------------------------------------------
// Derived figures and alerts
// ---------------------------------------------------------------------------

func summarize(s *ccSnapshot) {
	byNode := map[string]*ccNode{}
	for i := range s.Nodes {
		byNode[s.Nodes[i].Name] = &s.Nodes[i]
	}
	// Fresh counters: the namespace list is reused between refreshes.
	nss := make([]ccNamespace, len(s.Namespaces))
	for i, ns := range s.Namespaces {
		nss[i] = ccNamespace{Name: ns.Name, Phase: ns.Phase, Created: ns.Created}
	}
	s.Namespaces = nss

	// Namespaces seen only through their pods (not read yet) count too.
	known := map[string]bool{}
	for _, ns := range s.Namespaces {
		known[ns.Name] = true
	}
	for _, p := range s.Pods {
		if !known[p.NS] {
			known[p.NS] = true
			s.Namespaces = append(s.Namespaces, ccNamespace{Name: p.NS, Phase: "Active"})
		}
	}
	nsIdx := map[string]*ccNamespace{}
	for i := range s.Namespaces {
		nsIdx[s.Namespaces[i].Name] = &s.Namespaces[i]
	}
	for i := range s.Pods {
		p := &s.Pods[i]
		if n := byNode[p.Node]; n != nil && p.Status != "Completed" && p.Phase != "Failed" {
			n.Pods++
			n.CPUReq += p.CPUReq
			n.MemReq += p.MemReq
			n.CPULim += p.CPULim
			n.MemLim += p.MemLim
		}
		ns := nsIdx[p.NS]
		ns.Pods++
		if p.Status == "Running" {
			ns.Running++
		}
		if p.problem() {
			ns.Problems++
		}
		ns.CPUUse += p.CPUUse
		ns.MemUse += p.MemUse
		ns.CPUReq += p.CPUReq
		ns.MemReq += p.MemReq
	}

	s.Alerts = buildAlerts(s)
}

func buildAlerts(s *ccSnapshot) []ccAlert {
	var a []ccAlert
	add := func(level int, kind, ns, name, msg string, since time.Time) {
		obj := strings.ToLower(kind) + "/" + name
		if ns != "" {
			obj = ns + "/" + obj
		}
		a = append(a, ccAlert{Level: level, Object: obj, Message: msg, Since: since, Target: ccTarget{kind, ns, name}})
	}
	if s.Readyz != "" && s.Readyz != "ok" {
		add(2, "API", "", "readyz", "API server not ready: "+s.Readyz, time.Time{})
	}
	for _, n := range s.Nodes {
		switch {
		case n.Unreachable:
			add(2, "Node", "", n.Name, "doesn't answer (powered off or off the network?)", time.Time{})
		case !n.Ready:
			add(2, "Node", "", n.Name, "NotReady", time.Time{})
		case len(n.Pressure) > 0:
			add(1, "Node", "", n.Name, strings.Join(n.Pressure, ", "), time.Time{})
		}
		if n.HasUsage && n.memPct() >= 90 {
			add(1, "Node", "", n.Name, fmt.Sprintf("memory %.0f%% used", n.memPct()), time.Time{})
		}
		if n.HasStats && n.FSCap > 0 && pct(n.FSUsed, n.FSCap) >= 85 {
			add(1, "Node", "", n.Name, fmt.Sprintf("disk %.0f%% full", pct(n.FSUsed, n.FSCap)), time.Time{})
		}
		if n.Unschedulable {
			add(1, "Node", "", n.Name, "cordoned: no new pods are scheduled here", time.Time{})
		}
	}
	for _, p := range s.Pods {
		if !p.problem() || p.Status == "Terminating" {
			continue
		}
		level := 1
		switch p.Status {
		case "CrashLoopBackOff", "ImagePullBackOff", "ErrImagePull", "Error", "OOMKilled", "Evicted", "Failed",
			"CreateContainerConfigError", "InvalidImageName":
			level = 2
		}
		msg := p.Status
		if p.Status == "Running" {
			msg = fmt.Sprintf("running but %d/%d containers ready", p.Ready, p.Total)
		}
		if p.Restarts > 0 {
			msg += fmt.Sprintf(" · %d restarts", p.Restarts)
		}
		since := p.Created
		if !p.LastRestart.IsZero() {
			since = p.LastRestart
		}
		add(level, "Pod", p.NS, p.Name, msg, since)
	}
	for _, w := range s.Workloads {
		if w.Ready < w.Want {
			add(1, w.Kind, w.NS, w.Name, fmt.Sprintf("%d/%d ready", w.Ready, w.Want), time.Time{})
		}
	}
	for _, app := range s.Apps {
		switch {
		case app.Health == "Degraded" || app.Health == "Missing":
			add(2, "App", "", app.Name, "Argo CD: "+app.Health+" "+app.Message, time.Time{})
		case app.Sync == "OutOfSync" || app.Health == "Progressing" || app.Phase == "Failed" || app.Phase == "Error":
			msg := "Argo CD: " + app.Sync + " · " + app.Health
			if app.Phase == "Failed" || app.Phase == "Error" {
				msg += " · sync " + app.Phase
			}
			add(1, "App", "", app.Name, msg, time.Time{})
		}
	}
	for _, v := range s.Volumes {
		switch {
		case v.Longhorn && v.Robustness == "faulted":
			add(2, "Volume", v.NS, orDefault(v.PVC, v.Name), "Longhorn volume faulted", time.Time{})
		case v.Longhorn && v.Robustness == "degraded":
			add(1, "Volume", v.NS, orDefault(v.PVC, v.Name), "Longhorn volume degraded (missing a replica)", time.Time{})
		case !v.Longhorn && v.State == "pending":
			add(1, "Volume", v.NS, v.PVC, "claim Pending", time.Time{})
		}
	}
	if s.HasLonghorn {
		for _, v := range s.Volumes {
			if on, n := v.copiesOn(); v.Longhorn && v.Replicas > 1 && n == 1 && v.Robustness != "faulted" {
				add(1, "Volume", v.NS, orDefault(v.PVC, v.Name), "all copies on "+on+": losing that node loses it (B in Storage spreads them)", time.Time{})
			}
		}
		for _, n := range s.NoEngine {
			add(1, "Node", "", n, "Longhorn can't keep volume copies here (B in Storage fixes it)", time.Time{})
		}
	}
	for _, d := range s.Disks {
		if d.Total > 0 && pct(d.Total-d.Available, d.Total) >= 85 {
			add(1, "Node", "", d.Node, fmt.Sprintf("Longhorn disks %.0f%% full", pct(d.Total-d.Available, d.Total)), time.Time{})
		}
	}
	for _, c := range s.Certs {
		switch {
		case !c.Ready:
			add(1, "Certificate", c.NS, c.Name, "not ready: "+c.Reason, time.Time{})
		case !c.NotAfter.IsZero() && time.Until(c.NotAfter) < 7*24*time.Hour:
			add(1, "Certificate", c.NS, c.Name, "expires "+c.NotAfter.Local().Format("2006-01-02"), time.Time{})
		}
	}
	sort.SliceStable(a, func(i, j int) bool { return a[i].Level > a[j].Level })
	return a
}

// ---------------------------------------------------------------------------
// History for graphs
// ---------------------------------------------------------------------------

const ccHistoryLen = 240

type ccRing struct{ v []float64 }

func (r *ccRing) push(x float64) {
	r.v = append(r.v, x)
	if len(r.v) > ccHistoryLen {
		r.v = r.v[len(r.v)-ccHistoryLen:]
	}
}

func (r *ccRing) last() float64 {
	if len(r.v) == 0 {
		return 0
	}
	return r.v[len(r.v)-1]
}

type ccHistory struct {
	cpu, mem   ccRing // cluster %, of allocatable
	nodeCPU    map[string]*ccRing
	nodeMem    map[string]*ccRing
	nodeRx     map[string]*ccRing
	nodeTx     map[string]*ccRing
	rx, tx     ccRing // cluster bytes/s
	lastPushed time.Time
}

func newCCHistory() *ccHistory {
	return &ccHistory{nodeCPU: map[string]*ccRing{}, nodeMem: map[string]*ccRing{},
		nodeRx: map[string]*ccRing{}, nodeTx: map[string]*ccRing{}}
}

func ringOf(m map[string]*ccRing, k string) *ccRing {
	if m[k] == nil {
		m[k] = &ccRing{}
	}
	return m[k]
}

func (h *ccHistory) add(s *ccSnapshot) {
	if !s.HasMetrics || s.Time.Equal(h.lastPushed) || s.Errs["api"] != "" {
		return
	}
	h.lastPushed = s.Time
	var cu, ca, mu, ma int64
	var rx, tx float64
	for _, n := range s.Nodes {
		if !n.HasUsage {
			continue
		}
		cu, ca, mu, ma = cu+n.CPUUse, ca+n.CPUAlloc, mu+n.MemUse, ma+n.MemAlloc
		ringOf(h.nodeCPU, n.Name).push(n.cpuPct())
		ringOf(h.nodeMem, n.Name).push(n.memPct())
		ringOf(h.nodeRx, n.Name).push(n.RxRate)
		ringOf(h.nodeTx, n.Name).push(n.TxRate)
		rx += n.RxRate
		tx += n.TxRate
	}
	h.cpu.push(pct(cu, ca))
	h.mem.push(pct(mu, ma))
	h.rx.push(rx)
	h.tx.push(tx)
}
