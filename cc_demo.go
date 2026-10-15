package main

// Demo data for the Command Center: the API answers a five-node homelab
// would give, with usage that moves over time. It goes through the same
// parsers as a real cluster, so the demo shows exactly what you'd see.

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"
)

type demoCCSource struct {
	start   time.Time
	mu      sync.Mutex
	deleted map[string]time.Time // pods "restarted" in the demo
	cordon  map[string]bool
}

func newDemoCCSource() *demoCCSource {
	return &demoCCSource{start: time.Now(), deleted: map[string]time.Time{}, cordon: map[string]bool{}}
}

func (*demoCCSource) noProbe()         {}
func (*demoCCSource) Label() string    { return "demo data" }
func (*demoCCSource) Close()           {}
func (d *demoCCSource) since() float64 { return time.Since(d.start).Seconds() }

type demoPodSpec struct {
	ns, name, node, image string
	cpu, mem              float64 // typical usage: millicores, MiB
	status                string  // "" running
	restarts              int
}

var demoCCNodes = []struct {
	name, ip, role string
	cpu, memGi     int
	ready          bool
}{
	{"cp1", "10.99.0.11", "control-plane", 4, 16, true},
	{"cp2", "10.99.0.12", "control-plane", 4, 16, true},
	{"cp3", "10.99.0.13", "control-plane", 4, 16, true},
	{"w1", "10.99.0.21", "", 8, 32, true},
	{"w2", "10.99.0.22", "", 8, 32, false},
}

var demoCCPods = func() []demoPodSpec {
	p := []demoPodSpec{
		{"kube-system", "kube-apiserver-cp1", "cp1", "registry.k8s.io/kube-apiserver:v1.36.2", 310, 820, "", 0},
		{"kube-system", "kube-apiserver-cp2", "cp2", "registry.k8s.io/kube-apiserver:v1.36.2", 240, 760, "", 0},
		{"kube-system", "kube-apiserver-cp3", "cp3", "registry.k8s.io/kube-apiserver:v1.36.2", 220, 740, "", 0},
		{"kube-system", "etcd-cp1", "cp1", "registry.k8s.io/etcd:3.6.4-0", 120, 210, "", 0},
		{"kube-system", "etcd-cp2", "cp2", "registry.k8s.io/etcd:3.6.4-0", 110, 190, "", 0},
		{"kube-system", "etcd-cp3", "cp3", "registry.k8s.io/etcd:3.6.4-0", 105, 185, "", 0},
		{"kube-system", "coredns-7c65d6cfc9-4xk2p", "cp1", "registry.k8s.io/coredns/coredns:v1.12.0", 6, 24, "", 0},
		{"kube-system", "coredns-7c65d6cfc9-9tzqr", "w1", "registry.k8s.io/coredns/coredns:v1.12.0", 5, 22, "", 0},
		{"kube-system", "cilium-operator-6f9c8d-xk2", "cp2", "quay.io/cilium/operator-generic:v1.18.1", 4, 48, "", 0},
		{"kube-system", "metrics-server-5d9f7b-qq8", "w1", "registry.k8s.io/metrics-server/metrics-server:v0.8.0", 8, 30, "", 0},
		{"argocd", "argocd-server-57889849d7-hz8c4", "w1", "quay.io/argoproj/argocd:v3.1.0", 12, 96, "", 0},
		{"argocd", "argocd-repo-server-6c7f9d-2kq", "w1", "quay.io/argoproj/argocd:v3.1.0", 35, 210, "", 0},
		{"argocd", "argocd-application-controller-0", "cp3", "quay.io/argoproj/argocd:v3.1.0", 140, 420, "", 0},
		{"argocd", "argocd-redis-7d8b9c-p2x", "cp1", "redis:7.2-alpine", 3, 12, "", 0},
		{"longhorn-system", "longhorn-manager-x8k2d", "w1", "longhornio/longhorn-manager:v1.9.1", 45, 160, "", 0},
		{"longhorn-system", "longhorn-ui-5c9d8f-ab", "cp2", "longhornio/longhorn-ui:v1.9.1", 1, 18, "", 0},
		{"ingress-nginx", "ingress-nginx-controller-7d9c-k2", "w1", "registry.k8s.io/ingress-nginx/controller:v1.13.0", 18, 140, "", 0},
		{"metallb-system", "metallb-controller-6c8d-9k", "cp1", "quay.io/metallb/controller:v0.15.2", 2, 30, "", 0},
		{"cert-manager", "cert-manager-6d4b8c-77x", "cp2", "quay.io/jetstack/cert-manager-controller:v1.18.2", 3, 44, "", 0},
		{"cattle-system", "rancher-7f8d9c-m2k", "w1", "rancher/rancher:v2.15.2", 160, 1180, "", 0},
		{"jellyfin", "jellyfin-6b9d8f7c4-tq2wz", "w1", "linuxserver/jellyfin:10.11.10", 420, 1650, "", 0},
		{"nextcloud", "nextcloud-5d8c9f-w4x", "w1", "nextcloud:29", 60, 380, "", 0},
		{"nextcloud", "nextcloud-db-0", "w1", "postgres:16", 25, 210, "", 0},
		{"n8n", "n8n-7c9d8b-k2x", "cp3", "n8nio/n8n:1.112.0", 14, 260, "", 0},
		{"qbittorrent", "qbittorrent-5f8c9d-r7x", "w1", "lscr.io/linuxserver/qbittorrent:5.1.2", 30, 220, "CrashLoopBackOff", 14},
		{"wg-easy", "wg-easy-6d9c8f-z2k", "cp1", "ghcr.io/wg-easy/wg-easy:15", 2, 40, "", 0},
		{"home-assistant", "home-assistant-0", "w2", "ghcr.io/home-assistant/home-assistant:2026.10", 0, 0, "Pending", 0},
	}
	for _, n := range demoCCNodes {
		p = append(p,
			demoPodSpec{"kube-system", "cilium-" + n.name, n.name, "quay.io/cilium/cilium:v1.18.1", 28, 190, "", 0},
			demoPodSpec{"longhorn-system", "longhorn-csi-plugin-" + n.name, n.name, "longhornio/longhorn-csi-plugin:v1.9.1", 3, 40, "", 0},
		)
	}
	return p
}()

// wave is a smooth, per-name varying factor around 1.
func (d *demoCCSource) wave(name string, speed float64) float64 {
	h := 0
	for _, c := range name {
		h = h*31 + int(c)
	}
	t := d.since()
	phase := float64(h%628) / 100
	return 1 + 0.35*math.Sin(t*speed/10+phase) + 0.15*math.Sin(t*speed/3.7+phase*2)
}

func (d *demoCCSource) GetMany(paths []string) []ccResult {
	out := make([]ccResult, len(paths))
	for i, p := range paths {
		if p == "/readyz" {
			out[i].data = []byte("ok")
			continue
		}
		v, err := d.get(p)
		if err != nil {
			out[i].err = err
			continue
		}
		out[i].data, out[i].err = json.Marshal(v)
	}
	return out
}

func (d *demoCCSource) Do(r ccRequest) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	switch {
	case r.Method == http.MethodDelete && strings.Contains(r.Path, "/pods/"):
		parts := strings.Split(r.Path, "/")
		d.deleted[parts[len(parts)-1]] = time.Now()
		return nil
	case r.Method == http.MethodPatch && strings.HasPrefix(r.Path, "/api/v1/nodes/"):
		name := strings.TrimPrefix(r.Path, "/api/v1/nodes/")
		d.cordon[name] = strings.Contains(r.Body, "true")
		return nil
	}
	return errors.New("not available in the demo")
}

type obj2 = map[string]any

func (d *demoCCSource) get(path string) (any, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	created := time.Now().Add(-41 * 24 * time.Hour).UTC().Format(time.RFC3339)
	switch {
	case path == "/version":
		return obj2{"gitVersion": "v1.36.2"}, nil
	case path == "/api/v1/nodes":
		var items []obj2
		for _, n := range demoCCNodes {
			labels := obj2{"kubernetes.io/hostname": n.name}
			if n.role != "" {
				labels["node-role.kubernetes.io/"+n.role] = ""
			}
			if n.name == "w1" {
				labels["homelab.io/igpu"] = "intel"
			}
			ready := "True"
			if !n.ready {
				ready = "Unknown"
			}
			items = append(items, obj2{
				"metadata": obj2{"name": n.name, "labels": labels, "creationTimestamp": created},
				"spec":     obj2{"unschedulable": d.cordon[n.name]},
				"status": obj2{
					"capacity":    obj2{"cpu": fmt.Sprint(n.cpu), "memory": fmt.Sprintf("%dKi", n.memGi<<20), "pods": "110"},
					"allocatable": obj2{"cpu": fmt.Sprint(n.cpu), "memory": fmt.Sprintf("%dKi", n.memGi<<20-180<<10), "pods": "110"},
					"addresses":   []obj2{{"type": "InternalIP", "address": n.ip}, {"type": "Hostname", "address": n.name}},
					"conditions": []obj2{
						{"type": "MemoryPressure", "status": "False"},
						{"type": "DiskPressure", "status": "False"},
						{"type": "PIDPressure", "status": "False"},
						{"type": "Ready", "status": ready, "reason": map[bool]string{true: "KubeletReady", false: "NodeStatusUnknown"}[n.ready]},
					},
					"nodeInfo": obj2{"kubeletVersion": "v1.36.2", "osImage": "Ubuntu 24.04.3 LTS", "kernelVersion": "6.8.0-85-generic",
						"containerRuntimeVersion": "containerd://2.1.4", "architecture": "amd64"},
				},
			})
		}
		return obj2{"items": items}, nil
	case path == "/apis/metrics.k8s.io/v1beta1/nodes":
		var items []obj2
		for _, n := range demoCCNodes {
			if !n.ready {
				continue
			}
			var cpu, mem float64 = 150, 900 // system overhead
			for _, p := range demoCCPods {
				if p.node == n.name && p.status == "" {
					cpu += p.cpu * d.wave(p.name, 1)
					mem += p.mem * (0.9 + 0.1*d.wave(p.name, 0.3))
				}
			}
			items = append(items, obj2{"metadata": obj2{"name": n.name},
				"usage": obj2{"cpu": fmt.Sprintf("%dm", int(cpu)), "memory": fmt.Sprintf("%dMi", int(mem))}})
		}
		return obj2{"items": items}, nil
	case path == "/api/v1/pods":
		var items []obj2
		for _, p := range demoCCPods {
			name := p.name
			age := 9 * 24 * time.Hour
			if t, ok := d.deleted[p.name]; ok {
				age = time.Since(t)
				if age < 4*time.Second {
					continue // being replaced
				}
			}
			cs := obj2{"name": strings.Split(name, "-")[0], "ready": true, "restartCount": p.restarts,
				"state": obj2{"running": obj2{"startedAt": time.Now().Add(-age).UTC().Format(time.RFC3339)}}}
			phase := "Running"
			switch p.status {
			case "CrashLoopBackOff":
				cs["ready"] = false
				cs["state"] = obj2{"waiting": obj2{"reason": "CrashLoopBackOff"}}
				cs["lastTerminationState"] = obj2{"terminated": obj2{"reason": "Error", "exitCode": 1,
					"finishedAt": time.Now().Add(-2 * time.Minute).UTC().Format(time.RFC3339)}}
			case "Pending":
				phase = "Pending"
				cs = nil
			}
			node := p.node
			if p.status == "Pending" {
				node = ""
			}
			pod := obj2{
				"metadata": obj2{"name": name, "namespace": p.ns, "creationTimestamp": time.Now().Add(-age).UTC().Format(time.RFC3339),
					"ownerReferences": []obj2{demoOwner(name)}},
				"spec": obj2{"nodeName": node, "containers": []obj2{{"name": strings.Split(name, "-")[0], "image": p.image,
					"resources": obj2{"requests": obj2{"cpu": fmt.Sprintf("%dm", int(p.cpu/2+10)), "memory": fmt.Sprintf("%dMi", int(p.mem/2+16))},
						"limits": obj2{"memory": fmt.Sprintf("%dMi", int(p.mem*2+64))}}}}},
				"status": obj2{"phase": phase, "podIP": fmt.Sprintf("10.0.%d.%d", len(p.node)%3, len(name)*7%250+2), "qosClass": "Burstable"},
			}
			if cs != nil {
				pod["status"].(obj2)["containerStatuses"] = []obj2{cs}
			}
			demoPodSecurity(pod, p.ns, name)
			items = append(items, pod)
		}
		return obj2{"items": items}, nil
	case path == "/apis/metrics.k8s.io/v1beta1/pods":
		var items []obj2
		for _, p := range demoCCPods {
			if p.status != "" {
				continue
			}
			items = append(items, obj2{"metadata": obj2{"name": p.name, "namespace": p.ns},
				"containers": []obj2{{"name": strings.Split(p.name, "-")[0], "usage": obj2{
					"cpu": fmt.Sprintf("%dm", int(p.cpu*d.wave(p.name, 1))), "memory": fmt.Sprintf("%dMi", int(p.mem*(0.9+0.1*d.wave(p.name, 0.3))))}}}})
		}
		return obj2{"items": items}, nil
	case strings.HasSuffix(path, "/proxy/stats/summary"):
		name := strings.TrimSuffix(strings.TrimPrefix(path, "/api/v1/nodes/"), "/proxy/stats/summary")
		t := d.since()
		rate := 180e3 * d.wave(name, 2)
		if name == "w1" {
			rate = 4.2e6 * d.wave(name, 2) // the media server
		}
		return obj2{"node": obj2{
			"startTime": time.Now().Add(-9 * 24 * time.Hour).UTC().Format(time.RFC3339),
			"fs":        obj2{"capacityBytes": 250 << 30, "usedBytes": int64(float64(250<<30) * map[bool]float64{true: 0.71, false: 0.38}[name == "w1"])},
			"network": obj2{"time": time.Now().UTC().Format(time.RFC3339Nano), "interfaces": []obj2{
				{"name": "eth0", "rxBytes": 9e9 + rate*t, "txBytes": 4e9 + rate*0.35*t}}},
		}}, nil
	case path == "/api/v1/namespaces":
		seen := map[string]bool{}
		var items []obj2
		for _, ns := range append([]string{"default"}, func() []string {
			var l []string
			for _, p := range demoCCPods {
				l = append(l, p.ns)
			}
			return l
		}()...) {
			if !seen[ns] {
				seen[ns] = true
				items = append(items, obj2{"metadata": obj2{"name": ns, "creationTimestamp": created}, "status": obj2{"phase": "Active"}})
			}
		}
		return obj2{"items": items}, nil
	case path == "/api/v1/services":
		lb := func(ns, name, ip string, ports ...int) obj2 {
			var ps []obj2
			for _, p := range ports {
				proto := "TCP"
				if p == 51820 || p == 7359 {
					proto = "UDP"
				}
				ps = append(ps, obj2{"port": p, "protocol": proto})
			}
			return obj2{"metadata": obj2{"name": name, "namespace": ns}, "spec": obj2{"type": "LoadBalancer", "clusterIP": "10.96.4.12", "ports": ps},
				"status": obj2{"loadBalancer": obj2{"ingress": []obj2{{"ip": ip}}}}}
		}
		return obj2{"items": []obj2{
			lb("ingress-nginx", "ingress-nginx-controller", "10.99.0.200", 80, 443),
			lb("wg-easy", "wg-easy", "10.99.0.201", 51820),
			lb("jellyfin", "jellyfin-lan", "10.99.0.202", 8921, 7359),
			lb("qbittorrent", "qbittorrent-lan", "10.99.0.203", 6881),
			{"metadata": obj2{"name": "kubernetes", "namespace": "default"}, "spec": obj2{"type": "ClusterIP", "clusterIP": "10.96.0.1", "ports": []obj2{{"port": 443}}}},
		}}, nil
	case path == "/apis/networking.k8s.io/v1/ingresses":
		ing := func(ns, host, svc string, port int) obj2 {
			return obj2{"metadata": obj2{"name": ns, "namespace": ns}, "spec": obj2{
				"tls":   []obj2{{"hosts": []string{host}}},
				"rules": []obj2{{"host": host, "http": obj2{"paths": []obj2{{"backend": obj2{"service": obj2{"name": svc, "port": obj2{"number": port}}}}}}}}},
				"status": obj2{"loadBalancer": obj2{"ingress": []obj2{{"ip": "10.99.0.200"}}}}}
		}
		return obj2{"items": []obj2{
			ing("argocd", "argocd.homelab.example", "argocd-server", 80),
			ing("longhorn-system", "longhorn.homelab.example", "longhorn-frontend", 80),
			ing("cattle-system", "rancher.homelab.example", "rancher", 80),
			ing("jellyfin", "jellyfin.homelab.example", "jellyfin", 8096),
			ing("nextcloud", "cloud.homelab.example", "nextcloud", 80),
			ing("n8n", "n8n.homelab.example", "n8n", 5678),
			func() obj2 { // the one left on plain http
				i := ing("qbittorrent", "torrent.homelab.example", "qbittorrent", 8080)
				delete(i["spec"].(obj2), "tls")
				return i
			}(),
			ing("wg-easy", "vpn.homelab.example", "wg-easy", 51821),
		}}, nil
	case path == "/apis/argoproj.io/v1alpha1/applications":
		app := func(name, ns, sync, health string) obj2 {
			return obj2{"metadata": obj2{"name": name}, "spec": obj2{"destination": obj2{"namespace": ns},
				"source": obj2{"repoURL": "git@github.com:you/homelab-gitops.git", "path": "apps/" + name}},
				"status": obj2{"sync": obj2{"status": sync, "revision": "4f2c9a1e7b"}, "health": obj2{"status": health}}}
		}
		return obj2{"items": []obj2{
			app("cert-manager", "cert-manager", "Synced", "Healthy"), app("ingress-nginx", "ingress-nginx", "Synced", "Healthy"),
			app("longhorn", "longhorn-system", "Synced", "Healthy"), app("metallb", "metallb-system", "Synced", "Healthy"),
			app("metrics-server", "kube-system", "Synced", "Healthy"), app("rancher", "cattle-system", "Synced", "Healthy"),
			app("jellyfin", "jellyfin", "Synced", "Healthy"), app("nextcloud", "nextcloud", "OutOfSync", "Healthy"),
			app("n8n", "n8n", "Synced", "Healthy"), app("qbittorrent", "qbittorrent", "Synced", "Degraded"),
			app("wg-easy", "wg-easy", "Synced", "Healthy"), app("home-assistant", "home-assistant", "Synced", "Progressing"),
		}}, nil
	case strings.HasPrefix(path, "/api/v1/events"):
		ev := func(ago time.Duration, ns, kind, name, reason, msg string, count int) obj2 {
			return obj2{"metadata": obj2{"creationTimestamp": time.Now().Add(-ago).UTC().Format(time.RFC3339)},
				"involvedObject": obj2{"kind": kind, "name": name, "namespace": ns}, "reason": reason, "message": msg,
				"type": "Warning", "count": count, "lastTimestamp": time.Now().Add(-ago).UTC().Format(time.RFC3339)}
		}
		return obj2{"items": []obj2{
			ev(40*time.Second, "qbittorrent", "Pod", "qbittorrent-5f8c9d-r7x", "BackOff", "Back-off restarting failed container qbittorrent in pod qbittorrent-5f8c9d-r7x", 61),
			ev(3*time.Minute, "home-assistant", "Pod", "home-assistant-0", "FailedScheduling", "0/5 nodes are available: 1 node(s) had untolerated taint {node.kubernetes.io/unreachable}, 4 node(s) didn't match pod's node affinity/selector.", 12),
			ev(6*time.Minute, "", "Node", "w2", "NodeNotReady", "Node w2 status is now: NodeNotReady", 1),
			ev(22*time.Minute, "longhorn-system", "Volume", "pvc-7f3a", "Degraded", "volume pvc-7f3a is degraded: replica on w2 is unavailable", 1),
		}}, nil
	case path == "/apis/longhorn.io/v1beta2/volumes":
		vol := func(name, ns, pvc, node, rob string, sizeGi, usedGi float64) obj2 {
			return obj2{"metadata": obj2{"name": name}, "spec": obj2{"size": fmt.Sprint(int64(sizeGi * (1 << 30))), "numberOfReplicas": 2},
				"status": obj2{"state": "attached", "robustness": rob, "currentNodeID": node, "actualSize": int64(usedGi * (1 << 30)),
					"kubernetesStatus": obj2{"pvcName": pvc, "namespace": ns}}}
		}
		return obj2{"items": []obj2{
			vol("pvc-1a2b", "jellyfin", "jellyfin-config", "w1", "healthy", 5, 1.8),
			vol("pvc-3c4d", "nextcloud", "data", "w1", "healthy", 100, 41),
			vol("pvc-7f3a", "nextcloud", "db", "w1", "degraded", 10, 2.2),
			vol("pvc-5e6f", "n8n", "n8n-data", "cp3", "healthy", 5, 0.4),
			vol("pvc-8a9b", "argocd", "redis-data", "cp1", "healthy", 1, 0.1),
		}}, nil
	case path == "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings":
		crb := func(name string, subjects ...obj2) obj2 {
			return obj2{"metadata": obj2{"name": name}, "roleRef": obj2{"kind": "ClusterRole", "name": "cluster-admin"}, "subjects": subjects}
		}
		return obj2{"items": []obj2{
			crb("cluster-admin", obj2{"kind": "Group", "name": "system:masters"}),
			crb("kubeadm:cluster-admins", obj2{"kind": "Group", "name": "kubeadm:cluster-admins"}),
			crb("cattle-admin-binding", obj2{"kind": "ServiceAccount", "name": "rancher", "namespace": "cattle-system"}),
			crb("n8n-cluster-access", obj2{"kind": "ServiceAccount", "name": "n8n", "namespace": "n8n"}),
		}}, nil
	case path == "/apis/networking.k8s.io/v1/networkpolicies":
		return obj2{"items": []obj2{{"metadata": obj2{"name": "default-deny", "namespace": "nextcloud"}}}}, nil
	case path == "/apis/longhorn.io/v1beta2/replicas":
		var items []obj2
		for vol, nodes := range map[string][]string{"pvc-1a2b": {"w1", "cp1"}, "pvc-3c4d": {"w1", "w1"},
			"pvc-7f3a": {"w1", "w2"}, "pvc-5e6f": {"cp1", "w1"}, "pvc-8a9b": {"cp1", "w1"}} {
			for _, n := range nodes {
				items = append(items, obj2{"spec": obj2{"volumeName": vol, "nodeID": n}})
			}
		}
		return obj2{"items": items}, nil
	case path == "/apis/longhorn.io/v1beta2/engineimages":
		return obj2{"items": []obj2{{"status": obj2{"state": "deployed",
			"nodeDeploymentMap": obj2{"cp1": true, "cp2": false, "cp3": false, "w1": true, "w2": true}}}}}, nil
	case path == "/apis/longhorn.io/v1beta2/nodes":
		var items []obj2
		for _, n := range demoCCNodes {
			total := int64(200 << 30)
			if n.role == "" {
				total = 900 << 30
			}
			items = append(items, obj2{"metadata": obj2{"name": n.name}, "status": obj2{"diskStatus": obj2{"default": obj2{
				"storageMaximum": total, "storageAvailable": total * 6 / 10}}}})
		}
		return obj2{"items": items}, nil
	case path == "/api/v1/persistentvolumeclaims":
		pvc := func(ns, name, vol string) obj2 {
			return obj2{"metadata": obj2{"name": name, "namespace": ns}, "spec": obj2{"volumeName": vol, "storageClassName": "longhorn"},
				"status": obj2{"phase": "Bound"}}
		}
		return obj2{"items": []obj2{pvc("jellyfin", "jellyfin-config", "pvc-1a2b"), pvc("nextcloud", "data", "pvc-3c4d"),
			pvc("nextcloud", "db", "pvc-7f3a"), pvc("n8n", "n8n-data", "pvc-5e6f"), pvc("argocd", "redis-data", "pvc-8a9b"),
			{"metadata": obj2{"name": "config", "namespace": "home-assistant"}, "spec": obj2{"storageClassName": "longhorn",
				"resources": obj2{"requests": obj2{"storage": "5Gi"}}}, "status": obj2{"phase": "Pending"}}}}, nil
	case strings.HasPrefix(path, "/apis/apps/v1/"):
		kind := strings.TrimPrefix(path, "/apis/apps/v1/")
		w := func(ns, name string, ready, want int) obj2 {
			if kind == "daemonsets" {
				return obj2{"metadata": obj2{"name": name, "namespace": ns}, "status": obj2{"numberReady": ready, "desiredNumberScheduled": want}}
			}
			return obj2{"metadata": obj2{"name": name, "namespace": ns}, "spec": obj2{"replicas": want}, "status": obj2{"readyReplicas": ready}}
		}
		switch kind {
		case "daemonsets":
			return obj2{"items": []obj2{w("kube-system", "cilium", 4, 5), w("longhorn-system", "longhorn-csi-plugin", 4, 5)}}, nil
		case "statefulsets":
			return obj2{"items": []obj2{w("home-assistant", "home-assistant", 0, 1), w("nextcloud", "nextcloud-db", 1, 1)}}, nil
		}
		return obj2{"items": []obj2{w("argocd", "argocd-server", 1, 1), w("qbittorrent", "qbittorrent", 0, 1), w("jellyfin", "jellyfin", 1, 1)}}, nil
	case path == "/apis/metallb.io/v1beta1/ipaddresspools":
		return obj2{"items": []obj2{{"spec": obj2{"addresses": []string{"10.99.0.200-10.99.0.220"}}}}}, nil
	case path == "/apis/cert-manager.io/v1/certificates":
		return obj2{"items": []obj2{
			{"metadata": obj2{"name": "jellyfin-tls", "namespace": "jellyfin"}, "status": obj2{"notAfter": time.Now().Add(60 * 24 * time.Hour).UTC().Format(time.RFC3339),
				"conditions": []obj2{{"type": "Ready", "status": "True"}}}},
		}}, nil
	}
	return nil, errors.New("404: the server could not find the requested resource")
}

// demoLogs is a pod's log in the demo.
func demoLogs(pod string) string {
	var b strings.Builder
	now := time.Now()
	for i := 30; i > 0; i-- {
		t := now.Add(-time.Duration(i) * 7 * time.Second).UTC().Format("2006-01-02T15:04:05Z")
		switch {
		case strings.HasPrefix(pod, "qbittorrent") && i < 4:
			fmt.Fprintf(&b, "%s \x1b[31mERROR\x1b[0m VPN tunnel not up: waiting for gluetun (PIA login missing)\n", t)
		case i%9 == 0:
			fmt.Fprintf(&b, "%s \x1b[33mWARN\x1b[0m  slow request GET /api/health took 1.2s\n", t)
		default:
			fmt.Fprintf(&b, "%s \x1b[32mINFO\x1b[0m  %s: handled request in %dms\n", t, pod, 3+i%17)
		}
	}
	return b.String()
}

// demoPodSecurity gives the demo pods the security settings real ones have
// (for the SOC console): system agents privileged on the host, a VPN
// with NET_ADMIN, a media server mounting node folders, ...
func demoPodSecurity(pod obj2, ns, name string) {
	spec := pod["spec"].(obj2)
	c := spec["containers"].([]obj2)[0]
	sc := obj2{}
	c["securityContext"] = sc
	hostPath := func(paths ...string) {
		var vols []obj2
		for i, p := range paths {
			vols = append(vols, obj2{"name": fmt.Sprintf("host%d", i), "hostPath": obj2{"path": p}})
		}
		spec["volumes"] = vols
	}
	switch {
	case strings.HasPrefix(name, "cilium-") && !strings.HasPrefix(name, "cilium-operator"):
		sc["privileged"] = true
		spec["hostNetwork"] = true
		hostPath("/sys/fs/bpf", "/proc", "/run/cilium")
	case strings.HasPrefix(name, "longhorn-csi-plugin"), strings.HasPrefix(name, "longhorn-manager"):
		sc["privileged"] = true
		hostPath("/var/lib/kubelet", "/dev", "/var/lib/longhorn")
	case strings.HasPrefix(name, "kube-apiserver"), strings.HasPrefix(name, "etcd"):
		spec["hostNetwork"] = true
		hostPath("/etc/kubernetes/pki")
	case strings.HasPrefix(name, "home-assistant"):
		spec["hostNetwork"] = true
		sc["privileged"] = true
		hostPath("/run/dbus")
	case strings.HasPrefix(name, "jellyfin"):
		hostPath("/mnt/media")
	case strings.HasPrefix(name, "wg-easy"):
		sc["capabilities"] = obj2{"add": []string{"NET_ADMIN", "SYS_MODULE"}}
	case strings.HasPrefix(name, "qbittorrent"):
		sc["capabilities"] = obj2{"add": []string{"NET_ADMIN"}}
	case strings.HasPrefix(name, "n8n"):
		spec["serviceAccountName"] = "n8n"
		c["image"] = "n8nio/n8n:latest"
	case ns == "argocd" || ns == "cert-manager":
		sc["runAsNonRoot"] = true
		sc["allowPrivilegeEscalation"] = false
	}
	if name == "nextcloud-db-0" {
		delete(c["resources"].(obj2), "limits")
	}
}

// demoOwner: the controller a demo pod belongs to.
func demoOwner(name string) obj2 {
	parent := strings.TrimSuffix(name, name[strings.LastIndex(name, "-"):])
	switch {
	case strings.HasPrefix(name, "kube-apiserver-"), strings.HasPrefix(name, "etcd-"):
		return obj2{"kind": "Node", "name": name[strings.LastIndex(name, "-")+1:]}
	case strings.HasSuffix(name, "-0"):
		return obj2{"kind": "StatefulSet", "name": parent}
	case strings.HasPrefix(name, "longhorn-csi-plugin-"), strings.HasPrefix(name, "cilium-") && !strings.HasPrefix(name, "cilium-operator"):
		return obj2{"kind": "DaemonSet", "name": parent}
	}
	return obj2{"kind": "ReplicaSet", "name": parent}
}
