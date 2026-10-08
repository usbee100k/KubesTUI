package main

// Manifest generation for Docker Compose imports (see compose.go).

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/compose-spec/compose-go/v2/types"
	"go.yaml.in/yaml/v3"
)

type obj = map[string]any

func writeYAML(path string, docs ...obj) error {
	var buf bytes.Buffer
	for i, d := range docs {
		if i > 0 {
			buf.WriteString("---\n")
		}
		out, err := yaml.Marshal(d)
		if err != nil {
			return err
		}
		buf.Write(out)
	}
	return os.WriteFile(path, buf.Bytes(), 0o644)
}

func appLabels(app, svc string) obj {
	return obj{
		"app.kubernetes.io/name":       svc,
		"app.kubernetes.io/part-of":    app,
		"app.kubernetes.io/managed-by": "kubestui-compose",
	}
}

func selectorLabels(app, svc string) obj {
	return obj{"app.kubernetes.io/name": svc, "app.kubernetes.io/part-of": app}
}

func probeFrom(h *types.HealthCheckConfig) obj {
	if h == nil || h.Disable || len(h.Test) == 0 {
		return nil
	}
	var cmd []string
	switch h.Test[0] {
	case "NONE":
		return nil
	case "CMD":
		cmd = h.Test[1:]
	case "CMD-SHELL":
		cmd = []string{"sh", "-c", strings.Join(h.Test[1:], " ")}
	default:
		cmd = []string{"sh", "-c", strings.Join(h.Test, " ")}
	}
	if len(cmd) == 0 {
		return nil
	}
	retries := 3
	if h.Retries != nil {
		retries = int(*h.Retries)
	}
	return obj{
		"exec":                obj{"command": cmd},
		"periodSeconds":       durationSeconds(h.Interval, 30),
		"timeoutSeconds":      durationSeconds(h.Timeout, 30),
		"failureThreshold":    retries,
		"initialDelaySeconds": durationSeconds(h.StartPeriod, 0),
	}
}

func writeApp(root string, plan *importPlan) error {
	app := plan.app
	dir := filepath.Join(root, appsDirRel, app)
	res := filepath.Join(dir, "resources")
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(res, 0o755); err != nil {
		return err
	}

	var files []string
	write := func(name string, docs ...obj) error {
		files = append(files, name)
		return writeYAML(filepath.Join(res, name), docs...)
	}

	// Volumes.
	var pvcNames []string
	for n := range plan.pvcs {
		pvcNames = append(pvcNames, n)
	}
	sort.Strings(pvcNames)
	for _, n := range pvcNames {
		p := plan.pvcs[n]
		mode := "ReadWriteOnce"
		if p.shared {
			mode = "ReadWriteMany" // Longhorn serves RWX over NFS
		}
		if err := write("pvc-"+n+".yaml", obj{
			"apiVersion": "v1",
			"kind":       "PersistentVolumeClaim",
			"metadata":   obj{"name": n, "namespace": app, "labels": obj{"app.kubernetes.io/part-of": app}},
			"spec": obj{
				"accessModes":      []string{mode},
				"storageClassName": "longhorn",
				"resources":        obj{"requests": obj{"storage": p.size}},
			},
		}); err != nil {
			return err
		}
	}

	// Files from bind mounts.
	var cmNames []string
	for n := range plan.configMap {
		cmNames = append(cmNames, n)
	}
	sort.Strings(cmNames)
	for _, n := range cmNames {
		if err := write(n+"-configmap.yaml", obj{
			"apiVersion": "v1",
			"kind":       "ConfigMap",
			"metadata":   obj{"name": n, "namespace": app, "labels": obj{"app.kubernetes.io/part-of": app}},
			"data":       plan.configMap[n],
		}); err != nil {
			return err
		}
	}

	for _, sp := range plan.services {
		s := sp.svc

		// Container.
		c := obj{"name": sp.name, "image": s.Image}
		if len(s.Entrypoint) > 0 {
			c["command"] = []string(s.Entrypoint)
		}
		if len(s.Command) > 0 {
			c["args"] = []string(s.Command)
		}
		var env []obj
		for _, kv := range sp.plainEnv {
			env = append(env, obj{"name": kv[0], "value": kv[1]})
		}
		for _, kv := range sp.secretEnv {
			env = append(env, obj{"name": kv[0], "valueFrom": obj{"secretKeyRef": obj{"name": app + "-secrets", "key": kv[1]}}})
		}
		sort.Slice(env, func(i, j int) bool { return env[i]["name"].(string) < env[j]["name"].(string) })
		if len(env) > 0 {
			c["env"] = env
		}
		var cports []obj
		seenPort := map[string]bool{}
		for _, p := range sp.ports {
			k := fmt.Sprintf("%d/%s", p.target, p.protocol)
			if seenPort[k] {
				continue
			}
			seenPort[k] = true
			cports = append(cports, obj{"containerPort": int(p.target), "protocol": p.protocol})
		}
		if len(cports) > 0 {
			c["ports"] = cports
		}
		if s.WorkingDir != "" {
			c["workingDir"] = s.WorkingDir
		}
		if s.Tty {
			c["tty"] = true
		}
		if s.StdinOpen {
			c["stdin"] = true
		}

		sec := obj{}
		needsPrivileged := s.Privileged
		for _, v := range sp.volumes {
			if v.kind == "hostpath" && strings.HasPrefix(v.hostPath, "/dev/") {
				needsPrivileged = true // device access
			}
		}
		if needsPrivileged {
			sec["privileged"] = true
		}
		caps := obj{}
		strip := func(l []string) []string {
			var out []string
			for _, c := range l {
				out = append(out, strings.TrimPrefix(strings.ToUpper(c), "CAP_"))
			}
			return out
		}
		if len(s.CapAdd) > 0 {
			caps["add"] = strip(s.CapAdd)
		}
		if len(s.CapDrop) > 0 {
			caps["drop"] = strip(s.CapDrop)
		}
		if len(caps) > 0 {
			sec["capabilities"] = caps
		}
		if s.User != "" {
			u, g, _ := strings.Cut(s.User, ":")
			if n, err := strconv.ParseInt(u, 10, 64); err == nil {
				sec["runAsUser"] = n
			} else {
				sp.warnings = append(sp.warnings, "user "+s.User+" is a name; Kubernetes needs a numeric UID, so it was not set")
			}
			if n, err := strconv.ParseInt(g, 10, 64); err == nil && g != "" {
				sec["runAsGroup"] = n
			}
		}
		if s.ReadOnly {
			sec["readOnlyRootFilesystem"] = true
		}
		if len(sec) > 0 {
			c["securityContext"] = sec
		}

		resources := obj{}
		limits, requests := obj{}, obj{}
		cpuLimit, memLimit := s.CPUS, s.MemLimit
		var cpuReq float32
		memReq := s.MemReservation
		if s.Deploy != nil {
			if l := s.Deploy.Resources.Limits; l != nil {
				if l.NanoCPUs > 0 {
					cpuLimit = float32(l.NanoCPUs)
				}
				if l.MemoryBytes > 0 {
					memLimit = l.MemoryBytes
				}
			}
			if r := s.Deploy.Resources.Reservations; r != nil {
				cpuReq = float32(r.NanoCPUs)
				if r.MemoryBytes > 0 {
					memReq = r.MemoryBytes
				}
			}
		}
		if q := cpuQuantity(cpuLimit); q != "" {
			limits["cpu"] = q
		}
		if q := memQuantity(memLimit); q != "" {
			limits["memory"] = q
		}
		if q := cpuQuantity(cpuReq); q != "" {
			requests["cpu"] = q
		}
		if q := memQuantity(memReq); q != "" {
			requests["memory"] = q
		}
		if len(limits) > 0 {
			resources["limits"] = limits
		}
		if len(requests) > 0 {
			resources["requests"] = requests
		}
		if len(resources) > 0 {
			c["resources"] = resources
		}

		if p := probeFrom(s.HealthCheck); p != nil {
			c["readinessProbe"] = p
			live := obj{}
			for k, v := range p {
				live[k] = v
			}
			c["livenessProbe"] = live
		}

		// Volumes and mounts.
		var vols, mounts []obj
		hasRWO := false
		var nodePin string
		usesDRI := false
		for i, v := range sp.volumes {
			name := fmt.Sprintf("vol-%d", i)
			m := obj{"name": name, "mountPath": v.target}
			if v.readOnly {
				m["readOnly"] = true
			}
			switch v.kind {
			case "pvc":
				vols = append(vols, obj{"name": name, "persistentVolumeClaim": obj{"claimName": v.claim}})
				if !plan.pvcs[v.claim].shared {
					hasRWO = true
				}
			case "configmap":
				vols = append(vols, obj{"name": name, "configMap": obj{"name": v.cmName}})
				m["subPath"] = v.cmKey
			case "hostpath":
				vols = append(vols, obj{"name": name, "hostPath": obj{"path": v.hostPath}})
				if v.node != "" {
					nodePin = v.node
				}
				if strings.HasPrefix(v.hostPath, "/dev/dri") {
					usesDRI = true
				}
			case "emptydir":
				ed := obj{}
				if v.medium != "" {
					ed["medium"] = v.medium
				}
				if v.limit != "" {
					ed["sizeLimit"] = v.limit
				}
				vols = append(vols, obj{"name": name, "emptyDir": ed})
			}
			mounts = append(mounts, m)
		}
		if len(mounts) > 0 {
			c["volumeMounts"] = mounts
		}

		pod := obj{"containers": []obj{c}}
		if len(vols) > 0 {
			pod["volumes"] = vols
		}

		// sysctls: set inside the pod's own network namespace at start.
		var sysctls []string
		var sysKeys []string
		for k := range s.Sysctls {
			sysKeys = append(sysKeys, k)
		}
		sort.Strings(sysKeys)
		for _, k := range sysKeys {
			if strings.HasPrefix(k, "net.") {
				sysctls = append(sysctls, k+"="+s.Sysctls[k])
			} else {
				sp.warnings = append(sp.warnings, "sysctl "+k+" isn't per-pod; skipped")
			}
		}
		if len(sysctls) > 0 {
			pod["initContainers"] = []obj{{
				"name":            "sysctls",
				"image":           "busybox:1.37",
				"securityContext": obj{"privileged": true},
				"command":         []string{"sh", "-c", "sysctl -w " + strings.Join(sysctls, " ")},
			}}
		}

		if s.NetworkMode == "host" {
			pod["hostNetwork"] = true
			pod["dnsPolicy"] = "ClusterFirstWithHostNet"
		}
		if len(s.ExtraHosts) > 0 {
			byIP := map[string][]string{}
			for host, ips := range s.ExtraHosts {
				for _, ip := range ips {
					if ip == "host-gateway" {
						sp.warnings = append(sp.warnings, "extra_hosts "+host+":host-gateway has no Kubernetes equivalent; skipped")
						continue
					}
					byIP[ip] = append(byIP[ip], host)
				}
			}
			var aliases []obj
			for ip, hosts := range byIP {
				sort.Strings(hosts)
				aliases = append(aliases, obj{"ip": ip, "hostnames": hosts})
			}
			sort.Slice(aliases, func(i, j int) bool { return aliases[i]["ip"].(string) < aliases[j]["ip"].(string) })
			if len(aliases) > 0 {
				pod["hostAliases"] = aliases
			}
		}
		if s.StopGracePeriod != nil {
			pod["terminationGracePeriodSeconds"] = durationSeconds(s.StopGracePeriod, 30)
		}
		if nodePin != "" {
			pod["nodeSelector"] = obj{"kubernetes.io/hostname": nodePin}
		} else if usesDRI {
			// GPU/iGPU nodes, labelled by Node Feature Discovery.
			pod["affinity"] = obj{"nodeAffinity": obj{"requiredDuringSchedulingIgnoredDuringExecution": obj{
				"nodeSelectorTerms": []obj{
					{"matchExpressions": []obj{{"key": "homelab.io/gpu", "operator": "In", "values": []string{"true"}}}},
					{"matchExpressions": []obj{{"key": "homelab.io/igpu", "operator": "Exists"}}},
				},
			}}}
		}

		deploy := obj{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata":   obj{"name": sp.name, "namespace": app, "labels": appLabels(app, sp.name)},
			"spec": obj{
				"replicas": 1,
				"selector": obj{"matchLabels": selectorLabels(app, sp.name)},
				"template": obj{
					"metadata": obj{"labels": appLabels(app, sp.name)},
					"spec":     pod,
				},
			},
		}
		if hasRWO {
			deploy["spec"].(obj)["strategy"] = obj{"type": "Recreate"} // RWO volume: one pod at a time
		}
		if err := write(sp.name+"-deployment.yaml", deploy); err != nil {
			return err
		}

		// Service named after the compose service, so other services in the
		// app reach it by the same name they used in Docker (e.g. "db:5432").
		if len(cports) > 0 {
			var sports []obj
			for _, cp := range cports {
				port := cp["containerPort"].(int)
				proto := cp["protocol"].(string)
				sports = append(sports, obj{
					"name":       fmt.Sprintf("p%d-%s", port, strings.ToLower(proto)),
					"port":       port,
					"targetPort": port,
					"protocol":   proto,
				})
			}
			if err := write(sp.name+"-service.yaml", obj{
				"apiVersion": "v1",
				"kind":       "Service",
				"metadata":   obj{"name": sp.name, "namespace": app, "labels": appLabels(app, sp.name)},
				"spec":       obj{"type": "ClusterIP", "selector": selectorLabels(app, sp.name), "ports": sports},
			}); err != nil {
				return err
			}
		}

		// LAN services: one LoadBalancer per IP.
		byIP := map[string][]*portPlan{}
		var ips []string
		for _, p := range sp.ports {
			if p.kind == "lan" {
				if _, ok := byIP[p.ip]; !ok {
					ips = append(ips, p.ip)
				}
				byIP[p.ip] = append(byIP[p.ip], p)
			}
		}
		for i, ip := range ips {
			name := sp.name + "-lan"
			if i > 0 {
				name = fmt.Sprintf("%s-lan-%d", sp.name, i+1)
			}
			var lports []obj
			for _, p := range byIP[ip] {
				pub, err := strconv.Atoi(p.published)
				if err != nil {
					pub = int(p.target)
				}
				lports = append(lports, obj{
					"name":       fmt.Sprintf("p%d-%s", pub, strings.ToLower(p.protocol)),
					"port":       pub,
					"targetPort": int(p.target),
					"protocol":   p.protocol,
				})
			}
			if err := write(name+"-service.yaml", obj{
				"apiVersion": "v1",
				"kind":       "Service",
				"metadata": obj{"name": name, "namespace": app, "labels": appLabels(app, sp.name),
					"annotations": obj{"metallb.io/loadBalancerIPs": ip}},
				"spec": obj{"type": "LoadBalancer", "selector": selectorLabels(app, sp.name), "ports": lports},
			}); err != nil {
				return err
			}
		}

		// Web UIs: one Ingress per hostname.
		for _, p := range sp.ports {
			if p.kind != "web" {
				continue
			}
			ann := obj{
				"cert-manager.io/cluster-issuer":              "homelab-ca",
				"nginx.ingress.kubernetes.io/proxy-body-size": "0", // uploads of any size
			}
			if p.https {
				ann["nginx.ingress.kubernetes.io/backend-protocol"] = "HTTPS"
			}
			name := dnsName(strings.Split(p.host, ".")[0])
			if err := write(name+"-ingress.yaml", obj{
				"apiVersion": "networking.k8s.io/v1",
				"kind":       "Ingress",
				"metadata":   obj{"name": name, "namespace": app, "labels": appLabels(app, sp.name), "annotations": ann},
				"spec": obj{
					"ingressClassName": "nginx",
					"tls":              []obj{{"hosts": []string{p.host}, "secretName": name + "-tls"}},
					"rules": []obj{{
						"host": p.host,
						"http": obj{"paths": []obj{{
							"path":     "/",
							"pathType": "Prefix",
							"backend":  obj{"service": obj{"name": sp.name, "port": obj{"number": int(p.target)}}},
						}}},
					}},
				},
			}); err != nil {
				return err
			}
		}
	}

	sort.Strings(files)
	if err := writeYAML(filepath.Join(res, "kustomization.yaml"), obj{
		"apiVersion": "kustomize.config.k8s.io/v1beta1",
		"kind":       "Kustomization",
		"resources":  files,
	}); err != nil {
		return err
	}

	// Argo CD Application, like apps/infrastructure/<name>/app.yaml.
	branch := os.Getenv("GIT_BRANCH")
	if branch == "" {
		branch = "main"
	}
	appYAML := obj{
		"apiVersion": "argoproj.io/v1alpha1",
		"kind":       "Application",
		"metadata": obj{
			"name":        app,
			"namespace":   "argocd",
			"annotations": obj{"argocd.argoproj.io/sync-wave": "50"},
			// Removing the app from Git also removes what it deployed.
			"finalizers": []string{"resources-finalizer.argocd.argoproj.io"},
		},
		"spec": obj{
			"project": "homelab",
			"sources": []obj{{
				"repoURL":        os.Getenv("GITHUB_REPO"),
				"targetRevision": branch,
				"path":           appsDirRel + "/" + app + "/resources",
			}},
			"destination": obj{"server": "https://kubernetes.default.svc", "namespace": app},
			"syncPolicy": obj{
				"automated":   obj{"prune": true, "selfHeal": true},
				"syncOptions": []string{"CreateNamespace=true", "ServerSideApply=true"},
			},
		},
	}
	if err := writeYAML(filepath.Join(dir, "app.yaml"), appYAML); err != nil {
		return err
	}

	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte(importReadme(plan)), 0o644); err != nil {
		return err
	}

	return updateAppsKustomization(root, app, true)
}

// updateAppsKustomization adds or removes "<app>/app.yaml" in
// apps/applications/kustomization.yaml (created if missing).
func updateAppsKustomization(root, app string, add bool) error {
	path := filepath.Join(root, appsDirRel, "kustomization.yaml")
	var entries []string
	if data, err := os.ReadFile(path); err == nil {
		var k struct {
			Resources []string `yaml:"resources"`
		}
		if err := yaml.Unmarshal(data, &k); err == nil {
			entries = k.Resources
		}
	}
	want := app + "/app.yaml"
	var out []string
	for _, e := range entries {
		if e != want {
			out = append(out, e)
		}
	}
	if add {
		out = append(out, want)
	}
	sort.Strings(out)
	if out == nil {
		out = []string{}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	var buf bytes.Buffer
	buf.WriteString("# Apps imported from Docker Compose (KubesTUI). Managed by the importer.\n")
	body, _ := yaml.Marshal(obj{
		"apiVersion": "kustomize.config.k8s.io/v1beta1",
		"kind":       "Kustomization",
		"resources":  out,
	})
	buf.Write(body)
	return os.WriteFile(path, buf.Bytes(), 0o644)
}

func importReadme(plan *importPlan) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\nImported from Docker Compose by KubesTUI on %s.\n\n", plan.app, time.Now().Format("2006-01-02"))
	b.WriteString("## Access\n\n")
	for _, sp := range plan.services {
		for _, p := range sp.ports {
			switch p.kind {
			case "web":
				fmt.Fprintf(&b, "- **%s**: https://%s\n", sp.name, p.host)
			case "lan":
				fmt.Fprintf(&b, "- **%s**: %s:%s/%s on your LAN\n", sp.name, p.ip, p.published, strings.ToLower(p.protocol))
			default:
				fmt.Fprintf(&b, "- **%s**: `%s.%s:%d` inside the cluster\n", sp.name, sp.name, plan.namespace, p.target)
			}
		}
	}
	if len(plan.secrets) > 0 {
		fmt.Fprintf(&b, "\n## Secrets\n\nSensitive settings live only in the cluster Secret `%s/%s-secrets` (not in Git). "+
			"Re-import or `kubectl -n %s edit secret %s-secrets` to change them.\n", plan.namespace, plan.app, plan.namespace, plan.app)
	}
	var warns []string
	for _, sp := range plan.services {
		for _, w := range sp.warnings {
			warns = append(warns, sp.name+": "+w)
		}
	}
	if len(warns) > 0 {
		b.WriteString("\n## Review\n\n")
		for _, w := range warns {
			b.WriteString("- " + w + "\n")
		}
	}
	b.WriteString("\n## Remove\n\nKubesTUI: **Remove Imported App**. This deletes the app and its volumes.\n")
	return b.String()
}

// applySecret creates the namespace and the app's Secret directly in the
// cluster (stdin to kubectl, so values never appear on a command line).
func applySecret(plan *importPlan) error {
	ns := exec.Command("kubectl", "create", "namespace", plan.namespace, "--dry-run=client", "-o", "yaml")
	nsYAML, err := ns.Output()
	if err != nil {
		return err
	}
	apply := exec.Command("kubectl", "apply", "-f", "-")
	apply.Stdin = bytes.NewReader(nsYAML)
	if out, err := apply.CombinedOutput(); err != nil {
		return fmt.Errorf("%v: %s", err, out)
	}

	data, err := yaml.Marshal(obj{
		"apiVersion": "v1",
		"kind":       "Secret",
		"metadata": obj{"name": plan.app + "-secrets", "namespace": plan.namespace,
			"labels": obj{"app.kubernetes.io/part-of": plan.app, "app.kubernetes.io/managed-by": "kubestui-compose"}},
		"type":       "Opaque",
		"stringData": plan.secrets,
	})
	if err != nil {
		return err
	}
	apply = exec.Command("kubectl", "apply", "-f", "-")
	apply.Stdin = bytes.NewReader(data)
	if out, err := apply.CombinedOutput(); err != nil {
		return fmt.Errorf("%v: %s", err, out)
	}
	return nil
}

// runComposeRemove is `kubestui compose-remove`.
func runComposeRemove() int {
	root, err := gitopsDir()
	if err != nil {
		fmt.Println(cFail + err.Error())
		return 1
	}
	in := &prompter{in: bufio.NewReader(os.Stdin)}

	entries, _ := os.ReadDir(filepath.Join(root, appsDirRel))
	var apps []string
	for _, e := range entries {
		if e.IsDir() && fileExists(filepath.Join(root, appsDirRel, e.Name(), "app.yaml")) {
			apps = append(apps, e.Name())
		}
	}
	fmt.Println()
	fmt.Println("=============================================")
	fmt.Println(" Remove an imported app")
	fmt.Println("=============================================")
	fmt.Println()
	if len(apps) == 0 {
		fmt.Println("  No imported apps in " + appsDirRel + "/.")
		return 0
	}
	for i, a := range apps {
		fmt.Printf("  %d) %s\n", i+1, a)
	}
	fmt.Println()
	var app string
	for {
		a := in.ask(fmt.Sprintf("App to remove [1-%d]", len(apps)), "")
		if n, err := strconv.Atoi(a); err == nil && n >= 1 && n <= len(apps) {
			app = apps[n-1]
			break
		}
		fmt.Println("  [ERROR] Enter a number from the list.")
	}
	fmt.Println()
	fmt.Println(cWarn + "This removes " + app + " from the cluster, including its volumes (data) and secrets.")
	if in.ask("Type "+app+" to confirm", "") != app {
		fmt.Println("Cancelled. Nothing was changed.")
		return 1
	}
	if err := os.RemoveAll(filepath.Join(root, appsDirRel, app)); err != nil {
		fmt.Println(cFail + err.Error())
		return 1
	}
	if err := updateAppsKustomization(root, app, false); err != nil {
		fmt.Println(cFail + err.Error())
		return 1
	}
	fmt.Println(cOK + "Removed " + appsDirRel + "/" + app + "/")
	writeResult(app)
	return 0
}
