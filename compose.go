package main

// Docker Compose import: turns a docker-compose.yml into an Argo CD app in
// the GitOps repo (apps/applications/<name>/, laid out like the other apps),
// fitted to this cluster: Longhorn volumes, ingress with the homelab CA,
// MetalLB IPs for LAN services, and passwords in a cluster Secret instead of
// git. Parsing uses compose-go, the library Docker Compose and Kompose use, so
// variables, .env files and every port/volume syntax behave like Docker.
//
// Runs on a control plane (install.sh --run compose-import / compose-remove),
// reading answers from the terminal. install.sh prepares the GitOps checkout
// before and commits/pushes after. Environment from install.sh:
//   GITOPS_DIR, GITHUB_REPO, GIT_BRANCH, BASE_DOMAIN, METALLB_RANGE,
//   VPN_LB_IP, COMPOSE_FILE (optional), KUBESTUI_RESULT_FILE, and
//   COMPOSE_SOURCE_NODE + COMPOSE_SOURCE_DIR when the compose file came
//   from a node (its folders can then be copied into the new volumes).

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/compose-spec/compose-go/v2/cli"
	"github.com/compose-spec/compose-go/v2/loader"
	"github.com/compose-spec/compose-go/v2/types"
)

const (
	appsDirRel     = "apps/applications"
	maxConfigBytes = 512 * 1024 // bind-mounted files up to this size become ConfigMaps
)

// ---------------------------------------------------------------------------
// Terminal prompts
// ---------------------------------------------------------------------------

type prompter struct{ in *bufio.Reader }

func (p *prompter) ask(question, def string) string {
	if def != "" {
		fmt.Printf("%s [%s]: ", question, def)
	} else {
		fmt.Printf("%s: ", question)
	}
	line, err := p.in.ReadString('\n')
	if err != nil && line == "" {
		fmt.Println()
		os.Exit(130) // input closed (Ctrl+D / session ended)
	}
	if line = strings.TrimSpace(line); line == "" {
		return def
	}
	return line
}

func (p *prompter) choose(question string, options []string, def string) string {
	for {
		a := strings.ToLower(p.ask(question+" ("+strings.Join(options, "/")+")", def))
		for _, o := range options {
			if a == o || (a != "" && strings.HasPrefix(o, a)) {
				return o
			}
		}
		fmt.Println("  [ERROR] Choose one of: " + strings.Join(options, ", "))
	}
}

// size asks for a volume size until it gets one (5Gi, 500Mi, 1Ti, 10).
func (p *prompter) size(question, def string) string {
	for {
		a := strings.TrimSpace(p.ask(question, def))
		if sizePattern.MatchString(a) {
			return normSize(a)
		}
		fmt.Println("    [ERROR] Enter a size like 5Gi, 500Mi or 1Ti.")
	}
}

func (p *prompter) yes(question string, def bool) bool {
	d := "y"
	if !def {
		d = "n"
	}
	return p.choose(question, []string{"y", "n"}, d) == "y"
}

const (
	cInfo = "\x1b[0;34m[INFO]\x1b[0m "
	cOK   = "\x1b[0;32m[ OK ]\x1b[0m "
	cWarn = "\x1b[1;33m[WARN]\x1b[0m "
	cFail = "\x1b[0;31m[FAIL]\x1b[0m "
)

// ---------------------------------------------------------------------------
// Names and helpers
// ---------------------------------------------------------------------------

var dnsUnsafe = regexp.MustCompile(`[^a-z0-9-]+`)

func dnsName(s string) string {
	s = strings.Trim(dnsUnsafe.ReplaceAllString(strings.ToLower(s), "-"), "-")
	if len(s) > 50 {
		s = strings.Trim(s[:50], "-")
	}
	if s == "" {
		s = "app"
	}
	return s
}

var sensitiveEnv = regexp.MustCompile(`(?i)(pass(word)?|passwd|secret|token|api_?key|private_?key|credential|auth|cookie|salt)`)

func envSensitive(name string) bool { return sensitiveEnv.MatchString(name) }

func memQuantity(b types.UnitBytes) string {
	if b <= 0 {
		return ""
	}
	mi := (int64(b) + (1<<20 - 1)) >> 20
	return fmt.Sprintf("%dMi", mi)
}

func cpuQuantity(c float32) string {
	if c <= 0 {
		return ""
	}
	return fmt.Sprintf("%dm", int(c*1000+0.5))
}

func durationSeconds(d *types.Duration, def int) int {
	if d == nil {
		return def
	}
	s := int(time.Duration(*d).Seconds())
	if s < 1 {
		return 1
	}
	return s
}

// ---------------------------------------------------------------------------
// MetalLB address pool
// ---------------------------------------------------------------------------

func poolAddresses(rng string) []netip.Addr {
	var start, end netip.Addr
	if strings.Contains(rng, "/") {
		p, err := netip.ParsePrefix(rng)
		if err != nil {
			return nil
		}
		p = p.Masked()
		start = p.Addr()
		end = start
		for a := start; p.Contains(a); a = a.Next() {
			end = a
		}
	} else if a, b, ok := strings.Cut(rng, "-"); ok {
		var err1, err2 error
		start, err1 = netip.ParseAddr(strings.TrimSpace(a))
		end, err2 = netip.ParseAddr(strings.TrimSpace(b))
		if err1 != nil || err2 != nil {
			return nil
		}
	} else {
		return nil
	}
	var out []netip.Addr
	for a := start; a.Compare(end) <= 0 && len(out) < 4096; a = a.Next() {
		out = append(out, a)
	}
	return out
}

var lbIPPattern = regexp.MustCompile(`metallb\.io/loadBalancerIPs:\s*"?([0-9.]+)`)

// usedLBIPs collects addresses already taken by LoadBalancer services, the
// VPN, and other imported apps in the GitOps repo.
func usedLBIPs(gitopsDir string) map[string]bool {
	used := map[string]bool{}
	if ip := os.Getenv("VPN_LB_IP"); ip != "" {
		used[ip] = true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "kubectl", "get", "svc", "-A", "-o",
		`jsonpath={range .items[*]}{.status.loadBalancer.ingress[*].ip}{" "}{.metadata.annotations.metallb\.io/loadBalancerIPs}{"\n"}{end}`).Output(); err == nil {
		for _, f := range strings.Fields(string(out)) {
			for _, ip := range strings.Split(f, ",") {
				used[ip] = true
			}
		}
	}
	_ = filepath.Walk(filepath.Join(gitopsDir, "apps"), func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && strings.HasSuffix(path, ".yaml") {
			if data, err := os.ReadFile(path); err == nil {
				for _, m := range lbIPPattern.FindAllSubmatch(data, -1) {
					used[string(m[1])] = true
				}
			}
		}
		return nil
	})
	return used
}

// nodeNames lists the cluster's node names (nil if it can't be asked).
func nodeNames() []string {
	rows, err := clusterNodes()
	if err != nil {
		return nil
	}
	var names []string
	for _, r := range rows {
		names = append(names, strings.ToLower(r.name))
	}
	return names
}

var ingressHostPattern = regexp.MustCompile(`(?m)^\s*-?\s*host:\s*"?([a-z0-9][a-z0-9.-]*\.[a-z0-9.-]+)`)

// usedHosts collects ingress hostnames other apps already use: in the
// cluster and in the GitOps repo. The app being (re)imported doesn't count.
func usedHosts(gitopsDir, app string) map[string]string {
	used := map[string]string{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "kubectl", "get", "ingress", "-A", "-o",
		`jsonpath={range .items[*]}{.metadata.namespace}{" "}{.spec.rules[*].host}{"\n"}{end}`).Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			f := strings.Fields(line)
			if len(f) < 2 || f[0] == app {
				continue
			}
			for _, h := range f[1:] {
				used[strings.ToLower(h)] = f[0]
			}
		}
	}
	own := filepath.Join(gitopsDir, appsDirRel, app) + string(filepath.Separator)
	_ = filepath.Walk(filepath.Join(gitopsDir, "apps"), func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".yaml") || strings.HasPrefix(path, own) {
			return nil
		}
		if data, err := os.ReadFile(path); err == nil {
			for _, m := range ingressHostPattern.FindAllSubmatch(data, -1) {
				if _, ok := used[string(m[1])]; !ok {
					rel, _ := filepath.Rel(gitopsDir, path)
					used[string(m[1])] = rel
				}
			}
		}
		return nil
	})
	return used
}

var hostnamePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

// webPortFor picks the port that gets the web UI by default: the first
// well-known web port, else the first published TCP port that isn't a
// database or a low system port. 0 if none.
func webPortFor(s types.ServiceConfig) uint32 {
	var fallback uint32
	for _, pc := range s.Ports {
		if pc.Published == "" || strings.EqualFold(pc.Protocol, "udp") || knownInternalPort(pc.Target) {
			continue
		}
		if knownWebPort(pc.Target) {
			return pc.Target
		}
		if fallback == 0 && (pc.Target >= 1024 || pc.Target == 80 || pc.Target == 443) {
			fallback = pc.Target
		}
	}
	return fallback
}

// ---------------------------------------------------------------------------
// The plan: what gets generated
// ---------------------------------------------------------------------------

type portPlan struct {
	target    uint32
	published string
	protocol  string // TCP / UDP
	kind      string // web / lan / internal
	host      string // web
	https     bool   // web backend speaks HTTPS
	ip        string // lan
}

type volumePlan struct {
	target   string
	readOnly bool
	kind     string // pvc / configmap / hostpath / emptydir
	claim    string // pvc name
	size     string
	cmName   string
	cmKey    string
	hostPath string
	hostType string // hostpath: Directory / CharDevice ("" = no check)
	node     string // hostpath: pin to node
	medium   string // emptydir
	limit    string // emptydir
}

type servicePlan struct {
	name      string
	svc       types.ServiceConfig
	ports     []*portPlan
	volumes   []*volumePlan
	plainEnv  [][2]string
	secretEnv [][2]string // name, secret key
	warnings  []string
}

type importPlan struct {
	app       string
	namespace string
	services  []*servicePlan
	pvcs      map[string]*pvcPlan
	configMap map[string]map[string]string // name -> key -> content
	secrets   map[string]string            // key -> value
	warnings  []string
	notes     []string

	// Folders to copy into their new volumes before the app starts (the
	// compose file came from a node): node, folder there, claim.
	copies [][3]string
}

type pvcPlan struct {
	name   string
	size   string
	shared bool
}

func knownWebPort(p uint32) bool {
	switch p {
	case 80, 443, 3000, 3001, 5000, 5055, 7878, 8000, 8080, 8081, 8082, 8083, 8096, 8112,
		8123, 8181, 8200, 8265, 8384, 8443, 8686, 8787, 8888, 8989, 9000, 9090, 9091, 9117, 9696, 32400:
		return true
	}
	return false
}

func knownInternalPort(p uint32) bool {
	switch p {
	case 5432, 3306, 6379, 27017, 9200, 11211, 5672, 2181, 9092, 4222:
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

func gitopsDir() (string, error) {
	d := os.Getenv("GITOPS_DIR")
	if d == "" {
		return "", errors.New("GITOPS_DIR is not set (run through install.sh --run compose-import)")
	}
	return d, nil
}

func writeResult(s string) {
	if f := os.Getenv("KUBESTUI_RESULT_FILE"); f != "" {
		_ = os.WriteFile(f, []byte(s), 0o600)
	}
}

// loadCompose parses a compose file the way Docker Compose does.
func loadCompose(file string) (*types.Project, error) {
	abs, err := filepath.Abs(file)
	if err != nil {
		return nil, err
	}
	opts, err := cli.NewProjectOptions([]string{abs},
		cli.WithWorkingDirectory(filepath.Dir(abs)),
		cli.WithOsEnv,
		cli.WithEnvFiles(), // .env next to the compose file, like `docker compose`
		cli.WithDotEnv,
		cli.WithResolvedPaths(false),
		cli.WithName(dnsName(filepath.Base(filepath.Dir(abs)))),
		// env_file is read below: with relative paths kept (so ./config
		// stays recognizable), the loader would look for it in the
		// program's working folder instead of next to the compose file.
		cli.WithLoadOptions(func(o *loader.Options) { o.SkipResolveEnvironment = true }),
	)
	if err != nil {
		return nil, err
	}
	proj, err := cli.ProjectFromOptions(context.Background(), opts)
	if err != nil {
		return nil, err
	}
	base := filepath.Dir(abs)
	for name, s := range proj.Services {
		for i, ef := range s.EnvFiles {
			if !filepath.IsAbs(ef.Path) {
				s.EnvFiles[i].Path = filepath.Join(base, ef.Path)
			}
		}
		proj.Services[name] = s
	}
	return proj.WithServicesEnvironmentResolved(false)
}

// composeLocalFiles lists files next to the compose file that an import
// needs: the compose file, .env, env_files and small bind-mounted files.
// Used by workstations to upload the right files.
func composeLocalFiles(file string) ([]string, error) {
	proj, err := loadCompose(file)
	if err != nil {
		return nil, err
	}
	base := filepath.Dir(must(filepath.Abs(file)))
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		if !filepath.IsAbs(p) {
			p = filepath.Join(base, p)
		}
		rel, err := filepath.Rel(base, p)
		if err != nil || strings.HasPrefix(rel, "..") || seen[rel] {
			return
		}
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() && st.Size() <= maxConfigBytes {
			seen[rel] = true
			out = append(out, rel)
		}
	}
	add(file)
	add(".env")
	for _, s := range proj.Services {
		for _, ef := range s.EnvFiles {
			add(ef.Path)
		}
		for _, v := range s.Volumes {
			if v.Type == types.VolumeTypeBind && isRelativeSource(v.Source) {
				add(v.Source)
			}
		}
	}
	return out, nil
}

func must[T any](v T, _ error) T { return v }

func isRelativeSource(s string) bool {
	return strings.HasPrefix(s, "./") || strings.HasPrefix(s, "../") || s == "." ||
		(!filepath.IsAbs(s) && !strings.HasPrefix(s, "~") && !strings.HasPrefix(s, "/"))
}

// runComposeImport is `kubestui compose-import`.
func runComposeImport() int {
	in := &prompter{in: bufio.NewReader(os.Stdin)}
	root, err := gitopsDir()
	if err != nil {
		fmt.Println(cFail + err.Error())
		return 1
	}
	domain := os.Getenv("BASE_DOMAIN")

	fmt.Println()
	fmt.Println("=============================================")
	fmt.Println(" Import a Docker Compose app")
	fmt.Println("=============================================")
	fmt.Println()

	file := os.Getenv("COMPOSE_FILE")
	if file == "" {
		for {
			file = strings.Trim(in.ask("Path to docker-compose.yml", ""), `"'`)
			if st, err := os.Stat(file); err == nil && st.IsDir() {
				for _, n := range []string{"compose.yaml", "compose.yml", "docker-compose.yml", "docker-compose.yaml"} {
					if _, err := os.Stat(filepath.Join(file, n)); err == nil {
						file = filepath.Join(file, n)
						break
					}
				}
			}
			if _, err := os.Stat(file); err == nil {
				break
			}
			fmt.Println("  [ERROR] File not found.")
		}
	}

	proj, err := loadCompose(file)
	if err != nil {
		fmt.Println(cFail + "Could not read the compose file: " + err.Error())
		return 1
	}
	if len(proj.Services) == 0 {
		fmt.Println(cFail + "No services in the compose file.")
		return 1
	}

	var names []string
	for n := range proj.Services {
		names = append(names, n)
	}
	sort.Strings(names)

	fmt.Println(cOK + fmt.Sprintf("Read %s: %d service(s): %s", filepath.Base(file), len(names), strings.Join(names, ", ")))
	fmt.Println()

	// App name.
	appsDir := filepath.Join(root, appsDirRel)
	def := dnsName(proj.Name)
	if len(names) == 1 {
		def = dnsName(names[0])
	}
	var app string
	for {
		app = dnsName(in.ask("App name (also its namespace and URL)", def))
		if _, err := os.Stat(filepath.Join(appsDir, app)); err == nil {
			if in.yes("  "+app+" already exists. Replace it", false) {
				break
			}
			continue
		}
		break
	}

	plan := &importPlan{app: app, namespace: app, pvcs: map[string]*pvcPlan{},
		configMap: map[string]map[string]string{}, secrets: map[string]string{}}

	pool := poolAddresses(os.Getenv("METALLB_RANGE"))
	used := usedLBIPs(root)
	nextFree := func() string {
		for _, a := range pool {
			if !used[a.String()] {
				return a.String()
			}
		}
		return ""
	}

	// Named volumes used by more than one service need shared access.
	volUsers := map[string]int{}
	for _, n := range names {
		for _, v := range proj.Services[n].Volumes {
			if v.Type == types.VolumeTypeVolume && v.Source != "" {
				volUsers[v.Source]++
			}
		}
	}

	composeDir := filepath.Dir(must(filepath.Abs(file)))
	// The compose file came from a node (Import from a node): its folders
	// are there, in srcDir, and can be copied into the new volumes.
	srcNode, srcDir := os.Getenv("COMPOSE_SOURCE_NODE"), os.Getenv("COMPOSE_SOURCE_DIR")
	if srcDir == "" {
		srcNode = ""
	}
	var srcSizes map[string]int64 // folder on the node -> bytes it holds
	_ = json.Unmarshal([]byte(os.Getenv("COMPOSE_SOURCE_SIZES")), &srcSizes)
	// sizeFor suggests a volume size for a folder: its data plus room to
	// grow when it was measured, else a default by its use.
	sizeFor := func(folder, target string) string {
		b, ok := srcSizes[folder]
		if !ok {
			return volumeSize(target)
		}
		fmt.Printf("    (%s holds %s on %s)\n", folder, fmtBytes(b), srcNode)
		gi := (b*3/2 + (1<<30 - 1)) >> 30 // 1.5x, in whole GiB
		if def := volumeSize(target); gi < 5 && def == "5Gi" {
			gi = 5
		}
		return strconv.FormatInt(max(gi, 1), 10) + "Gi"
	}
	webCount := 0 // services with a web UI: each gets its own hostname
	for _, n := range names {
		if webPortFor(proj.Services[n]) != 0 {
			webCount++
		}
	}

	hostsTaken := usedHosts(root, app) // hostname -> who uses it
	nodes := nodeNames()
	lanTaken := map[string]bool{} // "ip port/proto" used by this import

	for _, n := range names {
		s := proj.Services[n]
		sp := &servicePlan{name: dnsName(n), svc: s}
		plan.services = append(plan.services, sp)

		fmt.Printf("\n\x1b[1m── %s\x1b[0m  (%s)\n", n, s.Image)

		if s.Image == "" {
			fmt.Println(cFail + "No image: services built from a Dockerfile (build:) can't be imported. Push the image to a registry and set image:.")
			return 1
		}
		if s.Build != nil {
			sp.warnings = append(sp.warnings, "has build: settings; the image "+s.Image+" is used as-is")
		}

		// Ports. One web UI (hostname) per service by default; the other
		// published ports default to the LAN, which is how Docker had them.
		webPort := webPortFor(s)
		lanIP := "" // this service's LAN IP; its LAN ports share it
		for _, pc := range s.Ports {
			pp := &portPlan{target: pc.Target, published: pc.Published, protocol: strings.ToUpper(pc.Protocol)}
			if pp.protocol == "" {
				pp.protocol = "TCP"
			}
			if pc.Published == "" {
				pp.kind = "internal"
				sp.ports = append(sp.ports, pp)
				continue
			}
			def := "lan"
			switch {
			case knownInternalPort(pc.Target):
				def = "internal"
			case pc.Target == webPort && pp.protocol != "UDP":
				def = "web"
			}
			label := fmt.Sprintf("  Port %s->%d/%s:  web UI (https://…), lan (own IP), or internal", pc.Published, pc.Target, strings.ToLower(pp.protocol))
			fmt.Println(label)
			opts := []string{"web", "lan", "internal"}
			if pp.protocol == "UDP" {
				opts = []string{"lan", "internal"}
			}
			pp.kind = in.choose("    use as", opts, def)
			switch pp.kind {
			case "web":
				host := app
				if webCount > 1 {
					host = dnsName(app + "-" + sp.name)
					if host == app+"-"+app {
						host = app
					}
				}
				suffix := "." + domain
				if domain == "" {
					suffix = ".home.arpa"
				}
				suggest := host + suffix
				if _, taken := hostsTaken[suggest]; taken {
					suggest = fmt.Sprintf("%s-%d%s", host, pc.Target, suffix)
				}
				for {
					h := strings.ToLower(strings.TrimSuffix(in.ask("    hostname", suggest), "."))
					if !hostnamePattern.MatchString(h) {
						fmt.Println("    [ERROR] Not a hostname (like " + host + suffix + ").")
						continue
					}
					if by, taken := hostsTaken[h]; taken {
						fmt.Println("    [ERROR] " + h + " is already used by " + by + ". Choose another hostname.")
						continue
					}
					pp.host = h
					hostsTaken[h] = fmt.Sprintf("%s port %d", n, pc.Target)
					break
				}
				pp.https = pc.Target == 443 || pc.Target == 8443 || pc.Target == 8920
			case "lan":
				suggest := lanIP
				if suggest == "" {
					suggest = nextFree()
				}
				for {
					ip := in.ask("    LAN IP (from the MetalLB pool "+os.Getenv("METALLB_RANGE")+")", suggest)
					a, err := netip.ParseAddr(ip)
					inPool := false
					for _, p := range pool {
						if p == a {
							inPool = true
						}
					}
					key := fmt.Sprintf("%s %s/%s", ip, pp.published, pp.protocol)
					switch {
					case err != nil:
						fmt.Println("    [ERROR] Not an IP address.")
					case len(pool) > 0 && !inPool:
						fmt.Println("    [ERROR] Must be inside the MetalLB pool.")
					case used[ip] && ip != lanIP:
						fmt.Println("    [ERROR] Already in use.")
					case lanTaken[key]:
						fmt.Println("    [ERROR] Port " + pp.published + "/" + strings.ToLower(pp.protocol) + " is already used on " + ip + ".")
					default:
						pp.ip = ip
						used[ip] = true
						lanTaken[key] = true
						if lanIP == "" {
							lanIP = ip
						}
					}
					if pp.ip != "" {
						break
					}
				}
			}
			sp.ports = append(sp.ports, pp)
		}
		for _, e := range s.Expose {
			if p, err := strconv.Atoi(strings.Split(e, "/")[0]); err == nil {
				sp.ports = append(sp.ports, &portPlan{target: uint32(p), protocol: "TCP", kind: "internal"})
			}
		}

		// Volumes. A pod runs on one node, so all of a service's host
		// folders must be on the same node.
		hostNode := ""
		for _, v := range s.Volumes {
			vp := &volumePlan{target: v.Target, readOnly: v.ReadOnly}
			switch v.Type {
			case types.VolumeTypeVolume:
				claim := dnsName(v.Source)
				if v.Source == "" {
					claim = dnsName(sp.name + "-" + filepath.Base(v.Target))
				}
				if pv, ok := plan.pvcs[claim]; ok {
					vp.kind, vp.claim = "pvc", pv.name
					break
				}
				size := in.size(fmt.Sprintf("  Volume %s -> %s: size", orDefault(v.Source, "(anonymous)"), v.Target), "5Gi")
				plan.pvcs[claim] = &pvcPlan{name: claim, size: size, shared: volUsers[v.Source] > 1}
				vp.kind, vp.claim = "pvc", claim
			case types.VolumeTypeBind:
				src := v.Source
				local := src
				if !filepath.IsAbs(local) {
					local = filepath.Join(composeDir, src)
				}
				st, statErr := os.Stat(local)
				switch {
				case isRelativeSource(src) && statErr == nil && st.Mode().IsRegular() && st.Size() <= maxConfigBytes:
					data, _ := os.ReadFile(local)
					cm := sp.name + "-files"
					key := configMapKey(src)
					if plan.configMap[cm] == nil {
						plan.configMap[cm] = map[string]string{}
					}
					plan.configMap[cm][key] = string(data)
					vp.kind, vp.cmName, vp.cmKey = "configmap", cm, key
					fmt.Printf("  File %s -> %s: stored in the app (ConfigMap)\n", src, v.Target)
				case isRelativeSource(src):
					claim := uniqueClaim(plan, dnsName(sp.name+"-"+filepath.Base(src)))
					folder := path.Join(srcDir, filepath.ToSlash(src))
					fmt.Printf("  Folder %s -> %s:\n", src, v.Target)
					size := in.size("    Longhorn volume size", sizeFor(folder, v.Target))
					plan.pvcs[claim] = &pvcPlan{name: claim, size: size}
					vp.kind, vp.claim = "pvc", claim
					if srcNode != "" {
						copyFromNode(in, plan, sp, srcNode, folder, v.Target, claim)
					} else {
						sp.warnings = append(sp.warnings, fmt.Sprintf("%s starts empty: copy your Docker data from %s if you need it", v.Target, src))
					}
				case strings.HasPrefix(src, "/dev/"):
					vp.kind, vp.hostPath = "hostpath", src
				default:
					fmt.Printf("  Host path %s -> %s:\n", src, v.Target)
					longhorn := "longhorn (new empty volume)"
					if srcNode != "" {
						longhorn = "longhorn (new volume, can copy the data from " + srcNode + ")"
					}
					def := "longhorn"
					if b, ok := srcSizes[src]; ok {
						fmt.Printf("    (%s holds %s on %s)\n", src, fmtBytes(b), srcNode)
						if b >= 50<<30 {
							def = "host" // a media library: keep it where it is
							fmt.Println("    That's a lot to copy into a volume: host keeps using the folder on " + srcNode + ".")
						}
					}
					choice := in.choose("    "+longhorn+" or host (use that folder on one node)", []string{"longhorn", "host"}, def)
					if choice == "host" {
						vp.kind, vp.hostPath = "hostpath", src
						vp.node = askNode(in, src, nodes, hostNode, srcNode)
						hostNode = vp.node
					} else {
						claim := uniqueClaim(plan, dnsName(sp.name+"-"+filepath.Base(src)))
						size := in.size("    size", sizeFor(src, v.Target))
						plan.pvcs[claim] = &pvcPlan{name: claim, size: size}
						vp.kind, vp.claim = "pvc", claim
						if srcNode != "" {
							copyFromNode(in, plan, sp, srcNode, src, v.Target, claim)
						} else {
							sp.warnings = append(sp.warnings, fmt.Sprintf("%s starts empty (was %s on the Docker host)", v.Target, src))
						}
					}
				}
			case types.VolumeTypeTmpfs:
				vp.kind, vp.medium = "emptydir", "Memory"
			default:
				sp.warnings = append(sp.warnings, fmt.Sprintf("volume type %q at %s isn't supported; skipped", v.Type, v.Target))
				continue
			}
			sp.volumes = append(sp.volumes, vp)
		}
		for _, t := range s.Tmpfs {
			sp.volumes = append(sp.volumes, &volumePlan{target: strings.Split(t, ":")[0], kind: "emptydir", medium: "Memory"})
		}
		if s.ShmSize > 0 {
			sp.volumes = append(sp.volumes, &volumePlan{target: "/dev/shm", kind: "emptydir", medium: "Memory", limit: memQuantity(s.ShmSize)})
		}

		// Environment: sensitive values go to the cluster Secret.
		var keys []string
		for k := range s.Environment {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var sensitive []string
		for _, k := range keys {
			v := s.Environment[k]
			if v == nil {
				sp.warnings = append(sp.warnings, "environment variable "+k+" has no value; skipped")
				continue
			}
			if envSensitive(k) && *v != "" {
				sensitive = append(sensitive, k)
			} else {
				if envSensitive(k) {
					sp.warnings = append(sp.warnings, k+" is empty: set it in .env (or the environment) and import again")
				}
				sp.plainEnv = append(sp.plainEnv, [2]string{k, *v})
			}
		}
		if len(sensitive) > 0 {
			fmt.Printf("  Sensitive settings: %s\n", strings.Join(sensitive, ", "))
			toSecret := in.yes("    keep these in a cluster Secret (not in git)", true)
			for _, k := range sensitive {
				v := *s.Environment[k]
				if toSecret {
					key := sp.name + "." + k
					plan.secrets[key] = v
					sp.secretEnv = append(sp.secretEnv, [2]string{k, key})
				} else {
					sp.plainEnv = append(sp.plainEnv, [2]string{k, v})
				}
			}
		}

		// Things with no clean Kubernetes equivalent.
		if strings.HasPrefix(s.NetworkMode, "service:") || strings.HasPrefix(s.NetworkMode, "container:") {
			sp.warnings = append(sp.warnings, "network_mode "+s.NetworkMode+" isn't supported (it runs as its own pod)")
		}
		for _, v := range s.Volumes {
			if strings.Contains(v.Source, "docker.sock") {
				sp.warnings = append(sp.warnings, "mounts the Docker socket; there is no Docker on cluster nodes")
			}
		}
		if wantsGPU(s) {
			sp.warnings = append(sp.warnings, "requests GPUs; needs the NVIDIA device plugin, not set up by homelabCD")
		}
		if len(s.Ulimits) > 0 {
			sp.warnings = append(sp.warnings, "ulimits aren't supported by Kubernetes; skipped")
		}
		if len(s.Configs) > 0 || len(s.Secrets) > 0 {
			sp.warnings = append(sp.warnings, "compose configs:/secrets: aren't converted; use environment or bind-mounted files")
		}
		if s.Restart == "no" {
			sp.warnings = append(sp.warnings, `restart: "no" ignored; Kubernetes always restarts it`)
		}
		// Devices. Compose templates often list hardware that only some
		// machines have (e.g. Raspberry Pi /dev/vchiq). A missing device
		// would keep the pod from starting, so each one is a choice, and
		// the default is whether this node has it.
		for _, d := range s.Devices {
			if !strings.HasPrefix(d.Source, "/dev/") {
				continue
			}
			vp := &volumePlan{target: orDefault(d.Target, d.Source), kind: "hostpath", hostPath: d.Source}
			here := ""
			st, err := os.Stat(d.Source)
			if err == nil {
				if st.IsDir() {
					vp.hostType = "Directory"
				} else if st.Mode()&os.ModeCharDevice != 0 {
					vp.hostType = "CharDevice"
				}
			} else {
				here = " (not on " + nodeHostname() + ")"
			}
			if !in.yes(fmt.Sprintf("  Device %s%s: pass it through", d.Source, here), err == nil) {
				sp.warnings = append(sp.warnings, "device "+d.Source+" not passed through")
				continue
			}
			sp.volumes = append(sp.volumes, vp)
		}
	}

	// Summary.
	fmt.Println()
	fmt.Println("=============================================")
	fmt.Printf(" Plan: %s  ->  %s/%s/\n", app, appsDirRel, app)
	fmt.Println("=============================================")
	for _, sp := range plan.services {
		fmt.Printf("  %s\n", sp.name)
		for _, p := range sp.ports {
			switch p.kind {
			case "web":
				fmt.Printf("    https://%s  ->  port %d\n", p.host, p.target)
			case "lan":
				fmt.Printf("    %s:%s/%s (LAN)  ->  port %d\n", p.ip, p.published, strings.ToLower(p.protocol), p.target)
			default:
				fmt.Printf("    %s:%d (inside the cluster)\n", sp.name, p.target)
			}
		}
		for _, v := range sp.volumes {
			switch v.kind {
			case "pvc":
				fmt.Printf("    %s  <- Longhorn volume %s (%s)\n", v.target, v.claim, plan.pvcs[v.claim].size)
			case "configmap":
				fmt.Printf("    %s  <- file stored in the app\n", v.target)
			case "hostpath":
				fmt.Printf("    %s  <- host %s%s\n", v.target, v.hostPath, ifNode(v.node))
			case "emptydir":
				fmt.Printf("    %s  <- temporary (memory)\n", v.target)
			}
		}
		if len(sp.secretEnv) > 0 {
			fmt.Printf("    %d secret setting(s) in Secret %s-secrets (cluster only)\n", len(sp.secretEnv), app)
		}
		for _, w := range sp.warnings {
			fmt.Println("    " + cWarn + w)
		}
	}
	fmt.Println()

	if !in.yes("Create it and deploy through GitOps", true) {
		fmt.Println(cWarn + "Cancelled. Nothing was written.")
		return 1
	}

	if err := writeApp(root, plan); err != nil {
		fmt.Println(cFail + err.Error())
		return 1
	}
	if len(plan.secrets) > 0 {
		if err := applySecret(plan); err != nil {
			fmt.Println(cFail + "Could not create the Secret: " + err.Error())
			return 1
		}
		fmt.Println(cOK + fmt.Sprintf("Stored %d secret setting(s) in %s/%s-secrets", len(plan.secrets), app, app))
	}
	fmt.Println(cOK + "Wrote " + appsDirRel + "/" + app + "/")
	result := app
	for _, c := range plan.copies {
		result += "\nCOPY\t" + c[0] + "\t" + c[1] + "\t" + c[2]
	}
	writeResult(result)
	return 0
}

// volumeSize suggests a size for a folder: config folders are small.
func volumeSize(target string) string {
	if strings.Contains(strings.ToLower(target), "config") {
		return "1Gi"
	}
	return "5Gi"
}

// copyFromNode asks whether to bring a folder's data along (the compose
// file came from a node) and records it.
func copyFromNode(in *prompter, plan *importPlan, sp *servicePlan, node, folder, target, claim string) {
	if in.yes(fmt.Sprintf("    copy the data from %s:%s into it", node, folder), true) {
		plan.copies = append(plan.copies, [3]string{node, folder, claim})
		fmt.Printf("    %s will start with the files from %s:%s\n", target, node, folder)
		return
	}
	sp.warnings = append(sp.warnings, fmt.Sprintf("%s starts empty (was %s on %s)", target, folder, node))
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func ifNode(n string) string {
	if n == "" {
		return ""
	}
	return " on " + n
}

// askNode asks which node has a host folder. It must be a cluster node, and
// the same node as the service's other host folders (pinned, if any).
func askNode(in *prompter, src string, nodes []string, pinned, suggest string) string {
	def := pinned
	if def == "" {
		def = suggest
	}
	if def == "" {
		def = nodeHostname()
		if len(nodes) > 0 && !slices.Contains(nodes, def) {
			def = nodes[0]
		}
	}
	for {
		n := strings.ToLower(in.ask("    node that has "+src, def))
		switch {
		case len(nodes) > 0 && !slices.Contains(nodes, n):
			fmt.Println("    [ERROR] " + n + " isn't a node in this cluster. Nodes: " + strings.Join(nodes, ", "))
		case pinned != "" && n != pinned:
			fmt.Println("    [ERROR] The pod runs on " + pinned + " (an earlier host folder is there), so this folder must be on " + pinned + " too.")
		default:
			if len(nodes) == 0 {
				fmt.Println("    " + cWarn + "Couldn't list the cluster's nodes to check " + n + "; if it's wrong, the pod won't start.")
			}
			return n
		}
	}
}

// uniqueClaim avoids two volumes ending up as one claim (e.g. /a/lib and /b/lib).
func uniqueClaim(plan *importPlan, claim string) string {
	name := claim
	for i := 2; plan.pvcs[name] != nil; i++ {
		name = fmt.Sprintf("%s-%d", claim, i)
	}
	return name
}

var sizePattern = regexp.MustCompile(`^(\d+)\s*([KMGT]i?)?[bB]?$`)

func normSize(s string) string {
	s = strings.TrimSpace(s)
	m := sizePattern.FindStringSubmatch(s)
	if m == nil {
		return "5Gi"
	}
	unit := m[2]
	switch unit {
	case "":
		unit = "Gi"
	case "K", "M", "G", "T":
		unit += "i"
	}
	return m[1] + unit
}

func nodeHostname() string {
	h, _ := os.Hostname()
	return strings.ToLower(h)
}

// wantsGPU reports compose GPU requests (gpus: or deploy device reservations).
func wantsGPU(s types.ServiceConfig) bool {
	if len(s.Gpus) > 0 {
		return true
	}
	if s.Deploy != nil && s.Deploy.Resources.Reservations != nil {
		for _, d := range s.Deploy.Resources.Reservations.Devices {
			for _, c := range d.Capabilities {
				if c == "gpu" {
					return true
				}
			}
		}
	}
	return false
}

var cmKeyUnsafe = regexp.MustCompile(`[^-._a-zA-Z0-9]+`)

func configMapKey(path string) string {
	k := cmKeyUnsafe.ReplaceAllString(filepath.Base(path), "-")
	if k == "" || k == "." || k == ".." {
		k = "file"
	}
	return k
}
