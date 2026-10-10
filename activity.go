package main

// Live activity lights for the node menu header: one light for the
// cluster and one per node, refreshed from `kubectl get nodes` every few
// seconds. Nodes that join while KubesTUI is open are marked NEW.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rivo/tview"
	"go.yaml.in/yaml/v3"
)

const (
	// Written by the node-status DaemonSet (homelabCD's
	// apps/infrastructure/node-status) on every node.
	agentNodesFile  = "/var/lib/kubestui/nodes.json"
	agentStaleAfter = 30 * time.Second

	activityEvery   = 5 * time.Second
	activityNewFor  = 2 * time.Minute
	activityMaxRows = 10 // node lights shown before "+N more"
)

type activityPanel struct {
	app  *tview.Application
	view *tview.TextView

	// onRefresh runs on the UI goroutine after each poll with the number of
	// lines the panel wants, so the header can grow with the node count.
	onRefresh func(lines int)

	seen   map[string]time.Time // when each node first appeared
	polled bool                 // the first poll only records nodes, never as NEW
	beat   bool
}

func newActivityPanel(app *tview.Application) *activityPanel {
	a := &activityPanel{
		app:  app,
		view: tview.NewTextView().SetDynamicColors(true).SetWrap(false), // narrow terminal: cut, not wrap
		seen: map[string]time.Time{},
	}
	a.view.SetText("  [yellow::b]ACTIVITY[-::-]\n  [gray]● checking nodes…[-]")
	return a
}

// Start polls in the background for the life of the program.
func (a *activityPanel) Start() {
	go func() {
		for {
			rows, err := clusterNodes()
			a.app.QueueUpdateDraw(func() { a.update(rows, err) })
			time.Sleep(activityEvery)
		}
	}()
}

func (a *activityPanel) update(rows []nodeRow, err error) {
	now := time.Now()
	a.beat = !a.beat

	if name := readClusterName(); name != "" && name != cluster.Name {
		cluster.Name = name
	}

	for _, r := range rows {
		if _, ok := a.seen[r.name]; !ok {
			if a.polled {
				a.seen[r.name] = now
			} else {
				a.seen[r.name] = time.Time{} // there before KubesTUI opened
			}
		}
	}
	a.polled = true

	pulse := "[green]●[-]"
	if !a.beat {
		pulse = "[darkgreen]●[-]"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "  [yellow::b]ACTIVITY[-::-]   %s [gray]live · %s[-]\n", pulse, now.Format("15:04:05"))

	if err != nil {
		b.WriteString("  [red]●[-] [::b]" + pad(strings.ToUpper(tview.Escape(cluster.Name)), 14) + "[::-] [red]API unreachable[-]\n")
		b.WriteString("  [gray]  " + tview.Escape(apiHint(err)) + "[-]\n")
		a.view.SetText(b.String())
		a.resize(3)
		return
	}

	ready := 0
	for _, r := range rows {
		if r.status == "Ready" {
			ready++
		}
	}
	light := "[green]●[-]"
	switch {
	case len(rows) == 0 || ready == 0:
		light = "[red]●[-]"
	case ready < len(rows):
		light = "[yellow]●[-]"
	}
	fmt.Fprintf(&b, "  %s [::b]%s[::-] %d/%d nodes Ready\n", light, pad(strings.ToUpper(tview.Escape(cluster.Name)), 14), ready, len(rows))

	for i, r := range rows {
		if i == activityMaxRows {
			fmt.Fprintf(&b, "  [gray]  +%d more[-]\n", len(rows)-activityMaxRows)
			break
		}
		dot := "[green]●[-]"
		if r.status != "Ready" {
			dot = "[red]●[-]"
		}
		role := r.role
		if role == "-" {
			role = "worker"
		}
		line := fmt.Sprintf("  %s %s [gray]%-15s %s[-]", dot, pad(tview.Escape(r.name), 14), r.host, role)
		if r.status != "Ready" {
			line += " [red]NotReady[-]"
		}
		if t := a.seen[r.name]; !t.IsZero() && now.Sub(t) < activityNewFor {
			line += " [black:aqua:b] NEW [-:-:-]"
		}
		b.WriteString(line + "\n")
	}

	a.view.SetText(b.String())
	lines := 2 + len(rows)
	if len(rows) > activityMaxRows {
		lines = 3 + activityMaxRows
	}
	a.resize(lines)
}

func (a *activityPanel) resize(lines int) {
	if a.onRefresh != nil {
		a.onRefresh(lines)
	}
}

// pad left-aligns s in n columns, truncating long names.
func pad(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		r = append(r[:n-1], '…')
	}
	return string(r) + strings.Repeat(" ", n-len(r))
}

// errAgentMissing: no kubectl access and no node-status agent on this node.
var errAgentMissing = errors.New("node-status agent not running here")

// agentNodes reads the node list the node-status agent keeps on this node.
func agentNodes() ([]nodeRow, error) {
	info, err := os.Stat(agentNodesFile)
	if err != nil {
		return nil, errAgentMissing
	}
	if age := time.Since(info.ModTime()); age > agentStaleAfter {
		return nil, fmt.Errorf("no update for %s", age.Round(time.Second))
	}
	data, err := os.ReadFile(agentNodesFile)
	if err != nil {
		return nil, err
	}
	return parseNodes(data)
}

// apiHint explains a failed poll.
func apiHint(err error) string {
	switch {
	case errors.Is(err, errAgentMissing):
		return "no node-status agent here yet: run Update GitOps Templates"
	case strings.HasPrefix(err.Error(), "no update for"):
		return "this node can't reach the cluster API (" + err.Error() + ")"
	}
	return "can't read the node list; retrying"
}

// readClusterName reads cluster.name from homelabCD's config/cluster.yaml,
// so a rename shows up without restarting KubesTUI.
func readClusterName() string {
	root := os.Getenv("HOMELABCD_ROOT")
	if root == "" {
		return ""
	}
	data, err := os.ReadFile(filepath.Join(root, "config", "cluster.yaml"))
	if err != nil {
		return ""
	}
	var cfg struct {
		Cluster struct {
			Name string `yaml:"name"`
		} `yaml:"cluster"`
	}
	if yaml.Unmarshal(data, &cfg) != nil {
		return ""
	}
	return strings.TrimSpace(cfg.Cluster.Name)
}

// platformTitle is the border title of the node screens, named after the
// cluster. Workstations manage several clusters and keep the generic title.
func platformTitle() string {
	if !nodeMode() || cluster.Name == "" {
		return " HOMELAB KUBERNETES PLATFORM "
	}
	return " " + strings.ToUpper(cluster.Name) + " KUBERNETES PLATFORM "
}
