package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// ---------------------------------------------------------------------------
// Data
// ---------------------------------------------------------------------------

type clusterInfo struct {
	Name, Version, VIP, Runtime, CNI string
}

type operation struct {
	Title    string
	Desc     string
	Op       string // install.sh --run argument
	Commands []string
}

var cluster = clusterInfo{
	Name:    "homelab",
	Version: "v1.36.2",
	VIP:     "192.168.50.222", 
	Runtime: "containerd",
	CNI:     "cilium",
}

var dryRun = true

var operations = []operation{
	{
		Title: "Bootstrap New Cluster",
		Desc:  "Initialise the first control plane node and install the CNI.",
		Op:    "bootstrap",
		Commands: []string{
			"${HOMELABCD_INSTALL} --run bootstrap",
		},
	},
	{
		Title: "Join Additional Control Plane",
		Desc:  "Join another control plane node behind the VIP.",
		Op:    "controlplane",
		Commands: []string{
			"${HOMELABCD_INSTALL} --run controlplane",
		},
	},
	{
		Title: "Join Worker Node",
		Desc:  "Join a worker node to the cluster.",
		Op:    "worker",
		Commands: []string{
			"${HOMELABCD_INSTALL} --run worker",
		},
	},
	{
		Title: "Repair Existing Node",
		Desc:  "Restart containerd/kubelet and show node status.",
		Op:    "repair",
		Commands: []string{
			"${HOMELABCD_INSTALL} --run repair",
		},
	},
	{
		Title: "Generate Join Commands",
		Desc:  "Print fresh join commands for control plane and worker nodes.",
		Op:    "join-commands",
		Commands: []string{
			"${HOMELABCD_INSTALL} --run join-commands",
		},
	},
	{
		Title: "Cluster Health Check",
		Desc:  "Verify nodes, system pods, etcd and Cilium status.",
		Op:    "health",
		Commands: []string{
			"${HOMELABCD_INSTALL} --run health",
		},
	},
	{
		Title: "Cluster Configuration",
		Desc:  "Show the current cluster configuration.",
		Op:    "config",
		Commands: []string{
			"${HOMELABCD_INSTALL} --run config",
		},
	},
}

const toggleTitle = "Toggle Dry-Run / Live"

// ---------------------------------------------------------------------------
// UI
// ---------------------------------------------------------------------------

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func loadCluster() {
	cluster.Name = envOr("CLUSTER_NAME", cluster.Name)
	cluster.Version = envOr("KUBERNETES_VERSION", cluster.Version)
	cluster.VIP = envOr("VIP_ADDRESS", cluster.VIP)
	cluster.Runtime = envOr("CONTAINER_RUNTIME", cluster.Runtime)
	cluster.CNI = envOr("CNI", cluster.CNI)
}

func installerPath() string {
	return envOr("HOMELABCD_INSTALL", "")
}

func useASCIIBorders() {
	tview.Borders.Horizontal = '-'
	tview.Borders.Vertical = '|'
	tview.Borders.TopLeft = '+'
	tview.Borders.TopRight = '+'
	tview.Borders.BottomLeft = '+'
	tview.Borders.BottomRight = '+'
	tview.Borders.LeftT = '+'
	tview.Borders.RightT = '+'
	tview.Borders.TopT = '+'
	tview.Borders.BottomT = '+'
	tview.Borders.Cross = '+'

	tview.Borders.HorizontalFocus = '-'
	tview.Borders.VerticalFocus = '|'
	tview.Borders.TopLeftFocus = '+'
	tview.Borders.TopRightFocus = '+'
	tview.Borders.BottomLeftFocus = '+'
	tview.Borders.BottomRightFocus = '+'
}

func modeText() string {
	if dryRun {
		return "[green::b]SAFE-DRY-RUN[-::-]"
	}
	return "[red::b]LIVE[-::-]"
}

func infoText() string {
	row := func(k, v string) string {
		return fmt.Sprintf("  [yellow::b]%-9s[-::-] %s\n", k, v)
	}
	var b strings.Builder
	b.WriteString(row("CLUSTER", cluster.Name))
	b.WriteString(row("VERSION", cluster.Version))
	b.WriteString(row("VIP", cluster.VIP))
	b.WriteString(row("RUNTIME", cluster.Runtime))
	b.WriteString(row("CNI", cluster.CNI))
	b.WriteString(row("MODE", modeText()))
	return b.String()
}

func expand(s string) string {
	install := installerPath()
	if install == "" {
		install = "./install.sh"
	}
	r := strings.NewReplacer(
		"{{VIP}}", cluster.VIP,
		"{{VERSION}}", cluster.Version,
		"${HOMELABCD_INSTALL}", install,
	)
	return r.Replace(s)
}

func detailText(op operation) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("\n  [yellow::b]%s[-::-]\n", op.Title))
	b.WriteString(fmt.Sprintf("  %s\n\n", op.Desc))
	b.WriteString(fmt.Sprintf("  MODE  %s\n\n", modeText()))
	if dryRun {
		b.WriteString("  [green]DRY-RUN: the following commands would be executed:[-]\n\n")
	} else {
		b.WriteString("  [red]LIVE: ENTER runs the homelabCD installer operation.[-]\n\n")
	}
	for _, c := range op.Commands {
		b.WriteString("    $ " + tview.Escape(expand(c)) + "\n")
	}
	return b.String()
}

func footerText(page string) string {
	if page == "detail" && !dryRun {
		return " [aqua::b]ENTER[-::-] Execute    [aqua::b]ESC[-::-] Back    [aqua::b]Q[-::-] Quit"
	}
	return " [aqua::b]UP/DOWN[-::-] Navigate    [aqua::b]ENTER[-::-] Select    [aqua::b]ESC[-::-] Back    [aqua::b]Q[-::-] Quit"
}

func runOperation(app *tview.Application, op operation) {
	install := installerPath()
	app.Suspend(func() {
		fmt.Printf("\n=== %s ===\n\n", op.Title)
		if install == "" {
			fmt.Println("HOMELABCD_INSTALL is not set. Launch this TUI from homelabCD install.sh.")
		} else {
			cmd := exec.Command("bash", install, "--run", op.Op)
			cmd.Stdin = os.Stdin
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			cmd.Env = os.Environ()
			if err := cmd.Run(); err != nil {
				fmt.Printf("\n[FAIL] %s: %v\n", op.Op, err)
			}
		}
		fmt.Print("\nPress Enter to return to KubesTUI...")
		_, _ = bufio.NewReader(os.Stdin).ReadBytes('\n')
	})
}

func main() {
	loadCluster()
	useASCIIBorders()

	app := tview.NewApplication()
	pages := tview.NewPages()

	info := tview.NewTextView().SetDynamicColors(true)
	info.SetText(infoText())

	opsHeader := tview.NewTextView().SetDynamicColors(true)
	opsHeader.SetText("\n  [yellow::b]OPERATIONS[-::-]")

	list := tview.NewList().
		ShowSecondaryText(false).
		SetHighlightFullLine(true).
		SetMainTextColor(tcell.ColorWhite).
		SetSelectedTextColor(tcell.ColorBlack).
		SetSelectedBackgroundColor(tcell.ColorAqua)

	detail := tview.NewTextView().SetDynamicColors(true).SetScrollable(true)
	detail.SetBorder(true).SetTitle(" OPERATION ").SetTitleAlign(tview.AlignLeft)

	footer := tview.NewTextView().SetDynamicColors(true)
	footer.SetText(footerText("main"))

	var selected operation

	showDetail := func(op operation) {
		selected = op
		detail.SetText(detailText(op))
		detail.ScrollToBeginning()
		pages.SwitchToPage("detail")
		footer.SetText(footerText("detail"))
		app.SetFocus(detail)
	}

	for _, op := range operations {
		op := op
		list.AddItem("  "+op.Title, "", 0, func() { showDetail(op) })
	}
	list.AddItem("  "+toggleTitle, "", 0, func() {
		dryRun = !dryRun
		info.SetText(infoText())
	})

	body := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(nil, 1, 0, false).
		AddItem(info, 6, 0, false).
		AddItem(opsHeader, 2, 0, false).
		AddItem(list, 0, 1, true)
	body.SetBorder(true).
		SetTitle(" HOMELAB KUBERNETES PLATFORM ").
		SetTitleAlign(tview.AlignLeft)

	mainScreen := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(body, 0, 1, true).
		AddItem(footer, 1, 0, false)

	detailScreen := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(detail, 0, 1, true).
		AddItem(footer, 1, 0, false)

	pages.AddPage("main", mainScreen, true, true)
	pages.AddPage("detail", detailScreen, true, false)

	app.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		name, _ := pages.GetFrontPage()
		switch ev.Key() {
		case tcell.KeyEscape:
			if name != "main" {
				pages.SwitchToPage("main")
				footer.SetText(footerText("main"))
				app.SetFocus(list)
				return nil
			}
		case tcell.KeyEnter:
			if name == "detail" && !dryRun {
				runOperation(app, selected)
				return nil
			}
		case tcell.KeyRune:
			if ev.Rune() == 'q' || ev.Rune() == 'Q' {
				app.Stop()
				return nil
			}
		}
		return ev
	})

	if err := app.SetRoot(pages, true).EnableMouse(true).Run(); err != nil {
		panic(err)
	}
}
