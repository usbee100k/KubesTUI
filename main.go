package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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
		Title: "Remote Join Control Plane",
		Desc:  "SSH to another node and execute controlplane.sh remotely.",
		Op:    "remote-controlplane",
		Commands: []string{
			"SSH → remote node → ${HOMELABCD_INSTALL} --run controlplane",
		},
	},
	{
		Title: "Remote Join Worker",
		Desc:  "SSH to another node and execute worker.sh remotely.",
		Op:    "remote-worker",
		Commands: []string{
			"SSH → remote node → ${HOMELABCD_INSTALL} --run worker",
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

func runRemoteOperation(app *tview.Application, op operation) {

	install := installerPath()

	if install == "" {
		fmt.Println("HOMELABCD_INSTALL is not set.")
		return
	}

	remoteScript := ""

	switch op.Op {
	case "remote-worker":
		remoteScript = "worker"

	case "remote-controlplane":
		remoteScript = "controlplane"

	default:
		fmt.Printf("Unsupported remote operation: %s\n", op.Op)
		return
	}

	app.Suspend(func() {

		reader := bufio.NewReader(os.Stdin)

		fmt.Println()
		fmt.Println("==================================================")
		fmt.Println("             REMOTE NODE EXECUTION")
		fmt.Println("==================================================")
		fmt.Println()

		remoteHost := readRemoteValue(
			reader,
			"Remote host/IP: ",
		)

		if remoteHost == "" {
			fmt.Println("Remote host cannot be empty.")
			return
		}

		remoteUser := readRemoteValue(
			reader,
			"SSH username: ",
		)

		if remoteUser == "" {
			fmt.Println("SSH username cannot be empty.")
			return
		}

		remotePort := readRemoteValue(
			reader,
			"SSH port [22]: ",
		)

		if remotePort == "" {
			remotePort = "22"
		}

		defaultKey := filepath.Join(
			os.Getenv("HOME"),
			".ssh",
			"id_ed25519",
		)

		remoteKey := readRemoteValue(
			reader,
			fmt.Sprintf("SSH key [%s]: ", defaultKey),
		)

		if remoteKey == "" {
			remoteKey = defaultKey
		}

		if _, err := os.Stat(remoteKey); err != nil {
			fmt.Printf(
				"SSH key not found: %s\n",
				remoteKey,
			)
			return
		}

		localHome, err := os.UserHomeDir()

		if err != nil {
			fmt.Printf(
				"[FAIL] Could not determine local home directory: %v\n",
				err,
			)
			return
		}

		ageKey := filepath.Join(
			localHome,
			".config",
			"sops",
			"age",
			"keys.txt",
		)

		if _, err := os.Stat(ageKey); err != nil {
			fmt.Println()
			fmt.Println("[FAIL] AGE private key not found:")
			fmt.Println(ageKey)
			fmt.Println()
			fmt.Println(
				"The bootstrap node must have the AGE key used to decrypt",
			)
			fmt.Println(
				"the encrypted worker/control-plane join credentials.",
			)
			return
		}

		sourceRoot := filepath.Dir(install)

		localBootstrapPackage := filepath.Join(
			sourceRoot,
			"generated",
			"bootstrap",
			"secrets",
		)

		encryptedJoin := ""

		switch remoteScript {

		case "worker":
			encryptedJoin = filepath.Join(
				localBootstrapPackage,
				"worker_join.enc",
			)

		case "controlplane":
			encryptedJoin = filepath.Join(
				localBootstrapPackage,
				"controlplane_join.enc",
			)
		}

		if _, err := os.Stat(encryptedJoin); err != nil {
			fmt.Println()
			fmt.Printf(
				"[FAIL] Missing encrypted %s join package:\n",
				remoteScript,
			)
			fmt.Println(encryptedJoin)
			fmt.Println()
			fmt.Println(
				"Run the bootstrap-package step before using remote node execution.",
			)
			return
		}

		fmt.Println()
		fmt.Printf(
			"Target      : %s@%s:%s\n",
			remoteUser,
			remoteHost,
			remotePort,
		)
		fmt.Printf(
			"Operation   : %s\n",
			remoteScript,
		)
		fmt.Printf(
			"SSH key     : %s\n",
			remoteKey,
		)
		fmt.Println()

		fmt.Println("[INFO] Testing SSH connection...")

		sshTest := exec.Command(
			"ssh",
			"-p", remotePort,
			"-i", remoteKey,
			"-o", "BatchMode=yes",
			"-o", "StrictHostKeyChecking=accept-new",
			"-o", "ConnectTimeout=10",
			"-o", "IdentitiesOnly=yes",
			fmt.Sprintf(
				"%s@%s",
				remoteUser,
				remoteHost,
			),
			"echo connected",
		)

		sshTest.Stdout = os.Stdout
		sshTest.Stderr = os.Stderr

		if err := sshTest.Run(); err != nil {
			fmt.Printf(
				"[FAIL] SSH connection failed: %v\n",
				err,
			)
			return
		}

		fmt.Println("[ OK ] SSH connection successful.")
		fmt.Println()

		remoteRoot := "/opt/homelabCD"

		fmt.Println("[INFO] Preparing remote directory...")

		prepare := exec.Command(
			"ssh",
			"-t",
			"-p", remotePort,
			"-i", remoteKey,
			"-o", "StrictHostKeyChecking=accept-new",
			"-o", "IdentitiesOnly=yes",
			fmt.Sprintf(
				"%s@%s",
				remoteUser,
				remoteHost,
			),
			fmt.Sprintf(
				"sudo mkdir -p %s && sudo chown %s:%s %s",
				remoteRoot,
				remoteUser,
				remoteUser,
				remoteRoot,
			),
		)

		prepare.Stdin = os.Stdin
		prepare.Stdout = os.Stdout
		prepare.Stderr = os.Stderr

		if err := prepare.Run(); err != nil {
			fmt.Printf(
				"[FAIL] Could not prepare remote directory: %v\n",
				err,
			)
			return
		}

		fmt.Println("[ OK ] Remote directory ready.")
		fmt.Println()

		fmt.Println("[INFO] Copying homelabCD to remote node...")

		tarCmd := exec.Command(
			"tar",
			"--exclude=.git",
			"--exclude=generated/secrets",
			"-C",
			sourceRoot,
			"-czf",
			"-",
			".",
		)

		sshCmd := exec.Command(
			"ssh",
			"-p", remotePort,
			"-i", remoteKey,
			"-o", "BatchMode=yes",
			"-o", "StrictHostKeyChecking=accept-new",
			"-o", "IdentitiesOnly=yes",
			fmt.Sprintf(
				"%s@%s",
				remoteUser,
				remoteHost,
			),
			fmt.Sprintf(
				"tar -xzf - -C %s",
				remoteRoot,
			),
		)

		pipe, err := tarCmd.StdoutPipe()

		if err != nil {
			fmt.Printf(
				"[FAIL] Could not create archive pipe: %v\n",
				err,
			)
			return
		}

		sshCmd.Stdin = pipe
		sshCmd.Stdout = os.Stdout
		sshCmd.Stderr = os.Stderr

		if err := tarCmd.Start(); err != nil {
			fmt.Printf(
				"[FAIL] Could not start archive: %v\n",
				err,
			)
			return
		}

		if err := sshCmd.Start(); err != nil {
			fmt.Printf(
				"[FAIL] Could not start remote transfer: %v\n",
				err,
			)

			_ = tarCmd.Process.Kill()

			return
		}

		if err := tarCmd.Wait(); err != nil {
			fmt.Printf(
				"[FAIL] Could not archive homelabCD: %v\n",
				err,
			)
			return
		}

		if err := sshCmd.Wait(); err != nil {
			fmt.Printf(
				"[FAIL] Could not copy homelabCD: %v\n",
				err,
			)
			return
		}

		fmt.Println(
			"[ OK ] homelabCD copied to remote node.",
		)
		fmt.Println()

		fmt.Println("[INFO] Copying AGE private key...")

		remoteAgeTemp := "/tmp/homelab-age-keys.txt"

		scpAge := exec.Command(
			"scp",
			"-P", remotePort,
			"-i", remoteKey,
			"-o", "StrictHostKeyChecking=accept-new",
			"-o", "IdentitiesOnly=yes",
			ageKey,
			fmt.Sprintf(
				"%s@%s:%s",
				remoteUser,
				remoteHost,
				remoteAgeTemp,
			),
		)

		scpAge.Stdout = os.Stdout
		scpAge.Stderr = os.Stderr

		if err := scpAge.Run(); err != nil {
			fmt.Printf(
				"[FAIL] Could not copy AGE private key: %v\n",
				err,
			)
			return
		}

		installAge := exec.Command(
			"ssh",
			"-t",
			"-p", remotePort,
			"-i", remoteKey,
			"-o", "StrictHostKeyChecking=accept-new",
			"-o", "IdentitiesOnly=yes",
			fmt.Sprintf(
				"%s@%s",
				remoteUser,
				remoteHost,
			),
			"sudo mkdir -p /root/.config/sops/age && " +
				"sudo install -m 600 " +
				remoteAgeTemp +
				" /root/.config/sops/age/keys.txt && " +
				"rm -f " +
				remoteAgeTemp,
		)

		installAge.Stdin = os.Stdin
		installAge.Stdout = os.Stdout
		installAge.Stderr = os.Stderr

		if err := installAge.Run(); err != nil {
			fmt.Printf(
				"[FAIL] Could not install AGE private key: %v\n",
				err,
			)
			return
		}

		fmt.Println("[ OK ] AGE private key installed.")
		fmt.Println()

		fmt.Printf(
			"[INFO] Executing %s operation on %s...\n",
			remoteScript,
			remoteHost,
		)

		remoteInstall := fmt.Sprintf(
			"sudo env HOME=/root BOOTSTRAP_PACKAGE_DIR=%s/generated/bootstrap bash %s/install.sh --run %s",
			remoteRoot,
			remoteRoot,
			remoteScript,
		)

		remoteExec := exec.Command(
			"ssh",
			"-t",
			"-p", remotePort,
			"-i", remoteKey,
			"-o", "StrictHostKeyChecking=accept-new",
			"-o", "IdentitiesOnly=yes",
			fmt.Sprintf(
				"%s@%s",
				remoteUser,
				remoteHost,
			),
			remoteInstall,
		)

		remoteExec.Stdin = os.Stdin
		remoteExec.Stdout = os.Stdout
		remoteExec.Stderr = os.Stderr

		if err := remoteExec.Run(); err != nil {
			fmt.Printf(
				"\n[FAIL] Remote %s operation failed: %v\n",
				remoteScript,
				err,
			)
			return
		}

		fmt.Printf(
			"\n[ OK ] Remote %s operation completed.\n",
			remoteScript,
		)
	})

	fmt.Print(
		"\nPress Enter to return to KubesTUI...",
	)

	_, _ = bufio.NewReader(os.Stdin).ReadBytes('\n')
}

func readRemoteValue(reader *bufio.Reader, prompt string) string {

	fmt.Print(prompt)

	value, err := reader.ReadString('\n')
	if err != nil {
		return ""
	}

	return strings.TrimSpace(value)
}

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

	if strings.HasPrefix(op.Op, "remote-") {
		runRemoteOperation(app, op)
		return
	}

	install := installerPath()

	app.Suspend(func() {

		fmt.Printf("\n=== %s ===\n\n", op.Title)

		if install == "" {

			fmt.Println(
				"HOMELABCD_INSTALL is not set. Launch this TUI from homelabCD install.sh.",
			)

		} else {

			cmd := exec.Command(
				"bash",
				install,
				"--run",
				op.Op,
			)

			cmd.Stdin = os.Stdin
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			cmd.Env = os.Environ()

			if err := cmd.Run(); err != nil {
				fmt.Printf(
					"\n[FAIL] %s: %v\n",
					op.Op,
					err,
				)
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
