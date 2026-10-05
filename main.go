package main

import (
	"bufio"
	"fmt"
	"os"
	"io"
	"net"
	"strconv"
	"time"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
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
			"IP address / hostname: ",
		)

		if remoteHost == "" {
			fmt.Println("Remote host cannot be empty.")
			return
		}

		remoteUser := os.Getenv("HOMELAB_REMOTE_USER")

		if remoteUser == "" {
			remoteUser = os.Getenv("USER")
		}

		if remoteUser == "" {
			remoteUser = "root"
		}

		remoteAddr := fmt.Sprintf(
			"%s:22",
			remoteHost,
		)

		fmt.Println()
		fmt.Printf("SSH user : %s\n", remoteUser)
		fmt.Printf("Target   : %s\n", remoteAddr)
		fmt.Printf("Operation: %s\n", remoteScript)
		fmt.Println()


		fmt.Println("[INFO] Reading SSH host fingerprint...")

		scan := exec.Command(
			"ssh-keyscan",
			"-T", "10",
			"-t",
			"ed25519,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256",
			remoteHost,
		)

		keyscanOutput, err := scan.Output()

		if err != nil || len(keyscanOutput) == 0 {
			fmt.Printf(
				"[FAIL] Could not retrieve SSH fingerprint from %s\n",
				remoteHost,
			)
			return
		}

		var hostKeyLine string

		for _, line := range strings.Split(
			strings.TrimSpace(string(keyscanOutput)),
			"\n",
		) {

			line = strings.TrimSpace(line)

			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			fields := strings.Fields(line)

			if len(fields) >= 3 {
				hostKeyLine = fields[1] + " " + fields[2]
				break
			}
		}

		if hostKeyLine == "" {
			fmt.Println("[FAIL] Could not parse SSH host key.")
			return
		}

		hostKey, _, _, _, err := ssh.ParseAuthorizedKey(
			[]byte(hostKeyLine),
		)

		if err != nil {
			fmt.Printf(
				"[FAIL] Could not parse SSH host key: %v\n",
				err,
			)
			return
		}

		fingerprint := ssh.FingerprintSHA256(hostKey)

		fmt.Println()
		fmt.Println("==================================================")
		fmt.Println("                 SSH FINGERPRINT")
		fmt.Println("==================================================")
		fmt.Println()
		fmt.Printf("Host: %s\n", remoteHost)
		fmt.Printf("SHA256: %s\n", fingerprint)
		fmt.Println()

		trust := readRemoteValue(
			reader,
			"Trust this host fingerprint? [y/N]: ",
		)

		if strings.ToLower(trust) != "y" &&
			strings.ToLower(trust) != "yes" {

			fmt.Println()
			fmt.Println("SSH connection cancelled.")
			return
		}

		fmt.Println()
		fmt.Printf(
			"SSH password for %s@%s: ",
			remoteUser,
			remoteHost,
		)

		passwordBytes, err := term.ReadPassword(
			int(os.Stdin.Fd()),
		)

		fmt.Println()

		if err != nil {
			fmt.Printf(
				"[FAIL] Could not read password: %v\n",
				err,
			)
			return
		}

		password := string(passwordBytes)

		if password == "" {
			fmt.Println("[FAIL] Password cannot be empty.")
			return
		}

	
		fmt.Println("[INFO] Connecting to remote node...")

		clientConfig := &ssh.ClientConfig{
			User: remoteUser,
			Auth: []ssh.AuthMethod{
				ssh.Password(password),
			},
			HostKeyCallback: ssh.FixedHostKey(hostKey),
			Timeout: 10 * time.Second,
		}

		client, err := ssh.Dial(
			"tcp",
			remoteAddr,
			clientConfig,
		)

		if err != nil {
			fmt.Printf(
				"[FAIL] SSH connection failed: %v\n",
				err,
			)
			return
		}

		defer client.Close()

		fmt.Println("[ OK ] SSH connection established.")
		fmt.Println()

	
		remoteRoot := "/opt/homelabCD"


		fmt.Println("[INFO] Validating sudo access...")

		sudoSession, err := client.NewSession()

		if err != nil {
			fmt.Printf(
				"[FAIL] Could not create sudo session: %v\n",
				err,
			)
			return
		}

		sudoInput, err := sudoSession.StdinPipe()

		if err != nil {
			sudoSession.Close()
			fmt.Printf(
				"[FAIL] Could not open sudo input: %v\n",
				err,
			)
			return
		}

		sudoSession.Stdout = os.Stdout
		sudoSession.Stderr = os.Stderr

		if err := sudoSession.Start(
			"sudo -S -p '' -v",
		); err != nil {
			sudoSession.Close()
			fmt.Printf(
				"[FAIL] Could not validate sudo access: %v\n",
				err,
			)
			return
		}

		if _, err := io.WriteString(
			sudoInput,
			password+"\n",
		); err != nil {
			sudoSession.Close()
			fmt.Printf(
				"[FAIL] Could not send sudo password: %v\n",
				err,
			)
			return
		}

		_ = sudoInput.Close()

		if err := sudoSession.Wait(); err != nil {
			fmt.Printf(
				"[FAIL] Sudo authentication failed: %v\n",
				err,
			)
			return
		}

		fmt.Println("[ OK ] Sudo access confirmed.")
		fmt.Println()


		fmt.Println("[INFO] Preparing remote directory...")

		prepareSession, err := client.NewSession()

		if err != nil {
			fmt.Printf(
				"[FAIL] Could not create remote session: %v\n",
				err,
			)
			return
		}

		prepareCmd := fmt.Sprintf(
			"sudo -n mkdir -p %s && "+
				"sudo -n chown %s:%s %s",
			remoteRoot,
			remoteUser,
			remoteUser,
			remoteRoot,
		)

		if err := prepareSession.Run(
			prepareCmd,
		); err != nil {
			prepareSession.Close()

			fmt.Printf(
				"[FAIL] Could not prepare remote directory: %v\n",
				err,
			)
			return
		}

		prepareSession.Close()

		fmt.Println("[ OK ] Remote directory ready.")
		fmt.Println()


		fmt.Println("[INFO] Copying homelabCD...")

		sourceRoot := filepath.Dir(install)

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

		tarOutput, err := tarCmd.StdoutPipe()

		if err != nil {
			fmt.Printf(
				"[FAIL] Could not create archive: %v\n",
				err,
			)
			return
		}

		transferSession, err := client.NewSession()

		if err != nil {
			fmt.Printf(
				"[FAIL] Could not create transfer session: %v\n",
				err,
			)
			return
		}

		transferSession.Stdin = tarOutput
		transferSession.Stdout = os.Stdout
		transferSession.Stderr = os.Stderr

		if err := transferSession.Start(
			fmt.Sprintf(
				"tar -xzf - -C %s",
				remoteRoot,
			),
		); err != nil {
			transferSession.Close()

			fmt.Printf(
				"[FAIL] Could not start remote transfer: %v\n",
				err,
			)
			return
		}

		if err := tarCmd.Start(); err != nil {
			transferSession.Close()

			fmt.Printf(
				"[FAIL] Could not start local archive: %v\n",
				err,
			)
			return
		}

		if err := tarCmd.Wait(); err != nil {
			transferSession.Close()

			fmt.Printf(
				"[FAIL] Could not create archive: %v\n",
				err,
			)
			return
		}

		if err := transferSession.Wait(); err != nil {
			fmt.Printf(
				"[FAIL] Could not transfer homelabCD: %v\n",
				err,
			)
			return
		}

		fmt.Println(
			"[ OK ] homelabCD copied to remote node.",
		)
		fmt.Println()


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
			fmt.Printf(
				"[FAIL] AGE key not found: %s\n",
				ageKey,
			)
			return
		}

		ageData, err := os.ReadFile(ageKey)

		if err != nil {
			fmt.Printf(
				"[FAIL] Could not read AGE key: %v\n",
				err,
			)
			return
		}

		fmt.Println("[INFO] Copying AGE private key...")

		ageSession, err := client.NewSession()

		if err != nil {
			fmt.Printf(
				"[FAIL] Could not create AGE transfer session: %v\n",
				err,
			)
			return
		}

		ageInput, err := ageSession.StdinPipe()

		if err != nil {
			ageSession.Close()

			fmt.Printf(
				"[FAIL] Could not open AGE transfer: %v\n",
				err,
			)
			return
		}

		ageSession.Stdout = os.Stdout
		ageSession.Stderr = os.Stderr

		if err := ageSession.Start(
			"cat > /tmp/homelab-age-keys.txt",
		); err != nil {
			ageSession.Close()

			fmt.Printf(
				"[FAIL] Could not start AGE transfer: %v\n",
				err,
			)
			return
		}

		if _, err := ageInput.Write(ageData); err != nil {
			ageSession.Close()

			fmt.Printf(
				"[FAIL] Could not send AGE key: %v\n",
				err,
			)
			return
		}

		_ = ageInput.Close()

		if err := ageSession.Wait(); err != nil {
			fmt.Printf(
				"[FAIL] AGE key transfer failed: %v\n",
				err,
			)
			return
		}

		

		ageInstall, err := client.NewSession()

		if err != nil {
			fmt.Printf(
				"[FAIL] Could not create AGE install session: %v\n",
				err,
			)
			return
		}

		ageInstallCmd :=
			"sudo -n mkdir -p /root/.config/sops/age && " +
				"sudo -n install -m 600 " +
				"/tmp/homelab-age-keys.txt " +
				"/root/.config/sops/age/keys.txt && " +
				"rm -f /tmp/homelab-age-keys.txt"

		if err := ageInstall.Run(
			ageInstallCmd,
		); err != nil {
			ageInstall.Close()

			fmt.Printf(
				"[FAIL] Could not install AGE key: %v\n",
				err,
			)
			return
		}

		ageInstall.Close()

		fmt.Println("[ OK ] AGE private key installed.")
		fmt.Println()

		fmt.Printf(
			"[INFO] Executing %s on %s...\n",
			remoteScript,
			remoteHost,
		)

		runSession, err := client.NewSession()

		if err != nil {
			fmt.Printf(
				"[FAIL] Could not create execution session: %v\n",
				err,
			)
			return
		}

		termWidth := 120
		termHeight := 40

		modes := ssh.TerminalModes{
			ssh.ECHO:          1,
			ssh.TTY_OP_ISPEED: 14400,
			ssh.TTY_OP_OSPEED: 14400,
		}

		termName := os.Getenv("TERM")

		if termName == "" {
			termName = "xterm"
		}

		if err := runSession.RequestPty(
			termName,
			termHeight,
			termWidth,
			modes,
		); err != nil {
			runSession.Close()

			fmt.Printf(
				"[FAIL] Could not allocate remote terminal: %v\n",
				err,
			)
			return
		}

		runSession.Stdin = os.Stdin
		runSession.Stdout = os.Stdout
		runSession.Stderr = os.Stderr

		remoteCommand := fmt.Sprintf(
			"sudo -n env HOME=/root "+
				"BOOTSTRAP_PACKAGE_DIR=%s/generated/bootstrap "+
				"bash %s/install.sh --run %s",
			remoteRoot,
			remoteRoot,
			remoteScript,
		)

		if err := runSession.Run(
			remoteCommand,
		); err != nil {

			fmt.Printf(
				"\n[FAIL] Remote %s operation failed: %v\n",
				remoteScript,
				err,
			)

			runSession.Close()
			return
		}

		runSession.Close()

		fmt.Println()
		fmt.Printf(
			"[ OK ] Remote %s operation completed.\n",
			remoteScript,
		)
	})

	// IMPORTANT:
	// Do NOT read os.Stdin here.
	// app.Suspend() returns to the TUI automatically.
}

func getSSHHostFingerprint(
	host string,
	port int,
	user string,
) (ssh.PublicKey, string, error) {

	addr := net.JoinHostPort(
		host,
		strconv.Itoa(port),
	)

	rawConn, err := net.DialTimeout(
		"tcp",
		addr,
		10*time.Second,
	)

	if err != nil {
		return nil, "", err
	}

	defer rawConn.Close()

	var serverKey ssh.PublicKey

	config := &ssh.ClientConfig{
		User: user,
		HostKeyCallback: func(
			hostname string,
			key ssh.PublicKey,
		) error {

			serverKey = key

			return nil
		},
		Timeout: 10 * time.Second,
	}

	// Authentication is intentionally omitted.
	// We only need the host key from the SSH handshake.
	_, _, _, _ = ssh.NewClientConn(
		rawConn,
		addr,
		config,
	)

	if serverKey == nil {
		return nil, "", fmt.Errorf(
			"SSH server did not provide a host key",
		)
	}

	return serverKey,
		ssh.FingerprintSHA256(serverKey),
		nil
}


func connectSSHWithPassword(
	host string,
	port int,
	user string,
	password string,
	hostKey ssh.PublicKey,
) (*ssh.Client, error) {

	addr := net.JoinHostPort(
		host,
		strconv.Itoa(port),
	)

	passwordAuth := ssh.Password(password)

	keyboardAuth := ssh.KeyboardInteractive(
		func(
			_user string,
			instruction string,
			questions []string,
			echos []bool,
		) ([]string, error) {

			answers := make([]string, len(questions))

			for i := range questions {
				answers[i] = password
			}

			return answers, nil
		},
	)

	config := &ssh.ClientConfig{
		User: user,

		Auth: []ssh.AuthMethod{
			passwordAuth,
			keyboardAuth,
		},

		HostKeyCallback: ssh.FixedHostKey(hostKey),

		Timeout: 15 * time.Second,
	}

	return ssh.Dial(
		"tcp",
		addr,
		config,
	)
}


func sshOutput(
	client *ssh.Client,
	command string,
) (string, error) {

	session, err := client.NewSession()

	if err != nil {
		return "", err
	}

	defer session.Close()

	output, err := session.CombinedOutput(command)

	return strings.TrimSpace(
		string(output),
	), err
}


func sshRun(
	client *ssh.Client,
	command string,
	stdin io.Reader,
	stdout io.Writer,
) error {

	session, err := client.NewSession()

	if err != nil {
		return err
	}

	defer session.Close()

	session.Stdin = stdin
	session.Stdout = stdout
	session.Stderr = os.Stderr

	return session.Run(command)
}


func copyRepositoryOverSSH(
	client *ssh.Client,
	sourceRoot string,
	remoteRoot string,
) error {

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

	tarPipe, err := tarCmd.StdoutPipe()

	if err != nil {
		return err
	}

	session, err := client.NewSession()

	if err != nil {
		return err
	}

	defer session.Close()

	session.Stdin = tarPipe
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr

	remoteCommand := fmt.Sprintf(
		"tar -xzf - -C %s",
		shellQuote(remoteRoot),
	)

	if err := tarCmd.Start(); err != nil {
		return err
	}

	err = session.Run(remoteCommand)

	tarErr := tarCmd.Wait()

	if err != nil {
		return err
	}

	return tarErr
}


func copyFileOverSSH(
	client *ssh.Client,
	localFile string,
	remoteFile string,
	mode string,
) error {

	file, err := os.Open(localFile)

	if err != nil {
		return err
	}

	defer file.Close()

	session, err := client.NewSession()

	if err != nil {
		return err
	}

	defer session.Close()

	session.Stdin = file
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr

	command := fmt.Sprintf(
		"umask 077; cat > %s; chmod %s %s",
		shellQuote(remoteFile),
		mode,
		shellQuote(remoteFile),
	)

	return session.Run(command)
}


func shellQuote(value string) string {

	return "'" +
		strings.ReplaceAll(
			value,
			"'",
			"'\\''",
		) +
		"'"
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
