package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"io"
	"net"
	"strconv"
	"time"
	"os/exec"
	osuser "os/user"
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

// notice leaves the TUI, prints a message, and waits for Enter so the message
// is not wiped when the TUI redraws.
func notice(app *tview.Application, msg string) {
	app.Suspend(func() {
		fmt.Printf("\n%s\n\nPress Enter to return to KubesTUI...", msg)
		_, _ = bufio.NewReader(os.Stdin).ReadBytes('\n')
	})
}

func runRemoteOperation(app *tview.Application, op operation) {

	install := installerPath()

	if install == "" {
		notice(app, "HOMELABCD_INSTALL is not set. Launch this TUI from homelabCD install.sh.")
		return
	}

	remoteScript := ""

	switch op.Op {
	case "remote-worker":
		remoteScript = "worker"

	case "remote-controlplane":
		remoteScript = "controlplane"

	default:
		notice(app, "Unsupported remote operation: "+op.Op)
		return
	}

	app.Suspend(func() {

		reader := bufio.NewReader(os.Stdin)

		// Pause on any failure before the remote session starts, otherwise the
		// TUI redraws immediately and the error text disappears.
		ranRemote := false
		defer func() {
			if !ranRemote {
				fmt.Print("\nPress Enter to return to KubesTUI...")
				_, _ = reader.ReadString('\n')
			}
		}()

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

		// Ask for the SSH username instead of silently picking one.
		// HOMELAB_REMOTE_USER, if set, is offered as the default.
		defaultUser := strings.TrimSpace(os.Getenv("HOMELAB_REMOTE_USER"))

		userPrompt := "SSH username: "
		if defaultUser != "" {
			userPrompt = fmt.Sprintf("SSH username [%s]: ", defaultUser)
		}

		remoteUser := readRemoteValue(reader, userPrompt)

		if remoteUser == "" {
			remoteUser = defaultUser
		}

		if remoteUser == "" {
			fmt.Println("SSH username cannot be empty.")
			return
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
			"ed25519,ecdsa,rsa",
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

		// ssh-keyscan returns one key per type (ed25519, ecdsa, rsa). The Go SSH
		// client may negotiate any of them, so trust all keys the user is shown
		// instead of pinning only the first one (that caused "host key mismatch").
		trustedKeys := map[string]bool{}
		var fingerprints []string

		for _, line := range strings.Split(
			strings.TrimSpace(string(keyscanOutput)),
			"\n",
		) {

			line = strings.TrimSpace(line)

			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			fields := strings.Fields(line)

			if len(fields) < 3 {
				continue
			}

			key, _, _, _, perr := ssh.ParseAuthorizedKey(
				[]byte(fields[1] + " " + fields[2]),
			)

			if perr != nil {
				continue
			}

			id := string(key.Marshal())

			if trustedKeys[id] {
				continue
			}

			trustedKeys[id] = true

			fingerprints = append(
				fingerprints,
				fmt.Sprintf(
					"%-22s %s",
					key.Type(),
					ssh.FingerprintSHA256(key),
				),
			)
		}

		if len(trustedKeys) == 0 {
			fmt.Println("[FAIL] Could not parse SSH host key.")
			return
		}

		hostKeyCallback := func(
			hostname string,
			remote net.Addr,
			key ssh.PublicKey,
		) error {

			if trustedKeys[string(key.Marshal())] {
				return nil
			}

			return fmt.Errorf(
				"host key mismatch: server presented %s %s",
				key.Type(),
				ssh.FingerprintSHA256(key),
			)
		}

		fmt.Println()
		fmt.Println("==================================================")
		fmt.Println("                 SSH FINGERPRINT")
		fmt.Println("==================================================")
		fmt.Println()
		fmt.Printf("Host: %s\n", remoteHost)
		for _, fp := range fingerprints {
			fmt.Printf("  %s\n", fp)
		}
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
			HostKeyCallback: hostKeyCallback,
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

		if out, err := sudoRun(
			client,
			password,
			fmt.Sprintf(
				"mkdir -p %s && chown %s: %s",
				shellQuote(remoteRoot),
				shellQuote(remoteUser),
				shellQuote(remoteRoot),
			),
		); err != nil {
			fmt.Printf(
				"[FAIL] Could not prepare remote directory: %v\n%s\n",
				err,
				out,
			)
			return
		}

		fmt.Println("[ OK ] Remote directory ready.")
		fmt.Println()


		fmt.Println("[INFO] Copying homelabCD...")

		sourceRoot := filepath.Dir(install)

		// The encrypted join package lives in generated/bootstrap and travels
		// inside the archive below (only .git and generated/secrets are
		// excluded). If it is missing locally, offer to fetch it from the
		// private bootstrap repo HERE, so the worker never needs GitHub access.
		encName := "worker_join.enc"
		if remoteScript == "controlplane" {
			encName = "controlplane_join.enc"
		}

		bootstrapDir := filepath.Join(sourceRoot, "generated", "bootstrap")
		encPath := filepath.Join(bootstrapDir, "secrets", encName)

		if _, err := os.Stat(encPath); err != nil {
			fmt.Printf("[WARN] Encrypted join package not found locally: %s\n", encPath)

			fetch := strings.ToLower(strings.TrimSpace(
				readRemoteValue(reader, "Fetch it from the bootstrap repository now? [Y/n]: "),
			))

			if fetch == "" || fetch == "y" {
				if err := fetchBootstrapPackage(sourceRoot, reader); err != nil {
					fmt.Printf("[FAIL] Could not fetch bootstrap package: %v\n", err)
				} else {
					fmt.Println("[ OK ] Bootstrap package fetched.")
				}
			}

			if _, err := os.Stat(encPath); err != nil {
				fmt.Println("[WARN] The node will not be able to get its join credentials.")

				answer := readRemoteValue(reader, "Continue anyway? [y/N]: ")

				if strings.ToLower(strings.TrimSpace(answer)) != "y" {
					return
				}
			}
		}

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
				shellQuote(remoteRoot),
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

		// Wait for the remote side to finish reading BEFORE calling tarCmd.Wait():
		// Wait closes the stdout pipe, and closing it while the SSH session is
		// still reading causes "read |0: file already closed".
		transferErr := transferSession.Wait()

		if transferErr != nil {
			// Remote stopped reading; make sure local tar cannot block on a full pipe.
			_ = tarCmd.Process.Kill()
		}

		tarErr := tarCmd.Wait()

		if transferErr != nil {
			fmt.Printf(
				"[FAIL] Could not transfer homelabCD: %v\n",
				transferErr,
			)
			return
		}

		if tarErr != nil {
			fmt.Printf(
				"[FAIL] Could not create archive: %v\n",
				tarErr,
			)
			return
		}

		fmt.Println(
			"[ OK ] homelabCD copied to remote node.",
		)
		fmt.Println()


		ageKey := ""
		candidates := ageKeyCandidates()

		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				ageKey = c
				break
			}
		}

		if ageKey == "" {
			fmt.Println("[FAIL] AGE key not found. Looked in:")
			for _, c := range candidates {
				fmt.Printf("         %s\n", c)
			}
			fmt.Println("       Set SOPS_AGE_KEY_FILE to the key's path and try again.")
			return
		}

		fmt.Printf("[INFO] Using AGE key: %s\n", ageKey)

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
			"umask 077; cat > /tmp/homelab-age-keys.txt",
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

		

		if out, err := sudoRun(
			client,
			password,
			"mkdir -p /root/.config/sops/age && "+
				"install -m 600 /tmp/homelab-age-keys.txt "+
				"/root/.config/sops/age/keys.txt && "+
				"rm -f /tmp/homelab-age-keys.txt",
		); err != nil {
			fmt.Printf(
				"[FAIL] Could not install AGE key: %v\n%s\n",
				err,
				out,
			)
			return
		}

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

		fd := int(os.Stdin.Fd())

		termWidth, termHeight := 120, 40
		if w, h, err := term.GetSize(fd); err == nil && w > 0 && h > 0 {
			termWidth, termHeight = w, h
		}

		modes := ssh.TerminalModes{
			ssh.ECHO:          0, // off so the sudo password is not echoed; re-enabled after sudo -v
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

		ranRemote = true

		runStdin, err := runSession.StdinPipe()

		if err != nil {
			runSession.Close()

			fmt.Printf(
				"[FAIL] Could not open remote input: %v\n",
				err,
			)
			return
		}

		runSession.Stdout = os.Stdout
		runSession.Stderr = os.Stderr

		remoteCommand := fmt.Sprintf(
			"sudo -S -p '' -v && stty echo && "+
				"sudo -n env HOME=/root "+
				"HOMELAB_REMOTE_MODE=true "+
				"BOOTSTRAP_PACKAGE_DIR=%s/generated/bootstrap "+
				"bash %s/install.sh --run %s",
			remoteRoot,
			remoteRoot,
			remoteScript,
		)

		restore := func() {}
		if oldState, err := term.MakeRaw(fd); err == nil {
			restore = func() { _ = term.Restore(fd, oldState) }
		}

		runErr := runSession.Start(remoteCommand)

		if runErr == nil {
			// First line goes to "sudo -S"; everything after is the user's typing.
			_, _ = io.WriteString(runStdin, password+"\n")

			go func() {
				_, _ = io.Copy(runStdin, os.Stdin)
			}()

			runErr = runSession.Wait()
		}

		restore()

		if err := runErr; err != nil {

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
			remote net.Addr,
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


// readEnvFileValue returns NAME from a simple KEY="value" env file ("" if absent).
func readEnvFileValue(path, name string) string {

	data, err := os.ReadFile(path)

	if err != nil {
		return ""
	}

	value := ""

	for _, line := range strings.Split(string(data), "\n") {

		line = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "export "))

		if strings.HasPrefix(line, name+"=") {
			value = strings.Trim(strings.TrimPrefix(line, name+"="), "\"' ")
		}
	}

	return value
}

// fetchBootstrapPackage clones the private bootstrap repo with the deploy key
// (on this machine) and places its contents in generated/bootstrap, which is
// the same layout upload_bootstrap_package pushes.
func fetchBootstrapPackage(sourceRoot string, reader *bufio.Reader) error {

	defaults := filepath.Join(sourceRoot, "config", "defaults.env")

	pick := func(name string) string {
		if v := strings.TrimSpace(os.Getenv(name)); v != "" {
			return v
		}
		return readEnvFileValue(defaults, name)
	}

	repo := pick("BOOTSTRAP_REPO")
	keyPath := pick("SSH_KEY_PATH")

	if repo == "" {
		repo = strings.TrimSpace(readRemoteValue(reader, "Bootstrap repository URL: "))
	}

	if keyPath == "" {
		keyPath = strings.TrimSpace(readRemoteValue(reader, "Deploy key path (SSH_KEY_PATH): "))
	}

	if repo == "" || keyPath == "" {
		return fmt.Errorf("bootstrap repository URL and deploy key path are required")
	}

	if _, err := os.Stat(keyPath); err != nil {
		return fmt.Errorf("deploy key not found: %s", keyPath)
	}

	tmp, err := os.MkdirTemp("", "bootstrap-fetch-")

	if err != nil {
		return err
	}

	defer os.RemoveAll(tmp)

	clone := exec.Command("git", "clone", "--depth", "1", repo, tmp)

	clone.Env = append(
		os.Environ(),
		"GIT_SSH_COMMAND=ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new "+
			"-o IdentitiesOnly=yes -i "+shellQuote(keyPath),
	)
	clone.Stdout = os.Stdout
	clone.Stderr = os.Stderr

	if err := clone.Run(); err != nil {
		return fmt.Errorf("git clone failed: %w", err)
	}

	_ = os.RemoveAll(filepath.Join(tmp, ".git"))

	dest := filepath.Join(sourceRoot, "generated", "bootstrap")

	if err := os.MkdirAll(dest, 0o755); err != nil {
		return err
	}

	if out, err := exec.Command("cp", "-a", tmp+"/.", dest+"/").CombinedOutput(); err != nil {
		return fmt.Errorf("copy failed: %v: %s", err, strings.TrimSpace(string(out)))
	}

	return nil
}

// sudoRun runs a shell script as root on the remote host, feeding the sudo
// password on stdin. It does not rely on a cached sudo timestamp (which does
// not carry over between separate SSH sessions).
func sudoRun(
	client *ssh.Client,
	password string,
	script string,
) (string, error) {

	session, err := client.NewSession()

	if err != nil {
		return "", err
	}

	defer session.Close()

	stdin, err := session.StdinPipe()

	if err != nil {
		return "", err
	}

	var out bytes.Buffer

	session.Stdout = &out
	session.Stderr = &out

	if err := session.Start(
		"sudo -S -p '' sh -c " + shellQuote(script),
	); err != nil {
		return strings.TrimSpace(out.String()), err
	}

	_, _ = io.WriteString(stdin, password+"\n")
	_ = stdin.Close()

	err = session.Wait()

	return strings.TrimSpace(out.String()), err
}

// ageKeyCandidates lists where the local AGE key may live. When the TUI is
// started through "sudo ./install.sh", HOME is /root, so the invoking user's
// home (SUDO_USER) must be checked too.
func ageKeyCandidates() []string {

	var paths []string

	add := func(p string) {
		if p == "" {
			return
		}
		for _, existing := range paths {
			if existing == p {
				return
			}
		}
		paths = append(paths, p)
	}

	add(strings.TrimSpace(os.Getenv("SOPS_AGE_KEY_FILE")))

	if home, err := os.UserHomeDir(); err == nil {
		add(filepath.Join(home, ".config", "sops", "age", "keys.txt"))
	}

	if su := strings.TrimSpace(os.Getenv("SUDO_USER")); su != "" {
		if u, err := osuser.Lookup(su); err == nil {
			add(filepath.Join(u.HomeDir, ".config", "sops", "age", "keys.txt"))
		}
	}

	return paths
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
