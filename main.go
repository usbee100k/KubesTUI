package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	osuser "os/user"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
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
	ReadOnly bool // safe to run in dry-run mode: changes nothing
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
		Title: "Move Node to Dedicated Longhorn Disk",
		Desc:  "Format a spare disk on a node, add it to Longhorn with all its space, move that node's replicas off the OS disk, then remove the old disk. No downtime; asks before anything is erased, and re-running resumes an interrupted move.",
		Op:    "longhorn-disk",
		Commands: []string{
			"${HOMELABCD_INSTALL} --run longhorn-disk",
		},
	},
	{
		Title: "Import Docker Compose App",
		Desc:  "Turn a docker-compose.yml into an app in your GitOps repo (apps/applications/<name>): web UIs get https://<name>.<domain>, LAN services a MetalLB IP, volumes go on Longhorn and passwords into a cluster Secret. Then it deploys and waits until it's healthy.",
		Op:    "compose-import",
		Commands: []string{
			"${HOMELABCD_INSTALL} --run compose-import",
		},
	},
	{
		Title: "Remove Imported App",
		Desc:  "Remove an app imported from Docker Compose, including its volumes and secrets.",
		Op:    "compose-remove",
		Commands: []string{
			"${HOMELABCD_INSTALL} --run compose-remove",
		},
	},
	{
		Title: "VPN Status",
		Desc:  "WireGuard (wg-easy) health: server, public endpoint, router forward target, connected clients and handshakes.",
		Op:    "vpn-status",
		Commands: []string{
			"${HOMELABCD_INSTALL} --run vpn-status",
		},
		ReadOnly: true,
	},
	{
		Title: "Set Up VPN",
		Desc:  "Add (or change) the WireGuard VPN: asks for the node subnet, public endpoint, port, VPN IP and web UI password, then deploys wg-easy through GitOps.",
		Op:    "vpn-setup",
		Commands: []string{
			"${HOMELABCD_INSTALL} --run vpn-setup",
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
		Desc:  "Report on nodes, control plane, etcd, Cilium, MetalLB, ingress, DNS, Argo CD apps, pods, storage and certificates.",
		Op:    "health",
		Commands: []string{
			"${HOMELABCD_INSTALL} --run health",
		},
		ReadOnly: true,
	},
	{
		Title: "Cluster Configuration",
		Desc:  "Show config/cluster.yaml and the live kubeadm cluster configuration.",
		Op:    "config",
		Commands: []string{
			"${HOMELABCD_INSTALL} --run config",
		},
		ReadOnly: true,
	},
	{
		Title: "Update homelabCD and KubesTUI",
		Desc:  "Pull the latest homelabCD from GitHub (your saved settings in config/ are kept) and rebuild KubesTUI. Doesn't change the cluster. Reopen KubesTUI (kbtui) afterwards to use the new version.",
		Op:    "update",
		Commands: []string{
			"${HOMELABCD_INSTALL} --run update",
		},
	},
}

const toggleTitle = "Toggle Dry-Run / Live"

// remoteFlow provisions a node over SSH and runs its join remotely. It runs
// in a KubesTUI subprocess on the embedded terminal (see remotejoin.go), so
// it talks to the user through plain stdin/stdout. Values already collected
// by the remote-join form are taken from pre instead of being prompted for.
// Returns true on success.
func remoteFlow(opName string, pre remotePrefill) bool {

	install := installerPath()

	if install == "" {
		fmt.Println("[FAIL] HOMELABCD_INSTALL is not set. Launch this TUI from homelabCD install.sh.")
		return false
	}

	remoteScript := ""

	switch opName {
	case "remote-worker":
		remoteScript = "worker"

	case "remote-controlplane":
		remoteScript = "controlplane"

	default:
		fmt.Println("[FAIL] Unsupported remote operation: " + opName)
		return false
	}

	{

		reader := bufio.NewReader(os.Stdin)

		fmt.Println()
		fmt.Println("==================================================")
		fmt.Println("             REMOTE NODE EXECUTION")
		fmt.Println("==================================================")
		fmt.Println()

		remoteHost := pre.Host
		if remoteHost == "" {
			remoteHost = readRemoteValue(
				reader,
				"IP address / hostname: ",
			)
		}

		if remoteHost == "" {
			fmt.Println("Remote host cannot be empty.")
			return false
		}

		// Ask for the SSH username instead of silently picking one.
		// HOMELAB_REMOTE_USER, if set, is offered as the default.
		defaultUser := strings.TrimSpace(os.Getenv("HOMELAB_REMOTE_USER"))

		userPrompt := "SSH username: "
		if defaultUser != "" {
			userPrompt = fmt.Sprintf("SSH username [%s]: ", defaultUser)
		}

		remoteUser := pre.User
		if remoteUser == "" {
			remoteUser = readRemoteValue(reader, userPrompt)
		}

		if remoteUser == "" {
			remoteUser = defaultUser
		}

		if remoteUser == "" {
			fmt.Println("SSH username cannot be empty.")
			return false
		}

		remotePort := pre.Port
		if remotePort <= 0 {
			remotePort = 22
		}

		remoteAddr := net.JoinHostPort(remoteHost, strconv.Itoa(remotePort))

		fmt.Println()
		fmt.Printf("SSH user : %s\n", remoteUser)
		fmt.Printf("Target   : %s\n", remoteAddr)
		fmt.Printf("Operation: %s\n", remoteScript)
		fmt.Println()

		fmt.Println("[INFO] Reading SSH host fingerprint...")

		scan := exec.Command(
			"ssh-keyscan",
			"-T", "10",
			"-p", strconv.Itoa(remotePort),
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
			return false
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
			return false
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
			return false
		}

		password := pre.Password

		if password == "" {
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
				return false
			}

			password = string(passwordBytes)
		}

		if password == "" {
			fmt.Println("[FAIL] Password cannot be empty.")
			return false
		}

		fmt.Println("[INFO] Connecting to remote node...")

		clientConfig := &ssh.ClientConfig{
			User: remoteUser,
			Auth: []ssh.AuthMethod{
				ssh.Password(password),
			},
			HostKeyCallback: hostKeyCallback,
			Timeout:         10 * time.Second,
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
			return false
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
			return false
		}

		sudoInput, err := sudoSession.StdinPipe()

		if err != nil {
			sudoSession.Close()
			fmt.Printf(
				"[FAIL] Could not open sudo input: %v\n",
				err,
			)
			return false
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
			return false
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
			return false
		}

		_ = sudoInput.Close()

		if err := sudoSession.Wait(); err != nil {
			fmt.Printf(
				"[FAIL] Sudo authentication failed: %v\n",
				err,
			)
			return false
		}

		fmt.Println("[ OK ] Sudo access confirmed.")
		fmt.Println()

		fmt.Println("[INFO] Preparing remote directory...")

		if out, err := sudoRun(
			client,
			password,
			fmt.Sprintf(
				// -R: a previous run's installer (run with sudo) leaves
				// root-owned files, e.g. generated/, that the copy below
				// (run as the SSH user) could not overwrite.
				"mkdir -p %s && chown -R %s: %s",
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
			return false
		}

		fmt.Println("[ OK ] Remote directory ready.")
		fmt.Println()

		// Workers: offer to create a fresh join token on a control plane, so no
		// stored (possibly expired) join package or GitHub access is needed.
		joinCmd := ""

		if remoteScript == "worker" {

			generate := false

			if pre.GenerateToken != nil {
				generate = *pre.GenerateToken
			} else {
				gen := strings.ToLower(strings.TrimSpace(readRemoteValue(
					reader,
					"Generate a fresh join token from a control plane now? [Y/n]: ",
				)))
				generate = gen == "" || gen == "y" || gen == "yes"
			}

			if generate {

				cmd, gerr := generateJoinCommand(reader, remoteUser, password)

				if gerr != nil {
					fmt.Printf("[FAIL] Could not generate join token: %v\n", gerr)
					return false
				}

				joinCmd = cmd

				fmt.Println("[ OK ] Fresh join token generated (valid 2 hours).")
				fmt.Println()
			}
		}

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

		if _, err := os.Stat(encPath); err != nil && joinCmd == "" {
			fmt.Printf("[WARN] Encrypted join package not found locally: %s\n", encPath)

			fetch := strings.ToLower(strings.TrimSpace(
				readRemoteValue(reader, "Fetch it from the bootstrap repository now? [Y/n]: "),
			))

			if fetch == "" || fetch == "y" {
				if err := fetchBootstrapPackage(sourceRoot, reader); err != nil {
					fmt.Printf("[FAIL] Could not fetch bootstrap package: %v\n", err)
				} else if _, serr := os.Stat(encPath); serr != nil {
					fmt.Printf("[WARN] Repository cloned, but it has no secrets/%s.\n", encName)
					fmt.Println("       Bootstrap a control plane first (it uploads the package).")
				} else {
					fmt.Println("[ OK ] Bootstrap package fetched.")
				}
			}

			if _, err := os.Stat(encPath); err != nil {
				fmt.Println("[WARN] The node will not be able to get its join credentials.")

				answer := readRemoteValue(reader, "Continue anyway? [y/N]: ")

				if strings.ToLower(strings.TrimSpace(answer)) != "y" {
					return false
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
			return false
		}

		transferSession, err := client.NewSession()

		if err != nil {
			fmt.Printf(
				"[FAIL] Could not create transfer session: %v\n",
				err,
			)
			return false
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
			return false
		}

		if err := tarCmd.Start(); err != nil {
			transferSession.Close()

			fmt.Printf(
				"[FAIL] Could not start local archive: %v\n",
				err,
			)
			return false
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
			return false
		}

		if tarErr != nil {
			fmt.Printf(
				"[FAIL] Could not create archive: %v\n",
				tarErr,
			)
			return false
		}

		fmt.Println(
			"[ OK ] homelabCD copied to remote node.",
		)
		fmt.Println()

		if joinCmd != "" {

			fmt.Println("[INFO] Installing fresh join command on the node...")

			script := "#!/usr/bin/env bash\nset -euo pipefail\n" + joinCmd + "\n"

			if err := uploadViaTmp(
				client,
				password,
				script,
				"/tmp/homelab-worker-join.sh",
				remoteRoot+"/generated/secrets",
				"worker_join.sh",
				"700",
			); err != nil {
				fmt.Printf("[FAIL] Could not install join command: %v\n", err)
				return false
			}

			fmt.Println("[ OK ] Join command installed.")
			fmt.Println()

		} else {

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
				return false
			}

			fmt.Printf("[INFO] Using AGE key: %s\n", ageKey)

			ageData, err := os.ReadFile(ageKey)

			if err != nil {
				fmt.Printf(
					"[FAIL] Could not read AGE key: %v\n",
					err,
				)
				return false
			}

			fmt.Println("[INFO] Copying AGE private key...")

			ageSession, err := client.NewSession()

			if err != nil {
				fmt.Printf(
					"[FAIL] Could not create AGE transfer session: %v\n",
					err,
				)
				return false
			}

			ageInput, err := ageSession.StdinPipe()

			if err != nil {
				ageSession.Close()

				fmt.Printf(
					"[FAIL] Could not open AGE transfer: %v\n",
					err,
				)
				return false
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
				return false
			}

			if _, err := ageInput.Write(ageData); err != nil {
				ageSession.Close()

				fmt.Printf(
					"[FAIL] Could not send AGE key: %v\n",
					err,
				)
				return false
			}

			_ = ageInput.Close()

			if err := ageSession.Wait(); err != nil {
				fmt.Printf(
					"[FAIL] AGE key transfer failed: %v\n",
					err,
				)
				return false
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
				return false
			}

			fmt.Println("[ OK ] AGE private key installed.")
			fmt.Println()

		}

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
			return false
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
			return false
		}

		runStdin, err := runSession.StdinPipe()

		if err != nil {
			runSession.Close()

			fmt.Printf(
				"[FAIL] Could not open remote input: %v\n",
				err,
			)
			return false
		}

		runSession.Stdout = os.Stdout
		runSession.Stderr = os.Stderr

		joinEnv := ""
		if joinCmd != "" {
			joinEnv = "HOMELAB_JOIN_PROVIDED=true "
		}

		remoteCommand := fmt.Sprintf(
			"sudo -S -p '' -v && stty echo && "+
				"sudo -n env HOME=/root "+
				"HOMELAB_REMOTE_MODE=true %s"+
				"BOOTSTRAP_PACKAGE_DIR=%s/generated/bootstrap "+
				"bash %s/install.sh --run %s",
			joinEnv,
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
			return false
		}

		runSession.Close()

		fmt.Println()
		fmt.Printf(
			"[ OK ] Remote %s operation completed.\n",
			remoteScript,
		)
	}

	return true
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

// configValue looks for NAME in the environment, then in config/*.env.
func configValue(sourceRoot, name string) string {

	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}

	files, _ := filepath.Glob(filepath.Join(sourceRoot, "config", "*.env"))

	for _, f := range files {
		if v := readEnvFileValue(f, name); v != "" {
			return v
		}
	}

	return ""
}

// yamlConfigValue looks for a simple "key: value" line in config/ and generated/ YAML files.
func yamlConfigValue(sourceRoot string, keys ...string) string {

	var files []string

	for _, dir := range []string{"config", "generated"} {
		m, _ := filepath.Glob(filepath.Join(sourceRoot, dir, "*.y*ml"))
		files = append(files, m...)
	}

	for _, f := range files {

		data, err := os.ReadFile(f)

		if err != nil {
			continue
		}

		for _, line := range strings.Split(string(data), "\n") {

			line = strings.TrimSpace(line)

			for _, k := range keys {

				if !strings.HasPrefix(line, k+":") {
					continue
				}

				v := strings.Trim(
					strings.TrimSpace(strings.TrimPrefix(line, k+":")),
					"\"' ",
				)

				if v != "" && v != "null" {
					return v
				}
			}
		}
	}

	return ""
}

func isPrivateKeyFile(path string) bool {

	data, err := os.ReadFile(path)

	if err != nil || len(data) == 0 {
		return false
	}

	if len(data) > 400 {
		data = data[:400]
	}

	return strings.Contains(string(data), "PRIVATE KEY")
}

// findDeployKeys lists likely SSH private keys on this machine.
func findDeployKeys(sourceRoot string) []string {

	var dirs []string

	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, filepath.Join(home, ".ssh"))
	}

	if su := strings.TrimSpace(os.Getenv("SUDO_USER")); su != "" {
		if u, err := osuser.Lookup(su); err == nil {
			dirs = append(dirs, filepath.Join(u.HomeDir, ".ssh"))
		}
	}

	dirs = append(
		dirs,
		filepath.Join(sourceRoot, "generated"),
		filepath.Join(sourceRoot, "generated", "ssh"),
		filepath.Join(sourceRoot, "config"),
	)

	seen := map[string]bool{}

	var found []string

	for _, dir := range dirs {

		entries, err := os.ReadDir(dir)

		if err != nil {
			continue
		}

		for _, e := range entries {

			if e.IsDir() || strings.HasSuffix(e.Name(), ".pub") {
				continue
			}

			path := filepath.Join(dir, e.Name())

			if seen[path] || !isPrivateKeyFile(path) {
				continue
			}

			seen[path] = true
			found = append(found, path)
		}
	}

	return found
}

// fetchBootstrapPackage clones the private bootstrap repo with the deploy key
// (on this machine) and places its contents in generated/bootstrap, which is
// the same layout upload_bootstrap_package pushes.
func fetchBootstrapPackage(sourceRoot string, reader *bufio.Reader) error {

	// Find the values the project already saved instead of asking for them.
	repo := configValue(sourceRoot, "BOOTSTRAP_REPO")

	if repo == "" {
		repo = yamlConfigValue(sourceRoot, "bootstrap_repo")
	}

	keyPath := configValue(sourceRoot, "SSH_KEY_PATH")

	if keyPath == "" {
		keyPath = yamlConfigValue(sourceRoot, "ssh_key_path", "deploy_key_path", "deploy_key")
	}

	if repo != "" {
		fmt.Printf("[INFO] Bootstrap repository: %s\n", repo)
	}

	if keyPath != "" {
		fmt.Printf("[INFO] Deploy key: %s\n", keyPath)
	}

	if repo == "" {
		fmt.Println()
		fmt.Println("Enter the private bootstrap repository URL,")
		fmt.Println("for example: git@github.com:user/bootstrap-repo.git")
		repo = strings.TrimSpace(readRemoteValue(reader, "Bootstrap repository URL: "))
	}

	if keyPath == "" {
		keys := findDeployKeys(sourceRoot)

		fmt.Println()
		fmt.Println("Enter the path of the SSH deploy key that has access to the repository.")

		if len(keys) > 0 {
			fmt.Println("Private keys found on this machine:")
			for i, k := range keys {
				fmt.Printf("  %d) %s\n", i+1, k)
			}
		}

		choice := strings.TrimSpace(readRemoteValue(reader, "Key number or full path: "))

		if n, err := strconv.Atoi(choice); err == nil && n >= 1 && n <= len(keys) {
			keyPath = keys[n-1]
		} else {
			keyPath = choice
		}
	}

	if strings.HasPrefix(keyPath, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			keyPath = filepath.Join(home, keyPath[2:])
		}
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

var joinCommandPattern = regexp.MustCompile(
	`^kubeadm join [A-Za-z0-9.:\[\]-]+ --token [a-z0-9.]+ ` +
		`--discovery-token-ca-cert-hash sha256:[a-f0-9]{64}$`,
)

// parseJoinCommand extracts and validates the "kubeadm join ..." line from the
// output of "kubeadm token create --print-join-command". kubeadm prints it
// split over two lines with a trailing backslash, so those are joined first.
func parseJoinCommand(output string) (string, error) {

	text := strings.ReplaceAll(output, "\\\n", " ")

	for _, line := range strings.Split(text, "\n") {

		line = strings.Join(strings.Fields(line), " ")

		if !strings.HasPrefix(line, "kubeadm join ") {
			continue
		}

		if !joinCommandPattern.MatchString(line) {
			return "", fmt.Errorf("unexpected join command format: %s", line)
		}

		return line, nil
	}

	return "", fmt.Errorf("no join command found in output: %s", strings.TrimSpace(output))
}

func promptPassword(prompt string) (string, error) {

	fmt.Print(prompt)

	b, err := term.ReadPassword(int(os.Stdin.Fd()))

	fmt.Println()

	return string(b), err
}

// trustAndDial shows the host's SSH key fingerprints, asks the user to trust
// them, then connects with a password.
func trustAndDial(
	reader *bufio.Reader,
	host, user, password string,
) (*ssh.Client, error) {

	raw, err := exec.Command(
		"ssh-keyscan", "-T", "10", "-t", "ed25519,ecdsa,rsa", host,
	).Output()

	if err != nil || len(raw) == 0 {
		return nil, fmt.Errorf("could not read SSH host keys from %s", host)
	}

	trusted := map[string]bool{}

	var fingerprints []string

	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {

		fields := strings.Fields(strings.TrimSpace(line))

		if len(fields) < 3 || strings.HasPrefix(fields[0], "#") {
			continue
		}

		key, _, _, _, perr := ssh.ParseAuthorizedKey(
			[]byte(fields[1] + " " + fields[2]),
		)

		if perr != nil || trusted[string(key.Marshal())] {
			continue
		}

		trusted[string(key.Marshal())] = true

		fingerprints = append(
			fingerprints,
			fmt.Sprintf("%-22s %s", key.Type(), ssh.FingerprintSHA256(key)),
		)
	}

	if len(trusted) == 0 {
		return nil, fmt.Errorf("could not parse SSH host keys from %s", host)
	}

	fmt.Printf("\nHost: %s\n", host)

	for _, fp := range fingerprints {
		fmt.Printf("  %s\n", fp)
	}

	fmt.Println()

	answer := strings.ToLower(strings.TrimSpace(
		readRemoteValue(reader, "Trust this host fingerprint? [y/N]: "),
	))

	if answer != "y" && answer != "yes" {
		return nil, fmt.Errorf("host fingerprint not trusted")
	}

	return ssh.Dial(
		"tcp",
		net.JoinHostPort(host, "22"),
		&ssh.ClientConfig{
			User: user,
			Auth: []ssh.AuthMethod{ssh.Password(password)},
			HostKeyCallback: func(
				hostname string,
				remote net.Addr,
				key ssh.PublicKey,
			) error {
				if trusted[string(key.Marshal())] {
					return nil
				}
				return fmt.Errorf(
					"host key mismatch: server presented %s %s",
					key.Type(),
					ssh.FingerprintSHA256(key),
				)
			},
			Timeout: 10 * time.Second,
		},
	)
}

// generateJoinCommand creates a fresh, short-lived bootstrap token on a
// control plane and returns the validated "kubeadm join ..." command.
func generateJoinCommand(
	reader *bufio.Reader,
	defaultUser, defaultPassword string,
) (string, error) {

	const tokenCmd = "kubeadm token create --ttl 2h --print-join-command"

	// The token comes from an existing control plane. Running on one (the
	// usual case), use it without asking; otherwise ask which one.
	host := ""

	if _, err := os.Stat("/etc/kubernetes/admin.conf"); err != nil {
		fmt.Println("The join token is created on an existing control plane of the cluster.")
		host = strings.TrimSpace(readRemoteValue(
			reader,
			"Existing control plane to create the token on (IP/hostname, blank = this machine): ",
		))
	}

	var output string

	if host == "" {

		fmt.Println("[INFO] Creating join token on this machine...")

		cmd := exec.Command(
			"sudo", "kubeadm", "token", "create",
			"--ttl", "2h", "--print-join-command",
		)
		cmd.Stdin = os.Stdin
		cmd.Stderr = os.Stderr

		raw, err := cmd.Output()

		if err != nil {
			return "", fmt.Errorf("%v (is kubeadm installed on a control plane here?)", err)
		}

		output = string(raw)

	} else {

		user := strings.TrimSpace(readRemoteValue(
			reader,
			fmt.Sprintf("Control plane SSH user [%s]: ", defaultUser),
		))

		if user == "" {
			user = defaultUser
		}

		password := defaultPassword

		reuse := strings.ToLower(strings.TrimSpace(readRemoteValue(
			reader,
			"Use the same password as the worker? [Y/n]: ",
		)))

		if reuse == "n" || reuse == "no" {

			pw, err := promptPassword(
				fmt.Sprintf("SSH password for %s@%s: ", user, host),
			)

			if err != nil || pw == "" {
				return "", fmt.Errorf("could not read password")
			}

			password = pw
		}

		client, err := trustAndDial(reader, host, user, password)

		if err != nil {
			return "", err
		}

		defer client.Close()

		fmt.Println("[INFO] Creating join token on the control plane...")

		out, err := sudoRun(client, password, tokenCmd)

		if err != nil {
			return "", fmt.Errorf("%v: %s", err, out)
		}

		output = out
	}

	return parseJoinCommand(output)
}

// uploadViaTmp writes content to a temp file as the SSH user, then installs it
// as root at destDir/destName with the given mode.
func uploadViaTmp(
	client *ssh.Client,
	password, content, tmpPath, destDir, destName, mode string,
) error {

	session, err := client.NewSession()

	if err != nil {
		return err
	}

	defer session.Close()

	stdin, err := session.StdinPipe()

	if err != nil {
		return err
	}

	if err := session.Start("umask 077; cat > " + shellQuote(tmpPath)); err != nil {
		return err
	}

	_, _ = io.WriteString(stdin, content)
	_ = stdin.Close()

	if err := session.Wait(); err != nil {
		return err
	}

	out, err := sudoRun(
		client,
		password,
		fmt.Sprintf(
			"mkdir -p %s && install -m %s %s %s && rm -f %s",
			shellQuote(destDir),
			mode,
			shellQuote(tmpPath),
			shellQuote(path.Join(destDir, destName)),
			shellQuote(tmpPath),
		),
	)

	if err != nil {
		return fmt.Errorf("%v: %s", err, out)
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
	if op.ReadOnly {
		b.WriteString("  [green]READ-ONLY: ENTER runs this in any mode; it changes nothing.[-]\n\n")
	} else if dryRun {
		b.WriteString("  [green]DRY-RUN: the following commands would be executed:[-]\n\n")
	} else {
		b.WriteString("  [red]LIVE: ENTER runs the homelabCD installer operation.[-]\n\n")
	}
	for _, c := range op.Commands {
		b.WriteString("    $ " + tview.Escape(expand(c)) + "\n")
	}
	return b.String()
}

func footerText(page string, op operation) string {
	if page == "detail" && (!dryRun || op.ReadOnly) {
		return " [aqua::b]ENTER[-::-] Execute    [aqua::b]ESC[-::-] Back    [aqua::b]Q[-::-] Quit"
	}
	return " [aqua::b]UP/DOWN[-::-] Navigate    [aqua::b]ENTER[-::-] Select    [aqua::b]ESC[-::-] Back    [aqua::b]Q[-::-] Quit"
}

// version is set at build time: -ldflags "-X main.version=v1.2.3".
var version = "dev"

// openRemoteJoin is set in main; it shows the remote-join form for op.
var openRemoteJoin func(op operation)

func runOperation(app *tview.Application, op operation) {

	// Remote joins: a form, then the join runs in the embedded terminal.
	if strings.HasPrefix(op.Op, "remote-") {
		openRemoteJoin(op)
		return
	}

	tuiRunner.start(op)
}

func main() {
	// Docker Compose import/removal, run by install.sh on a control plane.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "compose-import":
			os.Exit(runComposeImport())
		case "compose-remove":
			os.Exit(runComposeRemove())
		}
	}

	// Subprocess mode: run a remote join on the embedded terminal.
	if op := os.Getenv(remoteOpEnv); op != "" {
		os.Unsetenv(remoteOpEnv)
		os.Exit(runRemoteHeadless(op))
	}

	// --node hands over to kbtui before the terminal is touched.
	if !nodeMode() && startupMode(os.Args[1:]) == modeNode {
		openNodeMenu()
	}

	loadCluster()
	useASCIIBorders()

	app := tview.NewApplication()
	if screen, err := tcell.NewScreen(); err == nil {
		app.SetScreen(screen)
		uiScreen = screen
	}
	uiApp = app

	// Not launched by homelabCD's install.sh: a workstation, unless this
	// Linux machine is a cluster node, in which case ask (see mode.go).
	if !nodeMode() {
		useASCIIBorders()
		switch startupMode(os.Args[1:]) {
		case modeAsk:
			chooseMode(app)
		default:
			w := setupWorkstation(app)
			if hasArg(os.Args[1:], "--demo") {
				w.openDemo()
			}
		}
		if err := app.Run(); err != nil {
			panic(err)
		}
		if launchNodeMenu {
			openNodeMenu()
		}
		return
	}
	pages := tview.NewPages()
	uiPages = pages

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
	var selected operation

	footer.SetText(footerText("main", selected))

	showDetail := func(op operation) {
		selected = op
		detail.SetText(detailText(op))
		detail.ScrollToBeginning()
		pages.SwitchToPage("detail")
		footer.SetText(footerText("detail", selected))
		app.SetFocus(detail)
	}

	for _, op := range operations {
		op := op
		list.AddItem("  "+op.Title, "", 0, func() { showDetail(op) })
	}
	list.AddItem("  SSH Console", "", 0, func() { sshPage.Show() })
	list.AddItem("  Share KubesTUI with a Workstation", "", 0, func() { sharer.Start() })
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

	backToDetail := func(op operation) {
		pages.SwitchToPage("detail")
		footer.SetText(footerText("detail", op))
		app.SetFocus(detail)
	}
	backToMain := func() {
		pages.SwitchToPage("main")
		footer.SetText(footerText("main", selected))
		app.SetFocus(list)
	}

	tuiRunner = newRunner(app, pages, footer, backToDetail)
	termPage = newTermScreen(app, pages, footer)
	sshPage = newSSHConsole(app, pages, footer, backToMain)
	sharer = newSharePage(app, pages, footer, backToMain)
	openRemoteJoin = func(op operation) {
		back := func() { backToDetail(op) }
		showRemoteJoinForm(app, pages, footer, op, back, launchLocalJoin(back))
	}

	app.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		if emergencyQuit(app, ev) {
			return nil
		}
		name, _ := pages.GetFrontPage()
		switch name {
		case "run":
			return tuiRunner.handleKey(ev)
		case "term":
			return termPage.HandleKey(ev)
		case "ssh":
			return sshPage.HandleKey(ev)
		case "share":
			return sharer.HandleKey(ev)
		case "sshform", "rjform", "ask":
			return ev // the form handles its own keys; ESC cancels it
		}
		switch ev.Key() {
		case tcell.KeyEscape:
			if name != "main" {
				pages.SwitchToPage("main")
				footer.SetText(footerText("main", selected))
				app.SetFocus(list)
				return nil
			}
		case tcell.KeyEnter:
			if name == "detail" && (!dryRun || selected.ReadOnly) {
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
