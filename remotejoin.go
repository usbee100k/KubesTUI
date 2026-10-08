package main

// Remote join: a form collects the connection details, then remoteFlow runs
// in a KubesTUI subprocess on the embedded terminal. Any further prompts
// (host fingerprint, control-plane credentials, ...) appear in that terminal.

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// remotePrefill carries form values to the subprocess over fd 3, so the
// password never appears in argv or the environment.
type remotePrefill struct {
	Host          string `json:"host"`
	User          string `json:"user"`
	Port          int    `json:"port"`
	Password      string `json:"password"`
	GenerateToken *bool  `json:"generateToken,omitempty"`
}

const (
	remoteOpEnv = "KUBESTUI_REMOTE_OP"
	// prefillFileEnv names a 0600 file holding the prefill JSON. Used when a
	// workstation drives the join over SSH, where fd 3 isn't available.
	// The file is deleted as soon as it is read.
	prefillFileEnv = "KUBESTUI_PREFILL_FILE"
)

// runRemoteHeadless is the subprocess entry point. Returns the exit code.
func runRemoteHeadless(op string) int {
	var pre remotePrefill
	if path := os.Getenv(prefillFileEnv); path != "" {
		os.Unsetenv(prefillFileEnv)
		if data, err := os.ReadFile(path); err == nil {
			_ = json.Unmarshal(data, &pre)
		}
		_ = os.Remove(path)
	} else if f := os.NewFile(3, "prefill"); f != nil {
		_ = json.NewDecoder(f).Decode(&pre)
		f.Close()
	}

	ok := remoteFlow(op, pre)

	if ok {
		fmt.Println("\r\n\x1b[1;32m✓ Remote join finished.\x1b[0m")
		return 0
	}
	fmt.Println("\r\n\x1b[1;31m✗ Remote join did not complete. See the messages above.\x1b[0m")
	return 1
}

// centered wraps p in a fixed-size box in the middle of the screen.
func centered(p tview.Primitive, width, height int) tview.Primitive {
	return tview.NewFlex().
		AddItem(nil, 0, 1, false).
		AddItem(tview.NewFlex().SetDirection(tview.FlexRow).
			AddItem(nil, 0, 1, false).
			AddItem(p, height, 1, true).
			AddItem(nil, 0, 1, false), width, 1, true).
		AddItem(nil, 0, 1, false)
}

func styleForm(form *tview.Form) {
	form.SetLabelColor(tcell.ColorYellow).
		SetFieldBackgroundColor(tcell.ColorDarkSlateGray).
		SetFieldTextColor(tcell.ColorWhite).
		SetButtonBackgroundColor(tcell.ColorAqua).
		SetButtonTextColor(tcell.ColorBlack).
		SetBorderPadding(1, 1, 2, 2)
	form.SetBorder(true).SetTitleAlign(tview.AlignLeft)
}

func defaultSSHUser() string {
	for _, v := range []string{os.Getenv("HOMELAB_REMOTE_USER"), os.Getenv("SUDO_USER")} {
		if v = strings.TrimSpace(v); v != "" && v != "root" {
			return v
		}
	}
	return "root"
}

// showRemoteJoinForm opens the form for a remote-worker / remote-controlplane op.
// joinLauncher starts a remote join with the collected form values.
type joinLauncher func(op operation, pre remotePrefill, role string) error

// launchLocalJoin runs the join in a KubesTUI subprocess on this node.
func launchLocalJoin(onBack func()) joinLauncher {
	return func(op operation, pre remotePrefill, role string) error {
		self, err := os.Executable()
		if err != nil {
			return err
		}
		termPage.Open(termLaunch{
			title:  fmt.Sprintf("REMOTE JOIN  %s → %s@%s", role, pre.User, pre.Host),
			target: fmt.Sprintf("%s@%s:%d  (%s)", pre.User, pre.Host, pre.Port, role),
			name:   self,
			env:    append(os.Environ(), remoteOpEnv+"="+op.Op),
			okText: "JOINED",
			extra: func() ([]*os.File, error) {
				r, w, err := os.Pipe()
				if err != nil {
					return nil, err
				}
				go func() {
					_ = json.NewEncoder(w).Encode(pre)
					w.Close()
				}()
				return []*os.File{r}, nil
			},
		}, onBack)
		return nil
	}
}

func showRemoteJoinForm(app *tview.Application, pages *tview.Pages, footer *tview.TextView, op operation, onBack func(), launch joinLauncher) {
	role := "worker"
	if op.Op == "remote-controlplane" {
		role = "control plane"
	}

	store := loadHostStore()
	last := store.Last

	user := defaultSSHUser()
	port := "22"
	host := ""
	if last != nil {
		host, user, port = last.Host, last.User, strconv.Itoa(last.portOr22())
	}

	generate := true

	errText := tview.NewTextView().SetDynamicColors(true)
	var rjPanel tview.Primitive // set below; re-shown if launching fails

	form := tview.NewForm()
	form.AddInputField("Node IP / hostname", host, 32, nil, nil).
		AddInputField("SSH user", user, 32, nil, nil).
		AddInputField("SSH port", port, 6, tview.InputFieldInteger, nil).
		AddPasswordField("SSH / sudo password", "", 32, '*', nil)
	if role == "worker" {
		form.AddCheckbox("Fresh join token", generate, func(checked bool) { generate = checked })
	}

	closeForm := func() {
		pages.RemovePage("rjform")
		onBack()
	}

	form.AddButton("Start join", func() {
		host := strings.TrimSpace(form.GetFormItemByLabel("Node IP / hostname").(*tview.InputField).GetText())
		user := strings.TrimSpace(form.GetFormItemByLabel("SSH user").(*tview.InputField).GetText())
		portText := strings.TrimSpace(form.GetFormItemByLabel("SSH port").(*tview.InputField).GetText())
		password := form.GetFormItemByLabel("SSH / sudo password").(*tview.InputField).GetText()

		port, err := strconv.Atoi(portText)
		switch {
		case host == "":
			errText.SetText("  [red]Enter the node's IP address or hostname.[-]")
			return
		case user == "":
			errText.SetText("  [red]Enter the SSH user.[-]")
			return
		case err != nil || port < 1 || port > 65535:
			errText.SetText("  [red]SSH port must be 1-65535.[-]")
			return
		case password == "":
			errText.SetText("  [red]The password is needed for SSH and sudo on the node.[-]")
			return
		}

		if !demoActive {
			store.remember(hostEntry{Host: host, User: user, Port: port})
			_ = store.save()
		}

		pre := remotePrefill{Host: host, User: user, Port: port, Password: password}
		if role == "worker" {
			g := generate
			pre.GenerateToken = &g
		}

		pages.RemovePage("rjform")
		if err := launch(op, pre, role); err != nil {
			pages.AddPage("rjform", rjPanel, true, true)
			errText.SetText("  [red]" + tview.Escape(err.Error()) + "[-]")
		}
	})
	form.AddButton("Cancel", closeForm)
	form.SetCancelFunc(closeForm)

	styleForm(form)
	form.SetBorder(false) // the panel around it has the frame

	intro := tview.NewTextView().SetDynamicColors(true).SetText(
		"\n  [yellow::b]Join a new " + role + " over SSH[-::-]\n" +
			"  KubesTUI copies homelabCD to the node and runs the join there.\n" +
			"  The password is used for SSH and sudo and is never saved.\n" +
			"  [gray]A fresh join token is created on a control plane (valid 2h).[-]")

	panel := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(intro, 5, 0, false).
		AddItem(form, 0, 1, true).
		AddItem(errText, 1, 0, false)
	panel.SetBorder(true).
		SetTitle(fmt.Sprintf(" REMOTE JOIN %s ", strings.ToUpper(role))).
		SetTitleAlign(tview.AlignLeft)

	// intro 5 + form (padding 2 + fields + gaps + buttons) + error line + border 2
	height := 5 + 2 + 7 + 2 + 1 + 2
	if role == "worker" {
		height += 2
	} else {
		intro.SetText(strings.Replace(intro.GetText(false), "\n  [gray]A fresh join token is created on a control plane (valid 2h).[-]", "", 1))
	}

	rjPanel = centered(panel, 72, height)
	pages.AddPage("rjform", rjPanel, true, true)
	footer.SetText(" [aqua::b]TAB[-::-] Next field    [aqua::b]ENTER[-::-] Select    [aqua::b]ESC[-::-] Cancel")
	app.SetFocus(form)
}
