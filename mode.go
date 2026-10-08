package main

// Choosing between node mode and workstation mode.
//
//   - Started by kbtui / install.sh (HOMELABCD_INSTALL set): node menu.
//   - --node / --workstation: that mode, no questions.
//   - Linux machine that is a cluster node: a quick chooser.
//   - Anything else (Windows, macOS, other Linux): workstation.
//
// The node menu needs the settings install.sh exports, so "Node menu" hands
// over to the kbtui launcher rather than starting it here.

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// kbtuiPath is homelabCD's node-menu launcher. KUBESTUI_KBTUI overrides it
// (for a non-standard install, or testing).
func kbtuiPath() string {
	if p := os.Getenv("KUBESTUI_KBTUI"); p != "" {
		return p
	}
	return "/usr/local/bin/kbtui"
}

type startup int

const (
	modeWorkstation startup = iota
	modeNode
	modeAsk
)

// launchNodeMenu is set by the chooser; main opens kbtui after the TUI exits.
var launchNodeMenu bool

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// looksLikeNode reports whether this machine is (or is set up as) a node.
func looksLikeNode() bool {
	return runtime.GOOS == "linux" &&
		(fileExists(kbtuiPath()) || fileExists("/etc/kubernetes/kubelet.conf"))
}

func hasArg(args []string, flag string) bool {
	for _, a := range args {
		if a == flag {
			return true
		}
	}
	return false
}

func startupMode(args []string) startup {
	for _, a := range args {
		switch a {
		case "--node":
			return modeNode
		case "--workstation", "--demo":
			return modeWorkstation
		}
	}
	if looksLikeNode() {
		return modeAsk
	}
	return modeWorkstation
}

// openNodeMenu replaces KubesTUI with kbtui, which loads the homelabCD
// settings and starts the node menu.
func openNodeMenu() {
	if !fileExists(kbtuiPath()) {
		fmt.Fprintln(os.Stderr, "The node menu isn't installed on this machine ("+kbtuiPath()+" is missing).")
		fmt.Fprintln(os.Stderr, "On the bootstrap node, run homelabCD's install.sh once to set it up.")
		os.Exit(1)
	}
	cmd := exec.Command(kbtuiPath())
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintln(os.Stderr, "Could not start kbtui:", err)
		os.Exit(1)
	}
	os.Exit(0)
}

// chooseMode shows the "node or workstation?" screen as the app's root.
func chooseMode(app *tview.Application) {
	host, _ := os.Hostname()
	nodeReady := fileExists(kbtuiPath())

	text := fmt.Sprintf("\n  [yellow::b]HOW DO YOU WANT TO USE KUBESTUI?[-::-]\n\n"+
		"  [white::b]%s[-::-] is part of a cluster.\n\n"+
		"  [aqua::b]Node menu[-::-]    Bootstrap, join this machine, repair it,\n"+
		"               health checks, SSH console, share KubesTUI.\n\n"+
		"  [aqua::b]Workstation[-::-]  Control clusters remotely over SSH,\n"+
		"               like from a laptop.\n", tview.Escape(host))
	if !nodeReady {
		text += "\n  [yellow]The node menu isn't installed here: run homelabCD's install.sh once.[-]\n"
	}
	text += "\n  [gray]Skip this next time: kubestui --node  or  --workstation[-]"

	info := tview.NewTextView().SetDynamicColors(true).SetText(text)

	choices := tview.NewList().
		ShowSecondaryText(false).
		SetHighlightFullLine(true).
		SetMainTextColor(tcell.ColorWhite).
		SetSelectedTextColor(tcell.ColorBlack).
		SetSelectedBackgroundColor(tcell.ColorAqua)
	if nodeReady {
		choices.AddItem("  Node menu", "", 'n', func() {
			launchNodeMenu = true
			app.Stop()
		})
	}
	choices.AddItem("  Workstation", "", 'w', func() { setupWorkstation(app) })
	choices.AddItem("  Quit", "", 'q', app.Stop)
	choices.SetBorderPadding(0, 0, 1, 1)

	panel := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(info, 0, 1, false).
		AddItem(choices, 4, 0, true)
	panel.SetBorder(true).SetTitle(" HOMELAB KUBERNETES PLATFORM ").SetTitleAlign(tview.AlignLeft)

	height := 20
	if !nodeReady {
		height = 21
	}
	footer := tview.NewTextView().SetDynamicColors(true).
		SetText(" [aqua::b]UP/DOWN[-::-] Choose    [aqua::b]ENTER[-::-] Open    [aqua::b]N / W / Q[-::-] Shortcut")
	root := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(centered(panel, 66, height), 0, 1, true).
		AddItem(footer, 1, 0, false)

	app.SetInputCapture(nil)
	app.SetRoot(root, true).EnableMouse(true).EnablePaste(true)
	app.SetFocus(choices)
}
