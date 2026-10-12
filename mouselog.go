package main

// KUBESTUI_MOUSELOG=<file> records every mouse event KubesTUI receives,
// to debug terminals that report mouse drags differently.

import (
	"fmt"
	"os"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

func enableMouseLog(app *tview.Application) {
	path := os.Getenv("KUBESTUI_MOUSELOG")
	if path == "" {
		return
	}
	f, err := os.Create(path)
	if err != nil {
		return
	}
	start := time.Now()
	app.SetMouseCapture(func(ev *tcell.EventMouse, action tview.MouseAction) (*tcell.EventMouse, tview.MouseAction) {
		x, y := ev.Position()
		fmt.Fprintf(f, "%7dms x=%-3d y=%-3d buttons=%#x mods=%#x action=%d\n",
			time.Since(start).Milliseconds(), x, y, ev.Buttons(), ev.Modifiers(), action)
		return ev, action
	})
}
