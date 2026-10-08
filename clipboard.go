package main

// Copying output: to the clipboard (OSC 52, which Windows Terminal, iTerm2,
// kitty, WezTerm and recent xterm support, also across SSH), and to log files
// as a fallback that always works.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
)

// uiScreen is the tcell screen, set in main.
var uiScreen tcell.Screen

// copyToClipboard posts text to the system clipboard of the terminal that
// KubesTUI is displayed in. Returns false if there is no screen.
func copyToClipboard(text string) bool {
	if uiScreen == nil {
		return false
	}
	uiScreen.SetClipboard([]byte(text))
	return true
}

var unsafeFileChars = regexp.MustCompile(`[^A-Za-z0-9._@-]+`)

// saveLog writes text to ~/kubestui-logs/<label>-<timestamp>.log.
func saveLog(label, text string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		home = os.TempDir()
	}
	dir := filepath.Join(home, "kubestui-logs")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	name := strings.Trim(unsafeFileChars.ReplaceAllString(label, "-"), "-")
	if name == "" {
		name = "session"
	}
	path := filepath.Join(dir, name+"-"+time.Now().Format("20060102-150405")+".log")
	return path, os.WriteFile(path, []byte(text), 0o600)
}

// shortPath shows paths under the home directory as ~/...
func shortPath(path string) string {
	if home, err := os.UserHomeDir(); err == nil && strings.HasPrefix(path, home+"/") {
		return "~" + strings.TrimPrefix(path, home)
	}
	return path
}
