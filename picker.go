package main

// A file or folder picker for terminals that don't accept drag-and-drop
// (an elevated Windows Terminal, some WSL setups): opens the normal
// Windows dialog through PowerShell, from Windows or from WSL, and returns
// the chosen paths (as /mnt/c/... paths under WSL).

import (
	"errors"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
)

// inWSL: Linux running under Windows (powershell.exe is reachable).
func inWSL() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	if os.Getenv("WSL_DISTRO_NAME") != "" {
		return true
	}
	v, _ := os.ReadFile("/proc/version")
	return strings.Contains(strings.ToLower(string(v)), "microsoft")
}

// pickerAvailable: a Windows file dialog can be opened from here.
func pickerAvailable() bool {
	if runtime.GOOS != "windows" && !inWSL() {
		return false
	}
	_, err := exec.LookPath("powershell.exe")
	return err == nil
}

const pickFilesScript = `
[Console]::OutputEncoding = [Text.Encoding]::UTF8
Add-Type -AssemblyName System.Windows.Forms
$owner = New-Object System.Windows.Forms.Form -Property @{TopMost = $true}
$d = New-Object System.Windows.Forms.OpenFileDialog
$d.Title = 'Files to send to the node'
$d.Multiselect = $true
if ($d.ShowDialog($owner) -eq 'OK') { $d.FileNames }
`

const pickFolderScript = `
[Console]::OutputEncoding = [Text.Encoding]::UTF8
Add-Type -AssemblyName System.Windows.Forms
$owner = New-Object System.Windows.Forms.Form -Property @{TopMost = $true}
$d = New-Object System.Windows.Forms.FolderBrowserDialog
$d.Description = 'Folder to send to the node (with everything inside it)'
$d.ShowNewFolderButton = $false
if ($d.ShowDialog($owner) -eq 'OK') { $d.SelectedPath }
`

// pickPaths opens the Windows picker and blocks until it closes. It
// returns nothing (and no error) if the user cancels.
func pickPaths(folder bool) ([]string, error) {
	if !pickerAvailable() {
		return nil, errors.New("no file picker here: type the path instead")
	}
	script := pickFilesScript
	if folder {
		script = pickFolderScript
	}
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-STA", "-Command", script)
	if inWSL() && fileExists("/mnt/c") {
		cmd.Dir = "/mnt/c" // PowerShell can't start in a \\wsl$ folder
	}
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	var paths []string
	for _, line := range strings.Split(strings.ReplaceAll(string(out), "\r", ""), "\n") {
		if line = strings.TrimSpace(strings.TrimPrefix(line, "\ufeff")); line != "" {
			paths = append(paths, localPath(line))
		}
	}
	return paths, nil
}

var windowsDrivePath = regexp.MustCompile(`^([A-Za-z]):[\\/]`)

// localPath turns a Windows path (C:\Users\...) into the /mnt/c/Users/...
// path WSL sees, when running under WSL; other paths are unchanged.
func localPath(p string) string {
	if runtime.GOOS != "linux" {
		return p
	}
	m := windowsDrivePath.FindStringSubmatch(p)
	if m == nil {
		return p
	}
	rest := strings.ReplaceAll(p[3:], `\`, "/")
	return "/mnt/" + strings.ToLower(m[1]) + "/" + rest
}

// quotePaths joins paths for the form's box, the way a drop pastes them.
func quotePaths(paths []string) string {
	q := make([]string, len(paths))
	for i, p := range paths {
		q[i] = `"` + p + `"`
	}
	return strings.Join(q, " ")
}
