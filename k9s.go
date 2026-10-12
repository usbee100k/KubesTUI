package main

// k9s from the workstation. KubesTUI downloads a pinned k9s release once
// (checked against the release's checksums) into ~/.kubestui/bin, unless k9s
// is already on PATH, then hands it the real terminal with this cluster's
// kubeconfig (the VPN one while the tunnel is up). Quitting k9s returns to
// KubesTUI.

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/rivo/tview"
)

const k9sVersion = "v0.51.0"

func k9sInstallPath() string {
	name := "k9s"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return filepath.Join(kubestuiDir(), "bin", name)
}

// findK9s prefers a k9s the user installed; otherwise the one KubesTUI
// downloaded. Empty if there is neither.
func findK9s() string {
	if p, err := exec.LookPath("k9s"); err == nil {
		return p
	}
	if _, err := os.Stat(k9sInstallPath()); err == nil {
		return k9sInstallPath()
	}
	return ""
}

func httpGetBytes(url string) ([]byte, error) {
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", url, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 256<<20))
}

// installK9s downloads k9s for this OS/arch, verifies it and installs it.
func installK9s() (string, error) {
	osName := map[string]string{"linux": "Linux", "darwin": "Darwin", "windows": "Windows"}[runtime.GOOS]
	if osName == "" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		return "", fmt.Errorf("no k9s download for %s/%s; install k9s yourself and put it on PATH", runtime.GOOS, runtime.GOARCH)
	}
	ext := ".tar.gz"
	if runtime.GOOS == "windows" {
		ext = ".zip"
	}
	asset := fmt.Sprintf("k9s_%s_%s%s", osName, runtime.GOARCH, ext)
	base := "https://github.com/derailed/k9s/releases/download/" + k9sVersion + "/"

	sums, err := httpGetBytes(base + "checksums.sha256")
	if err != nil {
		return "", err
	}
	want := ""
	for _, line := range strings.Split(string(sums), "\n") {
		if f := strings.Fields(line); len(f) == 2 && f[1] == asset {
			want = f[0]
		}
	}
	if want == "" {
		return "", fmt.Errorf("%s not listed in the release checksums", asset)
	}

	archive, err := httpGetBytes(base + asset)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(archive)
	if got := hex.EncodeToString(sum[:]); got != want {
		return "", fmt.Errorf("checksum mismatch for %s (got %s, want %s)", asset, got, want)
	}

	dest := k9sInstallPath()
	bin, err := extractFile(archive, ext, filepath.Base(dest))
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return "", err
	}
	tmp := dest + ".tmp"
	if err := os.WriteFile(tmp, bin, 0o755); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, dest); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	return dest, nil
}

// extractFile returns the file called name from a .zip or .tar.gz archive.
func extractFile(archive []byte, ext, name string) ([]byte, error) {
	if ext == ".zip" {
		zr, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
		if err != nil {
			return nil, err
		}
		for _, f := range zr.File {
			if filepath.Base(f.Name) == name {
				rc, err := f.Open()
				if err != nil {
					return nil, err
				}
				defer rc.Close()
				return io.ReadAll(rc)
			}
		}
		return nil, fmt.Errorf("%s not found in the download", name)
	}
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("%s not found in the download", name)
		}
		if err != nil {
			return nil, err
		}
		if hdr.Typeflag == tar.TypeReg && filepath.Base(hdr.Name) == name {
			return io.ReadAll(tr)
		}
	}
}

func (w *workstation) openK9s() {
	p := w.current
	if p.demo {
		w.clusterNote.SetText("  [black:yellow:b] DEMO [-:-:-] [gray] k9s needs a real cluster; pair one to use it.[-]")
		return
	}
	if !p.HasKube {
		w.showKubectl() // explains why there is no kubeconfig
		return
	}
	kubeconfig := p.kubeconfigPath()
	if tunnelFor(p) != nil {
		if _, err := os.Stat(p.kubeconfigVPNPath()); err == nil {
			kubeconfig = p.kubeconfigVPNPath()
		}
	}

	if bin := findK9s(); bin != "" {
		w.runK9s(bin, kubeconfig)
		return
	}
	showConfirm("K9S",
		fmt.Sprintf("k9s isn't installed on this computer.\n\nDownload k9s %s from GitHub (checksum-verified) into %s?",
			k9sVersion, shortPath(filepath.Dir(k9sInstallPath()))),
		"Download", "Cancel", func(ok bool) {
			if !ok {
				return
			}
			w.clusterNote.SetText("  [aqua]Downloading k9s " + k9sVersion + "…[-]")
			go func() {
				bin, err := installK9s()
				w.app.QueueUpdateDraw(func() {
					if err != nil {
						w.clusterNote.SetText("  [red]k9s download failed: " + tview.Escape(err.Error()) + "[-]")
						return
					}
					w.clusterNote.SetText("  [green]Installed k9s " + k9sVersion + " → " + tview.Escape(shortPath(bin)) + "[-]")
					w.runK9s(bin, kubeconfig)
				})
			}()
		})
}

// runK9s gives k9s the whole terminal until it exits. The VPN tunnel (if
// any) keeps running meanwhile, so kubeconfig-vpn works.
func (w *workstation) runK9s(bin, kubeconfig string) {
	var runErr error
	w.app.Suspend(func() {
		cmd := exec.Command(bin)
		cmd.Env = append(os.Environ(), "KUBECONFIG="+kubeconfig)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		runErr = cmd.Run()
	})
	if runErr != nil {
		w.clusterNote.SetText("  [red]k9s: " + tview.Escape(runErr.Error()) + "[-]")
		return
	}
	p := w.current
	p.LastUsed = time.Now()
	_ = p.save()
}
