//go:build !linux

package main

// Stubs so KubesTUI still builds on Windows/macOS (e.g. to preview the UI
// on a workstation). Operations and SSH sessions need Linux: they report
// this message instead of running.

import (
	"errors"
	"os"
	"syscall"
)

const ptySupported = false

var errNoPTY = errors.New("the built-in terminal needs Linux: run KubesTUI on a cluster node (kbtui)")

func openPTY() (master, slave *os.File, err error) { return nil, nil, errNoPTY }

func ptyProcAttr() *syscall.SysProcAttr { return nil }

func ptySetSize(fd, cols, rows int) {}

func ptyEchoOff(fd int) (off, ok bool) { return false, false }

func hangupSession(pid int) {}
