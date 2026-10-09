//go:build linux

package main

// Linux pseudo-terminal support for the operation runner and the embedded
// terminal. Other platforms get the stubs in pty_other.go.

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

const ptySupported = true

func openPTY() (master, slave *os.File, err error) {
	master, err = os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	fd := int(master.Fd())
	if err = unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
		master.Close()
		return nil, nil, fmt.Errorf("unlockpt: %w", err)
	}
	n, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
	if err != nil {
		master.Close()
		return nil, nil, fmt.Errorf("ptsname: %w", err)
	}
	slave, err = os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		master.Close()
		return nil, nil, err
	}
	return master, slave, nil
}

// ptyProcAttr starts the child in a new session with the pty as its
// controlling terminal, so Ctrl+C and prompts reading /dev/tty reach it.
func ptyProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
}

func ptySetSize(fd, cols, rows int) {
	_ = unix.IoctlSetWinsize(fd, unix.TIOCSWINSZ, &unix.Winsize{Row: uint16(rows), Col: uint16(cols)})
}

// ptyEchoOff reports whether the program has turned terminal echo off
// (a password prompt). ok is false if the state can't be read.
func ptyEchoOff(fd int) (off, ok bool) {
	t, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return false, false
	}
	return t.Lflag&unix.ECHO == 0, true
}

// hangupSession sends SIGHUP to the whole session led by pid.
func hangupSession(pid int) {
	_ = syscall.Kill(-pid, syscall.SIGHUP)
}

// killSession kills the whole session led by pid.
func killSession(pid int) {
	_ = syscall.Kill(-pid, syscall.SIGKILL)
}
