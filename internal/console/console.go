//go:build windows

// Package console provides the Windows console interactions the CLI needs:
// line input, hidden PIN input, and UAC elevation.
package console

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

var (
	kernel32               = syscall.NewLazyDLL("kernel32.dll")
	pSetConsoleMode        = kernel32.NewProc("SetConsoleMode")
	pGetConsoleProcessList = kernel32.NewProc("GetConsoleProcessList")
	shell32                = syscall.NewLazyDLL("shell32.dll")
	pIsUserAnAdmin         = shell32.NewProc("IsUserAnAdmin")
	pShellExecuteW         = shell32.NewProc("ShellExecuteW")
)

const enableEchoInput = 0x0004

var (
	stdin        = bufio.NewReader(os.Stdin)
	modeMu       sync.Mutex
	savedMode    uint32
	echoDisabled bool
)

// ReadLine reads one line from stdin without the line terminator.
func ReadLine() (string, error) {
	s, err := stdin.ReadString('\n')
	if err != nil && !(errors.Is(err, io.EOF) && s != "") {
		return "", err
	}
	return strings.TrimRight(s, "\r\n"), nil
}

// Prompt prints msg and returns the trimmed line the user types.
func Prompt(msg string) (string, error) {
	fmt.Print(msg)
	s, err := ReadLine()
	return strings.TrimSpace(s), err
}

// PromptHidden prints msg and reads a line without echoing it, for PINs. When
// stdin is not a console (redirected input) the line is read as is.
func PromptHidden(msg string) (string, error) {
	fmt.Print(msg)
	h := syscall.Handle(os.Stdin.Fd())
	var mode uint32
	if err := syscall.GetConsoleMode(h, &mode); err != nil {
		return ReadLine()
	}
	modeMu.Lock()
	savedMode, echoDisabled = mode, true
	pSetConsoleMode.Call(uintptr(h), uintptr(mode&^enableEchoInput))
	modeMu.Unlock()

	s, err := ReadLine()
	restoreEcho()
	fmt.Println()
	return s, err
}

func restoreEcho() {
	modeMu.Lock()
	defer modeMu.Unlock()
	if echoDisabled {
		pSetConsoleMode.Call(os.Stdin.Fd(), uintptr(savedMode))
		echoDisabled = false
	}
}

// Confirm asks a yes/no question; anything other than yes means no.
func Confirm(msg string) bool {
	s, err := Prompt(msg + " [y/N]: ")
	return err == nil && IsYes(s)
}

// IsYes reports whether s is an affirmative answer.
func IsYes(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "y", "yes":
		return true
	}
	return false
}

// HandleInterrupt makes Ctrl+C restore the console echo before exiting. The
// console mode belongs to the console, not the process, so leaving echo off
// would break the user's shell.
func HandleInterrupt() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		<-c
		restoreEcho()
		fmt.Println("\nCancelled.")
		os.Exit(130)
	}()
}

// IsAdmin reports whether the process runs elevated.
func IsAdmin() bool {
	r, _, _ := pIsUserAnAdmin.Call()
	return r != 0
}

// OwnsConsole reports whether this process is the only one attached to its
// console, i.e. it was started from Explorer or by the elevation relaunch and
// its window closes as soon as it exits.
func OwnsConsole() bool {
	var pids [2]uint32
	n, _, _ := pGetConsoleProcessList.Call(uintptr(unsafe.Pointer(&pids[0])), uintptr(len(pids)))
	return n == 1
}

// QuoteArgs joins args into a Windows command line.
func QuoteArgs(args []string) string {
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = syscall.EscapeArg(a)
	}
	return strings.Join(quoted, " ")
}

// RelaunchElevated starts this executable again with the same arguments
// through the UAC prompt. The elevated copy gets its own console window.
func RelaunchElevated(args []string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cwd, _ := os.Getwd()
	verb, _ := syscall.UTF16PtrFromString("runas")
	file, _ := syscall.UTF16PtrFromString(exe)
	params, _ := syscall.UTF16PtrFromString(QuoteArgs(args))
	dir, _ := syscall.UTF16PtrFromString(cwd)
	const swShowNormal = 1
	r, _, _ := pShellExecuteW.Call(0,
		uintptr(unsafe.Pointer(verb)), uintptr(unsafe.Pointer(file)),
		uintptr(unsafe.Pointer(params)), uintptr(unsafe.Pointer(dir)), swShowNormal)
	if r <= 32 {
		return fmt.Errorf("administrator rights were not granted (code %d)", r)
	}
	return nil
}
