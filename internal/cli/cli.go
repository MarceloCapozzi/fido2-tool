//go:build windows

// Package cli implements the fido2-tool command line and interactive menu.
package cli

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/marcelocapozzi/fido2-tool/internal/console"
	"github.com/marcelocapozzi/fido2-tool/internal/fido"
)

// Version is set at build time with -ldflags "-X ...cli.Version=x.y.z".
var Version = "dev"

const usage = `fido2-tool %s - manage FIDO2 security keys

Usage: fido2-tool [command] [options]
Without a command, an interactive menu opens.

Commands:
  list      List the connected security keys
  info      Show information about a key
  creds     List the passkeys stored on a key (asks for the PIN)
  rename    Change the user name or display name of a passkey
  delete    Delete a passkey
  pin       Set or change the PIN
  reset     Factory-reset a key (erases everything)
  version   Show the version

Options:
  -d, --device <n>            Key to use (number from 'list') when several are connected
      --cred <id>             Passkey to act on (ID shown by 'creds')
      --name <text>           New user name (rename)
      --display-name <text>   New display name (rename)
  -y, --yes                   Don't ask for confirmation (rename, delete)
  -v, --verbose               Show more details (list, info)
      --debug                 Print the libfido2 protocol trace (troubleshooting)

Examples:
  fido2-tool rename
  fido2-tool rename --cred 3f9a1c --display-name "Jane Doe (work)"
`

type options struct {
	device      string
	cred        string
	name        *string // nil when not given, so "" can clear the field
	displayName *string
	yes         bool
	verbose     bool
	debug       bool
}

func parseArgs(args []string) (cmd string, opts options, err error) {
	var positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "/?" {
			a = "-h"
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			positional = append(positional, a)
			continue
		}
		name, value, hasValue := strings.Cut(a, "=")
		takeValue := func() (string, error) {
			if hasValue {
				return value, nil
			}
			if i+1 >= len(args) {
				return "", fmt.Errorf("missing value for %s", name)
			}
			i++
			return args[i], nil
		}
		var v string
		switch name {
		case "-d", "--device":
			if v, err = takeValue(); err == nil {
				opts.device = v
			}
		case "--cred":
			if v, err = takeValue(); err == nil {
				opts.cred = v
			}
		case "--name":
			if v, err = takeValue(); err == nil {
				opts.name = &v
			}
		case "--display-name":
			if v, err = takeValue(); err == nil {
				opts.displayName = &v
			}
		case "-y", "--yes":
			opts.yes = true
		case "-v", "--verbose":
			opts.verbose = true
		case "--debug":
			opts.debug = true
		case "-h", "--help":
			positional = append(positional, "help")
		default:
			err = fmt.Errorf("unknown option: %s", a)
		}
		if err != nil {
			return "", opts, err
		}
	}
	switch len(positional) {
	case 0:
		return "", opts, nil
	case 1:
		return positional[0], opts, nil
	}
	return "", opts, fmt.Errorf("unexpected arguments: %s", strings.Join(positional[1:], " "))
}

var commands = map[string]func(*session) error{
	"list":   cmdList,
	"info":   cmdInfo,
	"creds":  cmdCreds,
	"rename": cmdRename,
	"delete": cmdDelete,
	"pin":    cmdPIN,
	"reset":  cmdReset,
}

// Main runs the tool with the given arguments and returns the exit code.
func Main(args []string) int {
	// Keep the window open when it would otherwise close with the process
	// (double-click from Explorer, elevated relaunch).
	pause := console.OwnsConsole()
	console.HandleInterrupt()
	code, keepPause := run(args)
	if pause && keepPause {
		fmt.Print("\nPress Enter to close...")
		console.ReadLine()
	}
	return code
}

// run returns the exit code and whether a console window owned by this
// process should wait before closing.
func run(args []string) (int, bool) {
	cmd, opts, err := parseArgs(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\nRun 'fido2-tool help' for usage.\n", err)
		return 2, true
	}
	switch cmd {
	case "help":
		fmt.Printf(usage, Version)
		return 0, true
	case "version":
		fmt.Println("fido2-tool", Version)
		return 0, true
	}
	fn, known := commands[cmd]
	if cmd != "" && !known {
		fmt.Fprintf(os.Stderr, "Unknown command: %s\nRun 'fido2-tool help' for usage.\n", cmd)
		return 2, true
	}

	// Since Windows 10 1903 only elevated processes may talk to FIDO keys
	// directly; otherwise Windows routes everything through Windows Hello.
	if !console.IsAdmin() {
		fmt.Println("fido2-tool needs administrator rights to access the security key.")
		if err := console.RelaunchElevated(args); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return 1, true
		}
		fmt.Println("A new window with administrator rights was opened.")
		return 0, false
	}

	flags := 0
	if opts.debug {
		flags |= fido.FlagDebug
	}
	if err := fido.Load(flags); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1, true
	}

	s := &session{opts: opts, interactive: true}
	if cmd == "" {
		menu(s)
		return 0, false
	}
	if err := fn(s); err != nil {
		printError(err)
		return 1, true
	}
	return 0, true
}

func printError(err error) {
	if errors.Is(err, errCancelled) {
		fmt.Println("Operation cancelled.")
		return
	}
	fmt.Fprintf(os.Stderr, "Error: %s\n", capitalize(describe(err)))
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	r := []rune(s)
	r[0] = []rune(strings.ToUpper(string(r[0])))[0]
	return string(r)
}

type menuItem struct {
	label string
	fn    func(*session) error
}

var menuItems = []menuItem{
	{"List connected keys", cmdList},
	{"Show key information", cmdInfo},
	{"List stored passkeys", cmdCreds},
	{"Change the user name or display name of a passkey", cmdRename},
	{"Delete a passkey", cmdDelete},
	{"Set or change the PIN", cmdPIN},
	{"Factory-reset the key (erases everything)", cmdReset},
}

func menu(s *session) {
	fmt.Printf("fido2-tool %s - manage FIDO2 security keys\n", Version)
	for {
		fmt.Println()
		for i, it := range menuItems {
			fmt.Printf("  %d) %s\n", i+1, it.label)
		}
		fmt.Println("  0) Exit")
		choice, err := console.Prompt("\nOption: ")
		if err != nil || choice == "0" || strings.EqualFold(choice, "q") {
			return
		}
		n, err := strconv.Atoi(choice)
		if err != nil || n < 1 || n > len(menuItems) {
			fmt.Println("Invalid option.")
			continue
		}
		fmt.Println()
		if err := menuItems[n-1].fn(s); err != nil {
			printError(err)
		}
	}
}
