//go:build windows

// Command fido2-tool manages FIDO2 security keys (PIN and stored passkeys) on
// Windows through libfido2.
package main

import (
	"os"

	"github.com/marcelocapozzi/fido2-tool/internal/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:]))
}
