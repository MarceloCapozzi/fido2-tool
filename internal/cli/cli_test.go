//go:build windows

package cli

import (
	"strings"
	"testing"
)

func strp(s string) *string { return &s }

func TestParseArgs(t *testing.T) {
	tests := []struct {
		args []string
		cmd  string
		want options
	}{
		{nil, "", options{}},
		{[]string{"list", "-v"}, "list", options{verbose: true}},
		{[]string{"info", "-d", "2", "--debug"}, "info", options{device: "2", debug: true}},
		{[]string{"--device=\\\\?\\hid#x", "info"}, "info", options{device: `\\?\hid#x`}},
		{
			[]string{"rename", "--cred", "3f9a1c", "--display-name", "Jane = Doe", "--name=", "-y"},
			"rename",
			options{cred: "3f9a1c", displayName: strp("Jane = Doe"), name: strp(""), yes: true},
		},
		{[]string{"-h"}, "help", options{}},
		{[]string{"/?"}, "help", options{}},
		{[]string{"--help"}, "help", options{}},
	}
	for _, tt := range tests {
		cmd, opts, err := parseArgs(tt.args)
		if err != nil {
			t.Errorf("parseArgs(%q): %v", tt.args, err)
			continue
		}
		if cmd != tt.cmd {
			t.Errorf("parseArgs(%q) cmd = %q, want %q", tt.args, cmd, tt.cmd)
		}
		if !optionsEqual(opts, tt.want) {
			t.Errorf("parseArgs(%q) opts = %+v, want %+v", tt.args, opts, tt.want)
		}
	}
}

func optionsEqual(a, b options) bool {
	ptrEq := func(x, y *string) bool {
		if x == nil || y == nil {
			return x == y
		}
		return *x == *y
	}
	return a.device == b.device && a.cred == b.cred && a.yes == b.yes &&
		a.verbose == b.verbose && a.debug == b.debug &&
		ptrEq(a.name, b.name) && ptrEq(a.displayName, b.displayName)
}

func TestParseArgsErrors(t *testing.T) {
	tests := []struct {
		args []string
		want string
	}{
		{[]string{"--bogus"}, "unknown option"},
		{[]string{"rename", "--cred"}, "missing value"},
		{[]string{"rename", "extra"}, "unexpected arguments"},
	}
	for _, tt := range tests {
		_, _, err := parseArgs(tt.args)
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("parseArgs(%q) error = %v, want it to contain %q", tt.args, err, tt.want)
		}
	}
}

func TestCapitalize(t *testing.T) {
	for in, want := range map[string]string{"": "", "wrong PIN.": "Wrong PIN.", "élan": "Élan"} {
		if got := capitalize(in); got != want {
			t.Errorf("capitalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEveryMenuItemIsACommand(t *testing.T) {
	if len(menuItems) != len(commands) {
		t.Errorf("menu has %d items but there are %d commands", len(menuItems), len(commands))
	}
}
