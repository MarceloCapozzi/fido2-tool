//go:build windows

package cli

import (
	"encoding/base64"
	"testing"

	"github.com/marcelocapozzi/fido2-tool/internal/fido"
)

var testCreds = []fido.Credential{
	{RPID: "example.com", ID: []byte{0x3f, 0x9a, 0x1c, 0x00, 0x11, 0x22, 0x33}, UserName: "jane", DisplayName: "Jane"},
	{RPID: "example.org", ID: []byte{0x3f, 0x9a, 0x2d, 0x44, 0x55, 0x66, 0x77}, UserName: "john", DisplayName: "John"},
}

func TestMatchCred(t *testing.T) {
	tests := []struct {
		ref    string
		wantRP string // "" means an error is expected
	}{
		{"3f9a1c", "example.com"},
		{"3F9A2D", "example.org"}, // case-insensitive
		{" 3f9a1c ", "example.com"},
		{base64.RawURLEncoding.EncodeToString(testCreds[1].ID), "example.org"},
		{"3f9a", ""}, // ambiguous
		{"ffff", ""}, // no match
		{"", ""},
	}
	for _, tt := range tests {
		c, err := matchCred(testCreds, tt.ref)
		switch {
		case tt.wantRP == "" && err == nil:
			t.Errorf("matchCred(%q) = %s, want an error", tt.ref, c.RPID)
		case tt.wantRP != "" && err != nil:
			t.Errorf("matchCred(%q): %v", tt.ref, err)
		case tt.wantRP != "" && c.RPID != tt.wantRP:
			t.Errorf("matchCred(%q) = %s, want %s", tt.ref, c.RPID, tt.wantRP)
		}
	}
}

func TestSelectKey(t *testing.T) {
	keys := []fido.DevInfo{{Path: `\\?\hid#a`}, {Path: `\\?\hid#b`}}
	if k, err := selectKey(keys, "2"); err != nil || k.Path != `\\?\hid#b` {
		t.Errorf("selectKey(2) = %v, %v", k, err)
	}
	if k, err := selectKey(keys, `\\?\hid#a`); err != nil || k.Path != `\\?\hid#a` {
		t.Errorf("selectKey(path) = %v, %v", k, err)
	}
	for _, ref := range []string{"0", "3", "nope"} {
		if _, err := selectKey(keys, ref); err == nil {
			t.Errorf("selectKey(%q) should fail", ref)
		}
	}
}

func TestFlagEditsKeepsUnchangedFields(t *testing.T) {
	c := testCreds[0]
	name, display := flagEdits(c, nil, strp("Jane Doe"))
	if name != "jane" || display != "Jane Doe" {
		t.Errorf("only --display-name: got %q, %q", name, display)
	}
	name, display = flagEdits(c, strp("jane.doe"), nil)
	if name != "jane.doe" || display != "Jane" {
		t.Errorf("only --name: got %q, %q", name, display)
	}
	name, display = flagEdits(c, strp(""), strp(""))
	if name != "" || display != "" {
		t.Errorf("empty values must clear the fields: got %q, %q", name, display)
	}
}

func TestDevLabel(t *testing.T) {
	if got := devLabel(fido.DevInfo{Manufacturer: "Yubico", Product: "YubiKey OTP+FIDO+CCID"}); got != "Yubico YubiKey OTP+FIDO+CCID" {
		t.Errorf("devLabel = %q", got)
	}
	if got := devLabel(fido.DevInfo{}); got != "FIDO security key" {
		t.Errorf("devLabel(empty) = %q", got)
	}
}
