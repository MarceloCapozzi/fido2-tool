//go:build windows

package cli

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/marcelocapozzi/fido2-tool/internal/fido"
)

func TestDescribe(t *testing.T) {
	tests := []struct {
		err  error
		want string
	}{
		{fido.ErrPinInvalid, "wrong PIN"},
		{fmt.Errorf("wrapped: %w", fido.ErrPinBlocked), "PIN is blocked"},
		{fido.ErrPinAuthBlocked, "Unplug the key"},
		{fido.ErrInvalidSubcommand, "does not support"},
		{fido.Error(0x7f), "returned an error"},
		{errors.New("plain error"), "plain error"},
	}
	for _, tt := range tests {
		if got := describe(tt.err); !strings.Contains(got, tt.want) {
			t.Errorf("describe(%v) = %q, want it to contain %q", tt.err, got, tt.want)
		}
	}
}

func TestFormatAAGUID(t *testing.T) {
	b := []byte{0xcb, 0x69, 0x48, 0x1e, 0x8f, 0xf7, 0x40, 0x39, 0x93, 0xec, 0x0a, 0x27, 0x29, 0xa1, 0x54, 0xa8}
	if got, want := formatAAGUID(b), "cb69481e-8ff7-4039-93ec-0a2729a154a8"; got != want {
		t.Errorf("formatAAGUID = %s, want %s", got, want)
	}
	if got := formatAAGUID([]byte{1, 2}); got != "0102" {
		t.Errorf("formatAAGUID(short) = %s, want raw hex", got)
	}
}

func TestFormatFirmware(t *testing.T) {
	for in, want := range map[uint64]string{0: "not reported", 0x050704: "5.7.4", 0x1_0000_0000: "0x100000000"} {
		if got := formatFirmware(in); got != want {
			t.Errorf("formatFirmware(%#x) = %q, want %q", in, got, want)
		}
	}
}

func TestShortID(t *testing.T) {
	if got := shortID([]byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04}); got != "deadbeef0102" {
		t.Errorf("shortID = %s", got)
	}
	if got := shortID([]byte{0xab}); got != "ab" {
		t.Errorf("shortID(short) = %s", got)
	}
}

func TestAlgName(t *testing.T) {
	if algName(-7) != "ES256" || algName(-8) != "EdDSA" || algName(-999) != "COSE -999" {
		t.Error("algName mismatch")
	}
}

func TestRenameSupport(t *testing.T) {
	tests := []struct {
		name string
		info fido.Info
		ok   bool
	}{
		{"CTAP 2.1", fido.Info{Versions: []string{"FIDO_2_0", "FIDO_2_1_PRE", "FIDO_2_1"}, Options: []fido.Option{{Name: "credMgmt", Value: true}}}, true},
		{"CTAP 2.1-PRE only", fido.Info{Versions: []string{"FIDO_2_0", "FIDO_2_1_PRE"}, Options: []fido.Option{{Name: "credentialMgmtPreview", Value: true}}}, false},
		{"no credential management", fido.Info{Versions: []string{"FIDO_2_1"}}, false},
	}
	for _, tt := range tests {
		ok, why := renameSupport(&tt.info)
		if ok != tt.ok {
			t.Errorf("%s: renameSupport = %v (%s), want %v", tt.name, ok, why, tt.ok)
		}
		if !ok && why == "" {
			t.Errorf("%s: missing reason", tt.name)
		}
	}
}

func TestValidateUserField(t *testing.T) {
	if err := validateUserField("display name", strings.Repeat("a", 64)); err != nil {
		t.Errorf("64 bytes must be accepted: %v", err)
	}
	if err := validateUserField("display name", strings.Repeat("a", 65)); err == nil {
		t.Error("65 bytes must be rejected")
	}
	// 33 two-byte runes are 66 bytes: the limit is in bytes, not characters.
	if err := validateUserField("display name", strings.Repeat("ñ", 33)); err == nil {
		t.Error("the limit must be measured in bytes")
	}
	if err := validateUserField("display name", "\xff"); err == nil {
		t.Error("invalid UTF-8 must be rejected")
	}
}

func TestValidatePIN(t *testing.T) {
	tests := []struct {
		pin    string
		minLen int
		ok     bool
	}{
		{"1234", 4, true},
		{"123", 4, false},
		{"12345", 6, false},
		{"ññññ", 4, true}, // length is counted in code points
		{strings.Repeat("1", 63), 4, true},
		{strings.Repeat("1", 64), 4, false},
		{"\xff\xfe\xfd\xfc", 4, false},
	}
	for _, tt := range tests {
		if err := validatePIN(tt.pin, tt.minLen); (err == nil) != tt.ok {
			t.Errorf("validatePIN(%q, %d) = %v, want ok=%v", tt.pin, tt.minLen, err, tt.ok)
		}
	}
}

func TestEffectiveMinPINLen(t *testing.T) {
	if effectiveMinPINLen(0) != 4 || effectiveMinPINLen(2) != 4 || effectiveMinPINLen(8) != 8 {
		t.Error("effectiveMinPINLen must be max(4, key minimum)")
	}
}
