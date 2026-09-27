//go:build windows

package cli

import (
	"encoding/hex"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/marcelocapozzi/fido2-tool/internal/fido"
)

const (
	// CTAP 2.1 lets authenticators truncate user names and display names to
	// 64 bytes, so longer values are rejected instead of being silently cut.
	maxUserFieldLen = 64
	// CTAP requires at least 4 code points and at most 63 bytes of UTF-8.
	minPINLen = 4
	maxPINLen = 63
)

// describe turns an error into a message an end user can act on.
func describe(err error) string {
	var fe fido.Error
	if !errors.As(err, &fe) {
		return err.Error()
	}
	switch fe {
	case fido.ErrPinInvalid:
		return "wrong PIN."
	case fido.ErrPinBlocked:
		return "the PIN is blocked after too many wrong attempts. The only way to use the key again is to reset it, which erases all its passkeys."
	case fido.ErrPinAuthBlocked:
		return "too many wrong attempts in a row. Unplug the key, plug it back in and try again."
	case fido.ErrPinNotSet:
		return "the key has no PIN set."
	case fido.ErrPinRequired:
		return "this operation requires the key's PIN."
	case fido.ErrPinPolicy:
		return "the PIN does not meet the key's policy (minimum length, or the key requires a PIN change)."
	case fido.ErrTimeout, fido.ErrActionTimeout, fido.ErrUserActionTimeout:
		return "timed out. If the key is blinking, touch it to confirm."
	case fido.ErrNotAllowed, fido.ErrOperationDenied:
		return "the key refused the operation."
	case fido.ErrKeepaliveCancel:
		return "the operation was cancelled."
	case fido.ErrInvalidCommand, fido.ErrInvalidSubcommand:
		return "the key does not support this operation."
	case fido.ErrNoCredentials:
		return "there are no passkeys stored on the key."
	case fido.ErrUnauthorizedPerm:
		return "the PIN does not grant permission for this operation."
	case fido.ErrTx, fido.ErrRx:
		return "communication with the key failed. Make sure it is still connected."
	}
	return fmt.Sprintf("the key returned an error: %v", fe)
}

var algNames = map[int]string{-7: "ES256", -8: "EdDSA", -35: "ES384", -257: "RS256"}

func algName(a int) string {
	if n, ok := algNames[a]; ok {
		return n
	}
	return fmt.Sprintf("COSE %d", a)
}

func formatAAGUID(b []byte) string {
	if len(b) != 16 {
		return hex.EncodeToString(b)
	}
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// formatFirmware renders the firmwareVersion field. Its encoding is vendor
// specific; YubiKeys encode major.minor.patch as 0xMMmmpp.
func formatFirmware(v uint64) string {
	if v == 0 {
		return "not reported"
	}
	if v <= 0xffffff {
		return fmt.Sprintf("%d.%d.%d", v>>16&0xff, v>>8&0xff, v&0xff)
	}
	return fmt.Sprintf("0x%x", v)
}

// shortID is the credential reference shown to users and accepted by --cred.
func shortID(id []byte) string {
	if len(id) > 6 {
		id = id[:6]
	}
	return hex.EncodeToString(id)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// renameSupport reports whether the key can update a passkey's user
// information, which only exists in final CTAP 2.1 (not 2.1-PRE).
func renameSupport(info *fido.Info) (bool, string) {
	credMgmt, _ := info.Option("credMgmt")
	preview, _ := info.Option("credentialMgmtPreview")
	if !credMgmt && !preview {
		return false, "the key does not support credential management"
	}
	if !info.HasVersion("FIDO_2_1") {
		return false, "the key implements a CTAP version older than 2.1 (YubiKey 5 needs firmware 5.7 or later; YubiKey firmware cannot be upgraded)"
	}
	return true, ""
}

func validateUserField(label, v string) error {
	if !utf8.ValidString(v) {
		return fmt.Errorf("the %s contains invalid characters", label)
	}
	if len(v) > maxUserFieldLen {
		return fmt.Errorf("the %s is too long (%d bytes; maximum %d)", label, len(v), maxUserFieldLen)
	}
	return nil
}

// effectiveMinPINLen combines the CTAP minimum with the key's own policy.
func effectiveMinPINLen(keyMin uint64) int {
	if keyMin > minPINLen {
		return int(keyMin)
	}
	return minPINLen
}

func validatePIN(pin string, minLen int) error {
	if !utf8.ValidString(pin) {
		return errors.New("the PIN contains invalid characters")
	}
	if n := utf8.RuneCountInString(pin); n < minLen {
		return fmt.Errorf("the PIN must have at least %d characters", minLen)
	}
	if len(pin) > maxPINLen {
		return fmt.Errorf("the PIN is too long (maximum %d bytes)", maxPINLen)
	}
	return nil
}
