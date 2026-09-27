//go:build windows

package cli

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/marcelocapozzi/fido2-tool/internal/console"
	"github.com/marcelocapozzi/fido2-tool/internal/fido"
)

var (
	errCancelled = errors.New("operation cancelled")
	errNoKeys    = errors.New("no security key found. Plug the key into a USB port and try again")
)

// session carries state across the commands run from one invocation or from
// the interactive menu.
type session struct {
	opts        options
	interactive bool
	pin         string // cached after the first successful use
	pinPath     string // device the cached PIN belongs to
}

func (s *session) forgetPIN() { s.pin, s.pinPath = "", "" }

// securityKeys lists the attached keys, leaving out the Windows Hello
// pseudo-device, which cannot be managed.
func securityKeys() ([]fido.DevInfo, error) {
	all, err := fido.Manifest()
	if err != nil {
		return nil, err
	}
	var keys []fido.DevInfo
	for _, d := range all {
		if !d.IsWinHello() {
			keys = append(keys, d)
		}
	}
	return keys, nil
}

func devLabel(d fido.DevInfo) string {
	if name := strings.TrimSpace(d.Manufacturer + " " + d.Product); name != "" {
		return name
	}
	return "FIDO security key"
}

// selectKey resolves a --device reference: a 1-based number from 'list' or
// a device path.
func selectKey(keys []fido.DevInfo, ref string) (fido.DevInfo, error) {
	if n, err := strconv.Atoi(ref); err == nil && n >= 1 && n <= len(keys) {
		return keys[n-1], nil
	}
	for _, k := range keys {
		if k.Path == ref {
			return k, nil
		}
	}
	return fido.DevInfo{}, fmt.Errorf("there is no key %q (see 'fido2-tool list')", ref)
}

// openDevice opens the key to work with: the one given by --device, the only
// one attached, or (interactively) the one the user chooses.
func (s *session) openDevice() (*fido.Device, fido.DevInfo, error) {
	keys, err := securityKeys()
	if err != nil {
		return nil, fido.DevInfo{}, err
	}
	if len(keys) == 0 {
		return nil, fido.DevInfo{}, errNoKeys
	}

	var chosen fido.DevInfo
	switch {
	case s.opts.device != "":
		if chosen, err = selectKey(keys, s.opts.device); err != nil {
			return nil, fido.DevInfo{}, err
		}
	case len(keys) == 1:
		chosen = keys[0]
	case s.interactive:
		printKeys(keys)
		n, err := promptIndex("Number of the key to use: ", len(keys))
		if err != nil {
			return nil, fido.DevInfo{}, err
		}
		chosen = keys[n]
	default:
		return nil, fido.DevInfo{}, fmt.Errorf("%d keys are connected; choose one with --device <number> (see 'fido2-tool list')", len(keys))
	}

	dev, err := fido.Open(chosen.Path)
	if err != nil {
		return nil, fido.DevInfo{}, fmt.Errorf("cannot open the key: %s", describe(err))
	}
	if chosen.Path != s.pinPath {
		s.forgetPIN()
	}
	return dev, chosen, nil
}

// promptIndex asks for a number from 1 to max and returns it 0-based.
func promptIndex(msg string, max int) (int, error) {
	for {
		s, err := console.Prompt(msg)
		if err != nil || s == "" {
			return 0, errCancelled
		}
		if n, err := strconv.Atoi(s); err == nil && n >= 1 && n <= max {
			return n - 1, nil
		}
		fmt.Printf("Enter a number from 1 to %d, or press Enter to cancel.\n", max)
	}
}

// withPIN runs fn with the key's PIN, asking for it when it is not cached
// and letting the user retry a mistyped PIN.
func (s *session) withPIN(dev *fido.Device, fn func(pin string) error) error {
	if !dev.HasPIN() {
		return errors.New("the key has no PIN. Set a PIN first to manage passkeys ('fido2-tool pin')")
	}
	// Most keys require re-plugging after 3 consecutive wrong PINs.
	const maxAttempts = 3
	for attempt := 1; ; attempt++ {
		pin := s.pin
		if pin == "" {
			var err error
			if pin, err = console.PromptHidden("Key PIN: "); err != nil {
				return err
			}
			if pin == "" {
				return errCancelled
			}
		}
		err := fn(pin)
		if !errors.Is(err, fido.ErrPinInvalid) {
			if err == nil {
				s.pin, s.pinPath = pin, dev.Path
			}
			return err
		}
		s.forgetPIN()
		msg := "wrong PIN."
		if n, rerr := dev.PINRetries(); rerr == nil {
			msg += fmt.Sprintf(" Attempts left before the PIN blocks: %d.", n)
		}
		if !s.interactive || attempt >= maxAttempts {
			return errors.New(msg)
		}
		fmt.Println(capitalize(msg))
	}
}

// loadCreds reads every passkey on the key, asking for the PIN as needed.
func (s *session) loadCreds(dev *fido.Device) ([]fido.Credential, fido.Metadata, error) {
	var creds []fido.Credential
	var meta fido.Metadata
	err := s.withPIN(dev, func(pin string) error {
		var err error
		if meta, err = dev.CredMetadata(pin); err != nil {
			return err
		}
		creds, err = dev.AllCredentials(pin)
		return err
	})
	return creds, meta, err
}

// matchCred finds the passkey a --cred reference points to: a hex prefix of
// the credential ID (as shown by 'creds') or the full ID in base64url.
func matchCred(creds []fido.Credential, ref string) (fido.Credential, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return fido.Credential{}, errors.New("empty passkey ID")
	}
	full, _ := base64.RawURLEncoding.DecodeString(strings.TrimRight(ref, "="))
	var matches []fido.Credential
	for _, c := range creds {
		if strings.HasPrefix(hex.EncodeToString(c.ID), strings.ToLower(ref)) ||
			(len(full) > 0 && bytes.Equal(full, c.ID)) {
			matches = append(matches, c)
		}
	}
	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		return fido.Credential{}, fmt.Errorf("there is no passkey with ID %q (see 'fido2-tool creds')", ref)
	}
	return fido.Credential{}, fmt.Errorf("ID %q matches several passkeys; use more characters", ref)
}

// pickCred selects a passkey by --cred or, interactively, by its number in
// the listing.
func (s *session) pickCred(creds []fido.Credential, action string) (fido.Credential, error) {
	if len(creds) == 0 {
		return fido.Credential{}, errors.New("there are no passkeys stored on the key")
	}
	if s.opts.cred != "" {
		return matchCred(creds, s.opts.cred)
	}
	if !s.interactive {
		return fido.Credential{}, errors.New("choose the passkey with --cred <ID> (see 'fido2-tool creds')")
	}
	printCreds(creds)
	fmt.Println()
	n, err := promptIndex(fmt.Sprintf("Number of the passkey to %s (Enter to cancel): ", action), len(creds))
	if err != nil {
		return fido.Credential{}, err
	}
	return creds[n], nil
}
