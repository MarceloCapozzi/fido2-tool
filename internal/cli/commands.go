//go:build windows

package cli

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/marcelocapozzi/fido2-tool/internal/console"
	"github.com/marcelocapozzi/fido2-tool/internal/fido"
)

func newTable() *tabwriter.Writer { return tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0) }

func printKeys(keys []fido.DevInfo) {
	w := newTable()
	fmt.Fprintln(w, " #\tKey\tVID:PID")
	for i, k := range keys {
		fmt.Fprintf(w, " %d\t%s\t%04x:%04x\n", i+1, devLabel(k), k.VendorID, k.ProductID)
	}
	w.Flush()
}

func printCreds(creds []fido.Credential) {
	w := newTable()
	fmt.Fprintln(w, " #\tSite\tUser name\tDisplay name\tID")
	for i, c := range creds {
		fmt.Fprintf(w, " %d\t%s\t%s\t%s\t%s\n", i+1, c.RPID, orDash(c.UserName), orDash(c.DisplayName), shortID(c.ID))
	}
	w.Flush()
}

func checkCredman(dev *fido.Device) error {
	if !dev.IsFIDO2() || !dev.SupportsCredman() {
		return errors.New("this key does not support passkey management")
	}
	return nil
}

func cmdList(s *session) error {
	keys, err := securityKeys()
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return errNoKeys
	}
	printKeys(keys)
	if s.opts.verbose {
		fmt.Println()
		for i, k := range keys {
			fmt.Printf(" %d  %s\n", i+1, k.Path)
		}
	}
	return nil
}

func cmdInfo(s *session) error {
	dev, di, err := s.openDevice()
	if err != nil {
		return err
	}
	defer dev.Close()

	w := newTable()
	defer w.Flush()
	fmt.Fprintf(w, "Key:\t%s (%04x:%04x)\n", devLabel(di), di.VendorID, di.ProductID)
	if !dev.IsFIDO2() {
		fmt.Fprintln(w, "Protocol:\tU2F/CTAP1 only (no passkey support)")
		return nil
	}
	info, err := dev.Info()
	if err != nil {
		return fmt.Errorf("cannot read the key information: %s", describe(err))
	}
	algs := make([]string, len(info.Algorithms))
	for i, a := range info.Algorithms {
		algs[i] = algName(a)
	}
	fmt.Fprintf(w, "AAGUID:\t%s\n", formatAAGUID(info.AAGUID))
	fmt.Fprintf(w, "Firmware:\t%s\n", formatFirmware(info.FirmwareVer))
	fmt.Fprintf(w, "Versions:\t%s\n", strings.Join(info.Versions, ", "))
	fmt.Fprintf(w, "Transports:\t%s\n", strings.Join(info.Transports, ", "))
	fmt.Fprintf(w, "Algorithms:\t%s\n", strings.Join(algs, ", "))
	fmt.Fprintf(w, "Extensions:\t%s\n", strings.Join(info.Extensions, ", "))

	switch {
	case !dev.SupportsPIN():
		fmt.Fprintln(w, "PIN:\tnot supported")
	case !dev.HasPIN():
		fmt.Fprintln(w, "PIN:\tnot set")
	default:
		state := "set"
		if n, err := dev.PINRetries(); err == nil {
			state += fmt.Sprintf(" (%d attempts left)", n)
		}
		if info.NewPINRequired {
			state += ", the key requires a PIN change"
		}
		fmt.Fprintf(w, "PIN:\t%s\n", state)
	}
	if info.MinPINLen > 0 {
		fmt.Fprintf(w, "Minimum PIN length:\t%d\n", info.MinPINLen)
	}
	if info.RKRemaining >= 0 {
		fmt.Fprintf(w, "Passkey slots left:\t%d\n", info.RKRemaining)
	}
	if ok, why := renameSupport(info); ok {
		fmt.Fprintln(w, "Rename passkeys:\tsupported")
	} else {
		fmt.Fprintf(w, "Rename passkeys:\tnot supported: %s\n", why)
	}
	if s.opts.verbose {
		opts := make([]string, len(info.Options))
		for i, o := range info.Options {
			opts[i] = fmt.Sprintf("%s=%t", o.Name, o.Value)
		}
		fmt.Fprintf(w, "Options:\t%s\n", strings.Join(opts, ", "))
		fmt.Fprintf(w, "Path:\t%s\n", di.Path)
	}
	return nil
}

func cmdCreds(s *session) error {
	dev, _, err := s.openDevice()
	if err != nil {
		return err
	}
	defer dev.Close()
	if err := checkCredman(dev); err != nil {
		return err
	}
	creds, meta, err := s.loadCreds(dev)
	if err != nil {
		return err
	}
	fmt.Printf("Stored passkeys: %d (room for %d more)\n\n", meta.Existing, meta.Remaining)
	if len(creds) > 0 {
		printCreds(creds)
	}
	return nil
}

// flagEdits applies --name and --display-name to the passkey's current user
// fields. The authenticator replaces the whole user entity, so fields that are
// not being changed must be sent with their current value.
func flagEdits(c fido.Credential, name, displayName *string) (newName, newDisplay string) {
	newName, newDisplay = c.UserName, c.DisplayName
	if name != nil {
		newName = *name
	}
	if displayName != nil {
		newDisplay = *displayName
	}
	return newName, newDisplay
}

// promptEdits asks for the new user fields; Enter keeps the current value.
func promptEdits(c fido.Credential) (newName, newDisplay string, err error) {
	newName, newDisplay = c.UserName, c.DisplayName
	fmt.Printf("\nPasskey for %s. Type a new value, or press Enter to keep the current one.\n", c.RPID)
	v, err := console.Prompt(fmt.Sprintf("User name [%s]: ", orDash(c.UserName)))
	if err != nil {
		return "", "", err
	}
	if v != "" {
		newName = v
	}
	if v, err = console.Prompt(fmt.Sprintf("Display name [%s]: ", orDash(c.DisplayName))); err != nil {
		return "", "", err
	}
	if v != "" {
		newDisplay = v
	}
	return newName, newDisplay, nil
}

func cmdRename(s *session) error {
	dev, _, err := s.openDevice()
	if err != nil {
		return err
	}
	defer dev.Close()
	if err := checkCredman(dev); err != nil {
		return err
	}
	info, err := dev.Info()
	if err != nil {
		return fmt.Errorf("cannot read the key information: %s", describe(err))
	}
	if ok, why := renameSupport(info); !ok {
		return fmt.Errorf("this key cannot rename passkeys: %s", why)
	}

	creds, _, err := s.loadCreds(dev)
	if err != nil {
		return err
	}
	c, err := s.pickCred(creds, "edit")
	if err != nil {
		return err
	}

	var newName, newDisplay string
	switch {
	case s.opts.name != nil || s.opts.displayName != nil:
		newName, newDisplay = flagEdits(c, s.opts.name, s.opts.displayName)
	case s.interactive:
		if newName, newDisplay, err = promptEdits(c); err != nil {
			return err
		}
	default:
		return errors.New("give the new value with --name <text> or --display-name <text>")
	}
	if err := validateUserField("user name", newName); err != nil {
		return err
	}
	if err := validateUserField("display name", newDisplay); err != nil {
		return err
	}
	if newName == c.UserName && newDisplay == c.DisplayName {
		fmt.Println("Nothing to change.")
		return nil
	}

	fmt.Printf("\nPasskey for %s (ID %s):\n", c.RPID, shortID(c.ID))
	if newName != c.UserName {
		fmt.Printf("  User name:    %q -> %q\n", c.UserName, newName)
	}
	if newDisplay != c.DisplayName {
		fmt.Printf("  Display name: %q -> %q\n", c.DisplayName, newDisplay)
	}
	if !s.opts.yes && !console.Confirm("Apply the change?") {
		return errCancelled
	}

	if err := s.withPIN(dev, func(pin string) error {
		return dev.UpdateUser(c.ID, c.UserID, newName, newDisplay, pin)
	}); err != nil {
		return fmt.Errorf("cannot update the passkey: %s", describe(err))
	}

	// Read the passkey back to show what the key actually stored.
	var after []fido.Credential
	if err := s.withPIN(dev, func(pin string) error {
		var err error
		after, err = dev.Credentials(c.RPID, pin)
		return err
	}); err != nil {
		fmt.Printf("Change applied (could not verify it: %s).\n", describe(err))
		return nil
	}
	for _, a := range after {
		if bytes.Equal(a.ID, c.ID) {
			fmt.Printf("Done. User name: %s   Display name: %s\n", orDash(a.UserName), orDash(a.DisplayName))
			return nil
		}
	}
	fmt.Println("Change applied.")
	return nil
}

func cmdDelete(s *session) error {
	dev, _, err := s.openDevice()
	if err != nil {
		return err
	}
	defer dev.Close()
	if err := checkCredman(dev); err != nil {
		return err
	}
	creds, _, err := s.loadCreds(dev)
	if err != nil {
		return err
	}
	c, err := s.pickCred(creds, "delete")
	if err != nil {
		return err
	}
	fmt.Printf("\nThe passkey for %s, user %s (ID %s), will be deleted.\n", c.RPID, orDash(c.UserName), shortID(c.ID))
	fmt.Println("You will no longer be able to sign in to that site with this key. This cannot be undone.")
	if !s.opts.yes && !console.Confirm("Delete the passkey?") {
		return errCancelled
	}
	if err := s.withPIN(dev, func(pin string) error {
		return dev.DeleteCredential(c.ID, pin)
	}); err != nil {
		return fmt.Errorf("cannot delete the passkey: %s", describe(err))
	}
	fmt.Println("Passkey deleted.")
	return nil
}

func readNewPIN(minLen int) (string, error) {
	for {
		p1, err := console.PromptHidden(fmt.Sprintf("New PIN (at least %d characters): ", minLen))
		if err != nil {
			return "", err
		}
		if p1 == "" {
			return "", errCancelled
		}
		if err := validatePIN(p1, minLen); err != nil {
			fmt.Println(capitalize(err.Error()) + ".")
			continue
		}
		p2, err := console.PromptHidden("Repeat the new PIN: ")
		if err != nil {
			return "", err
		}
		if p1 != p2 {
			fmt.Println("The PINs do not match. Try again.")
			continue
		}
		return p1, nil
	}
}

func cmdPIN(s *session) error {
	dev, _, err := s.openDevice()
	if err != nil {
		return err
	}
	defer dev.Close()
	if !dev.IsFIDO2() || !dev.SupportsPIN() {
		return errors.New("this key does not support a PIN")
	}
	var keyMin uint64
	if info, err := dev.Info(); err == nil {
		keyMin = info.MinPINLen
	}

	var oldPIN string
	if dev.HasPIN() {
		fmt.Println("Changing the key's PIN.")
		if oldPIN, err = console.PromptHidden("Current PIN: "); err != nil {
			return err
		}
		if oldPIN == "" {
			return errCancelled
		}
	} else {
		fmt.Println("The key has no PIN. A new one will be set.")
	}
	newPIN, err := readNewPIN(effectiveMinPINLen(keyMin))
	if err != nil {
		return err
	}
	if err := dev.SetPIN(newPIN, oldPIN); err != nil {
		if errors.Is(err, fido.ErrPinInvalid) {
			msg := "the current PIN is wrong."
			if n, rerr := dev.PINRetries(); rerr == nil {
				msg += fmt.Sprintf(" Attempts left before the PIN blocks: %d.", n)
			}
			return errors.New(msg)
		}
		return fmt.Errorf("cannot save the PIN: %s", describe(err))
	}
	s.forgetPIN()
	if oldPIN == "" {
		fmt.Println("PIN set.")
	} else {
		fmt.Println("PIN changed.")
	}
	return nil
}

// waitForKeys polls until exactly want security keys are attached.
func waitForKeys(want int, timeout time.Duration) ([]fido.DevInfo, error) {
	deadline := time.Now().Add(timeout)
	for {
		keys, err := securityKeys()
		if err == nil && len(keys) == want {
			return keys, nil
		}
		if time.Now().After(deadline) {
			return nil, errors.New("timed out")
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// resetConfirmation is the word the user must type to confirm a reset.
const resetConfirmation = "ERASE"

func cmdReset(s *session) error {
	keys, err := securityKeys()
	if err != nil {
		return err
	}
	switch {
	case len(keys) == 0:
		return errNoKeys
	case len(keys) > 1:
		return errors.New("to reset a key, leave only that key connected")
	}
	fmt.Printf("WARNING: ALL passkeys and the PIN on %s will be erased.\n", devLabel(keys[0]))
	fmt.Println("You will no longer be able to sign in with it on any site where it was registered.")
	answer, err := console.Prompt(fmt.Sprintf("Type %s to continue: ", resetConfirmation))
	if err != nil || answer != resetConfirmation {
		return errCancelled
	}

	// Keys only accept a reset within a few seconds of being plugged in.
	fmt.Println("\n1. Unplug the key now.")
	if _, err := waitForKeys(0, 60*time.Second); err != nil {
		return fmt.Errorf("the key was not unplugged: %v", err)
	}
	fmt.Println("2. Plug it back in.")
	keys, err = waitForKeys(1, 60*time.Second)
	if err != nil {
		return fmt.Errorf("the key was not detected: %v", err)
	}
	dev, err := fido.Open(keys[0].Path)
	if err != nil {
		return fmt.Errorf("cannot open the key: %s", describe(err))
	}
	defer dev.Close()
	fmt.Println("3. Touch the key to confirm the reset...")
	if err := dev.Reset(); err != nil {
		if errors.Is(err, fido.ErrNotAllowed) {
			return errors.New("the key refused the reset. It must be confirmed within a few seconds of plugging the key in; try again")
		}
		return fmt.Errorf("cannot reset the key: %s", describe(err))
	}
	s.forgetPIN()
	fmt.Println("Key reset. It no longer has any passkeys or PIN.")
	return nil
}
