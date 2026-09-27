//go:build windows

package fido

import (
	"errors"
	"unsafe"
)

// Metadata is the discoverable-credential usage of the authenticator.
type Metadata struct {
	Existing  uint64
	Remaining uint64
}

// RP is a relying party that has discoverable credentials on the device.
type RP struct {
	ID   string
	Name string
}

// Credential is a discoverable credential (passkey) stored on the device.
type Credential struct {
	RPID        string
	ID          []byte
	UserID      []byte
	UserName    string
	DisplayName string
	Protection  int // FIDO_CRED_PROT_* (0 when not reported)
	Algorithm   int // COSE algorithm
}

// CredMetadata returns how many passkeys are stored and how many fit.
func (d *Device) CredMetadata(pin string) (Metadata, error) {
	cpin, err := cstr(pin)
	if err != nil {
		return Metadata{}, err
	}
	m := call(pCredmanMetadataNew)
	if m == 0 {
		return Metadata{}, ErrInternal
	}
	defer call(pCredmanMetadataFree, uintptr(unsafe.Pointer(&m)))
	if err := check(call(pCredmanGetMetadata, d.h, m, uintptr(unsafe.Pointer(cpin)))); err != nil {
		return Metadata{}, err
	}
	return Metadata{
		Existing:  uint64(call(pCredmanRkExisting, m)),
		Remaining: uint64(call(pCredmanRkRemaining, m)),
	}, nil
}

// RPs lists the relying parties that have passkeys on the device.
func (d *Device) RPs(pin string) ([]RP, error) {
	cpin, err := cstr(pin)
	if err != nil {
		return nil, err
	}
	rp := call(pCredmanRpNew)
	if rp == 0 {
		return nil, ErrInternal
	}
	defer call(pCredmanRpFree, uintptr(unsafe.Pointer(&rp)))
	if err := check(call(pCredmanGetRp, d.h, rp, uintptr(unsafe.Pointer(cpin)))); err != nil {
		if errors.Is(err, ErrNoCredentials) {
			return nil, nil
		}
		return nil, err
	}
	n := call(pCredmanRpCount, rp)
	out := make([]RP, 0, n)
	for i := uintptr(0); i < n; i++ {
		out = append(out, RP{
			ID:   goString(call(pCredmanRpID, rp, i)),
			Name: goString(call(pCredmanRpName, rp, i)),
		})
	}
	return out, nil
}

// Credentials lists the passkeys stored for rpID.
func (d *Device) Credentials(rpID, pin string) ([]Credential, error) {
	crp, err := cstr(rpID)
	if err != nil {
		return nil, err
	}
	cpin, err := cstr(pin)
	if err != nil {
		return nil, err
	}
	rk := call(pCredmanRkNew)
	if rk == 0 {
		return nil, ErrInternal
	}
	defer call(pCredmanRkFree, uintptr(unsafe.Pointer(&rk)))
	if err := check(call(pCredmanGetRk, d.h, uintptr(unsafe.Pointer(crp)), rk, uintptr(unsafe.Pointer(cpin)))); err != nil {
		if errors.Is(err, ErrNoCredentials) {
			return nil, nil
		}
		return nil, err
	}
	n := call(pCredmanRkCount, rk)
	out := make([]Credential, 0, n)
	for i := uintptr(0); i < n; i++ {
		c := call(pCredmanRk, rk, i)
		if c == 0 {
			continue
		}
		out = append(out, Credential{
			RPID:        rpID,
			ID:          goBytes(call(pCredIDPtr, c), call(pCredIDLen, c)),
			UserID:      goBytes(call(pCredUserIDPtr, c), call(pCredUserIDLen, c)),
			UserName:    goString(call(pCredUserName, c)),
			DisplayName: goString(call(pCredDisplayName, c)),
			Protection:  int(int32(call(pCredProt, c))),
			Algorithm:   int(int32(call(pCredType, c))),
		})
	}
	return out, nil
}

// AllCredentials lists every passkey on the device, grouped by relying party.
func (d *Device) AllCredentials(pin string) ([]Credential, error) {
	rps, err := d.RPs(pin)
	if err != nil {
		return nil, err
	}
	var out []Credential
	for _, rp := range rps {
		creds, err := d.Credentials(rp.ID, pin)
		if err != nil {
			return nil, err
		}
		out = append(out, creds...)
	}
	return out, nil
}

// DeleteCredential removes the passkey with the given credential ID.
func (d *Device) DeleteCredential(id []byte, pin string) error {
	if len(id) == 0 {
		return ErrInvalidArgument
	}
	cpin, err := cstr(pin)
	if err != nil {
		return err
	}
	return check(call(pCredmanDelRk, d.h, uintptr(unsafe.Pointer(bp(id))), uintptr(len(id)), uintptr(unsafe.Pointer(cpin))))
}

// UpdateUser replaces the user name and display name of an existing passkey
// (CTAP 2.1 authenticatorCredentialManagement updateUserInformation). The
// user ID must be the one already stored; the authenticator replaces the
// whole user entity, so pass the current values for fields that don't change.
func (d *Device) UpdateUser(id, userID []byte, name, displayName, pin string) error {
	if len(id) == 0 || len(userID) == 0 {
		return ErrInvalidArgument
	}
	cname, err := cstr(name)
	if err != nil {
		return err
	}
	cdisplay, err := cstr(displayName)
	if err != nil {
		return err
	}
	cpin, err := cstr(pin)
	if err != nil {
		return err
	}
	c := call(pCredNew)
	if c == 0 {
		return ErrInternal
	}
	defer call(pCredFree, uintptr(unsafe.Pointer(&c)))
	if err := check(call(pCredSetID, c, uintptr(unsafe.Pointer(bp(id))), uintptr(len(id)))); err != nil {
		return err
	}
	if err := check(call(pCredSetUser, c, uintptr(unsafe.Pointer(bp(userID))), uintptr(len(userID)),
		uintptr(unsafe.Pointer(cname)), uintptr(unsafe.Pointer(cdisplay)), 0)); err != nil {
		return err
	}
	return check(call(pCredmanSetRk, d.h, c, uintptr(unsafe.Pointer(cpin))))
}
