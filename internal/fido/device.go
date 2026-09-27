//go:build windows

package fido

import (
	"strings"
	"unsafe"
)

const maxDevices = 64

// DevInfo describes an attached authenticator as reported by the HID layer.
type DevInfo struct {
	Path         string
	Manufacturer string
	Product      string
	VendorID     uint16
	ProductID    uint16
}

// IsWinHello reports whether the entry is the Windows Hello pseudo-device,
// which only proxies make-credential/get-assertion and cannot be managed.
func (d DevInfo) IsWinHello() bool { return strings.HasPrefix(d.Path, "windows://") }

// Manifest lists the FIDO devices currently attached.
func Manifest() ([]DevInfo, error) {
	list := call(pDevInfoNew, maxDevices)
	if list == 0 {
		return nil, ErrInternal
	}
	defer call(pDevInfoFree, uintptr(unsafe.Pointer(&list)), maxDevices)

	var n uintptr
	if err := check(call(pDevInfoManifest, list, maxDevices, uintptr(unsafe.Pointer(&n)))); err != nil {
		return nil, err
	}
	out := make([]DevInfo, 0, n)
	for i := uintptr(0); i < n; i++ {
		di := call(pDevInfoPtr, list, i)
		out = append(out, DevInfo{
			Path:         goString(call(pDevInfoPath, di)),
			Manufacturer: goString(call(pDevInfoManuf, di)),
			Product:      goString(call(pDevInfoProduct, di)),
			VendorID:     uint16(call(pDevInfoVendorID, di)),
			ProductID:    uint16(call(pDevInfoProdID, di)),
		})
	}
	return out, nil
}

// Device is an open handle to an authenticator.
type Device struct {
	h    uintptr
	Path string
}

// Open opens the device at path.
func Open(path string) (*Device, error) {
	cpath, err := cstr(path)
	if err != nil {
		return nil, err
	}
	h := call(pDevNew)
	if h == 0 {
		return nil, ErrInternal
	}
	if err := check(call(pDevOpen, h, uintptr(unsafe.Pointer(cpath)))); err != nil {
		call(pDevFree, uintptr(unsafe.Pointer(&h)))
		return nil, err
	}
	return &Device{h: h, Path: path}, nil
}

// Close closes the device and releases the handle.
func (d *Device) Close() {
	if d.h == 0 {
		return
	}
	call(pDevClose, d.h)
	call(pDevFree, uintptr(unsafe.Pointer(&d.h)))
	d.h = 0
}

// SetTimeout sets the per-operation timeout in milliseconds; -1 waits forever.
func (d *Device) SetTimeout(ms int) error {
	return check(call(pDevSetTimeout, d.h, uintptr(ms)))
}

func (d *Device) IsFIDO2() bool         { return cbool(call(pDevIsFIDO2, d.h)) }
func (d *Device) IsWinHello() bool      { return cbool(call(pDevIsWinHello, d.h)) }
func (d *Device) HasPIN() bool          { return cbool(call(pDevHasPin, d.h)) }
func (d *Device) SupportsPIN() bool     { return cbool(call(pDevSupportsPin, d.h)) }
func (d *Device) SupportsCredman() bool { return cbool(call(pDevSupportsCredman, d.h)) }

// PINRetries returns how many wrong PIN attempts remain before the PIN blocks.
func (d *Device) PINRetries() (int, error) {
	var n int32
	if err := check(call(pDevGetRetryCount, d.h, uintptr(unsafe.Pointer(&n)))); err != nil {
		return 0, err
	}
	return int(n), nil
}

// SetPIN sets the PIN when oldPIN is empty, or changes it otherwise.
func (d *Device) SetPIN(newPIN, oldPIN string) error {
	cnew, err := cstr(newPIN)
	if err != nil {
		return err
	}
	cold, err := cstr(oldPIN)
	if err != nil {
		return err
	}
	return check(call(pDevSetPin, d.h, uintptr(unsafe.Pointer(cnew)), uintptr(unsafe.Pointer(cold))))
}

// Reset erases every credential and the PIN. Authenticators usually accept it
// only within a few seconds of being plugged in, and require a touch.
func (d *Device) Reset() error {
	return check(call(pDevReset, d.h))
}

// Option is one entry of the authenticatorGetInfo options map.
type Option struct {
	Name  string
	Value bool
}

// Info is the parsed authenticatorGetInfo response.
type Info struct {
	Versions       []string
	Extensions     []string
	Transports     []string
	Options        []Option
	AAGUID         []byte
	Algorithms     []int
	FirmwareVer    uint64
	MinPINLen      uint64
	RKRemaining    int64 // -1 when the authenticator does not report it
	NewPINRequired bool
}

// HasVersion reports whether the authenticator advertises version v
// (e.g. "FIDO_2_1").
func (i *Info) HasVersion(v string) bool {
	for _, s := range i.Versions {
		if s == v {
			return true
		}
	}
	return false
}

// Option returns the value of option name and whether it was present.
func (i *Info) Option(name string) (value, present bool) {
	for _, o := range i.Options {
		if o.Name == name {
			return o.Value, true
		}
	}
	return false, false
}

// Info queries authenticatorGetInfo.
func (d *Device) Info() (*Info, error) {
	ci := call(pCborInfoNew)
	if ci == 0 {
		return nil, ErrInternal
	}
	defer call(pCborInfoFree, uintptr(unsafe.Pointer(&ci)))
	if err := check(call(pDevGetCborInfo, d.h, ci)); err != nil {
		return nil, err
	}

	info := &Info{
		Versions:       goStrings(call(pCborInfoVersionsPtr, ci), call(pCborInfoVersionsLen, ci)),
		Extensions:     goStrings(call(pCborInfoExtensionsPtr, ci), call(pCborInfoExtensionsLen, ci)),
		Transports:     goStrings(call(pCborInfoTransportsPtr, ci), call(pCborInfoTransportsLen, ci)),
		AAGUID:         goBytes(call(pCborInfoAaguidPtr, ci), call(pCborInfoAaguidLen, ci)),
		FirmwareVer:    uint64(call(pCborInfoFwVersion, ci)),
		MinPINLen:      uint64(call(pCborInfoMinPinLen, ci)),
		RKRemaining:    int64(call(pCborInfoRkRemaining, ci)),
		NewPINRequired: cbool(call(pCborInfoNewPinRequired, ci)),
	}

	nopt := call(pCborInfoOptLen, ci)
	names := goStrings(call(pCborInfoOptNamePtr, ci), nopt)
	if vp := call(pCborInfoOptValuePtr, ci); vp != 0 && len(names) > 0 {
		values := unsafe.Slice((*bool)(ptr(vp)), len(names))
		for i, n := range names {
			info.Options = append(info.Options, Option{Name: n, Value: values[i]})
		}
	}

	nalg := call(pCborInfoAlgCount, ci)
	for i := uintptr(0); i < nalg; i++ {
		info.Algorithms = append(info.Algorithms, int(int32(call(pCborInfoAlgCose, ci, i))))
	}
	return info, nil
}
