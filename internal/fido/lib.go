//go:build windows

// Package fido is a minimal binding to libfido2 (fido2.dll). The library is
// loaded at runtime through syscall, so the module builds without cgo or a C
// toolchain.
package fido

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

// Runtime dependencies of fido2.dll, in load order. They are loaded by
// absolute path before fido2.dll so that its imports resolve to these copies
// and never to whatever happens to be on PATH.
var deps = []string{"vcruntime140.dll", "zlib1.dll", "crypto-56.dll", "cbor.dll"}

// optionalDeps may be missing from the directory because they are usually
// installed system-wide.
var optionalDeps = map[string]bool{"vcruntime140.dll": true}

var (
	lib      = syscall.NewLazyDLL("fido2.dll")
	allProcs []*syscall.LazyProc
	loaded   bool
)

func np(name string) *syscall.LazyProc {
	p := lib.NewProc(name)
	allProcs = append(allProcs, p)
	return p
}

var (
	pInit   = np("fido_init")
	pStrerr = np("fido_strerr")

	pDevInfoNew      = np("fido_dev_info_new")
	pDevInfoFree     = np("fido_dev_info_free")
	pDevInfoManifest = np("fido_dev_info_manifest")
	pDevInfoPtr      = np("fido_dev_info_ptr")
	pDevInfoPath     = np("fido_dev_info_path")
	pDevInfoManuf    = np("fido_dev_info_manufacturer_string")
	pDevInfoProduct  = np("fido_dev_info_product_string")
	pDevInfoVendorID = np("fido_dev_info_vendor")
	pDevInfoProdID   = np("fido_dev_info_product")

	pDevNew             = np("fido_dev_new")
	pDevFree            = np("fido_dev_free")
	pDevOpen            = np("fido_dev_open")
	pDevClose           = np("fido_dev_close")
	pDevSetTimeout      = np("fido_dev_set_timeout")
	pDevIsFIDO2         = np("fido_dev_is_fido2")
	pDevIsWinHello      = np("fido_dev_is_winhello")
	pDevHasPin          = np("fido_dev_has_pin")
	pDevSupportsPin     = np("fido_dev_supports_pin")
	pDevSupportsCredman = np("fido_dev_supports_credman")
	pDevGetRetryCount   = np("fido_dev_get_retry_count")
	pDevSetPin          = np("fido_dev_set_pin")
	pDevReset           = np("fido_dev_reset")
	pDevGetCborInfo     = np("fido_dev_get_cbor_info")

	pCborInfoNew            = np("fido_cbor_info_new")
	pCborInfoFree           = np("fido_cbor_info_free")
	pCborInfoVersionsPtr    = np("fido_cbor_info_versions_ptr")
	pCborInfoVersionsLen    = np("fido_cbor_info_versions_len")
	pCborInfoExtensionsPtr  = np("fido_cbor_info_extensions_ptr")
	pCborInfoExtensionsLen  = np("fido_cbor_info_extensions_len")
	pCborInfoTransportsPtr  = np("fido_cbor_info_transports_ptr")
	pCborInfoTransportsLen  = np("fido_cbor_info_transports_len")
	pCborInfoOptNamePtr     = np("fido_cbor_info_options_name_ptr")
	pCborInfoOptValuePtr    = np("fido_cbor_info_options_value_ptr")
	pCborInfoOptLen         = np("fido_cbor_info_options_len")
	pCborInfoAaguidPtr      = np("fido_cbor_info_aaguid_ptr")
	pCborInfoAaguidLen      = np("fido_cbor_info_aaguid_len")
	pCborInfoAlgCount       = np("fido_cbor_info_algorithm_count")
	pCborInfoAlgCose        = np("fido_cbor_info_algorithm_cose")
	pCborInfoFwVersion      = np("fido_cbor_info_fwversion")
	pCborInfoMinPinLen      = np("fido_cbor_info_minpinlen")
	pCborInfoRkRemaining    = np("fido_cbor_info_rk_remaining")
	pCborInfoNewPinRequired = np("fido_cbor_info_new_pin_required")

	pCredNew         = np("fido_cred_new")
	pCredFree        = np("fido_cred_free")
	pCredSetID       = np("fido_cred_set_id")
	pCredSetUser     = np("fido_cred_set_user")
	pCredIDPtr       = np("fido_cred_id_ptr")
	pCredIDLen       = np("fido_cred_id_len")
	pCredUserIDPtr   = np("fido_cred_user_id_ptr")
	pCredUserIDLen   = np("fido_cred_user_id_len")
	pCredUserName    = np("fido_cred_user_name")
	pCredDisplayName = np("fido_cred_display_name")
	pCredProt        = np("fido_cred_prot")
	pCredType        = np("fido_cred_type")

	pCredmanMetadataNew  = np("fido_credman_metadata_new")
	pCredmanMetadataFree = np("fido_credman_metadata_free")
	pCredmanGetMetadata  = np("fido_credman_get_dev_metadata")
	pCredmanRkExisting   = np("fido_credman_rk_existing")
	pCredmanRkRemaining  = np("fido_credman_rk_remaining")
	pCredmanRpNew        = np("fido_credman_rp_new")
	pCredmanRpFree       = np("fido_credman_rp_free")
	pCredmanGetRp        = np("fido_credman_get_dev_rp")
	pCredmanRpCount      = np("fido_credman_rp_count")
	pCredmanRpID         = np("fido_credman_rp_id")
	pCredmanRpName       = np("fido_credman_rp_name")
	pCredmanRkNew        = np("fido_credman_rk_new")
	pCredmanRkFree       = np("fido_credman_rk_free")
	pCredmanGetRk        = np("fido_credman_get_dev_rk")
	pCredmanRkCount      = np("fido_credman_rk_count")
	pCredmanRk           = np("fido_credman_rk")
	pCredmanDelRk        = np("fido_credman_del_dev_rk")
	pCredmanSetRk        = np("fido_credman_set_dev_rk")
)

// Flags for Load and LoadFrom.
const (
	FlagDebug = 0x01 // FIDO_DEBUG: libfido2 writes a protocol trace to stderr
)

// Load loads fido2.dll and its dependencies from the executable's directory.
func Load(flags int) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return LoadFrom(filepath.Dir(exe), flags)
}

// LoadFrom loads fido2.dll and its dependencies from dir, resolves every
// function used by this package, and initializes libfido2. It must be called
// once before any other function in this package.
func LoadFrom(dir string, flags int) error {
	if loaded {
		return nil
	}
	for _, d := range deps {
		p := filepath.Join(dir, d)
		if _, err := os.Stat(p); err != nil {
			if optionalDeps[d] {
				continue
			}
			return fmt.Errorf("%s is missing from %s", d, dir)
		}
		if _, err := syscall.LoadDLL(p); err != nil {
			return fmt.Errorf("cannot load %s: %w", d, err)
		}
	}
	lib.Name = filepath.Join(dir, "fido2.dll")
	if err := lib.Load(); err != nil {
		return fmt.Errorf("cannot load fido2.dll: %w", err)
	}
	for _, p := range allProcs {
		if err := p.Find(); err != nil {
			return fmt.Errorf("incompatible fido2.dll: %w", err)
		}
	}
	pInit.Call(uintptr(flags))
	loaded = true
	return nil
}

// Error is a libfido2 error code (FIDO_ERR_* in fido/err.h). Positive values
// are CTAP status codes returned by the authenticator; negative values are
// errors raised by libfido2 itself.
type Error int

func (e Error) Error() string {
	if !loaded {
		return fmt.Sprintf("FIDO error %d", int(e))
	}
	r, _, _ := pStrerr.Call(uintptr(int(e)))
	return fmt.Sprintf("%s (%d)", goString(r), int(e))
}

// Error codes that callers handle explicitly.
const (
	ErrInvalidCommand    Error = 0x01
	ErrInvalidParameter  Error = 0x02
	ErrTimeout           Error = 0x05
	ErrOperationDenied   Error = 0x27
	ErrKeepaliveCancel   Error = 0x2d
	ErrNoCredentials     Error = 0x2e
	ErrUserActionTimeout Error = 0x2f
	ErrNotAllowed        Error = 0x30
	ErrPinInvalid        Error = 0x31
	ErrPinBlocked        Error = 0x32
	ErrPinAuthInvalid    Error = 0x33
	ErrPinAuthBlocked    Error = 0x34
	ErrPinNotSet         Error = 0x35
	ErrPinRequired       Error = 0x36
	ErrPinPolicy         Error = 0x37
	ErrActionTimeout     Error = 0x3a
	ErrInvalidSubcommand Error = 0x3e // CTAP2_ERR_INVALID_SUBCOMMAND
	ErrUnauthorizedPerm  Error = 0x40
	ErrTx                Error = -1
	ErrRx                Error = -2
	ErrInvalidArgument   Error = -7
	ErrInternal          Error = -9
	ErrNotFound          Error = -10
)

// check converts a libfido2 int return value into an error.
func check(r uintptr) error {
	if c := int(int32(r)); c != 0 {
		return Error(c)
	}
	return nil
}

// call invokes a libfido2 function. Go pointers must be converted to uintptr
// directly in the argument list so that uintptrescapes keeps them alive and
// in place for the duration of the call.
//
//go:uintptrescapes
func call(p *syscall.LazyProc, args ...uintptr) uintptr {
	r, _, _ := p.Call(args...)
	return r
}

// cbool reads a C bool return value; only the low byte is defined.
func cbool(r uintptr) bool { return r&0xff != 0 }

// cstr returns a NUL-terminated copy of s, or nil for the empty string, which
// libfido2 receives as NULL.
func cstr(s string) (*byte, error) {
	if s == "" {
		return nil, nil
	}
	p, err := syscall.BytePtrFromString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid text: contains a NUL character")
	}
	return p, nil
}

// ptr reinterprets a C address as a Go pointer. The memory is owned by
// libfido2, so the Go GC never tracks or moves it.
func ptr(p uintptr) unsafe.Pointer { return *(*unsafe.Pointer)(unsafe.Pointer(&p)) }

// goString copies a NUL-terminated C string.
func goString(p uintptr) string {
	if p == 0 {
		return ""
	}
	n := 0
	for *(*byte)(unsafe.Add(ptr(p), n)) != 0 {
		n++
	}
	return string(unsafe.Slice((*byte)(ptr(p)), n))
}

// goBytes copies n bytes of C memory.
func goBytes(p uintptr, n uintptr) []byte {
	if p == 0 || n == 0 {
		return nil
	}
	return append([]byte(nil), unsafe.Slice((*byte)(ptr(p)), int(n))...)
}

// goStrings copies a C array of n char pointers.
func goStrings(p uintptr, n uintptr) []string {
	if p == 0 || n == 0 {
		return nil
	}
	arr := unsafe.Slice((*uintptr)(ptr(p)), int(n))
	out := make([]string, n)
	for i, s := range arr {
		out[i] = goString(s)
	}
	return out
}

// bp returns a pointer to the first byte of b, or nil if b is empty.
func bp(b []byte) *byte {
	if len(b) == 0 {
		return nil
	}
	return &b[0]
}
