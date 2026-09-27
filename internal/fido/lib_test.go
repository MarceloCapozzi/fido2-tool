//go:build windows

package fido

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unsafe"
)

func addr(b []byte) uintptr { return uintptr(unsafe.Pointer(&b[0])) }

func TestGoString(t *testing.T) {
	b := []byte("hello\x00world\x00")
	if got := goString(addr(b)); got != "hello" {
		t.Errorf("goString = %q, want %q", got, "hello")
	}
	if got := goString(0); got != "" {
		t.Errorf("goString(NULL) = %q, want empty", got)
	}
	runtime.KeepAlive(b)
}

func TestGoBytesCopies(t *testing.T) {
	b := []byte{1, 2, 3, 4}
	got := goBytes(addr(b), 3)
	if string(got) != "\x01\x02\x03" {
		t.Fatalf("goBytes = %v, want [1 2 3]", got)
	}
	b[0] = 9
	if got[0] != 1 {
		t.Error("goBytes must copy, not alias, the C buffer")
	}
	if goBytes(0, 3) != nil || goBytes(addr(b), 0) != nil {
		t.Error("goBytes with NULL or zero length must return nil")
	}
	runtime.KeepAlive(b)
}

func TestGoStrings(t *testing.T) {
	a, b := []byte("FIDO_2_0\x00"), []byte("FIDO_2_1\x00")
	arr := []uintptr{addr(a), addr(b)}
	got := goStrings(uintptr(unsafe.Pointer(&arr[0])), 2)
	if strings.Join(got, ",") != "FIDO_2_0,FIDO_2_1" {
		t.Errorf("goStrings = %v", got)
	}
	if goStrings(0, 2) != nil {
		t.Error("goStrings(NULL) must return nil")
	}
	runtime.KeepAlive(a)
	runtime.KeepAlive(b)
	runtime.KeepAlive(arr)
}

func TestCstr(t *testing.T) {
	if p, err := cstr(""); p != nil || err != nil {
		t.Errorf("cstr(\"\") = %v, %v; want nil, nil (NULL)", p, err)
	}
	p, err := cstr("1234")
	if err != nil {
		t.Fatal(err)
	}
	if got := unsafe.String(p, 5); got != "1234\x00" {
		t.Errorf("cstr(\"1234\") = %q, want NUL-terminated", got)
	}
	if _, err := cstr("12\x0034"); err == nil {
		t.Error("cstr must reject strings with NUL")
	}
}

func TestCheck(t *testing.T) {
	if err := check(0); err != nil {
		t.Errorf("check(0) = %v, want nil", err)
	}
	// libfido2 returns a C int; the upper half of the register is undefined.
	if err := check(0xdeadbeef_00000031); !errors.Is(err, ErrPinInvalid) {
		t.Errorf("check(0x31) = %v, want ErrPinInvalid", err)
	}
	if err := check(uintptr(0xffffffff)); !errors.Is(err, ErrTx) {
		t.Errorf("check(-1) = %v, want ErrTx", err)
	}
}

func TestCbool(t *testing.T) {
	if !cbool(1) || cbool(0) || cbool(0xff00) {
		t.Error("cbool must only look at the low byte")
	}
}

func TestErrorMessageHasCode(t *testing.T) {
	if msg := ErrPinInvalid.Error(); !strings.Contains(msg, "49") {
		t.Errorf("Error() = %q, want it to include the code", msg)
	}
}

func TestInfoLookups(t *testing.T) {
	info := &Info{
		Versions: []string{"U2F_V2", "FIDO_2_0", "FIDO_2_1"},
		Options:  []Option{{"rk", true}, {"clientPin", false}},
	}
	if !info.HasVersion("FIDO_2_1") || info.HasVersion("FIDO_2_1_PRE") {
		t.Error("HasVersion mismatch")
	}
	if v, ok := info.Option("clientPin"); v || !ok {
		t.Errorf("Option(clientPin) = %v, %v; want false, true", v, ok)
	}
	if _, ok := info.Option("credMgmt"); ok {
		t.Error("Option(credMgmt) should be absent")
	}
}

func TestDevInfoIsWinHello(t *testing.T) {
	if !(DevInfo{Path: "windows://hello"}).IsWinHello() {
		t.Error("windows://hello must be detected as Windows Hello")
	}
	if (DevInfo{Path: `\\?\hid#vid_1050&pid_0407`}).IsWinHello() {
		t.Error("a HID path is not Windows Hello")
	}
}

// TestLibrary loads the vendored DLLs and exercises calls that need no
// authenticator. Without admin rights Windows only exposes the Windows Hello
// pseudo-device, so the manifest contents are not asserted.
func TestLibrary(t *testing.T) {
	dir := filepath.Join("..", "..", "third_party", "libfido2", "win64")
	if _, err := os.Stat(filepath.Join(dir, "fido2.dll")); err != nil {
		t.Skip("vendored fido2.dll not found")
	}
	if err := LoadFrom(dir, 0); err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}
	if msg := ErrPinInvalid.Error(); !strings.Contains(msg, "FIDO_ERR_PIN_INVALID") {
		t.Errorf("Error() = %q, want the libfido2 name", msg)
	}
	devs, err := Manifest()
	if err != nil {
		t.Fatalf("Manifest: %v", err)
	}
	for _, d := range devs {
		t.Logf("device %q (%s %s)", d.Path, d.Manufacturer, d.Product)
	}
	if _, err := Open(`\\?\hid#does-not-exist`); err == nil {
		t.Error("Open of a bogus path must fail")
	}
}
