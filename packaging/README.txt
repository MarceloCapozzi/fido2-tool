fido2-tool - manage FIDO2 security keys (YubiKey and compatible keys)
======================================================================

Requirements
- Windows 10 (version 1903 or later) or Windows 11, 64-bit.
- Administrator rights. Windows only lets elevated programs talk to a
  security key directly. If you start fido2-tool without them, it asks for
  confirmation (UAC) and continues in a new window.
- The key connected over USB. NFC is not supported.

Installation
Extract the whole folder. All the .dll files must stay next to
fido2-tool.exe.

Usage
- Double-click fido2-tool.exe to open the menu.
- Or, from a terminal:
    fido2-tool list      List the connected keys
    fido2-tool info      Show information about the key
    fido2-tool creds     List the stored passkeys (asks for the PIN)
    fido2-tool rename    Change the user name or display name of a passkey
    fido2-tool delete    Delete a passkey
    fido2-tool pin       Set or change the PIN
    fido2-tool reset     Factory-reset the key (erases everything)
    fido2-tool help      All options

Changing the user name or display name of a passkey
  fido2-tool rename
  (asks for the PIN, lists the passkeys, asks which one to edit and then the
  new user name and display name; press Enter to keep either one)

  or without questions:
  fido2-tool rename --cred <ID> --name "new.user" --display-name "New Name" --yes
  (the ID is the one shown by "fido2-tool creds"; you can give just one of
  the two values)

  This only changes what the key shows when you pick an account. The website
  still identifies your account the same way, so signing in is not affected.

  The key must support CTAP 2.1. A YubiKey 5 needs firmware 5.7 or later;
  "fido2-tool info" tells you whether renaming is supported.

Be careful with the PIN
After 8 wrong attempts the PIN blocks, and the only way to use the key again
is to reset it, which erases all its passkeys.

Licenses
See the licenses folder for fido2-tool (MIT) and the bundled components:
libfido2 (BSD-2-Clause), libcbor (MIT), LibreSSL (OpenSSL/SSLeay/ISC) and
zlib. vcruntime140.dll is the redistributable Microsoft Visual C++ Runtime.
