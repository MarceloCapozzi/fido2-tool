# libfido2 runtime (Windows x64)

Prebuilt DLLs that fido2-tool loads at runtime. They come unmodified from
the official **libfido2 1.17.0** Windows release by Yubico
(`Win64/Release/v143/dynamic`), and each one is Authenticode-signed by
Yubico AB.

| File | Component | Version | License |
|---|---|---|---|
| `win64/fido2.dll` | [libfido2](https://github.com/Yubico/libfido2) | 1.17.0 | BSD-2-Clause ([licenses/libfido2.txt](licenses/libfido2.txt)) |
| `win64/cbor.dll` | [libcbor](https://github.com/PJK/libcbor) | 0.13.0 | MIT ([licenses/libcbor.txt](licenses/libcbor.txt)) |
| `win64/crypto-56.dll` | [LibreSSL](https://www.libressl.org/) libcrypto | 4.1.0 | OpenSSL / SSLeay / ISC ([licenses/libressl.txt](licenses/libressl.txt)) |
| `win64/zlib1.dll` | [zlib](https://zlib.net/) | 1.3.1 | zlib ([licenses/zlib.txt](licenses/zlib.txt)) |

`SHA256SUMS` lists the expected hashes. `scripts/build.ps1` refuses to package
the DLLs if a hash doesn't match or a signature isn't valid.

All four DLLs also import `VCRUNTIME140.dll`. It is not vendored here: the
build script copies it from the local Visual Studio installation.

## Updating

1. Download the new Windows release from
   <https://developers.yubico.com/libfido2/Releases/> or
   <https://github.com/Yubico/libfido2/releases>.
2. Copy the four DLLs from `Win64/Release/v143/dynamic` into `win64/`.
   If a dependency's file name changed (for example `crypto-56.dll` after a
   LibreSSL major update), update `deps` in `internal/fido/lib.go` and
   `$dlls` in `scripts/build.ps1`.
3. Regenerate the checksums from `win64/`:
   ```sh
   sha256sum *.dll > ../SHA256SUMS
   ```
4. Update the versions in this file and the licenses if they changed, then
   run `go test ./...`. `TestLibrary` checks that every function the tool
   uses is still exported.
