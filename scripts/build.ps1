<#
.SYNOPSIS
Builds fido2-tool for Windows x64 and packages it with its runtime DLLs.

.DESCRIPTION
Verifies the vendored libfido2 DLLs (SHA-256 and Authenticode signature),
runs go vet and the tests, builds the executable, and assembles
dist\fido2-tool\ plus a zip ready to distribute and its .sha256 file.

.PARAMETER Version
Version stamped into the binary. Defaults to the current git tag
(without the leading "v"), or "dev" outside a tagged checkout.

.PARAMETER SkipTests
Skip go vet and go test.
#>
param(
    [string]$Version,
    [switch]$SkipTests
)
$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root

if (-not $Version) {
    $tag = git describe --tags --always --dirty 2>$null
    $Version = if ($LASTEXITCODE -eq 0 -and $tag) { $tag -replace '^v', '' } else { "dev" }
}

$libDir = Join-Path $root "third_party\libfido2\win64"
$dlls = "fido2.dll", "cbor.dll", "crypto-56.dll", "zlib1.dll"

# Verify the vendored binaries before shipping them.
$sums = @{}
foreach ($line in Get-Content (Join-Path $root "third_party\libfido2\SHA256SUMS")) {
    if ($line -match '^([0-9a-f]{64}) [ *](.+)$') { $sums[$Matches[2]] = $Matches[1] }
}
foreach ($dll in $dlls) {
    $path = Join-Path $libDir $dll
    $hash = (Get-FileHash -Algorithm SHA256 $path).Hash.ToLowerInvariant()
    if ($hash -ne $sums[$dll]) { throw "$dll does not match third_party\libfido2\SHA256SUMS" }
    $sig = Get-AuthenticodeSignature $path
    if ($sig.Status -ne "Valid" -or $sig.SignerCertificate.Subject -notmatch "O=Yubico AB") {
        throw "$dll is not validly signed by Yubico AB ($($sig.Status))"
    }
}

$env:CGO_ENABLED = "0"
$env:GOOS = "windows"
$env:GOARCH = "amd64"

if (-not $SkipTests) {
    go vet ./...
    if ($LASTEXITCODE) { throw "go vet failed" }
    go test ./...
    if ($LASTEXITCODE) { throw "go test failed" }
}

$dist = Join-Path $root "dist\fido2-tool"
if (Test-Path $dist) { Remove-Item -Recurse -Force $dist }
New-Item -ItemType Directory -Force (Join-Path $dist "licenses") | Out-Null

$ldflags = "-s -w -X github.com/marcelocapozzi/fido2-tool/internal/cli.Version=$Version"
go build -trimpath -ldflags $ldflags -o (Join-Path $dist "fido2-tool.exe") ./cmd/fido2-tool
if ($LASTEXITCODE) { throw "go build failed" }

foreach ($dll in $dlls) { Copy-Item (Join-Path $libDir $dll) $dist }

# App-local copy of the Visual C++ runtime, so target machines don't need the
# VC++ Redistributable installed. Microsoft's redistribution terms allow it.
$vcruntime = Get-ChildItem "${env:ProgramFiles(x86)}\Microsoft Visual Studio\*\*\VC\Redist\MSVC\*\x64\Microsoft.VC14*.CRT\vcruntime140.dll", "${env:ProgramFiles}\Microsoft Visual Studio\*\*\VC\Redist\MSVC\*\x64\Microsoft.VC14*.CRT\vcruntime140.dll" -ErrorAction SilentlyContinue |
    Sort-Object { $_.VersionInfo.FileVersionRaw } -Descending | Select-Object -First 1
if ($vcruntime) {
    Copy-Item $vcruntime.FullName $dist
} else {
    Write-Warning "vcruntime140.dll (x64) not found; install Visual Studio Build Tools to bundle it. The package will need the VC++ Redistributable on the target machine."
}

Copy-Item (Join-Path $root "packaging\README.txt") $dist
Copy-Item (Join-Path $root "LICENSE") (Join-Path $dist "licenses\fido2-tool.txt")
Copy-Item (Join-Path $root "third_party\libfido2\licenses\*.txt") (Join-Path $dist "licenses")

$zip = Join-Path $root "dist\fido2-tool-$Version-windows-amd64.zip"
if (Test-Path $zip) { Remove-Item -Force $zip }
Compress-Archive -Path $dist -DestinationPath $zip

# Checksum in sha256sum format, published next to the zip.
$zipHash = (Get-FileHash -Algorithm SHA256 $zip).Hash.ToLowerInvariant()
[IO.File]::WriteAllText("$zip.sha256", "$zipHash  $(Split-Path $zip -Leaf)`n")
Write-Host "Built $zip"
Write-Host "SHA-256 $zipHash"
