<#
.SYNOPSIS
Extracts the release notes for a version from CHANGELOG.md.

.DESCRIPTION
Finds the "## [<Version>] - <YYYY-MM-DD>" section of CHANGELOG.md and prints
its body, or writes it to -OutFile. Fails if the section is missing, has no
release date, or is empty, so a tag can't be released without notes. With
-ChecksumFile, the file's contents are appended as a SHA-256 block.

.EXAMPLE
.\scripts\release-notes.ps1 -Version 0.1.0
Previews the notes that the v0.1.0 release will get.
#>
param(
    [Parameter(Mandatory)][string]$Version,
    [string]$Changelog = (Join-Path (Split-Path $PSScriptRoot -Parent) "CHANGELOG.md"),
    [string]$ChecksumFile,
    [string]$OutFile
)
$ErrorActionPreference = "Stop"

$Version = $Version -replace '^v', ''
$v = [regex]::Escape($Version)
# Matches "## [0.1.0] - 2026-09-27" or "## 0.1.0 - 2026-09-27", but not
# "## [0.1.0-rc.1] - ...".
$heading = '^##\s+(?:\[' + $v + '\]|' + $v + ')(?:\s+-\s+(.*?))?\s*$'

$lines = @(Get-Content $Changelog)
$start = -1
$date = $null
for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($lines[$i] -match $heading) {
        $start = $i
        $date = $Matches[1]
        break
    }
}
if ($start -lt 0) {
    throw "CHANGELOG.md has no section for $Version. Add a '## [$Version] - YYYY-MM-DD' heading."
}
if ($date -notmatch '^\d{4}-\d{2}-\d{2}$') {
    throw "The CHANGELOG.md section for $Version has no release date. Use '## [$Version] - YYYY-MM-DD'."
}

$body = for ($i = $start + 1; $i -lt $lines.Count -and $lines[$i] -notmatch '^##\s'; $i++) {
    # Skip Keep a Changelog link definitions ("[0.1.0]: https://...").
    if ($lines[$i] -notmatch '^\[[^\]]+\]:\s+\S+') { $lines[$i] }
}
$notes = ($body -join "`n").Trim()
if (-not $notes) {
    throw "The CHANGELOG.md section for $Version is empty."
}

if ($ChecksumFile) {
    $fence = '```'
    $sum = (Get-Content $ChecksumFile -Raw).Trim()
    $notes += "`n`n## SHA-256`n`n$fence`n$sum`n$fence"
}

if ($OutFile) {
    [IO.File]::WriteAllText($OutFile, $notes + "`n")
} else {
    $notes
}
