# Changelog

All notable changes to this project are documented in this file. The format
is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project follows [Semantic Versioning](https://semver.org/).

Release notes on GitHub come from the section that matches the tag. To
release, rename `[Unreleased]` to `[x.y.z] - YYYY-MM-DD` (see "Releasing" in
the README).

## [0.1.0] - 2026-09-27

First release.

### Added

- List connected keys and show key information (firmware, CTAP versions, PIN state, free passkey slots).
- List, rename (user name and display name) and delete stored passkeys.
- Set or change the PIN.
- Factory reset with a guided unplug, replug and touch sequence.
- Interactive menu, plus commands for scripting.
- Automatic UAC elevation.
