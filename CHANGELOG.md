# Changelog

Each release on GitHub carries the section below that matches its tag. Orbis shows the same text
under "Show release notes" when it offers an update.

## v1.26.2

### Fixed
- One-click update failed with "read-only file system" on installs made by the installer. The
  service runs under `ProtectSystem=strict`, so the daemon cannot write beside its own binary.
  The download now lands in the data directory when that happens, and a transient systemd unit
  outside the sandbox keeps the rollback copy, installs the new binary and restarts the service.
- Transient update units get unique names and are collected, so a failed attempt never blocks
  the next one.
- `orbisd -update` reads the data directory from the configuration.

## v1.26.1

### Changed
- The release check runs every hour instead of every six.
- The update banner stays off the simple Settings page, which has its own Updates section.

## v1.26.0

### Added
- **Update detection.** Orbis checks the latest GitHub release two minutes after start and
  periodically, raises an "Orbis X is available" event once per version, and shows a banner on
  every page with the release notes.
- **One-click update on standalone installs.** A node running the bare binary under systemd
  downloads the release for its architecture, verifies it against the release's
  `sha256sums.txt`, confirms the new binary reports the expected version, keeps the old one as
  `orbisd.prev`, swaps and restarts the service. The page reloads when the new version is up.
  A binary started by hand is replaced and asked for a restart; a Docker node is told to pull.
- Updates card in Settings, About & diagnostics and in simple Settings: current and latest
  version, "Check now", "Update now", progress, release notes.
- Assistant tools `check_update` and `apply_update`.
- Headless `sudo orbisd -update` walks the same path from a shell.
- Releases now publish `sha256sums.txt` next to the binaries.

## v1.25.3 and earlier

See the commit history. Highlights of the 1.25 line: CPU and memory of the node shown on the
Overview, About and simple Home; cached configuration snapshots and memoised aggregates that
cut idle CPU on a Raspberry Pi 4 by roughly two thirds; the country rule guards that followed
the DNS outage caused by an enabled allow list with no countries.
