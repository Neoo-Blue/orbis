# Changelog

Each release on GitHub carries the section below that matches its tag. Orbis shows the same text
under "Show release notes" when it offers an update.

## v1.27.0

### Added
- **AdGuard Home and Pi-hole list compatibility.** The list parser now understands the whole of
  what those two accept: AdGuard rules with exceptions (`@@||cdn.example^`), `$important`,
  `$denyallow`, wildcards inside rules, `/regex/` rules, Pi-hole regex lists with their `;` options,
  hosts files with several names per line, dnsmasq, unbound `local-zone` and RPZ `CNAME .` lines.
  Exceptions in a list apply the way AdGuard applies them, an `$important` block beats a list's
  exception but never your own allow, and every rule DNS cannot honour (cosmetic, URL paths,
  `$dnstype`, `$client`, rewrites to real addresses) is counted rather than misapplied.
- **Allowlist and regex subscriptions.** A list can be marked as an allowlist (AdGuard Home's
  whitelist filters) or as a regex list (Pi-hole's regex.list). Your own rules can be regular
  expressions too.
- **Import a whole Pi-hole or AdGuard Home.** Domain tester, Import a list takes a Teleporter
  backup (v5 JSON or v6 gravity.db), Pi-hole's adlists, domain and regex lists, or
  `AdGuardHome.yaml` with its filters, allowlist filters and custom rules. Subscriptions become
  subscriptions, custom rules become your rules, and the preview shows what was skipped and why.
- **Popular lists.** One click on the Ad blocking page adds AdGuard DNS filter, OISD, HaGeZi
  (including its threat-intelligence feeds), URLhaus, Phishing Army, EasyPrivacy, Peter Lowe,
  NoCoin, WindowsSpyBlocker and the smart-TV list.
- **AI threat intelligence.** With the assistant configured, a scheduled assessment reads the
  window's attacks, threat-feed hits, anomalies, bans, blocked lookups and busiest destinations and
  writes a risk level, findings in plain words and the actions it would take. Threats, AI intel
  shows it; the simple Protection page shows the short form; assistant tools `threat_intel`,
  `run_threat_intel` and `decide_ai_action` expose it in chat.
- **AI active blocking.** Off by default. When on, proposed timed bans and domain blocks at or
  above the confidence you set are applied at once, at most N per check and never longer than the
  ban limit, audited and announced as events, and each one has an Undo. A guard rail refuses
  essential services, CDNs, update, certificate and time hosts, local names and anything on the
  never-act-on list whatever the model says.
- **Explain this.** Every event on the Events page and the simple Alerts page has a button that
  asks the assistant what it is, how dangerous it is, and what to do. The assistant tool `explain`
  does the same for events, intrusion alerts, addresses and hostnames.
- **Ask the assistant** on the Domain tester: an ad-or-tracking verdict for any hostname with
  confidence and breakage risk.

### Changed
- List entries are stored with their kind (exact, wildcard, regex, exception) and importance, so
  a subscribed AdGuard list behaves as it does in AdGuard Home.

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
