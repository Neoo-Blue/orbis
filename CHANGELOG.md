# Changelog

Each release on GitHub carries the section below that matches its tag. Orbis shows the same text
under "Show release notes" when it offers an update.

## v1.28.3

### Fixed
- **Pinned mobile apps behind the in-stream filter.** The YouTube app on a phone that is a
  filter client closes the connection the moment it sees the proxy's certificate, without a TLS
  alert. The proxy only counted alerts and silence as rejections, so the bypass never tripped and
  every thumbnail request failed the same way. An abrupt close or reset after the certificate now
  counts too; two on one host within five minutes splice that host through for a day, as before.

## v1.28.2

### Fixed
- The hourly list refresh rebuilt the whole index even when every list came back unchanged. It
  now rebuilds only when a list actually changed.

## v1.28.1

### Fixed
- **Every name was being blocked.** The v1.27.0 parser turned URL-pattern rules from AdBlock
  lists into regular expressions. One EasyPrivacy rule ending in a bare `|` became an empty
  alternation that matched every hostname, and the resolver sinkholed the whole network. Lines
  with AdBlock syntax now never reach the regex path, unanchored patterns with wildcards are
  skipped as URL patterns, and any list regex that matches an ordinary name such as example.com
  is rejected both when parsing and when building the index.
- **The index was rebuilt on every rule change.** Each discovered ad host, quick allow or block
  rebuilt all six million list entries from the database, taking a core for a minute and a
  second copy of the index in memory. The operator's rules and the configuration's overrides now
  live in a small overlay checked first; a rule change rebuilds only that, and full rebuilds that
  arrive while one is running are coalesced.
- **Allows cover subdomains.** Allowing a site allows its hostnames too, which is what breaks a
  site and what a person means.

### Changed
- The Domain tester names the list that blocked or excepted a name, instead of "list".
- The service unit caps the daemon at two cores' worth of CPU, so a rebuild or a scan cannot pin
  a small board's whole processor: peak draw is what browns out a Raspberry Pi on a weak supply.

## v1.28.0

### Added
- **A safety net for when Orbis itself is down.** Seven layers, each shown with its state under
  Settings, Safety net, and installed with one click or by the installer:
  - **Restart after a crash.** systemd restarts the service two seconds after a failure.
  - **Restart when it hangs.** The unit runs a software watchdog, and the daemon only sends the
    heartbeat while its own resolver answers a test query, so a process that is alive but wedged
    is restarted too.
  - **Lifeboat when it cannot come back.** After five failures in two minutes systemd hands the
    network to `orbis-lifeboat`, a standby built into the same binary that forwards DNS without
    filtering, serves DHCP so every device keeps its address, keeps forwarding and NAT up on a
    gateway, and puts intercepted devices back on the real gateway. It opens no database, loads no
    list and talks to no model. It retries Orbis on a backoff, serves a plain status page with a
    "Start Orbis now" button on the usual address, and hands back the moment Orbis starts.
  - **Devices go back to the real gateway.** A release step runs after every stop, clean or crash,
    and tells intercepted devices the gateway's real address instead of leaving them pointed at a
    dead node until their ARP cache expires.
  - **A second resolver in every lease.** DHCP hands out this node first and a public resolver
    second (the first public upstream, or 1.1.1.1), so a dead resolver does not read as a dead
    internet. Nodes that are not the DHCP server are told what to put in the router instead.
  - **Reboot a frozen board.** Opt-in. Where the board has a hardware watchdog, the setting is
    written for systemd to arm at the next boot, never live: a frozen kernel then resets and
    Orbis is back in about a minute. Off by default, because a watchdog is a reset button held
    by software, and a board on a weak power supply already resets often enough.
  - **Traffic keeps flowing through restarts.** The ruleset lives in the kernel and stays through a
    restart or an update; only DNS and DHCP pause, and the lifeboat covers those.
- A runbook for the case no software can cover, the box itself dying, written for the node's
  placement: gateway, intercepting, or resolver only.
- Assistant tools `safety_net` and `install_safety_net`.

## v1.27.2

### Changed
- **The flat map opens centred on your network.** The projection's central meridian is the
  node's own longitude, so the home sits in the middle of the map and connections fan out both
  ways. From the US West Coast that puts Asia on the left and Europe on the right instead of
  every line crossing the whole map from the far left. Countries the seam cuts through are
  drawn whole at both edges.

## v1.27.1

### Added
- **The globe's connection card says what a connection is for.** A Service row names the
  service behind the hostname (YouTube, iCloud, Steam) or, when no name was visible, the company
  whose network it is (Google, Netflix, Akamai). The card also shows how the name was learned
  (a DNS lookup the device made, or the TLS handshake), names the device that opened the
  connection instead of its address, and offers a guess for unnamed connections from what the
  device is and where it went: a Synology talking to Taiwan is its QuickConnect relay, a Tapo
  plug talking to Singapore is TP-Link's cloud. "Ask the assistant what this is" is on the card.

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
