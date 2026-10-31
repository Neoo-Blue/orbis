# Changelog

Each release on GitHub carries the section below that matches its tag. Orbis shows the same text
under "Show release notes" when it offers an update.


## v1.36.0

Orbis is now far easier to get around, it moves, and a blocked site can be asked for and opened in one
tap.

### Added
- **Ask to unblock.** The block page has a button to ask for the site, with an optional note. Whoever
  runs the network answers 1 hour, Today, Always or Deny from Needs you on the Overview, from
  Protection, Requests, or from a one-tap link in a notification that needs no sign-in. The person
  waiting does nothing: their page opens the site by itself, though a browser can take up to a minute
  to let go of the old answer.
- **Answer from your phone.** Protection, Requests sets up ntfy, a free push app with no account and
  nothing opened on your network. Each request arrives with Allow 1 hour and Deny on the notification
  itself. The buttons need the phone on home Wi-Fi or Tailscale.
- **Trusted devices.** Mark your own devices under Protection, Requests and their block page offers
  Unblock for an hour with no request.
- **Approvals are their own thing.** Each one covers one device for a set time unless you say
  otherwise, ends by itself, and can be ended early under Open right now. No blocklist is touched. A
  site on a threat list takes a second tap and is limited to one device for a limited time.
- **Why, in place.** A stopped row on the Overview or in the DNS log opens the decision in a drawer,
  with Allow or Block right there and Undo afterwards.

### Changed
- **Six sections instead of 29 links:** Overview, Traffic, Devices, Protection, Network and System,
  with each section's pages as tabs. A section remembers the tab you left it on, every old link still
  works, and 1 to 6, the [ and ] keys and / move around without the mouse.
- **Going back is instant.** The last eight pages stay ready, keeping their filters and scroll
  position, and page code is fetched before you ask for it.
- **It moves.** Pages slide the way the navigation is laid out, markers glide between tabs, numbers
  run to their new value, new rows arrive, drawers and toasts come and go, and loading holds the shape
  of the page. The Overview chart draws itself in, shows traffic travelling along its lines and keeps a
  slow watch round the shield. All of it stops if your system asks for reduced motion.
- **The Overview answers to the pointer.** Hovering a device or a stopped site lights it on the chart
  and in the lists, rows carry Allow and Pause, the history has a value under the pointer and a range
  to pick, and a device opens over the chart.

### Fixed
- **The block page could not appear on a device without the Orbis certificate.** Such a device was sent
  the sinkhole, which also shut off plain http. It now fails HTTPS at once and keeps the page, so a
  browser falling back from https shows it.
- **Hosted apps crashed on a node with no storage devices.**
- **Aggressive lists broke the Facebook app.** They block `b-graph.facebook.com`, the server the app
  depends on, along with its fallback and live connection. Those three now have a built-in exception,
  while Facebook's real trackers stay blocked.
- **Orbis told Firefox it could skip the filter.** Firefox asks `use-application-dns.net` whether a
  network allows encrypted DNS, and any answer, even a block, means yes. It now gets NXDOMAIN, the
  agreed no, so Firefox stays on the network's resolver unless someone has forced it on.

## v1.35.0

The interface is new, DNS is never stale, and the whole node does far less work. On the reference
Raspberry Pi 4: forwarded lookups fell from 79 ms to about 20 ms, cached ones from 2.5 ms to under
1 ms, the Go heap from about 600 MB to about 130 MB, and no log rows are dropped.

### Added
- **The block page.** A browser opening a blocked site gets a page saying what stopped it: the
  rule, the list, the device, and one line drawn from the device through each stage to the decision,
  with a link to review it in Orbis. It works on plain http for everyone, and on https for devices
  that trust the Orbis certificate. A device that refuses the certificate is detected after three
  tries and goes back to failing quietly for a day, so nobody is left looking at certificate
  warnings, and an ad inside someone else's page still fails silently. Only a name blocked in its
  own right gets the page. A name that merely leads to a blocked one, or sits in a blocked country,
  keeps the plain sinkhole: that name belongs to whoever runs it, and pointing it at this node would
  hand their page the node's origin. Settings, DNS, "Show a page when a site is blocked".
- **The orbit chart.** The Overview now answers "is my network safe?" in one sentence, beside a
  live map of the network: Orbis at the centre, devices on their orbits by what they are, each
  reaching the world through the gateway, and traffic running round the rim in one line per region
  as thick as the bytes on it. Blocked lookups stop at the shield and leave a mark you can open. Every
  warning now sits in one list, Needs you, beside what was just stopped. Simple mode's Home carries
  the chart too.
- **Internet health.** Continuous monitoring of the gateway and public resolvers, with latency,
  jitter, loss, 24 hours of history and an outage log. It tells you in one sentence whether a
  problem is your network or your provider.
- **Change timeline.** Every saved configuration is kept, the last 200 of them, with what changed and
  a line-by-line comparison, secrets hidden. Restore any version in one click. For anything touching
  the network it asks you to confirm within 60 seconds and rolls itself back if you cannot, so a
  change that cuts you off undoes itself, even if the node restarts or loses power in that minute.
  The rollback reloads the firewall too. Config edits are refused while a restore waits, and it
  tells you which changes only take effect after a restart, because the timer cannot test those.
  Neither a restore nor a rollback brings back an old admin password.
- **Zone matrix.** Firewall, Zone matrix: a grid of what happens between every pair of zones, with
  the rules that apply and the last hour of traffic in each cell. On a node in observe mode it says
  this is what would apply, not what is applied.
- **Every decision can be traced.** A blocked row in the DNS log, or a mark on the orbit chart's
  shield, opens the same route line the block page draws.

### Changed
- **A new look across both interfaces:** a star-atlas plate, Prussian blue with brass hairlines,
  jade for safe and vermilion for blocked, violet kept for a traced decision, set in Geist.
  Destructive buttons stay outlined until you mean it. The fonts are built in; the interface still
  makes no outside requests.
- **Restarts are quick.** The built block index is kept on disk, so filtering is back within seconds
  rather than after two and a half minutes, and shutdown no longer waits out its 20 second timeout.
- **Vermilion means a block or a threat, nothing else.** Faults such as a lost gateway are amber, so
  anything red on screen can be opened and traced to what decided it. The Overview's sentence, its
  mark and the chart's lines all share one state, so a fault can never sit on the safe colour.
- **The Overview says what each layer is doing:** DNS filtering, firewall, in-stream ads and threat
  feeds, each on, off or not enforced. Node CPU, memory and temperature moved into Subsystems.
- **The firewall opens ports 80 and 443 to your lan and vpn zones** when the block page is on, in inline
  mode. Everything else from your non-WAN zones gets a reset, so a blocked name fails at once on every
  port and in every zone rather than timing out. Guest and IoT zones still cannot reach the interface.
- **Traffic to Orbis itself skips the filter proxy,** so the block page sees the real device.
- **URLhaus now comes from AdGuard's compiled feed.** abuse.ch withdrew its free downloads. Existing
  installs move over on their own. 1Hosts (mini) switches itself off: it has been empty since March 2025.
- **Lists refresh together, overnight.** A pass takes everything due soon, between 02:00 and 05:00
  local time, and a list that has not changed costs nothing. Lists used to drift onto separate
  clocks, which rebuilt the whole index about once an hour.
- **Upstream DNS connections stay open.** Each miss used to pay seven TLS handshakes.
- **`dns.min_ttl` is gone.** It is ignored if present. Raising a TTL is what served a 60 second record
  for an hour.

### Fixed
- **NXDOMAIN reached clients as an empty success,** and so did SERVFAIL from an upstream. Every dead
  name on the network looked like a live one with no address.
- **The first upstream reply won the race even when it was SERVFAIL or a stale NXDOMAIN.** A real
  answer now wins outright, and "does not exist" needs a majority of resolvers.
- **A list refresh stopped all logging.** Each refresh rewrote the whole list in one transaction,
  which held the write lock for over 30 minutes on the largest list and dropped 125,000 log rows
  a day. Refreshes now write only what changed, in short transactions. This is also what tripped
  the interception load guard.
- **The write-ahead log grew past 1 GB** and is now cut back once it has been checkpointed.
- **A geo repair held the database write lock for minutes after every boot.** Logging stopped, devices
  and open ports failed to save with "database is locked", and a restart in that window waited out
  the 20 second shutdown timeout with DNS already down. It now runs only when a GeoIP database
  changes, reads and writes in small steps without holding the lock, and stops with the daemon.
- **A list download cut short by a restart was reported as a failed list.**
- **Cloaked trackers went upstream on every lookup,** because blocked CNAME answers were never
  cached. They now cost one query per TTL, and a rule change reaches what is already cached.
- **Every cached and allowed lookup scanned all 1,200 list regexes,** 2.5 ms a time on a Pi. A verdict
  is now remembered per name.
- **Lists answering "not modified" were fetched again every hour.**
- **Answers larger than the client asked for were sent over UDP anyway,** the EDNS flags of cached
  answers were being rewritten, and client cookies were forwarded to upstream resolvers.
- **Losing a race counted as a failure,** which took slower resolvers out of the pool.

### Faster
- Live events reach only the page that wants them, so the shell no longer re-renders four times a
  second. Opening Orbis takes one round trip instead of three, `/api/status` no longer forks
  `tailscale` on every poll, and hidden or paused views stop fetching.
- Flows are written every 30 seconds rather than 5, and repeat updates of one flow coalesce, which
  cuts most of the node's writes. A redundant index on the blocklist table is gone.
- The block list index needs about a fifth of the memory and nothing for the garbage collector to
  scan.
- The globe keeps its markers instead of rebuilding them on every live tick, hover is once a frame,
  and the flat map stops drawing when hidden.


## v1.34.0

### Added
- **Smart unblock.** Settings, Assistant, TypeSafe: "Suggest unblocks for blocks that break things".
  Every hour TypeSafe is asked what the names your devices keep getting refused are for. A
  push-notification, sign-in, app, update or content host that only one to three ad lists block is
  probably collateral damage from an aggressive list, and becomes an allow suggestion on the
  Assistant page. Turn on "Unblock the clearest ones automatically" and push, sign-in, app and
  update hosts blocked by one or two lists are allowed at once: at most three a day, each announced
  as an event, undoable from the Assistant page (an undone name is never unblocked automatically
  again), and withdrawn after a week unless something still uses it. Names on malware or DNS-bypass
  lists, Orbis's own policy blocks and your own blocks are never touched.
- **TypeSafe triages anomaly alerts.** With TypeSafe on and AI triage enabled, each finding is
  judged on its own against the device and the destination's name, port, country and network
  operator. One with an ordinary explanation (update checks, sync, push, a tunnel you run,
  peer-to-peer) is lowered to notice or info; one with none keeps the detector's severity. It
  never raises a finding.
- **Unknown devices get a type.** Virtual machines and containers (Proxmox, VMware, Xen and
  Parallels network cards) are recognised as servers. With "Identify unknown devices" on,
  TypeSafe names the rest from their hostname, vendor and the names they look up most: a device
  resolving Samsung TV services is a TV, one calling a robot-vacuum API is an appliance. A
  classification is only applied when TypeSafe is at least 60% sure, and never replaces one the
  built-in rules made.

### Fixed
- **No more "regular check-in" alerts for traffic inside your own network.** The beaconing
  detector flagged devices talking to this node, the router, the broadcast address and tailnet
  peers; on one home network that was 85 of 752 alerts in a week. Only destinations out on the
  internet are considered now.
- **A DHCP lease arriving while a device was being read could crash the daemon.** Every copy of
  a device the registry handed out shared its details map with the live record, which a new
  lease writes to. Copies now own their details.

## v1.33.0

### Added
- **TypeSafe can judge ad and tracker hosts.** Settings, Assistant, TypeSafe domain judge: turn it
  on and paste a key from console.typesafe.ai. Smart capture and the domain tester's "Ask the
  assistant" then ask TypeSafe's Jev model two typed questions per host (is it ad or tracking
  infrastructure, and how likely is a block to break something) and get calibrated probabilities
  back in about a third of a second, at a fraction of a cent per thousand hosts. It works with no
  chat model configured; when one is, it takes over if TypeSafe fails. Chat, briefs and reviews
  are unchanged.

### Fixed
- **Smart capture now asks the model about hosts it only saw in DNS.** Its heuristics measure
  referrers, response sizes and paths, so a host seen only as DNS lookups scored zero for lack
  of evidence and the model was never consulted; on a DNS-only node no candidate was ever
  judged. Each such host is now asked about once. Because a verdict on the name alone has
  nothing to be blended with, it stands on its own, and it can only send the host to review,
  never block it. Hosts waiting for review no longer crowd unjudged ones out of each pass.
- **A host keeps its smart-capture evidence through a quiet interval.** Referrers, response
  sizes and paths seen on an earlier pass used to be overwritten by the next pass that saw only
  DNS, so a likely beacon's score fell back toward zero whenever it went quiet for 15 minutes.

### Changed
- **The installer's output is easier to read.** Steps in cyan, warnings in yellow, errors in red,
  the success line and the address to open in bold green, secondary lines dimmed; the daemon's
  own log lines while it writes the units and systemd's symlink message are silenced unless
  something fails. Colour is skipped when the output is not a terminal or `NO_COLOR` is set.

## v1.32.1

### Fixed
- **Explain, Ask about a domain, Run review, Write a brief and Run an assessment no longer fail
  through the tunnel.** Each ran the model chain inside the request, up to two minutes on the
  free models, longer than Cloudflare waits for an origin, so from outside the LAN they came
  back as a 502 page. They now start in the background, the page asks again every few seconds,
  and the answer is handed back when it is ready. A client that gives up no longer cancels the
  work, and a second click while one runs joins it instead of starting another.

## v1.32.0

### Added
- **A guided first run.** The first screen after install sets everything a new node needs, in
  eleven short steps with a sensible default at each: the admin password (now, or skip and set
  it later), the node's name, time zone and location, simple or advanced interface, watch-only
  or gateway, what to run, the upstream resolvers, blocklist presets, the optional assistant and
  notifications, and finally the node's address to point the router at, with the placement check
  updating live as devices start using it. Optional steps can be skipped, a reload resumes where
  you were, and nothing secret is kept in the browser between reloads.
- **The one-line installer installs the latest release** rather than the nightly build
  (`CHANNEL=nightly` keeps the old behaviour), handles Arch, Fedora and openSUSE package names as
  well as Debian and Ubuntu, refuses cleanly on hosts without systemd with a pointer to the
  Docker path, warns on WSL where the node cannot see the LAN, persists every kernel setting the
  daemon needs and loads `nf_conntrack` at boot so they apply, waits for the service to answer
  before claiming success, and ends with the address to open and what the guided setup will do.

### Fixed
- **A request no longer waits behind a blocklist import to write its audit entry.** On a fresh
  node the default lists import for a minute or more; every step of the wizard, and any other
  audited action, waited on that lock for five seconds or more. Audit rows are written off the
  request now.

## v1.31.0

### Added
- **The globe colours connections by what they are for.** Streaming, social and messaging,
  gaming, web, DNS and other each have their own colour, chosen from the connection's service,
  app, name and port, so a household can see at a glance what the network is doing. The legend
  and the connection card name the kind. A blocked connection stays red in every colouring, so a
  rejected connection is always visible as one. The old colouring by verdict (allowed, blocked,
  filtered) is a toggle in the globe controls, and the choice is remembered.

## v1.30.6

### Fixed
- **Applying the kernel settings really persists them now.** 1.30.5 wrote the files but the
  daemon's hardened unit mounts `/etc` read-only, so the write failed silently while Apply
  reported success. The unit now allows `/etc/sysctl.d` and `/etc/modules-load.d` (a drop-in
  on already-installed nodes: `ReadWritePaths=/etc/sysctl.d /etc/modules-load.d`), and Apply
  reports `persisted` with the reason when it could not.

## v1.30.5

### Fixed
- **Applying the kernel settings survives a reboot.** The Apply button wrote the live values
  only, so the "kernel settings need attention" warning came back after every restart of the
  node. It now also writes `/etc/sysctl.d/99-orbis.conf` and asks the boot process to load
  `nf_conntrack` first, since the connection-tracking settings do not exist until it is loaded.

## v1.30.4

### Fixed
- **Explaining an address no longer borrows another device's event.** The explanation for an
  address was given the node's whole recent threat-hit list, and the model folded an unrelated
  device's hit into its answer (a Google address "blocked as hijacked" with the NAS's port and
  destination). It now sees only hits in which that address is one end.

## v1.30.3

### Fixed
- **The globe's live connections name their destination.** A connection that arrived over the
  live feed was shown as "name not visible" even when the flow carried the name; the card now
  reads it the same way the history view does, and a plain-HTTP connection says its name came
  from the request rather than from a TLS handshake.

### Changed
- **The assistant's explanation of a threat event sees what the device was doing.** It now gets
  the two minutes either side of the event: how many connections, to how many addresses and
  ports, how many got nothing back. A NAS contacting one listed address in the middle of a
  torrent's peer burst reads as what it is, instead of "critical, investigate immediately". The
  prompt also tells the model not to claim a drop the record does not report.

## v1.30.2

### Fixed
- **Opening a device no longer crashes the Devices page.** The simple interface's pause and
  resume routes were mounted as their own router at `/clients/{id}`, and that router's catch-all
  answered every other device path (`/clients/{id}`, `/flows`, `/destinations`, `/dns`) with the
  interface's HTML page. The drawer took the page for a device record and died on the first
  field it read. The routes are plain routes now, and the API client refuses an HTML body as
  data so a fall-through can only ever show an error, never crash a page. This predates 1.30.0
  but the clickable Overview rows led straight into it.
- **The simple Home no longer crashes on a node with nothing to report.** A clean bill of health
  arrived as `null` instead of an empty list.
- **The simple Home no longer crashes when ask-first is off.** Its new request counter read a
  queue the status does not carry when the feature is disabled.

## v1.30.1

### Fixed
- **The interface no longer waits seconds before it draws anything.** Every load checked whether
  other devices use this resolver by counting distinct clients across the whole lookup log, a
  million rows on a two-week retention, before the first page could render. The check now looks
  at the last day.
- **The globe no longer freezes for up to 16 seconds every minute.** Its country totals grouped a
  day of flows, and SQLite chose to walk the whole five-million-row table through the country
  index rather than the time index. The query now names the time index, and the answer is served
  from cache while a fresh one is computed in the background. The same stale-while-revalidate
  cache now covers the 24-hour summary, the health hero, top destinations and the biggest
  connections, so a page poll never waits on an aggregate after the first call; cache keys are
  by window length, not start time, so the entry is refreshed in place rather than recomputed
  under a new key on every poll. Retention pruning also runs `PRAGMA optimize` so the planner's
  statistics stay current.
- **The Reports page no longer crashes on a day with nothing to rank.** An empty list arrived as
  `null` and the page read its first element.
- **A report no longer takes fifteen seconds to build.** It pulled up to a hundred thousand
  lookup rows to count them; it now reads the cached summary.
- **A week-long report no longer hangs the page.** The Reports page opened on a seven-day window
  that takes minutes to assemble on a small node. It now opens on the last day, and a longer
  window is assembled in the background while the page says so and asks again, then kept for ten
  minutes.
- **Loading the interface no longer forces a cable rescan.** The onboarding state asked the link
  watcher to rescan on every load; it now reads the scan the watcher already keeps fresh.

## v1.30.0

### Fixed
- **The live UI no longer drops every two minutes.** A global request timeout cancelled the event WebSocket (and then tried to write a 504 onto the hijacked connection) and cut assistant replies that ran longer than 120 seconds. Those paths are now exempt; ordinary API calls still time out.
- **A live-event filter change no longer races the writer.** Updating the WebSocket subscription wrote the filter map from a second goroutine while events were being looked up in it.
- **Assistant replies no longer interleave with keepalive comments.** The SSE callback and the keepalive ticker both wrote to the same response; concurrent writes can tear frames and panic the server writer. They now share a lock.
- **Changing the admin password signs every other session out.** Sessions are HMAC cookies with no revocation table, so a stolen cookie stayed valid for 30 days after a password change. Setting a new password now rotates the signing key.
- **Login brute-force tracking no longer trusts `X-Forwarded-For`.** chi's RealIP middleware rewrites `RemoteAddr` from request headers, which chi itself documents as spoofable. Five failed logins attributed to a public address would ban that address for an hour. The TCP peer is used instead.
- **CORS, when enabled, no longer claims credentials against `*`.** Browsers reject that combination, so a remote UI could not call the API. CORS is for token headers, not the session cookie.
- **The setup password button stays disabled until the password is long enough.** The API already requires 10 characters; the form submitted shorter ones and showed the error afterwards.
- **The log writer no longer stalls behind a blocklist refresh.** Replacing a changed list deleted
  its old rows with a full scan of the 4.5 million-row domain table (there was no index on the
  list name) and then inserted the new rows one statement at a time, all while holding the write
  lock. On a Raspberry Pi that took minutes, during which the flow and DNS log filled its memory
  buffer and dropped rows (66,000 in three days on the reference node) and other writers failed
  with "database is locked". The list name is now indexed (built in the background a few seconds
  after start so DNS is not delayed; the first build still holds the write lock once) and rows are
  inserted 64 to a statement.
- **The write-ahead log no longer grows without bound.** It was only truncated after the six-hourly
  prune, and the pooled readers kept the automatic checkpoint from finishing, so it reached
  950 MB and every read had to consult it. The writer now checkpoints once a minute and the log
  is capped at 64 MB after a checkpoint.
- **Retention pruning no longer holds the write lock for minutes.** Old flows and lookups are
  deleted 20,000 rows at a time with a pause between chunks.
- **Listing devices no longer copies and sorts every live connection.** The device list counted
  flows per device by taking a full sorted snapshot of the live table, tens of thousands of rows
  on a busy network, every time a page polled it. It now counts in place.
- **Top-destination and biggest-connection panels are answered from a short cache.** Sorting a
  day of flows by bytes reads every row in the window; the overview asked for that every 30 s
  and Analytics per device. Those answers are now kept for 30-60 s like the summary already was.
- **Smart capture no longer runs one statement per sighting.** A domain seen 50 times in a pass
  was written 50 times; it is now one additive write.

- **A cached answer no longer serialises every lookup behind a deep copy.** The resolver copied
  the cached message while holding the cache lock; concurrent queries for anything waited for it.
  The copy now happens after the lock is released.
- **Resolver and event-bus counters are atomic.** They were plain integers incremented from every
  listener goroutine and read by the API, a data race the race detector flags.
- **A panic while forwarding can no longer wedge a name.** Duplicate concurrent lookups collapse
  onto one upstream call; if that call panicked, every later lookup for the name waited forever.

### Added
- **Answers are refreshed before they expire.** When a cached name is asked for in the last tenth
  of its TTL, Orbis serves the cached answer and fetches a new one in the background, so a name the
  network asks for constantly never pays the upstream round trip again. Answers shorter than ten
  seconds are left alone. The cache reports `prefetches`.
- **DNS answer latency is measured.** `/metrics` exposes `orbis_dns_answer_seconds`, a histogram
  of every answer from 1 ms to 1 s, and the resolver status carries the same buckets. "Is DNS
  slow" was a guess before.
- **API responses are gzip-compressed**, including the hashed interface assets. A day of
  connections was several megabytes of repetitive JSON over Wi-Fi. The live event stream and the
  assistant's reply stream are left uncompressed so they are never buffered.

### Changed
- **SQLite is tuned for an SD card.** Commits use `synchronous=NORMAL` under the write-ahead log
  (a power cut can lose the last moments of traffic log; the database stays consistent), each
  connection has a 16 MB page cache instead of 2 MB, the file is memory-mapped up to 256 MB, and
  flow rows are written 32 to a statement instead of one.

### UI
- **Pages load on demand.** Every page was compiled into one 895 KB script, and the 3D globe's
  renderer was preloaded on every route. The first paint now downloads 269 KB; each page fetches
  its own chunk when opened and the globe's renderer only when the globe is.
- **A busy network no longer re-renders the whole interface per lookup.** Live events are batched
  four times a second instead of once per WebSocket frame.
- **Polling pauses in a hidden tab** and resumes with a fresh fetch when the tab returns; a tick
  is skipped while the previous request is still in flight, so a slow node is not asked twice.
- **The globe stops drawing while its tab is hidden.**
- **Search results land where they point.** Choosing a setting from the command palette opened
  Settings on its first section because navigation rewrote the hash; a device result opened the
  list, not the device. Both now open the exact target, and `#/clients/<id>` is a link.
- **Each sidebar heading appears once.** Assistant and Problems, both in the Operate group, were
  rendered as two sections.
- **Timed pause on the advanced Devices page.** The 30 min / 1 h / 3 h / until-resumed pause that
  the simple interface had is on every device row and in the device drawer, with the time it
  lifts shown on the device and a Resume button while it is paused.
- **Overview rows act.** A busiest device opens that device, a blocked name opens Ad blocking, a
  heavy connection opens Connections, an event opens Events.
- **Destructive actions confirm in the app**, not with the browser's dialog: a titled sheet with
  Cancel and a red confirm, Escape cancels, focus returns to where it was.
- **Labels are attached to their fields, search has a name, drawers take focus when they open,
  and text inputs keep a visible focus ring.** Buttons and tabs are at least 36 px tall on a
  phone.
- **Empty states say what to do next** instead of only that there is nothing.
- **Ask-first requests show on the simple Home** as "N requests waiting for your OK" when there
  are any, linking to the inbox.

## v1.29.1

### Fixed
- **The interception load guard no longer blames interception for a restart.** On a Raspberry Pi
  the index rebuild and the first blocklist refresh after a start keep the database writer 60-100%
  busy for about ten minutes with nothing intercepted, which would have turned interception off
  after every restart. The guard now ignores the first ten minutes after a start and any time a
  blocklist refresh is running; those minutes neither count toward the five nor reset them.

## v1.29.0

### Fixed
- **An intercepted device that took a new address was left half-routed.** Interception tells a
  device, by its hardware address, that Orbis is the gateway, but brings its replies back and
  filters its lookups by its IP address. When the router handed an enrolled laptop a new lease,
  Orbis kept pulling the laptop's traffic in while matching only the old address, so its requests
  went out through Orbis and its answers came back around it. Sites failed to load and sign-ins
  such as Duo timed out, which looked like a DNS problem. Orbis now follows the device: when it
  shows up at a new address and answers for it, the enrolment moves with it, and until then the
  device is sent back to the router rather than intercepted on a guess.
- **A device left pointing at Orbis finds its way back to the router.** Turning interception off
  sends each device the router's real address, but a Windows laptop whose connections kept working
  through Orbis never asked again and stayed half-routed for as long as it was busy. In observe
  mode Orbis now notices any device on the LAN that sends it traffic without being intercepted and
  tells that device, and only that device, where the router is. It spots them from the packets it
  captures and from one-way connections in the kernel's connection table, which also catches a
  device that only sends UDP, such as a VPN or Wi-Fi calling. The message to a device also names
  its current address, and announces the router as well as answering for it. A device that keeps
  coming back is told less and less often, down to every 15 minutes: a sleeping Android phone's
  Wi-Fi chip replays its Wi-Fi-calling keepalive with the address it learned before, and nothing
  on the network reaches it until the phone wakes.
- **Putting a device back on the router no longer impersonates the router to the switch.** The
  frames that tell a device where the router is carried the router's hardware address as their
  Ethernet source, which teaches a switch that the router lives on Orbis's port and sends
  everyone's gateway traffic there until the router next speaks. They now come from Orbis's own
  address; the router's is only in the part the device reads.
- **The router and the Orbis node itself can no longer be enrolled.** Intercepting the gateway
  made the router see its own address on another machine. Existing entries for either are removed
  with an event saying so, and the enrol button refuses them.
- **Logging lookups and connections never waits for the disk.** When the queue of rows to write
  filled up, the connection tracker and the DNS handlers wrote it out themselves and waited behind
  whatever held the database, which on a Raspberry Pi could be a blocklist refresh for minutes.
  Rows now wait in memory for the writer; if the disk falls far behind, the newest are dropped and
  counted instead.

### Added
- **Interception turns itself off when the node cannot keep up.** Every intercepted device's
  connections are written to the database, and enrolling storage and servers can bury a small
  node's disk until the whole daemon stalls. If the writer is busy more than 60% of the time for
  five minutes in a row, or has to drop rows, while interception is on, Orbis sends every device
  back to the router, saves interception as off, and raises a critical event explaining why.
- `/metrics` reports the log writer (`orbis_store_pending_rows`, `orbis_store_busy_seconds_total`,
  `orbis_store_dropped_rows_total`, flush counts) and interception (`orbis_intercept_running`,
  `orbis_intercept_targets`).

## v1.28.6

### Fixed
- **The sponsor skip could jump the viewer forward after an ad.** The playhead is worked out
  between the player's reports by adding the time that has passed, and the content does not
  advance while an ad is on screen. A pod of ads was being added to the position all the same,
  so the first check after the ads saw a playhead a pod's length ahead of the viewer and seeked
  past a sponsor segment they had not reached yet.
- A television that has been playing quietly sends one report on connect, naming the video and
  giving the position together. The position was being filed under the video that came before it
  and discarded with it, so an unskippable ad on such a set was never reloaded past.
- Some televisions report the ad as the video they are playing. That was read as the viewer
  moving to another video, which threw away the position the reload needs.

## v1.28.5

### Fixed
- **YouTube on a television jumped back in the video.** When an unskippable ad could not be
  skipped, Orbis reloads the content past it and asks the player to resume where the viewer was.
  It worked out that position by adding the time since the player's last report, but a television
  reports nothing about the content while an ad is on screen, so the seconds spent watching the
  ad were counted as content watched. A pod of ads made it worse: each ad in the pod worked the
  position out again from the one before, so a video the viewer had barely started was reloaded
  several seconds in, and one they were deep into was reloaded near its beginning. The position
  is now taken only from the content's own reports, captured once when the pod begins, and a
  reload is only sent when Orbis actually knows where the viewer was.
- A state report carrying neither a position nor a duration is a load transition, which a
  television emits between the ads of a pod. It was being read as the content saying it was at
  zero, which erased the place the viewer was.

## v1.28.4

### Changed
- The in-stream filter proxy now logs why a client's connection was passed through or why its
  handshake failed, once per client and host every five minutes, so a device that will not accept
  filtering can be understood from the journal instead of guessed at.

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
