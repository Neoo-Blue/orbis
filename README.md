<div align="center">

# Orbis

<img width="1913" height="889" alt="Orbis globe view: live connections drawn as arcs from the network to the world" src="https://github.com/user-attachments/assets/3650f99c-d682-4e5c-a7b6-e938a7d18e13" />

**The firewall that follows the ad into the stream.**

A network firewall, a filtering DNS server, and three ad-removal engines at three different layers,
in one static binary with an embedded UI. It blocks what a blocklist can block, filters what only a
proxy can filter, and for the ads that live inside YouTube on a television it picks up the remote.

</div>

---

## Why this exists

Ad blocking on the network stopped working the day ads moved into the same connection as the
content. A DNS sinkhole cannot see a YouTube pre-roll, because the ad and the video come from the
same host over the same TLS session. A browser extension cannot see a television. Every product
in this space stops at one of those walls and calls the rest "not possible".

Orbis is built on the premise that each wall needs a different tool, and that the honest thing to
do is to say, per device, which tool applies and what it cannot reach.

| Layer | What it catches | What it needs |
|---|---|---|
| **DNS** | Ad and tracker hosts, first-party CNAME cloaks, DoH bypass, and a built-in list of the hosts smart TVs and streaming sticks use only for ads and viewing telemetry | Nothing on the client |
| **Wire** | Apps that hardcode IPs and never ask your resolver, matched on TLS SNI and decrypted QUIC Initials | Nothing on the client |
| **In-stream** | YouTube pre/mid-rolls and in-app ad payloads, stripped from the response before the page sees them, then an in-page engine that drives the player past anything that still starts, and SponsorBlock segments with no extension | The Orbis certificate on that device |
| **Player** | YouTube ads on a TV, Apple TV, console or Chromecast: Orbis attaches as a remote, mutes the ad on its first frame and skips it the moment YouTube allows | Nothing on the client, no certificate |

And underneath the ad engines, a real gateway: nftables firewall with zones and hit counters,
WireGuard and Tailscale in both directions, DHCP, multi-WAN, shaping, and a resolver that serves
DoT and DoH to your own devices.

## Where the others stop

This is not a claim to be better at what these tools do. It is a map of where each one ends and
where Orbis keeps going.

| | Pi-hole | AdGuard Home | NextDNS | pfSense / OPNsense | uBlock Origin | iSponsorBlockTV | **Orbis** |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| DNS blocklists, per-client policy | ● | ● | ● | ○ | | | ● |
| CNAME uncloaking | ○ | ● | ● | | ● | | ● |
| Blocks by TLS SNI and QUIC when DNS is bypassed | | | | ○ | | | ● |
| Strips YouTube ads from the response (with a CA) | | | | | ● (browser only) | | ● |
| In-page player engine and SponsorBlock without an extension | | | | | ● (extension) | | ● |
| YouTube ads on a TV or Apple TV, no certificate | | | | | | ● | ● |
| Per-ad ledger: what ran, for how long, why it ended | | | | | | | ● |
| Real firewall: zones, NAT, port forwarding, multi-WAN | | | | ● | | | ● |
| WireGuard server and client, Tailscale exit node | ○ | | | ● | | | ● |
| Every connection identified: host, app, ASN, country | | | | ○ | | | ● |
| Network map, live globe, anomaly detection | | | | | | | ● |
| IP threat feeds, timed bans, CrowdSec bouncer | | | | ○ | | | ● |
| Finds what you host (apps, containers, NAS) and forwards ports for it | | | | ○ | | | ● |
| Tells WAN from LAN by itself, runs a Wi-Fi network from a USB or built-in adapter | | | | ○ | | | ● |
| Block or allow whole countries, at DNS and in the packet filter | | ○ | | ○ | | | ● |
| Assistant with tools, MCP server | | | | | | | ● |

● built in · ○ partial or via add-on · blank: not in scope for that product

## The streaming ad problem, engine by engine

**The response filter.** With the Orbis certificate trusted, YouTube's InnerTube responses are
rewritten in flight: `adPlacements`, `playerAds`, `adSlots` and two dozen renamed relatives are
removed, promoted rows are dropped from feeds, and the ad reporting endpoints are answered locally
so the player never learns an ad failed to play. The inline `ytInitialPlayerResponse` in the page
is filtered too, so the first video of a session is not the one that slips through.

**The in-page engine.** Field names change; behaviour does not. A small ES5 script is injected as
the first thing in every YouTube document. It patches `JSON.parse` and `Response.json` to scrub ad
structures the static filter has not learned yet, and it watches the player itself: an ad break
that starts anyway is muted and driven to its end, a skip button is pressed the instant it
appears, overlay banners are closed. The same engine skips and mutes SponsorBlock segments, asking
Orbis for them over a same-origin path. The browser never talks to SponsorBlock, and it reports
its counters back to Orbis so the UI can show the layer is alive on a real screen. It runs in the
browser built into a Samsung or LG set as readily as in Chrome.

**The Lounge engine.** Televisions cannot install a certificate. So Orbis does what a phone does
when it casts: it attaches to the screen over YouTube's Lounge API as a remote control and watches
the same event stream the TV app emits. Every ad is handled as its own record: muted on the first
`adPlaying`, `skipAd` sent the moment `isSkippable` flips, retried on a schedule rather than
hammered, closed when the player says so. An ad pod is a sequence of records, not one long ad. And
because a television will sometimes go dark mid-ad and never say the ad ended, every ad carries a
deadline: past its own duration plus a grace period it is closed as *lost*, the volume comes back,
and the ledger says so. The history for each screen is in the UI, ad by ad: what ran, for how long,
skippable or not, how many skips were sent, and why it ended.

**The counters that tell the truth.** Some YouTube streams have the ad muxed into the video itself.
No filter anywhere can separate those bytes. Orbis counts server-stitched responses so a filter
that is broken and a stream that cannot be filtered do not look the same. A readiness panel
checks, separately, whether traffic reaches the proxy, whether TLS is being decrypted, and whether
ads are being stripped, because from the sofa every one of those failures looks identical.

### Coverage, stated plainly

| Screen | Engine | Needs | Result |
|---|---|---|---|
| Smart TV, Apple TV, console, Chromecast | Lounge | nothing | Ads muted from the first frame and skipped at the first chance; unskippable ads play muted |
| Laptop or desktop browser | Response filter + in-page | Orbis CA | Ads removed before the page sees them; anything that starts is driven past |
| TV browser, phone browser | Response filter + in-page | Orbis CA | Same as above |
| Mobile YouTube app | none | | Pins certificates, is not a castable screen. Cast it to a TV and the TV is covered |
| Server-side stitched ads | none | | Counted, not removed. Nothing on a network can |

## Everything else it is

**A full DNS server.** Filtering resolver with an LRU cache and a TTL floor, upstreams over plain,
DoT and DoH (encrypted by default), and a DoT/DoH server for your own clients so a phone keeps
using it off the LAN. It is happy to be nothing but the resolver: on a Raspberry Pi on port 53 it
replaces AdGuard Home or Pi-hole outright, lists and all. Local authoritative records with wildcards. Rewrites, conditional forwarding, per-client policies, safe search,
blocked-service bundles, rate limiting, rebinding protection.

**Ad blocking beyond the lists.** CNAME uncloaking, SNI and QUIC blocking for clients that never
ask your resolver, a DoH-bypass sinkhole, the built-in streaming-device list, and *smart capture*:
a heuristic pipeline (with an optional model) that scores hosts no list has caught yet and queues
them with evidence for a one-click verdict.

**Known-bad addresses, not just names.** Threat feeds (Spamhaus DROP, abuse.ch command
servers, addresses seen attacking) become nftables sets dropped in both directions, so a device
that never asks your resolver is still caught when it beacons to a listed address. Timed bans
from you, the assistant, the scan detector or a CrowdSec engine live in the same set.

**Knows what you host.** Every device is knocked on at ninety well-known ports and the page
behind each answer is read, so a Plex, a Home Assistant, a Portainer or a Synology is named
rather than numbered; a host that exposes its Docker Engine API names the container and image
behind each port. NAS and SAN devices are recognised by vendor and by the protocols they serve
(SMB, NFS, AFP, iSCSI, rsync, WebDAV), with who is using them right now and whether any of it is
exposed to the internet. Each service has a Forward button: a DNAT rule when this node is the
gateway, a UPnP mapping on the upstream router when it is not, with a warning before anything
that has no business on the open internet.

**Knows which cable is which.** Physical ports are classified from the default route, the
neighbours answering on them and where the known devices live: this one is the internet, that
one is the network, that port is empty, the wireless adapter is the Wi-Fi network. A cable
plugged in later is noticed within seconds and either applied, when the evidence is clear and
you allowed it, or proposed with its reasons.

**Its own Wi-Fi network.** With a wireless adapter, Orbis broadcasts an SSID through hostapd on
its own subnet, with itself as gateway, DHCP and resolver, translated out through the wired
side. Every device that joins is fully behind Orbis, threat sets and country rules included,
even when Orbis is not the main router. Bridge mode attaches the adapter to an existing bridge
instead.

**Countries, not just names.** Block a list of countries, or allow only a list. The resolver
refuses names whose answers land there for every device, new connections are marked and killed
where Orbis is in the path, and in block mode the countries' address ranges are loaded as
packet-filter sets on every enforcement point.

**A real firewall.** Zones with trust levels, an ordered rule table with live hit counters, NAT and
port forwarding, time-based rules, IPv6, flow offload, an anti-lockout rule, all compiled into one
nftables ruleset and loaded atomically after `nft -c` validation.

**A VPN, both ways.** WireGuard server with QR enrolment, outbound WireGuard with policy routing
and a kill switch, and Tailscale as a subnet router and exit node in both directions.

**Into the path without being the gateway.** ARP interception inserts Orbis in front of selected
devices only, forwards and NATs their traffic, and restores them cleanly the moment it stops. Your
existing router stays the router.

**A map of the network.** Devices identified by MAC prefix, open ports, DHCP fingerprint and
behaviour, with confidence and evidence. Hypervisors with their guests clustered under them,
storage, endpoints, and the traffic between them. Multi-WAN failover, CAKE shaping, static routes,
NAT-PMP, Wake-on-LAN, ping, traceroute, speed test, pcap export.

**Sight.** Every connection gets a hostname, an application, a network operator, a country and a
coordinate, from a kernel BPF prefilter that hands userspace only the packets that carry identity.
A 3D globe and a flat map of live and historical connections; every arc carries two crest trains,
cool for bytes leaving the network and warm for bytes arriving, so a download and an upload on
the same connection are both visible and tell apart. Time-series analytics over 14 days,
user-defined alerts to webhook or email, scheduled reports, Prometheus metrics.

**Ask first.** An opt-in per-device queue: the first time an enrolled device reaches a hostname it
has never reached before, it waits for your verdict, and the answer becomes a rule.

**An assistant that can do the work.** Twenty-four read tools and fifteen write tools over the
same code paths the UI uses: it explains a domain, places an address, reads a device's history, the
audit log or a service's usage, adds a shortcut, remembers a fact about your network, and files a
scrubbed problem report. Write access is off by default; everything lands in the audit log. The
same tools are exposed over MCP for an external assistant.

Press **⌘K** (or Ctrl-K) anywhere to jump to a page, device, or action.

## Install

One line, on a Debian/Ubuntu host, VM, or existing LXC, or on a Proxmox host:

```bash
curl -fsSL https://raw.githubusercontent.com/Neoo-Blue/orbis/main/deploy/bootstrap.sh | sudo bash
```

On a **Proxmox host** it creates a privileged LXC and installs Orbis inside it. On a
**Debian/Ubuntu** host, VM or container it installs in place: dependencies, the prebuilt binary, a
systemd service, and the GeoIP databases. It never changes how the network behaves; the node comes
up in observe mode. Overrides are documented at the top of
[deploy/bootstrap.sh](deploy/bootstrap.sh) (`CTID`, `BRIDGE`, `IP`, `STORAGE`, `SKIP_GEOIP`, ...).

Then open `http://<host>:8080`. A first-run wizard asks how the node should sit on the network and
checks whether it can actually see your traffic.

### On a Raspberry Pi, replacing AdGuard Home or Pi-hole

The binary and the image are built for arm64, and a Pi 4 runs the resolver for a household with
room to spare. The one-line installer works there too. What maps to what:

| You had | In Orbis |
|---|---|
| Filter list subscriptions | Ad blocking → Lists (hosts, domain, dnsmasq and AdBlock syntax) |
| Custom rules, `\|\|host^` and `@@` | Ad blocking → My rules, or a profile's deny and allow lists |
| Clients with filtering disabled | The **Unfiltered** profile, assigned per device |
| unbound or another DoT forwarder | `dns.upstreams` entries such as `tls://1.1.1.1:853`; `cache_size` and `min_ttl` are settings |
| Port 53, admin UI on 80 | `dns.listen` and `api.listen`; the UI moves with `api.listen` |

Stop the old resolver first. Two services cannot share port 53, and the DNS page says so rather
than failing quietly. Blocklists are indexed after the listener comes up, so the first minute after
a start on a Pi answers unfiltered; that window is logged and shown on the Problems page.

### Docker

```bash
docker run -d --name orbis --network host \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  -v orbis-config:/etc/orbis -v orbis-data:/var/lib/orbis \
  ghcr.io/neoo-blue/orbis:nightly
```

Or `docker compose up -d` with the bundled compose file. The image is multi-arch (amd64 and
arm64), about 44 MB on Alpine, with `:nightly` tracking main and `:latest` a tagged release. Host
networking is required: Orbis reads raw frames to pull SNI out of a ClientHello, and inside a
bridge network the only frames it would ever see are its own. See [docs/DOCKER.md](docs/DOCKER.md).

### In an LXC by hand

Orbis needs raw sockets, netfilter and network configuration, so it wants a privileged container:

```bash
pct create 115 local:vztmpl/debian-13-standard_13.1-2_amd64.tar.zst \
  --hostname orbis --cores 4 --memory 3072 --rootfs local-zfs:16 \
  --net0 name=eth0,bridge=vmbr0,ip=192.168.1.10/24,gw=192.168.1.1 \
  --unprivileged 0 --features nesting=1,keyctl=1

# WireGuard needs the TUN device
cat >> /etc/pve/lxc/115.conf <<'EOT'
lxc.cgroup2.devices.allow: c 10:200 rwm
lxc.mount.entry: /dev/net/tun dev/net/tun none bind,create=file
EOT

# Netfilter modules live in the host kernel; a container cannot load them
for m in nf_tables nft_ct nft_chain_nat nf_nat nf_conntrack nf_conntrack_netlink wireguard tun; do
  modprobe $m
done
sysctl -w net.netfilter.nf_conntrack_acct=1   # per-connection byte counters
```

## Getting the YouTube engines working

**Television.** Turn on the Lounge engine on the YouTube page. With auto-discover on, any TV that
advertises a screen id over DIAL is adopted with no code. Otherwise, YouTube on the TV → Settings →
*Link with TV code*, and enter the code. The screen row shows what it is doing and its ad history.

**Browser.** Ad blocking → In-stream ads: start the filter proxy, download the certificate, trust
it on the device. The readiness panel on that page tells you which of the four prerequisites is
missing when ads still show. The QUIC block is on by default so YouTube falls back to TCP where the
proxy can see it.

**The one thing to know about the mobile app.** It will not be filtered from the network. Cast it.

## Two interfaces: simple and advanced

The top bar switches between them, and Settings sets the default. **Simple** is
seven screens in plain words for a household: Home (is everything fine, ask a
question), Devices (pause internet with a timer, pick a profile, rename),
Protection (every filter as a sentence and a switch, fix or block a site, pair a
TV), Usage (what is using the internet), Ask, Alerts (what happened, in
sentences) and Settings. **Advanced** is every page and setting. On a phone both
become a bottom tab bar: simple keeps its seven screens there; advanced keeps
Overview, Connections, Devices and Assistant in the bar, with every other page one
tap away behind More and a search button in the top bar. Every page has been laid
out and checked at phone width ([docs/UX-AUDIT.md](docs/UX-AUDIT.md) records the audit). Both write the same configuration, so
nothing done in one is invisible in the other. **Profiles** (Kids, Homework,
Guests, Unfiltered, or your own) are per-device filtering policies with
switched-off apps, safe search, schedules and allow/deny lists, shared by both.

## Shortcuts: a name for something on a port

DNS can hold an address but never a port, so `nas:5001` can never be a record.
Orbis closes that gap with **shortcuts**: `deep.seek` → `http://192.168.50.223:8080`.
The resolver answers the name with the node's own address, and the node then
redirects the browser to the real host and port (default) or relays the traffic
so the address bar keeps the name. Works over http for every device that uses
Orbis for DNS; the assistant can add them too ("make deep.seek open 192.168.50.223:8080").

## The assistant, free models, and the periodic checks

The built-in assistant talks to Anthropic, OpenAI, OpenRouter or a local Ollama. On
OpenRouter it prefers the **free models**: the catalogue is fetched on a timer, every
free model that can call tools is probed with a fixed tool round-trip and a two-domain
classification, the survivors are ranked, and each request walks that ranking with
short per-model cooldowns (a rate-limited free model costs one failed attempt, not a
broken assistant). Your pinned model is the guaranteed last link. Usage is counted per
UTC day against the free tier's 1,000-request cap. Settings → Assistant shows the
ranking, the chains in effect, today's spend, and lets you pin your own order.

On a schedule the assistant also writes a **network brief** (what happened, anything
worth a look, node health) and runs a **blocklist review** that suggests names to allow
(collateral damage: CDNs, first-party APIs, push and update hosts), names to block (from
smart capture's evidence) and things to investigate. You accept or dismiss each one;
decisions are remembered so a dismissed idea does not come back. `remember` lets you
keep facts about your network that every prompt then sees.

## Services: who uses what

The **Services** page groups traffic into the applications a person recognises
(Netflix, YouTube, TikTok, Windows Update, a smart TV's telemetry) from a catalogue of
a few hundred hostnames with categories; unknown names fall back to their registrable
domain so nothing hides in "other". Counters are hourly rollups per device and per
service: connections, bytes down and up, DNS lookups and blocked lookups. Bytes are
accounted as deltas from the live flow table, so a long stream lands in the hours it
happened. Bytes exist only for devices whose traffic passes through the node
(intercepted, or the node inline as gateway); every other device shows lookups and is
marked DNS-only rather than shown as zero. The assistant answers "how much Netflix did
the TV watch this week" from the same rollups.

## Problem reports

What goes wrong on a node is recorded on the **Problems** page: subsystem start
failures, blocklists that stop parsing, an assistant that cannot reach any model, and
anything you report yourself. Every record is scrubbed first: addresses, MAC addresses,
device names, hostnames outside the project's own infrastructure, keys and email
addresses become placeholders. Nothing leaves the node unless you enable GitHub
reporting, and the preview shows the exact text before it is sent. Reports carry a
fingerprint so the same bug from many nodes is one issue with a count. Use your own
fine-grained token, or the project relay (`deploy/issue-relay`), which files on your
behalf without a token and applies a second pass of redaction.

On the maintainer side, a scheduled cloud agent works the board once a day: it
reads open issues, reproduces clear defects with a failing test, opens a pull
request on a `fix/issue-N` branch (never pushing to `main`), and triages the
rest with a comment. Humans review and merge. Nothing is deployed automatically.

## Threat intelligence and CrowdSec

DNS blocking stops a name from resolving. The **Threats** page works on addresses: feeds of
hijacked netblocks, live botnet command servers and addresses seen attacking are fetched on a
schedule, parsed (private and reserved ranges are refused, and no feed can black out more
than a /8), and loaded into nftables sets that drop connections to and from them. Where this
node is in the path (inline, or a device it intercepts) the connection is dropped; everywhere
else a hit is recorded, named to the device, and raised as an event, so a camera beaconing to
a command server is visible even from a node that only serves DNS. The hit list says which
was which. Your own servers and VPN endpoints go on an allow list that always wins.

**Bans** are timed decisions against an address or range, from you, from the assistant
("ban 203.0.113.7 for a day"), from the anomaly detector's scan findings when you let it, or
from **CrowdSec**. Orbis does not parse server logs or share intelligence; CrowdSec does both,
on the machines that serve the internet. Point Orbis at that engine's Local API with a key
from `cscli bouncers add orbis` and it acts as the bouncer: bans arrive within one poll,
are enforced at the gateway with country and operator shown, and are lifted when CrowdSec
lifts them.

## Hosted apps, storage and port forwarding

The **Hosted apps** page answers "what is running on my network" without an inventory
spreadsheet. On a schedule (and on demand) Orbis probes every device it has seen recently at
about ninety well-known ports, reads the front page of anything that speaks HTTP, and names the
service from it: Plex, Sonarr, Portainer, Proxmox, Home Assistant, n8n, a Synology's DSM, a
printer's CUPS page. A port that answered without a page is shown as a guess ("port 3001,
usually Uptime Kuma"), never as a fact. Where a host exposes its Docker Engine API, Orbis reads
the container list and puts the container name and image next to each published port, and if
it finds an Engine API open on the network without authentication it uses it and warns you,
because that port is root on that machine for anyone on the LAN. Services that should not face
the internet (storage protocols, admin panels, databases, remote desktop, SSH) are marked
sensitive.

**Storage** lists the NAS and SAN devices: recognised by vendor (Synology, QNAP, TrueNAS, and
so on), by the identifier's verdict, or by the protocols they serve, with the admin page, the
devices talking to them right now and how much, and any port forward that exposes them.

**Port forwarding** is one button per service. When this node is the gateway it writes the DNAT
rule and the matching forward-chain accept into its own ruleset. When it is not, it asks the
upstream router over UPnP, renews the lease, and lists the router's whole mapping table so the
ports a console or an old app opened are visible and removable. A router that announces UPnP but
does not actually serve it (eero does this) is reported as such rather than as a silent failure.
Forwarding a sensitive service needs an explicit confirmation, and the assistant will not do it
without telling you why a VPN or a tunnel is the better answer.

## Cables, Wi-Fi and countries

The **Cables & Wi-Fi** page tells the physical ports apart with evidence rather than a dropdown.
The wired port carrying the default route is the internet; other wired ports with a carrier are
the network; a wireless adapter is the Wi-Fi network; a port with no carrier is empty. Each
verdict lists what it rests on: the default route, how many neighbours answer on the port, how
many known devices live on its subnet. Two cables with the devices all behind the uplink is
what a freshly plugged, still-quiet LAN looks like and also what a mistake looks like, so that
case is a proposal, never applied silently. With auto-assign on, an unambiguous classification
is written to the WAN interface and the zones the moment a cable goes in; otherwise it waits
for one click. One cable means observe mode on the network, unless the access point is on, in
which case that cable is the uplink the Wi-Fi is translated onto. The onboarding wizard is
pre-filled from the same evidence.

**Wi-Fi.** A wireless adapter becomes an access point with one switch. Orbis writes the hostapd
configuration, takes the adapter from NetworkManager, picks 5 GHz when the adapter and the
country code allow it, and in routed mode gives the network its own subnet with Orbis as
gateway, DHCP server and resolver, translated out through the wired side in its own nftables
table. That table carries the threat and country sets too, so a phone on the Orbis network is
filtered at every layer even while the Pi it runs on is not the house's router. The passphrase
is generated when you do not set one and shown on the page behind the admin login. Connected
devices are listed with signal, bytes and names. Bridge mode hands the adapter to an existing
bridge and leaves addressing to the wired network.

**Countries.** The Countries tab on the Threats page blocks a list of countries or allows only
a list. Three layers act: the resolver refuses a name whose addresses land in a blocked country,
for every device that uses it; a new connection to or from one is marked and killed where Orbis
is in the path; and in block mode the countries' ranges, extracted once from the GeoIP database
and cached, are loaded into the packet filter on the main ruleset, the intercept table and the
Wi-Fi table. Allow mode enforces at the resolver and per connection, since the complement of a
short list is most of the internet. Devices, domains and addresses can be exempted, and the
page lists the countries your traffic actually went to last week so the list is built from
what happens rather than from memory.

## Modes and placement

**Observe** (the default) watches whatever traffic reaches it and records what it would have done.
No ruleset is installed, DHCP stays off, nothing is routed through it. Safe to leave indefinitely.

**Inline** makes it a real gateway: the ruleset is loaded, forwarding and NAT are enabled, DHCP
starts if a scope exists, and outbound DNS is redirected so a device with hardcoded resolvers still
gets filtered. A config that would forward without translating, or drop everything, is corrected
to observe on load with an explanation rather than silently misbehaving. Switching to inline is
refused, with the reason, while a prerequisite is missing (no `nft`, forwarding switched off in the
kernel, no LAN interface), and Settings lists what to fix, so the node never appears to accept
inline and quietly fall back.

To filter a network without becoming its gateway, use **ARP interception** per device, or point
your router's DHCP DNS at Orbis. On a switched network a node that is not in the path sees only its
own traffic and broadcast noise; the onboarding wizard measures this and tells you.

## Architecture

```
                      +------------ web UI (React + three.js) -------------+
                      |  globe . map . flows . devices . rules . youtube   |
                      +---------------------------+------------------------+
                                 REST + WebSocket + SSE
                      +---------------------------+------------------------+
                      |                    orbisd                          |
   +------------------+---------------+---------------+-------------------+
   | capture          | dnsproxy      | mitm          | lounge            |
   | AF_PACKET + BPF  | resolver +    | TLS strip,    | Lounge API remote |
   | TLS . QUIC . HTTP| DoT/DoH server| in-page engine| per-ad ledger     |
   +------------------+-------+-------+---------------+-------------------+
                      +-------+--------+------------------+--------------+
                      | flow tracker   | adblock matcher  | firewall/vpn |
                      | conntrack via  | 480k rules,      | nftables, wg |
                      | netlink        | smart capture    | tailscale    |
                      +-------+--------+------------------+--------------+
                              |
topology . intercept . discover . upnp . links . wifi . country . alerts . report . notify . usage . issues . threat . ai + mcp
                              |
                         SQLite (WAL)
```

Single static binary with the UI embedded. No cgo, no libpcap, no external database.

## Things learned the hard way

Each of these cost real time, and each is now a line in the code rather than a surprise.

- **The BPF prefilter is the whole performance story.** Without it every byte of every stream is
  copied to userspace. With it a gigabit link costs a handful of packets per flow.
- **QUIC Initials are decryptable** with a salt fixed by RFC 9001 and the connection ID sent in the
  clear, which is what keeps HTTP/3 from being a hole in the filter.
- **`/proc/net/nf_conntrack` does not exist** on current Debian, Ubuntu and Proxmox kernels.
  Conntrack is read over netlink, or every byte counter is zero.
- **The ruleset is generated whole and loaded in one transaction**, so the box is never briefly
  open or briefly cut off.
- **Anycast resolvers are corrected before GeoIP is consulted.** 1.1.1.1 is registered to APNIC in
  Australia; uncorrected, Australia is the busiest country on the globe by an order of magnitude.
- **A proxy that buffers a video segment is a proxy that breaks video.** Bodies are only pulled into
  memory when there is a realistic chance of rewriting them; everything else streams through with
  its original framing and encoding. Decoding a body and then discovering it is unusable restores
  the original bytes, not a truncated copy.
- **The Lounge server counts frame lengths in UTF-16 code units**, the way JavaScript measures a
  string. One emoji in a video title, counted as one code point, desyncs every frame after it and
  the session goes quiet with nothing in the log. The length is treated as a hint and the frame ends
  where its JSON closes.
- **`skipAd` is a no-op until the button is armed**, and a television that goes dark mid-ad never
  sends the end event. Retries are scheduled, not hammered, and every ad has a deadline.
- **A charset meta only counts inside the first kilobyte.** The injected engine goes after it, not
  before it.
- **Tailscale route acceptance is guarded** against a peer advertising a prefix this node is already
  on, which would route the LAN into the tunnel and strand the node.
- **A pinned app does not refuse the certificate, it hangs.** The first attempt used to wait on a
  handshake that would never finish. A six-second deadline now counts as a rejection, and the
  bypass is written to disk so a restart does not repeat the lesson.
- **Listen first, then rebuild the index.** Indexing six million blocklist entries takes a minute on
  a Pi 4. Doing it before the listener came up turned a one-minute unfiltered window into a
  one-minute DNS outage for every device in the house.
- **Free models fail per model, not per key.** A 429 from one free model is a two-minute cooldown
  for that model and a step down the ranking, not a broken assistant.
- **On a phone, a page is as wide as its widest tab strip.** Sections stack in grids whose single
  column auto-sizes to the widest child, so one unwrapped strip stretched every banner and card
  past the screen. One rule pinning that column to the screen width fixed every page at once.

## Configuration

Everything lives in `/etc/orbis/orbis.yaml` (mode `0600`; it holds API keys and private keys). The
Settings page maps one-to-one onto it. Secrets are masked in the API response and never returned;
config backup and restore preserves them so a bundle from the UI cannot overwrite live keys with
masks.

## Security posture

- One administrator, not a user model. **Do not expose port 8080 to the internet** directly; reach
  it over WireGuard, Tailscale, or a Cloudflare Tunnel with Access in front.
- TLS interception is invasive and off by default, scoped to an explicit host allowlist, with banks
  and pinned apps on a bypass list that always wins. An app that pins its certificate and rejects,
  or simply hangs on, the Orbis handshake is detected on that first attempt and bypassed for 24
  hours, so the YouTube app on a phone keeps working while the browser next to it is filtered. Only
  the CA certificate is downloadable; the private key never leaves the node.
- The in-page engine talks to nothing but the page it lives in and two same-origin paths that Orbis
  answers itself. Its counters are capped per report, because a counter is evidence.
- ARP interception is a legitimate technique against your own devices and an attack against a
  network you do not control. Enrolment is explicit and per-device.
- The assistant cannot change anything unless you turn write access on. Every mutating action, from
  the UI, the API, the assistant or MCP, is written to the audit log.

See [SECURITY.md](SECURITY.md).

## Development

```bash
go test -race ./...                  # the concurrency ones matter here
go vet ./...

cd web && npm run build              # the UI is embedded: build it before go build
cd web && npm run dev                # or iterate against a daemon on :8080
go run ./cmd/orbisd -config ./dev.yaml
go run ./cmd/orbisd -print-ruleset   # render nftables without applying
orbisd -mcp -config /etc/orbis/orbis.yaml   # the tool catalogue over MCP
```

The built UI under `cmd/orbisd/web/dist` is not committed; CI builds it for every push and
release. Releases ship `orbisd-linux-amd64`, `orbisd-linux-arm64` and the multi-arch image.

The competitive audit that drove much of the feature set is in
[docs/COMPETITIVE-AUDIT.md](docs/COMPETITIVE-AUDIT.md); the interface audit and the two-mode
design in [docs/UX-AUDIT.md](docs/UX-AUDIT.md); the MCP surface in [docs/MCP.md](docs/MCP.md).

## Licence

MIT. Blocklists retain their own licences. GeoIP data (c) DB-IP, CC-BY-4.0. SponsorBlock data is
provided by its contributors under CC BY-NC-SA 4.0.
