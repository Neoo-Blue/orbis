<div align="center">

# Orbis

<img width="1913" height="889" alt="Orbis globe view: live connections drawn as arcs from the network to the world" src="https://github.com/user-attachments/assets/3650f99c-d682-4e5c-a7b6-e938a7d18e13" />

**The firewall that follows the ad into the stream, and knows what your network is doing.**

One static binary with an embedded interface. A filtering resolver, a real firewall, three
ad-removal engines at three layers, intrusion detection, threat intelligence, country rules,
its own Wi-Fi network, a map of everything you host, and an assistant that can operate all of
it. Runs on a Raspberry Pi, an LXC, a VM, or in Docker.

[![CI](https://github.com/Neoo-Blue/orbis/actions/workflows/ci.yml/badge.svg)](https://github.com/Neoo-Blue/orbis/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/Neoo-Blue/orbis?display_name=tag)](https://github.com/Neoo-Blue/orbis/releases/latest)
[![Go](https://img.shields.io/github/go-mod/go-version/Neoo-Blue/orbis)](go.mod)
[![Image](https://img.shields.io/badge/ghcr.io-neoo--blue%2Forbis-2496ED)](https://github.com/Neoo-Blue/orbis/pkgs/container/orbis)
[![Licence](https://img.shields.io/badge/licence-MIT-blue)](LICENSE)

</div>

---

## Contents

- [What it is](#what-it-is)
- [Where the others stop](#where-the-others-stop)
- [Install](#install)
- [The first hour](#the-first-hour)
- [The streaming ad problem](#the-streaming-ad-problem)
- [Filtering by name](#filtering-by-name)
- [Security: intrusion detection, threat feeds, countries](#security-intrusion-detection-threat-feeds-countries)
- [The network: cables, Wi-Fi, firewall, VPN](#the-network-cables-wi-fi-firewall-vpn)
- [Seeing everything: globe, services, hosted apps, storage](#seeing-everything-globe-services-hosted-apps-storage)
- [Operating it: two interfaces and the assistant](#operating-it-two-interfaces-and-the-assistant)
- [Problem reports](#problem-reports)
- [Modes and placement](#modes-and-placement)
- [Architecture](#architecture)
- [Things learned the hard way](#things-learned-the-hard-way)
- [Configuration, security, development](#configuration)
- [Support and contributing](#support-and-contributing)

## What it is

Ad blocking on the network stopped working the day ads moved into the same connection as the
content. A DNS sinkhole cannot see a YouTube pre-roll, because the ad and the video come from the
same host over the same TLS session. A browser extension cannot see a television. Every product
in this space stops at one of those walls and calls the rest "not possible". Orbis is built on
the premise that each wall needs a different tool, and that the honest thing to do is to say,
per device, which tool applies and what it cannot reach.

That premise then spread to the rest of the network: a device that never asks your resolver
should still be caught when it beacons to a command server, a cable should be recognised as the
internet or the network without a dropdown, an SSH brute force against your NAS should end in a
ban at the gateway without a second product, and a person with no networking background should
be able to run all of it from a phone.

| Layer | What it does | What it needs on the device |
|---|---|---|
| **DNS** | Blocklists, CNAME uncloaking, DoH bypass sinkhole, per-device profiles, safe search, service bundles, a streaming-device list, country refusal, DoT and DoH served to your own devices | Nothing |
| **Wire** | Apps that hardcode addresses, matched on TLS SNI and decrypted QUIC Initials; threat feeds, bans and country ranges as packet-filter sets | Nothing |
| **In-stream** | YouTube ads stripped from responses before the page sees them, an in-page engine that drives the player past anything that starts, SponsorBlock without an extension | The Orbis certificate |
| **Player** | YouTube ads on a TV, Apple TV, console or Chromecast: Orbis attaches as a remote, mutes the ad on its first frame and skips it the moment YouTube allows | Nothing, no certificate |
| **Gateway** | nftables firewall with zones and live counters, WireGuard and Tailscale both ways, DHCP, multi-WAN, shaping, a Wi-Fi access point, port forwarding on itself or on the upstream router | Nothing |
| **Detection** | Brute force, scans and floods from this node's journal, syslog from other hosts, the login page and the flow table, into escalating bans; beaconing, DGA names and large uploads from the anomaly detector | Nothing |

## Where the others stop

This is not a claim to be better at what these tools do. It is a map of where each one ends and
where Orbis keeps going.

| | Pi-hole | AdGuard Home | NextDNS | pfSense / OPNsense | CrowdSec | uBlock Origin | iSponsorBlockTV | **Orbis** |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| DNS blocklists, per-client policy | ● | ● | ● | ○ | | | | ● |
| CNAME uncloaking | ○ | ● | ● | | | ● | | ● |
| Blocks by TLS SNI and QUIC when DNS is bypassed | | | | ○ | | | | ● |
| Strips YouTube ads from the response (with a CA) | | | | | | ● (browser) | | ● |
| In-page player engine and SponsorBlock without an extension | | | | | | ● (extension) | | ● |
| YouTube ads on a TV or Apple TV, no certificate | | | | | | | ● | ● |
| Real firewall: zones, NAT, port forwarding, multi-WAN | | | | ● | | | | ● |
| WireGuard server and client, Tailscale exit node | ○ | | | ● | | | | ● |
| Intrusion detection from logs and flows, escalating bans | | | | ○ | ● | | | ● |
| Community reputation feed | | | | | ● | | | via CrowdSec |
| IP threat feeds as packet-filter sets | | | | ○ | | | | ● |
| Block or allow whole countries at DNS and in the packet filter | | ○ | | ○ | | | | ● |
| Finds what you host (apps, containers, NAS), forwards ports for it | | | | ○ | | | | ● |
| Tells WAN from LAN by itself, runs a Wi-Fi network | | | | ○ | | | | ● |
| Every connection identified: host, app, operator, country | | | | ○ | | | | ● |
| Live globe, network map, anomaly detection | | | | | | | | ● |
| Simple interface a household can run from a phone | | ○ | ● | | | | | ● |
| Assistant with tools, MCP server | | | | | | | | ● |

● built in · ○ partial or via add-on · blank: not in scope for that product

## Install

One line, on a Debian/Ubuntu host, VM or existing LXC, on a Raspberry Pi, or on a Proxmox host:

```bash
curl -fsSL https://raw.githubusercontent.com/Neoo-Blue/orbis/main/deploy/bootstrap.sh | sudo bash
```

On a **Proxmox host** it creates a privileged LXC and installs Orbis inside it. On a
**Debian/Ubuntu** host, VM, container or Pi it installs in place: dependencies (nftables,
conntrack, WireGuard tools, hostapd, iw), the prebuilt binary for amd64 or arm64, a systemd
service, and the GeoIP databases. It never changes how the network behaves; the node comes up
in observe mode. Overrides are documented at the top of
[deploy/bootstrap.sh](deploy/bootstrap.sh) (`CTID`, `BRIDGE`, `IP`, `STORAGE`, `SKIP_GEOIP`).

Then open `http://<host>:8080`. A first-run wizard asks how the node should sit on the network,
pre-fills the internet-facing interface from what the cables say, and checks whether the node can
actually see your traffic.

### Replacing AdGuard Home or Pi-hole on a Raspberry Pi

A Pi 4 runs the resolver for a household with room to spare. What maps to what:

| You had | In Orbis |
|---|---|
| Filter list subscriptions | Ad blocking, Lists (hosts, domain, dnsmasq and AdBlock syntax) |
| Custom rules, `\|\|host^` and `@@` | Ad blocking, My rules, or a profile's deny and allow lists |
| Clients with filtering disabled | The **Unfiltered** profile, assigned per device |
| unbound or another DoT forwarder | `dns.upstreams` entries such as `tls://1.1.1.1:853`; `cache_size` and `min_ttl` are settings |
| Port 53, admin UI on 80 | `dns.listen` and `api.listen`; the UI moves with `api.listen` |

Stop the old resolver first: two services cannot share port 53, and the DNS page says so rather
than failing quietly. Blocklists are indexed after the listener comes up, so the first minute
after a start on a Pi answers unfiltered; that window is logged and shown on the Problems page.

### Docker

```bash
docker run -d --name orbis --network host \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  -v orbis-config:/etc/orbis -v orbis-data:/var/lib/orbis \
  ghcr.io/neoo-blue/orbis:latest
```

Or `docker compose up -d` with the bundled compose file. The image is multi-arch (amd64 and
arm64), about 44 MB on Alpine. `:latest` and `:stable` are the last tagged release, `:nightly`
tracks main. Host networking is required: Orbis reads raw frames to pull SNI out of a
ClientHello, and inside a bridge network the only frames it would ever see are its own. Mount
`/var/run/docker.sock` read-only and add `unix:///var/run/docker.sock` as a Docker host in
Settings, and the Hosted apps page names the containers on the host. See
[docs/DOCKER.md](docs/DOCKER.md).

### In an LXC by hand

Orbis needs raw sockets, netfilter and network configuration, so it wants a privileged container:

```bash
pct create 200 local:vztmpl/debian-13-standard_13.1-2_amd64.tar.zst \
  --hostname orbis --cores 4 --memory 3072 --rootfs local-zfs:16 \
  --net0 name=eth0,bridge=vmbr0,ip=192.168.1.10/24,gw=192.168.1.1 \
  --unprivileged 0 --features nesting=1,keyctl=1

# WireGuard needs the TUN device
cat >> /etc/pve/lxc/200.conf <<'EOT'
lxc.cgroup2.devices.allow: c 10:200 rwm
lxc.mount.entry: /dev/net/tun dev/net/tun none bind,create=file
EOT

# Netfilter modules live in the host kernel; a container cannot load them
for m in nf_tables nft_ct nft_chain_nat nf_nat nf_conntrack nf_conntrack_netlink wireguard tun; do
  modprobe $m
done
sysctl -w net.netfilter.nf_conntrack_acct=1   # per-connection byte counters
```

A container has no wireless adapter and no physical ports of its own, so the Wi-Fi and cable
features apply to bare-metal and VM installs.

### Updating

Orbis checks GitHub for a newer release every six hours and says so on every page and in
Settings, About & diagnostics. What happens next depends on how it was installed:

- **Binary under systemd** (the installer's way): one click. Orbis downloads the release for its
  architecture, checks it against the release's `sha256sums.txt`, confirms the new binary runs
  and reports the expected version, keeps the old one as `orbisd.prev`, and restarts the
  service. The page reloads when the new version is up, about half a minute later. The same
  path works headless: `sudo orbisd -update`.
- **Docker**: the banner tells you to pull. `docker pull ghcr.io/neoo-blue/orbis:stable` and
  recreate the container.
- **A binary started by hand**: Orbis replaces the file and asks you to restart the process.

To roll back after a bad update: `sudo cp /usr/local/bin/orbisd.prev /usr/local/bin/orbisd && sudo systemctl restart orbis`.

## The first hour

1. **Point devices at it.** Set your router's DHCP DNS to the node, or just the devices you want
   to start with. Everything on the DNS layer works from here: lists, profiles, safe search,
   service bundles, country refusal, shortcuts.
2. **Watch the Overview.** Devices appear as they resolve names. The Globe draws where the
   traffic goes; the Services page groups it into Netflix, YouTube, Windows Update and the rest.
3. **Pull one device in.** On the Interception page, intercept a phone or a TV. Its traffic now
   passes through the node by ARP without the router changing, so SNI and QUIC blocking, the
   threat and country sets, and the in-stream engines apply to it.
4. **Set up the TV.** On the YouTube page, turn on the Lounge engine; a TV that advertises itself
   is adopted with no code. Ads on it are muted on the first frame and skipped at the first
   chance from then on.
5. **Look at Hosted apps and Threats.** The first scan names what your hosts run and finds your
   NAS; the Threats page shows the feeds loaded and, once you forward a server's logs to the
   node, the attackers it has banned.
6. **Turn on Wi-Fi** if the node has an adapter. Devices that join the Orbis network are behind
   every layer at once, whether or not the node is your router.
7. **Go inline when you are ready.** With two cables, the Cables page says which is the internet
   and which is the network; inline mode makes the node the gateway with the firewall, NAT, DHCP
   and DNS redirection on. Nothing forces this step; a node that only serves DNS and intercepts a
   few devices is a complete deployment.

## The streaming ad problem

**The response filter.** With the Orbis certificate trusted, YouTube's InnerTube responses are
rewritten in flight: `adPlacements`, `playerAds`, `adSlots` and two dozen renamed relatives are
removed, promoted rows are dropped from feeds, and the ad reporting endpoints are answered
locally so the player never learns an ad failed to play. The inline `ytInitialPlayerResponse` in
the page is filtered too, so the first video of a session is not the one that slips through.

**The in-page engine.** Field names change; behaviour does not. A small ES5 script is injected as
the first thing in every YouTube document. It patches `JSON.parse` and `Response.json` to scrub
ad structures the static filter has not learned yet, and it watches the player itself: an ad
break that starts anyway is muted and driven to its end, a skip button is pressed the instant it
appears, overlay banners are closed. The same engine skips and mutes SponsorBlock segments,
asking Orbis for them over a same-origin path, so the browser never talks to SponsorBlock. It
reports its counters back so the interface can show the layer is alive on a real screen, and it
runs in the browser built into a Samsung or LG set as readily as in Chrome.

**The Lounge engine.** Televisions cannot install a certificate. So Orbis does what a phone does
when it casts: it attaches to the screen over YouTube's Lounge API as a remote control and
watches the same event stream the TV app emits. Every ad is its own record: muted on the first
`adPlaying`, `skipAd` sent the moment `isSkippable` flips, retried on a schedule rather than
hammered, closed when the player says so. An ad pod is a sequence of records, not one long ad.
Because a television will sometimes go dark mid-ad and never say the ad ended, every ad carries
a deadline: past its own duration plus a grace period it is closed as lost, the volume comes
back, and the ledger says so. The history for each screen is in the interface, ad by ad.

**The counters that tell the truth.** Some YouTube streams have the ad muxed into the video
itself. No filter anywhere can separate those bytes. Orbis counts server-stitched responses so
a filter that is broken and a stream that cannot be filtered do not look the same. A readiness
panel checks, separately, whether traffic reaches the proxy, whether TLS is being decrypted, and
whether ads are being stripped, because from the sofa every one of those failures looks
identical.

| Screen | Engine | Needs | Result |
|---|---|---|---|
| Smart TV, Apple TV, console, Chromecast | Lounge | nothing | Ads muted from the first frame and skipped at the first chance; unskippable ads play muted |
| Laptop or desktop browser | Response filter + in-page | Orbis CA | Ads removed before the page sees them; anything that starts is driven past |
| TV browser, phone browser | Response filter + in-page | Orbis CA | Same as above |
| Mobile YouTube app | none | | Pins certificates and is not a castable screen. Cast it to a TV and the TV is covered. The app keeps working: a pinned app is detected on its first handshake and bypassed |
| Server-side stitched ads | none | | Counted, not removed. Nothing on a network can |

**Getting the engines working.** Television: turn on the Lounge engine on the YouTube page; with
auto-discover on, any TV that advertises a screen id over DIAL is adopted with no code, otherwise
enter the code from YouTube's *Link with TV code* screen. Browser: on Ad blocking, In-stream ads,
start the filter proxy, download the certificate, trust it on the device; the readiness panel
tells you which of the four prerequisites is missing when ads still show. The QUIC block is on
by default so YouTube falls back to TCP where the proxy can see it.

## Filtering by name

**A full resolver.** LRU cache with a TTL floor, upstreams over plain, DoT and DoH (encrypted by
default), and a DoT/DoH server for your own devices so a phone keeps using it off the LAN. Local
authoritative records with wildcards, rewrites, conditional forwarding, rate limiting, rebinding
protection. Turn the cache up and the TTL floor to an hour and it is a drop-in for unbound in
front of a home network.

**Blocking beyond the lists.** CNAME uncloaking, SNI and QUIC blocking for devices that never
ask the resolver, a DoH-bypass sinkhole, the built-in list of hosts smart TVs and streaming
sticks use only for ads and telemetry, and *smart capture*: a heuristic pipeline, with an
optional model behind it, that scores hosts no list has caught yet and queues them with evidence
for a one-click verdict. A scheduled **blocklist review** by the assistant suggests names to
allow (collateral damage: CDNs, first-party APIs, push and update hosts) and names to block, and
remembers your decisions so a dismissed idea does not come back.

**Profiles.** Kids, Homework, Guests, Unfiltered, or your own: per-device policies with switched
off apps (TikTok, Roblox, and the rest, as one switch each), safe search, schedules and their own
allow and deny lists. The Unfiltered profile is what AdGuard Home calls a client with filtering
disabled.

**Ask first.** An opt-in per-device queue: the first time an enrolled device reaches a hostname
it has never reached before, it waits for your verdict, and the answer becomes a rule.

**Shortcuts.** DNS can hold an address but never a port, so `nas:5001` can never be a record.
A shortcut makes `nas.lan` open `http://192.168.1.20:5001`: the resolver answers the name
with the node's own address and the node redirects the browser, or relays so the address bar
keeps the name. Works for every device that uses Orbis for DNS.

## Security: intrusion detection, threat feeds, countries

**Intrusion detection, built in.** Orbis reads this node's own authentication journal, receives
syslog from any other host (`*.* @orbis:514` in rsyslog, or a NAS's log forwarding), watches its
own login page, and watches the flow table. Parsers recognise sshd, PAM, Synology DSM and QNAP
logins, web servers' 401, 403 and 404 bursts in combined and JSON formats, Home Assistant,
Nextcloud, Vaultwarden, Jellyfin, remote desktop and VPN handshake failures. Each scenario has a
window and a threshold: five SSH failures in five minutes, ten web logins, forty 404s in two
minutes, fifteen ports in a minute, and so on. Crossing it bans the address at the gateway, and
a repeat offender's ban doubles each time up to a week. An address inside your own network is
reported with the device's name instead of banned, because cutting a neighbour off at the
gateway would not stop it. The Attacks tab shows the sources, the scenarios, every alert with
country and operator, the worst offenders, and a box to paste a log line into to check that
forwarding is understood before an attack proves it. No cloud, no community feed, nothing
leaves the node.

**Threat feeds.** Feeds of hijacked netblocks, live botnet command servers and addresses seen
attacking (Spamhaus DROP, abuse.ch, Emerging Threats, Binary Defense, with the larger aggregates
available but off) are fetched on a schedule, parsed with private, reserved and over-wide ranges
refused, and loaded into nftables sets that drop connections to and from them. Where the node
is in the path the connection is dropped; everywhere else a hit is recorded, named to the
device, and raised as an event, so a camera beaconing to a command server is visible even from
a node that only serves DNS. Your own servers and VPN endpoints go on an allow list that always
wins.

**Bans** are timed decisions against an address or range: from the detector, from you, from the
assistant ("ban 203.0.113.7 for a day"), from the anomaly detector's scan findings when you let
it, or from **CrowdSec**, which stays optional for the one thing Orbis does not have, its
community reputation feed. Point Orbis at an engine's Local API with a key from `cscli bouncers
add orbis` and it acts as the bouncer too.

**Countries.** Block a list of countries, or allow only a list. Three layers act: the resolver
refuses a name whose addresses land in a blocked country, for every device that uses it; a new
connection to or from one is marked and killed where the node is in the path; and in block mode
the countries' ranges, extracted once from the GeoIP database, aggregated and cached, are loaded
into the packet filter on the main ruleset, the intercept table and the Wi-Fi table. Devices,
domains and addresses can be exempted, and the page lists the countries your traffic actually
went to last week so the list is built from what happens rather than from memory.

**Anomalies.** A scheduled sweep of the flow table finds beaconing (regular connections to one
place), names that look generated by malware, large uploads to somewhere new, and port or host
sweeps, and asks the assistant to explain each finding in a sentence before it reaches you.

## The network: cables, Wi-Fi, firewall, VPN

**Which cable is which.** Physical ports are classified from the default route, the neighbours
answering on them and where the known devices live: this one is the internet, that one is the
network, that port is empty, the wireless adapter is the Wi-Fi network. Each verdict lists its
evidence. Two cables with all the devices behind the uplink is what a freshly plugged, still
quiet LAN looks like and also what a mistake looks like, so that case is a proposal, never
applied silently. With auto-assign on, an unambiguous classification is written to the WAN
interface and the zones the moment a cable goes in; otherwise it waits for one click.

**Wi-Fi.** A wireless adapter becomes an access point with one switch. Orbis writes the hostapd
configuration, takes the adapter from NetworkManager, picks 5 GHz when the adapter and the
country code allow it, and in routed mode gives the network its own subnet with Orbis as
gateway, DHCP server and resolver, translated out through the wired side in its own nftables
table. That table carries the threat and country sets too, so a phone on the Orbis network is
filtered at every layer even while the node it runs on is not the network's router. The passphrase
is generated when you do not set one, shown with a QR code to join behind the admin login, and
replaceable with your own. Bridge mode hands the adapter to an existing bridge instead.

**A real firewall.** Zones with trust levels, an ordered rule table with live hit counters, NAT
and port forwarding, time-based rules, IPv6, flow offload, an anti-lockout rule, all compiled
into one nftables ruleset and loaded atomically after `nft -c` validation. Guest and IoT zones
are isolated from the rest by default.

**A VPN, both ways.** WireGuard server with QR enrolment, outbound WireGuard tunnels with policy
routing per device and a kill switch, and Tailscale as a subnet router and exit node in both
directions, with route acceptance guarded against a peer that would swallow the LAN.

**Into the path without being the gateway.** ARP interception inserts Orbis in front of selected
devices only, forwards and NATs their traffic, and restores them cleanly the moment it stops.
Your existing router stays the router.

**And the rest of a gateway.** DHCP with fingerprinting, VLANs, static routes, multi-WAN
failover, CAKE shaping, NAT-PMP for consoles, Wake-on-LAN, ping, traceroute, speed test, pcap
export.

## Seeing everything: globe, services, hosted apps, storage

**Every connection identified.** A kernel BPF prefilter hands userspace only the packets that
carry identity, so each connection gets a hostname, an application, a network operator, a
country and a coordinate at a fraction of the traffic's cost. Conntrack over netlink supplies
the byte counters.

**The globe.** A 3D globe and a flat map of live and historical connections. Every arc carries
two crest trains, cool for bytes leaving the network and warm for bytes arriving, so a download
and an upload on the same connection are both visible; an arc that something outside opened is
tinted so an unsolicited inbound connection stands out. Countries light up by traffic.

**Services.** Traffic grouped into the applications a person recognises (Netflix, YouTube,
TikTok, Windows Update, a smart TV's telemetry) from a catalogue of a few hundred hostnames;
unknown names fall back to their registrable domain so nothing hides in "other". Hourly rollups
per device and per service: connections, bytes each way, lookups and blocked lookups. Devices
whose traffic does not pass through the node are marked DNS-only rather than shown as zero.

**Hosted apps.** The other direction: what your own hosts run. Every device seen recently is
knocked on at about ninety well-known ports and the page behind each answer is read, so a Plex,
a Sonarr, a Portainer, a Proxmox, a Home Assistant or a Synology is named rather than numbered,
and a port that answered without a page is shown as a guess, never as a fact. A host that
exposes its Docker Engine API names the container and image behind each port; an Engine API
found open on the network without authentication is used and warned about, because it is root
on that machine for anyone on the LAN. NAS and SAN devices are recognised by vendor and by the
protocols they serve (SMB, NFS, AFP, iSCSI, rsync, WebDAV), with their admin page, who is using
them right now, and anything that exposes them to the internet.

**Port forwarding** is one button per service. When the node is the gateway it writes the DNAT
rule and the matching accept into its own ruleset. When it is not, it asks the upstream router
over UPnP, renews the lease, and lists the router's whole mapping table so the ports a console
or an old app opened are visible and removable. Storage, admin panels, databases and remote
desktops need an explicit confirmation, and the assistant will not forward them without saying
why a VPN or a tunnel is the better answer. A router that announces UPnP but does not actually
serve it is reported as such.

**A map of the network.** Devices identified by MAC prefix, open ports, DHCP fingerprint and
behaviour, with confidence and evidence; hypervisors with their guests clustered under them,
storage, endpoints, and the traffic between them. Time-series analytics over 14 days, alerts to
webhook or email, scheduled reports, Prometheus metrics.

## Operating it: two interfaces and the assistant

**Simple** is seven screens in plain words for a household: Home (is everything fine, ask a
question), Devices (pause internet with a timer, pick a profile, rename), Protection (every
filter as a sentence and a switch, fix or block a site, block known-bad addresses, block
countries, pair a TV), Usage, Ask, Alerts, Settings. **Advanced** is every page and setting.
Both write the same configuration, so nothing done in one is invisible in the other. On a phone
both become a bottom tab bar; every page has been laid out and checked at phone width
([docs/UX-AUDIT.md](docs/UX-AUDIT.md) records the audit). Settings has search, a glossary
explains every term in one sentence, and ⌘K jumps to any page, device or setting.

**The assistant** talks to Anthropic, OpenAI, OpenRouter or a local Ollama, with 29 read tools
and 21 write tools over the same code paths the interface uses. It explains why a domain is
blocked, places an address, reads a device's history, names what a host runs, forwards a port,
bans an attacker, turns the Wi-Fi on, adds a country rule, remembers facts about your network,
and files a scrubbed problem report. Write access is off by default and everything it does
lands in the audit log. The same tools are exposed over MCP for an external assistant.

On OpenRouter it prefers the **free models**: the catalogue is fetched on a timer, every free
model that can call tools is probed with a fixed tool round-trip and a classification test, the
survivors are ranked, and each request walks that ranking with short per-model cooldowns. Your
pinned model is the guaranteed last link. On a schedule it also writes a **network brief** (what
happened, anything worth a look, node health) that the simple Home shows in two sentences.

## Problem reports

What goes wrong on a node is recorded on the Problems page: subsystem start failures, blocklists
that stop parsing, an assistant that cannot reach any model, and anything you report yourself.
Every record is scrubbed first: addresses, MAC addresses, device names, hostnames outside the
project's own infrastructure, keys and email addresses become placeholders. Nothing leaves the
node unless you enable GitHub reporting, and the preview shows the exact text before it is sent.
Reports carry a fingerprint so the same bug from many nodes is one issue with a count. Use your
own fine-grained token, or the project relay (`deploy/issue-relay`), which files on your behalf
without a token and applies a second pass of redaction.

On the maintainer side, a scheduled cloud agent works the board once a day: it reads open
issues, reproduces clear defects with a failing test, opens a pull request on a `fix/issue-N`
branch (never pushing to `main`), and triages the rest with a comment. Humans review and merge.
Nothing is deployed automatically.

## Modes and placement

**Observe** (the default) watches whatever traffic reaches it and records what it would have
done. No ruleset is installed, DHCP stays off, nothing is routed through it. Safe to leave
indefinitely. Interception, the Wi-Fi network and DNS still enforce, each in its own table, so
observe mode on a Pi is a complete household deployment.

**Inline** makes it a real gateway: the ruleset is loaded, forwarding and NAT are enabled, DHCP
starts if a scope exists, and outbound DNS is redirected so a device with hardcoded resolvers
still gets filtered. A config that would forward without translating, or drop everything, is
corrected to observe on load with an explanation. Switching to inline is refused, with the
reason, while a prerequisite is missing (no `nft`, forwarding switched off, no LAN interface),
and Settings lists what to fix.

On a switched network a node that is not in the path sees only its own traffic and broadcast
noise; the onboarding wizard measures this and tells you, and interception is the answer for the
devices that matter.

## Architecture

```
                      +------------ web UI (React + three.js) -------------+
                      |  simple . advanced . globe . flows . devices . ... |
                      +---------------------------+------------------------+
                                 REST + WebSocket + SSE
                      +---------------------------+------------------------+
                      |                    orbisd                          |
   +------------------+---------------+---------------+-------------------+
   | capture          | dnsproxy      | mitm          | lounge            |
   | AF_PACKET + BPF  | resolver +    | TLS strip,    | Lounge API remote |
   | TLS . QUIC . HTTP| DoT/DoH server| in-page engine| per-ad ledger     |
   +------------------+-------+-------+---------------+-------------------+
   | flow tracker     | adblock       | firewall      | threat . country  |
   | conntrack via    | matcher,      | nftables,     | ids . wifi        |
   | netlink          | smart capture | intercept     | links . discover  |
   +------------------+-------+-------+---------------+-------------------+
      vpn . dhcp . netconf . upnp . topology . usage . alerts . report
                   notify . issues . ai (router, brief, review) . mcp
                              |
                         SQLite (WAL)
```

Single static binary with the interface embedded. No cgo, no libpcap, no external database, no
cloud. Every enforcement point (the main ruleset, the intercept table, the Wi-Fi table) carries
the same threat, ban and country sets, so a decision made once applies wherever the node is in
the path.

## Things learned the hard way

Each of these cost real time, and each is now a line in the code rather than a surprise.

- **The BPF prefilter is the whole performance story.** Without it every byte of every stream is
  copied to userspace. With it a gigabit link costs a handful of packets per flow.
- **QUIC Initials are decryptable** with a salt fixed by RFC 9001 and the connection ID sent in
  the clear, which is what keeps HTTP/3 from being a hole in the filter.
- **`/proc/net/nf_conntrack` does not exist** on current Debian, Ubuntu and Proxmox kernels.
  Conntrack is read over netlink, or every byte counter is zero.
- **The ruleset is generated whole and loaded in one transaction**, so the box is never briefly
  open or briefly cut off. Sets that change often (threats, bans, countries) are swapped in
  place instead, so counters survive.
- **Anycast resolvers are corrected before GeoIP is consulted.** 1.1.1.1 is registered to APNIC
  in Australia; uncorrected, Australia is the busiest country on the globe by an order of
  magnitude.
- **A proxy that buffers a video segment is a proxy that breaks video.** Bodies are only pulled
  into memory when there is a realistic chance of rewriting them; everything else streams
  through with its original framing and encoding.
- **The Lounge server counts frame lengths in UTF-16 code units**, the way JavaScript measures
  a string. One emoji in a video title desyncs every frame after it and the session goes quiet
  with nothing in the log. The length is a hint; the frame ends where its JSON closes.
- **`skipAd` is a no-op until the button is armed**, and a television that goes dark mid-ad
  never sends the end event. Retries are scheduled, not hammered, and every ad has a deadline.
- **A pinned app does not refuse the certificate, it hangs.** A six-second deadline counts as a
  rejection, and the bypass is written to disk so a restart does not repeat the lesson.
- **Listen first, then rebuild the index.** Indexing six million blocklist entries takes a
  minute on a Pi 4. Doing it before the listener came up turned a one-minute unfiltered window
  into a one-minute DNS outage for the whole house.
- **Tailscale route acceptance is guarded** against a peer advertising a prefix this node is
  already on, which would route the LAN into the tunnel and strand the node.
- **A city-level GeoIP database splits a country into a hundred thousand fragments.** A large
  country is well over a hundred thousand ranges before aggregation. Merging siblings and
  dropping contained prefixes is the difference between a set a small board loads in a second
  and one it cannot load.
- **A router can announce UPnP and never serve it.** Some consumer routers answer the SSDP
  search, accept the TCP connection for their description, and never reply. The failure is
  named, not swallowed.
- **A route moving is not a cable moving.** Tunnels and multi-WAN move the default route at
  runtime; a cable watcher keyed on it raised phantom "cable plugged in" events on every start.
- **The old hostapd is still letting go of the adapter when the new one starts.** After a
  daemon restart the first start fails unless it waits for its predecessor.
- **Free models fail per model, not per key.** A 429 from one free model is a two-minute
  cooldown for that model and a step down the ranking, not a broken assistant.
- **On a phone, a page is as wide as its widest tab strip.** Sections stack in grids whose
  single column auto-sizes to the widest child; one rule pinning that column to the screen
  width fixed every page at once.

## Configuration

Everything lives in `/etc/orbis/orbis.yaml` (mode `0600`; it holds API keys, the Wi-Fi
passphrase and private keys). The Settings page maps one-to-one onto it. Secrets are masked in
the API response and never returned; config backup and restore preserves them so a bundle from
the interface cannot overwrite live keys with masks.

## Security posture

- One administrator, not a user model. **Do not expose the interface to the internet** directly;
  reach it over WireGuard, Tailscale, or a Cloudflare Tunnel with Access in front. Wrong
  passwords on the login page feed the intrusion detector like any other login.
- TLS interception is invasive and off by default, scoped to an explicit host allowlist, with
  banks and pinned apps on a bypass list that always wins. A pinned app is detected on its first
  handshake and bypassed for a day. Only the CA certificate is downloadable; the private key
  never leaves the node.
- The in-page engine talks to nothing but the page it lives in and two same-origin paths that
  Orbis answers itself. Its counters are capped per report, because a counter is evidence.
- ARP interception is a legitimate technique against your own devices and an attack against a
  network you do not control. Enrolment is explicit and per-device.
- Threat feeds and country sets never contain private, reserved or wider-than-/8 ranges, however
  a feed is written, and bans are refused for local addresses.
- Forwarding a sensitive service to the internet needs an explicit confirmation, from a person
  or from the assistant after it has warned you.
- The assistant cannot change anything unless you turn write access on. Every mutating action,
  from the interface, the API, the assistant or MCP, is written to the audit log.

See [SECURITY.md](SECURITY.md).

## Development

```bash
go test -race ./...                  # the concurrency ones matter here
go vet ./...

cd web && npm run build              # the interface is embedded: build it before go build
cd web && npm run dev                # or iterate against a daemon on :8080
go run ./cmd/orbisd -config ./dev.yaml
go run ./cmd/orbisd -print-ruleset   # render nftables without applying
orbisd -mcp -config /etc/orbis/orbis.yaml   # the tool catalogue over MCP
```

The built interface under `cmd/orbisd/web/dist` is not committed; CI builds it for every push.
A `v*` tag publishes the release: `orbisd-linux-amd64`, `orbisd-linux-arm64` and the multi-arch
image as `:vX.Y.Z`, `:stable` and `:latest`. `:nightly` is rebuilt from main once a day.

The competitive audit that drove much of the feature set is in
[docs/COMPETITIVE-AUDIT.md](docs/COMPETITIVE-AUDIT.md); the interface audit and the two-mode
design in [docs/UX-AUDIT.md](docs/UX-AUDIT.md); the MCP surface in [docs/MCP.md](docs/MCP.md);
Docker specifics in [docs/DOCKER.md](docs/DOCKER.md); third-party notices in
[docs/ATTRIBUTION.md](docs/ATTRIBUTION.md).

## Support and contributing

- **Bugs and requests** go to [GitHub issues](https://github.com/Neoo-Blue/orbis/issues). A node
  can file its own scrubbed problem reports from the Problems page, and a scheduled maintainer
  routine triages the board daily and opens pull requests on `fix/issue-N` branches for clear
  defects. Humans review and merge; nothing is deployed automatically.
- **Pull requests** are welcome. Keep `go test -race ./...`, `go vet ./...` and the web build
  green, format only the files you touch, and describe the failure you saw before the fix.
- **Security reports** follow [SECURITY.md](SECURITY.md).
- **Releases** are tagged `vX.Y.Z`; each publishes the binaries and the multi-arch image.

## Licence

MIT. Blocklists and threat feeds retain their own licences. GeoIP data (c) DB-IP, CC-BY-4.0.
SponsorBlock data is provided by its contributors under CC BY-NC-SA 4.0.
