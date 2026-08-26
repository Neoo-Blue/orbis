# Orbis competitive audit

Audited 2026-08-26 against UniFi, Meraki, OPNsense, AdGuard Home, Pi-hole, NextDNS,
Little Snitch and uBlock Origin.

> **Status: closed in v1.1.0.** Every Tier 1, Tier 2 and Tier 3 gap below has been
> implemented. The three dead policy fields now work, and the sections marked
> "missing in Orbis" for DNS, ops and gateway features are historical. What remains
> open is only the Tier 4 list and the structural non-goals in section 5, which are
> deliberate. This document is kept as the record of what was found and why each
> decision was made.

Everything in the "Orbis today" column was verified by reading the source, not the README.
Where the README claims something the code does not do, this document follows the code.

## Method

Feature presence was checked by grepping `internal/` and `web/src` and then reading the
call sites, because substring matches lie: `radius` matched `border-radius` in the CSS,
`rbac` matched a file-permission test, `upnp` matched an SSDP multicast label. Every
"present" below has a real call path behind it.

## 1. Orbis today, verified

**Resolver.** Filtering DNS with an LRU cache keyed on the DO bit, upstream over plain,
DoT and DoH, selectable strategy, query log, local records and reverse PTR, Extended DNS
Errors, configurable block TTL and sinkhole shape.

**Blocking.** ~480k rules from 9 default subscriptions (including URLhaus, Phishing Army
and Hagezi TIF for malware, and a Hagezi list that sinkholes public DoH endpoints), hosts
/ ABP / dnsmasq syntax, CNAME uncloaking, SNI and QUIC-Initial blocking, and a smart
capture pipeline that scores unknown hostnames on referrer breadth, response size, path
shape and name entropy, escalating only the ambiguous band to a model.

**Firewall.** Zone model with trust levels, ordered rules with live counters, NAT and
port forward, IPv6, flow offload, nflog, anti-lockout, sysctl posture checks, and
time-of-day matching on rules. The ruleset is generated whole and loaded atomically after
`nft -c` validation.

**VPN.** WireGuard server with QR enrolment, outbound WireGuard tunnels with policy
routing and kill switch, and Tailscale in both directions (exit node in and out, subnet
router, per-device steering) with an overlap guard on route acceptance.

**Interception.** TLS MITM against an explicit SNI allowlist with a bypass list that
wins, InnerTube ad-slot stripping, generic JSON ad-key removal, tracker beacon dropping,
a cosmetic CSS blob, and a QUIC block so HTTP/3 cannot route around the proxy.

**YouTube without a CA.** The Lounge engine drives cast-capable players directly and
skips or mutes ads plus SponsorBlock segments, with DIAL auto-discovery and code pairing.

**Visibility.** AF_PACKET with a BPF prefilter, conntrack over netlink, TLS/QUIC/HTTP
DPI, GeoIP and ASN enrichment, hostname-derived app labels, a 3D globe and a flat map.

**Assistant.** 15 read tools and 11 write tools over the same code paths as the UI, write
access off by default, plus statistical anomaly detectors (beaconing, one-sided upload,
port sweeps, DGA-shaped lookups, new devices) that run with or without a model.

**Other.** DHCP with fingerprint-based identity, VLAN management, per-client policies,
audit log, event stream, minute stats, single-admin auth.

## 2. Bugs found during this audit

These are not gaps against competitors. They are features Orbis presents as working that
do nothing.

| Field | Status | Detail |
|---|---|---|
| `Policy.SafeSearch` | **fixed in v1.1.0** | Persisted in `policies` table, in the API and in `types.ts`. Never read by the resolver. Enabling it changes nothing. |
| `Policy.BlockDoH` | **fixed in v1.1.0** | Same. The global `adblock.block_dns_bypass` works, so the per-policy control is redundant and misleading. |
| `Policy.Schedule` | **fixed in v1.1.0** | Firewall *rule* schedules work via `scheduleMatch`. Policy schedules are stored and ignored, which is worse than absent because rule schedules prove the concept. |

The resolver enforces `Allowlist`, `Denylist` and `Categories` only. Fix by implementing
the three or deleting them. Given the project's stated posture of saying what does not
work rather than pretending, leaving them is the wrong call.

## 3. Head to head

### Pi-hole
Orbis exceeds it on nearly every axis: Pi-hole has no SNI or QUIC blocking, no CNAME
uncloaking by default, no flow analysis, no firewall, no VPN, no interception.

Missing in Orbis: **Teleporter-style backup and restore**, **DNS rebinding protection**,
**conditional forwarding**, per-group scheduling that actually runs, and an equivalent of
`pihole -t` style live tail outside the UI.

### AdGuard Home
The closest DNS-layer peer, and the gap list is the most actionable of any product here.

Missing in Orbis: **DoH / DoT / DoQ server for clients** (Orbis speaks encrypted DNS
upstream only, so clients reach it over plain port 53), **DNS rewrites**, **blocked
services** as one-click curated bundles (TikTok, Instagram, Roblox and so on),
**safe search enforcement** (dead field, see above), **DNS rate limiting**, **DNS
rebinding protection**, per-client encrypted-DNS identity, optimistic caching, and
**backup/restore**.

Orbis has that AdGuard Home does not: SNI/QUIC enforcement, packet-level flow analysis,
firewall, VPN, TLS interception, in-stream ad removal, the Lounge engine, geo
visualisation, and the assistant.

### NextDNS
Missing in Orbis: **per-device DoH profiles** (the roaming story, which is NextDNS's
whole point and depends on the DoH-server gap above), **curated parental-control
categories and app blocks**, **YouTube restricted mode**, **native-tracking bundles**
per OS vendor, **log retention and privacy controls** as a first-class setting, and
threat features Orbis lacks: **typosquatting**, **IDN homograph** and **DNS rebinding**
detection. Orbis does have DGA detection, which NextDNS also has.

Orbis wins on: everything off-DNS, plus local data ownership.

### uBlock Origin
Parity is partial **by design** and cannot be closed from the network.

Missing in Orbis: filter-list-driven **cosmetic rules** (Orbis injects one static CSS
blob and explicitly skips cosmetic rules when parsing lists), **scriptlet injection** and
anti-adblock defusing, **procedural cosmetic filters**, per-site switches, the element
picker, and the logger.

This is structural. Those features run inside the page. A network device can only
approximate them through MITM on every site, which is far more invasive than the current
narrow allowlist. Recommendation: do not chase this. Say plainly in the UI that a browser
extension complements Orbis rather than competing with it.

### Little Snitch
Missing in Orbis: **per-process and per-application identity**, code-signature-based app
attribution, **connection alerts that ask on first connection**, profiles that switch by
location, and the research assistant's crowd-sourced "what is this connection".

Per-process identity is structurally impossible without an agent on each host. Orbis
approximates it with hostname-derived app labels, which is genuinely weaker and should be
described as such.

**The ask-on-first-connection workflow is not impossible and is the most interesting
missing feature in this whole audit.** The README positions Orbis as "Little Snitch's
per-connection visibility applied to the whole network", but Orbis is observe-then-block,
never ask-then-decide. A queue of new destinations awaiting a verdict, per device, would
deliver the promise the tagline already makes.

### OPNsense
The reference for "is it a real firewall". Orbis matches it on atomic ruleset generation,
zones, NAT, IPv6, WireGuard and GeoIP data, and beats it on analysis and UX.

Missing in Orbis: **multi-WAN with gateway monitoring and failover**, **traffic shaping
and QoS**, **static routes**, **dynamic routing (BGP/OSPF)**, **CARP high availability**,
**UPnP/NAT-PMP**, **captive portal**, **RADIUS/LDAP auth**, **IDS/IPS (Suricata)**,
**config backup with versioned history**, **aliases** as reusable rule objects, 1:1 NAT,
outbound NAT rule control, and **Wake-on-LAN**.

Multi-WAN and QoS are the two that most undermine the "real gateway" claim for a home
that would otherwise put Orbis in line.

### UniFi
Missing in Orbis: everything that requires being an AP or switch controller (**SSID and
WiFi management**, band steering, PPSK, **PoE and port profiles**, adoption and
provisioning, topology map), plus **IDS/IPS**, **multi-WAN and LTE failover**, **speed
test**, **guest portal**, **multi-site**, **mobile app**, **cloud remote access**,
**scheduled backups** and **alerting**.

The AP and switch half is a different product category and should be an explicit non-goal.
The gateway half (multi-WAN, IDS, speed test, alerting) is fair game.

### Meraki
Missing in Orbis: **cloud dashboard and multi-tenancy**, org/network hierarchy and
**templates**, **group policies at scale**, **L7 firewall and per-app shaping**, **content
filtering by Talos-style category**, **AMP**, **IDS/IPS**, **SD-WAN and AutoVPN**,
**systems manager (MDM)**, **warm spare HA**, **splash pages**, **802.1X**, **packet
capture download**, **live tools (ping, traceroute, cable test)**, **event log export and
webhooks**, **summary reports**, and licensing/compliance machinery.

Most of this is enterprise shape, not home shape. The genuinely portable ideas are
**packet capture download**, **live diagnostic tools**, **webhook alerting** and
**scheduled summary reports**.

## 4. Consolidated gap register

Severity is about Orbis's own stated goals, not about matching every competitor.

### Tier 1: correctness, do first
| Gap | Why |
|---|---|
| Three dead policy fields | Ships a control that does nothing. Directly contradicts the project's honesty posture. |
| DNS rebinding protection | Real security hole. Pi-hole and AdGuard Home both have it. Small change. |
| DNS rate limiting | Amplification exposure on any node reachable beyond the LAN. |

### Tier 2: high value, moderate effort
| Gap | Why |
|---|---|
| DoH/DoT/DoQ **server** for clients | The single biggest differentiator gap. Unlocks the roaming-device story and stops plaintext 53 on the LAN. |
| DNS rewrites and conditional forwarding | Table stakes at this layer; every DNS peer has it. |
| Blocked services bundles | Cheap to build, high perceived value, the thing families actually want. |
| Backup and restore | Every peer has it. Currently one corrupted SQLite file from total loss. |
| Webhook / email alert delivery | Events already exist and never leave the box. |
| Prometheus `/metrics` | Cheap, and the stats are already collected. |
| Ask-on-first-connection queue | Delivers the Little Snitch promise the tagline already makes. |

### Tier 3: gateway completeness, expensive
Multi-WAN with failover, QoS and shaping, static routes, UPnP/NAT-PMP, HA/CARP,
packet capture download, live diagnostic tools, speed test, Wake-on-LAN.

### Tier 4: recommend against
IDS/IPS (Suricata is a large ongoing commitment, and the statistical anomaly detectors are
a defensible different bet), captive portal, RADIUS/802.1X, WiFi and switch management,
multi-user RBAC (single-admin is a documented deliberate choice), cloud multi-tenancy.

## 5. Structural non-goals, worth stating in the UI

- **WiFi, switch and AP management.** Orbis is not a controller for radios or ports.
- **Per-process attribution.** Requires an agent on each host. Hostname-derived app labels
  are an approximation and the UI should not imply otherwise.
- **In-page cosmetic filtering and scriptlets.** Belongs in a browser extension. Orbis
  should recommend one rather than pretend to replace it.
- **Mobile YouTube app filtering.** Certificate pinning plus no cast surface. Already
  stated honestly in the YouTube coverage matrix.
