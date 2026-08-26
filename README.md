<div align="center">

# Orbis

<img width="1913" height="889" alt="image" src="https://github.com/user-attachments/assets/3650f99c-d682-4e5c-a7b6-e938a7d18e13" />


**An AI-assisted network firewall, filtering resolver, DNS server and traffic analyser, in one binary.**

Little Snitch's per-connection visibility applied to the whole network, a real firewall and DNS
stack underneath, an interactive map of what your network actually is, and an assistant that can
read the flow table and change the rules.

</div>

---

## What it is

Orbis is a single static Go binary with an embedded React UI. It watches the traffic that reaches
it, identifies every connection, filters DNS and ads, and can act as the gateway, the resolver, or
a transparent filter for selected devices. It runs on bare metal, a VM, an LXC, or in Docker.

It ships in **observe** mode by default: it installs no rules, routes nothing, and is safe to leave
running while you decide what you want it to do. Becoming the gateway, the DNS server, or a
per-device filter are each separate, explicit choices you make in the UI.

## What it does

**Sees every connection.** A kernel BPF prefilter hands userspace only the packets that carry
identity: the TLS ClientHello, the QUIC Initial, the HTTP request line. A gigabit link costs a
handful of packets per flow rather than hundreds of thousands. Every connection gets a hostname, an
application, a network operator, a country and a coordinate.

**Is a full DNS server.** A filtering resolver with an LRU cache, upstreams over plain, DoT and DoH,
and a **DoT/DoH server for your own clients** so a phone keeps using it off the LAN and nobody on
the LAN can read your lookups off the wire. Local authoritative records (A, AAAA, CNAME, TXT, MX,
NS, SRV, PTR, with wildcards) make it authoritative for your own names. DNS rewrites, conditional
forwarding, per-client policies, safe search enforcement, blocked-service bundles, rate limiting,
and DNS-rebinding protection.

**Blocks ads at four layers.**

| Layer | Catches | Cost |
|---|---|---|
| DNS blocklists | The overwhelming majority of ads and trackers | Free, no client changes |
| CNAME uncloaking | First-party trackers that CNAME into ad networks | Free |
| SNI / QUIC | Apps that hardcode IPs and never ask your resolver | Free |
| Smart capture | Ad hosts no list has caught yet | Free (AI optional) |
| In-stream filter | YouTube pre/mid-rolls, in-app ad payloads | Needs a CA on each device |

**Removes YouTube ads two ways.** The MITM filter strips ad slots from the InnerTube player
response (needs the CA). The **Lounge engine** needs no certificate at all: it attaches to a TV,
Apple TV or console the way your phone does when it casts, and skips or mutes ads and SponsorBlock
segments by driving the player. The UI states plainly which device classes each can and cannot
cover.

**Is a real firewall.** Zones with trust levels, an ordered rule table with live hit counters, NAT
and port forwarding, time-based rules, IPv6, flow offload, an anti-lockout rule, compiled into a
single nftables ruleset and loaded atomically after `nft -c` validation.

**Is a VPN, both ways.** A WireGuard server with QR enrolment, outbound WireGuard tunnels with
policy routing and a kill switch, and full Tailscale integration in both directions.

**Gets into the path without being the gateway.** ARP interception inserts Orbis in front of
selected devices only: it answers ARP for the real gateway with its own address, forwards and NATs
their traffic, and restores them cleanly the moment it stops. Per-device, opt-in, with the eero (or
any router) still the real gateway underneath.

**Maps your network.** An interactive topology map that identifies devices by MAC prefix, open
port, DHCP fingerprint and behaviour, with confidence and evidence for every verdict. It tells a
Proxmox or Hyper-V host from a NAS from a workstation, clusters a hypervisor's guests under it, and
shows internal traffic with direction. A gateway page with multi-WAN failover, CAKE shaping, static
routes, NAT-PMP, Wake-on-LAN, ping, traceroute, speed test and pcap export.

**Analyses and reports.** Time-series charts for throughput, DNS and connections over up to 14
days. A user-defined alert engine (new device, device offline, bandwidth spike, domain queried,
block-rate spike) routed to webhook or email. Scheduled summary reports, downloadable as CSV or a
printable HTML page. Prometheus metrics. Config backup and restore.

**Asks before allowing.** An opt-in, per-device ask-on-first-connection queue: the first time an
enrolled device reaches a hostname it has never reached before, it waits for your verdict, and the
answer becomes a durable rule.

**Shows the shape of your network.** A 3D globe and a flat map of live and historical connections,
arcs coloured by verdict with a gradient that flows in the direction traffic was opened, and
countries lit up by how much of your traffic reaches them.

**Has an assistant that can do the work.** Fifteen read tools and eleven write tools over the same
code paths the UI uses. Ask what a device is talking to overnight, why a domain is blocked, or tell
it to block something and apply the ruleset. Write access is off by default; everything it does
lands in the audit log. It also speaks **MCP**, so an external assistant can use the same tools.

## Screens

| | |
|---|---|
| **Globe / Flat** | Live connections as arcs from your network to the world, coloured by verdict, filterable per device. |
| **Topology** | An interactive map of your LAN: hosts, their guests, storage, endpoints, and the traffic between them. |
| **Connections** | Every flow, live or historical, with the device that opened it and why it was allowed or blocked. |
| **Devices** | Everything on the network, identified by MAC vendor, DHCP fingerprint and behaviour, with live throughput. |
| **DNS** | The query log, upstream health, local records, and a "why is this blocked" lookup that gives a straight answer. |
| **Domain tester** | Trace a lookup through every stage that can stop it, then allow or block it in one click, or import a list. |
| **Ad blocking** | Lists, your own rules, the smart-capture review queue with its evidence, and the in-stream filter. |
| **YouTube** | The no-CA Lounge engine, device pairing, and an honest coverage matrix. |
| **Firewall / Gateway** | Rules with hit counters, multi-WAN, shaping, port mappings, and live diagnostic tools. |
| **Interception** | Enrol devices to route through Orbis by ARP, with the trade-offs stated plainly. |
| **VPN** | WireGuard peers with QR enrolment, and Tailscale exit-node control in both directions. |
| **Analytics** | Throughput, DNS and connection charts over up to 14 days. |
| **Alerts / Reports** | User-defined triggers and scheduled, exportable summaries. |
| **Assistant** | Chat, with every tool call and result shown inline. |
| **Ask first** | The per-device new-connection review queue. |
| **Settings** | Every subsystem, with the trade-offs written next to the switches. |

Press **⌘K** (or Ctrl-K) anywhere to jump to a page, device, or action.

## Install

Debian 12/13 or Ubuntu 22.04+, on bare metal, a VM, or an LXC.

```bash
# Build (Go 1.25+, Node 20+)
cd web && npm ci && npm run build && cd ..
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o orbisd ./cmd/orbisd

# Install
sudo ./deploy/install.sh ./orbisd

# Optional but recommended: real geolocation instead of continent-level guesses
sudo ./deploy/fetch-geoip.sh
```

Then open `http://<host>:8080`. A first-run wizard asks how the node should sit on the network and
checks, honestly, whether it can actually see your traffic.

### Docker

```bash
docker compose up -d
```

Host networking is required, not optional: Orbis reads raw frames to pull SNI out of a ClientHello,
and inside a bridge network the only frames it would ever see are its own. See
[docs/DOCKER.md](docs/DOCKER.md) for the full rationale, capabilities and volumes. The image is
about 44 MB on Alpine.

### Running in an LXC

Orbis needs raw sockets, netfilter and network configuration, so it wants a privileged container:

```bash
pct create 115 local:vztmpl/debian-13-standard_13.1-2_amd64.tar.zst \
  --hostname orbis --cores 4 --memory 3072 --rootfs local-zfs:16 \
  --net0 name=eth0,bridge=vmbr0,ip=192.168.1.10/24,gw=192.168.1.1 \
  --unprivileged 0 --features nesting=1,keyctl=1

# WireGuard needs the TUN device
cat >> /etc/pve/lxc/115.conf <<'EOF'
lxc.cgroup2.devices.allow: c 10:200 rwm
lxc.mount.entry: /dev/net/tun dev/net/tun none bind,create=file
EOF

# Netfilter modules live in the host kernel; a container cannot load them
for m in nf_tables nft_ct nft_chain_nat nf_nat nf_conntrack nf_conntrack_netlink wireguard tun; do
  modprobe $m
done
sysctl -w net.netfilter.nf_conntrack_acct=1   # per-connection byte counters
```

## Modes and placement

Orbis has two modes, and the distinction is the whole safety story.

**Observe** (the default) watches whatever traffic reaches it and records what it would have done.
No ruleset is installed, DHCP stays off, nothing is routed through it. It is safe to leave here
indefinitely.

**Inline** makes it a real gateway: the nftables ruleset is loaded, forwarding and NAT are enabled,
DHCP starts if a scope exists, and outbound DNS is redirected so a device with hardcoded resolvers
still gets filtered. Inline requires a firewall with at least one zone; a config that would forward
without translating, or drop everything, is corrected to observe on load with an explanation rather
than silently misbehaving.

To filter a network without becoming its gateway, use **ARP interception** (per device) or point
your router's DHCP DNS at Orbis. On a switched network a node that is not in the path sees only its
own traffic and broadcast noise; the onboarding wizard measures this and tells you.

## The assistant and MCP

The assistant has read and write tools that all go through the same code the UI uses, so there is
no API-only behaviour that could drift from what the model was told it was doing. With write access
off (the default) the mutating tools are not offered to the model at all.

The same tool catalogue is exposed over the Model Context Protocol:

```bash
orbisd -mcp -config /etc/orbis/orbis.yaml            # read-only
orbisd -mcp -mcp-write -config /etc/orbis/orbis.yaml # with write access
```

See [docs/MCP.md](docs/MCP.md).

Providers: Anthropic, OpenAI, OpenRouter, or a local Ollama. The anomaly detectors (beaconing,
one-sided uploads, port and host sweeps, DGA-style lookups) are statistical and run whether or not
a model is configured.

## Architecture

```
                      +------------ web UI (React + three.js) -------------+
                      |  globe . map . flows . devices . rules . chat      |
                      +---------------------------+------------------------+
                                 REST + WebSocket + SSE
                      +---------------------------+------------------------+
                      |                    orbisd                          |
   +------------------+---------------+---------------+-------------------+
   | capture          | dnsproxy      | mitm / lounge | firewall / vpn    |
   | AF_PACKET + BPF  | resolver +    | TLS strip /   | nftables, wg,     |
   | TLS . QUIC . HTTP| DoT/DoH server| player drive  | tailscale, dhcp   |
   +------------------+-------+-------+---------------+-------------------+
                      +-------+--------+------------------+--------------+
                      | flow tracker   | adblock matcher  | ai + mcp     |
                      | conntrack via  | 480k rules,      | chat, tools, |
                      | netlink        | smart capture    | anomaly, mcp |
                      +-------+--------+------------------+--------------+
                              |
             topology . intercept . alerts . report . notify
                              |
                         SQLite (WAL)
```

Single static binary with the UI embedded. No cgo, no libpcap, no external database.

## Configuration

Everything lives in `/etc/orbis/orbis.yaml` (mode `0600`; it holds API keys and private keys). The
Settings page maps one-to-one onto it, so you can drive Orbis from either and keep the file under
version control. Secrets are masked in the API response and never returned. Config backup and
restore preserves secrets, so a bundle downloaded from the UI cannot overwrite live keys with masks.

## Notable implementation details

- **The BPF prefilter** is the single most important performance decision. Without it, every byte
  of every stream is copied to userspace.
- **QUIC Initial decryption** keeps HTTP/3 from being a hole in the filter: the keys come from a
  salt fixed by RFC 9001 and the connection ID sent in the clear.
- **The nftables ruleset is generated whole and loaded in one transaction.** An atomic replace means
  the box is never briefly open or briefly cut off.
- **Conntrack is read over netlink**, because `/proc/net/nf_conntrack` requires a kernel option that
  current Debian, Ubuntu and Proxmox kernels ship disabled.
- **Anycast resolvers are corrected before the GeoIP database is consulted.** 1.1.1.1 is registered
  to APNIC in Australia; left uncorrected it makes Australia the busiest country on a globe by an
  order of magnitude.
- **Tailscale route acceptance is off by default and guarded** against a peer advertising a prefix
  that covers a network this node is already on, which would strand it.

## Security posture

- One administrator, not a user model. **Do not expose port 8080 to the internet** directly; reach
  it over WireGuard, Tailscale, or a Cloudflare Tunnel with Access in front.
- TLS interception is genuinely invasive and off by default, scoped to an explicit host allowlist,
  with banks and pinned apps on a bypass list that always wins. Only the CA certificate is
  downloadable; the private key never leaves the node.
- ARP interception is a legitimate technique against your own devices and an attack against a
  network you do not control. Enrolment is explicit and per-device, and the restore-on-stop path is
  treated as carefully as the takeover.
- The assistant cannot change anything unless you turn write access on.
- Every mutating action, from the UI, the API, the assistant or MCP, is written to the audit log.

## Development

```bash
go test ./...            # unit tests
go test -race ./...      # the concurrency ones matter here
go vet ./...

cd web && npm run dev    # UI against a daemon on :8080
go run ./cmd/orbisd -config ./dev.yaml
go run ./cmd/orbisd -print-ruleset   # render nftables without applying
```

The competitive audit that drove much of the feature set is in
[docs/COMPETITIVE-AUDIT.md](docs/COMPETITIVE-AUDIT.md).

## Licence

MIT. Blocklists retain their own licences. GeoIP data (c) DB-IP, CC-BY-4.0.
