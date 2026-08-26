<div align="center">

# Orbis

<img width="1913" height="889" alt="image" src="https://github.com/user-attachments/assets/3650f99c-d682-4e5c-a7b6-e938a7d18e13" />


**An AI-assisted network firewall, filtering resolver and traffic analyser — in one binary.**

Little Snitch's per-connection visibility, applied to the whole network, with UniFi's
operational surface and an assistant that can actually read the flow table and change the rules.

</div>

---

## What it does

**Sees every connection.** A kernel BPF filter hands userspace only the packets that carry
identity — the TLS ClientHello, the QUIC Initial, the HTTP request line — so a gigabit link costs
a handful of packets per flow instead of hundreds of thousands. Every connection gets a hostname,
an application, a network operator and a coordinate.

**Blocks ads properly, at three layers.**

| Layer | Catches | Cost |
|---|---|---|
| DNS blocklists | The overwhelming majority of ads and trackers | Free, no client changes |
| CNAME uncloaking | First-party trackers that CNAME into ad networks | Free |
| SNI / QUIC | Apps that hardcode IPs and never ask your resolver | Free |
| Smart capture | Ad hosts no list has caught yet | Free (AI optional) |
| In-stream filter | YouTube pre/mid-rolls, in-app ad payloads | Needs a CA on each device |

**Discovers new ad infrastructure on its own.** Smart capture scores every hostname the network
reaches that no list covers — third-party referrer ratio, response size, request breadth, name
entropy, network operator — and promotes the confident ones automatically. The genuinely ambiguous
cases go to a review queue with the evidence attached. If an AI provider is configured, only those
ambiguous cases are escalated to it: a few dozen questions a day, not tens of thousands.

**Removes YouTube ads.** DNS cannot: YouTube serves ads from the same hosts as video, over the
same connection. Orbis terminates TLS for an explicit host allowlist and strips `adPlacements`,
`playerAds` and `adSlots` from the InnerTube player response. This works on web and the native
apps. It does not work on server-side stitched ads, and the UI says so rather than pretending.

**Is a real firewall.** Zones with trust levels, an ordered rule table with live hit counters,
NAT and port forwarding, time-based rules, IPv6, flow offload — compiled into a single nftables
ruleset and loaded atomically, with `nft -c` validation first and an anti-lockout rule you have to
deliberately disable.

**Is a VPN, both ways.** A WireGuard server for remote access (peers get the same filtering they
would on the LAN, with QR-code enrolment), outbound WireGuard tunnels with policy routing and a
kill switch, and full Tailscale integration: advertise this network as an exit node, route through
someone else's, advertise LAN subnets as a subnet router, and steer individual devices through the
tunnel while everything else uses the WAN.

**Has an assistant that can do the work.** Not a chatbot bolted on the side — it calls the same
code the UI does. Ask "what is the TV talking to overnight", "why is this domain blocked",
"anything unusual today", or tell it to block a domain and apply the ruleset. Write access is off
by default; when it is on, everything it does lands in the audit log.

**Shows you the shape of your network.** A 3D globe and a flat map of live and historical
connections, arcs coloured by verdict, filterable per device, with a running ticker of what just
happened.

---

## Screens

| | |
|---|---|
| **Globe / Flat** | Live connections as arcs from your network to the world. Hover for the host, app, operator and volume; click to inspect or kill. |
| **Connections** | Every flow, live or historical, with the device that opened it and why it was allowed or blocked. |
| **Devices** | Everything on the network, identified by MAC vendor, DHCP fingerprint and behaviour, with live throughput. |
| **DNS** | The query log, upstream health, and a "why is this blocked" lookup that gives a straight answer. |
| **Ad blocking** | Lists, your own rules, the smart-capture review queue with its evidence, and the in-stream filter. |
| **Firewall** | Rules with hit counters, the generated nftables ruleset in a preview pane, and kernel settings checks. |
| **VPN** | WireGuard peers with QR enrolment, and Tailscale exit-node control in both directions. |
| **Assistant** | Chat, with every tool call and result shown inline. |
| **Settings** | Every subsystem, with the trade-offs written next to the switches. |

---

## Install

Debian 12/13 or Ubuntu 22.04+, on bare metal, a VM, or an LXC.

```bash
# Build (Go 1.24+, Node 20+)
cd web && npm ci && npm run build && cd ..
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o orbisd ./cmd/orbisd

# Install
sudo ./deploy/install.sh ./orbisd

# Optional but recommended: real geolocation instead of continent-level guesses
sudo ./deploy/fetch-geoip.sh
```

Then open `http://<host>:8080` and set an admin password.

**The installer changes nothing about how your network behaves.** It installs the binary, writes
a config in observe mode, and starts the service. Becoming the gateway is a separate, explicit
decision you make in the UI.

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

---

## Modes

Orbis has exactly two, and the distinction is the whole safety story.

**Observe** (the default) watches whatever traffic reaches it and records what it *would* have
done. No ruleset is installed. DHCP stays off. Nothing is routed through it. You can point one
device's DNS at it, watch the filtering work, and change your mind at any point. It is safe to
leave a node here indefinitely.

**Inline** makes it a real gateway: the nftables ruleset is loaded, forwarding and NAT are enabled,
DHCP starts if a scope exists, and outbound DNS is redirected to the local resolver so a device
with hardcoded resolvers still gets filtered.

The UI never switches modes on your behalf.

---

## How the ad blocking actually works

Each layer catches what the one before it cannot.

**1. DNS blocklists.** Nine subscriptions by default, ~480,000 rules indexed into a lock-free
matcher. Hosts files, plain domain lists, AdBlock network rules and dnsmasq syntax are all
understood; cosmetic rules and exception rules are skipped rather than misapplied. A wildcard on a
single label — a whole-TLD block — is honoured only when *you* wrote it, never when it comes from
a list, because that is almost always a parse artefact and honouring it takes the network offline.

**2. CNAME uncloaking.** A first-party name that CNAMEs into an ad network is invisible to a
matcher that only sees the queried name. Every hop of the chain is re-checked. This is now the
dominant tracker evasion technique.

**3. SNI and QUIC blocking.** Devices that hardcode `8.8.8.8`, or apps that speak DoH directly,
never touch your resolver. Orbis reads the SNI out of the TLS ClientHello and — by decrypting the
QUIC Initial packet, whose keys are derived from the connection ID travelling in the clear — out
of HTTP/3 handshakes too, and applies the same policy.

**4. Smart capture.** Every hostname the network reaches that no list covers becomes a candidate.
Explicit heuristics score it: how many unrelated sites referred to it, how one-sided the referrer
ratio is, how small the responses are, whether the path looks like `/pixel` or `/rtb`, how random
the leftmost label looks, whether the operator is a known ad network. Confident results are blocked
automatically, subject to a daily cap. The uncertain middle band — and only that band — is
escalated to the model with the raw evidence and no leading language. Critical infrastructure
(OCSP, NTP, OS updates, push, captive-portal detection) can never be auto-blocked no matter how it
scores.

**5. The in-stream filter.** For ads that share a hostname with content. Opt-in, narrow by
default, with a bypass list that always wins.

---

## The assistant

It has fifteen read tools and eleven write tools, all of which go through the same code paths the
UI uses. There is no "API-only" behaviour that could drift from what the model was told it was
doing.

With write access **off** (the default) the mutating tools are not offered to the model at all —
it can inspect and propose, but it cannot act. That is deliberate: a model told it can do
something and then blocked produces a worse conversation than one that was never offered the
capability.

Providers: Anthropic, OpenAI, OpenRouter, or a local Ollama. The anomaly detectors — beaconing,
one-sided uploads, port and host sweeps, DGA-style lookups — are statistical and run whether or
not a model is configured. The model only triages what they find, and its job there is mostly to
say "this is a software update checking in" so the alert list stays worth reading.

---

## Architecture

```
                      ┌──────────── web UI (React + three.js) ────────────┐
                      │  globe · flat map · flows · devices · rules · chat │
                      └───────────────────────┬───────────────────────────┘
                                 REST + WebSocket + SSE
                      ┌───────────────────────┴───────────────────────────┐
                      │                    orbisd                          │
   ┌──────────────────┼───────────────┬───────────────┬───────────────────┤
   │ capture          │ dnsproxy      │ mitm          │ firewall / vpn    │
   │ AF_PACKET + BPF  │ DoT/DoH/UDP   │ TLS intercept │ nftables, wg,     │
   │ TLS · QUIC · HTTP│ cache, block  │ ad stripping  │ tailscale, dhcp   │
   └──────────────────┴───────┬───────┴───────────────┴───────────────────┘
                      ┌───────┴────────┬──────────────────┐
                      │ flow tracker   │ adblock matcher  │  ai
                      │ conntrack via  │ 480k rules,      │  chat + tools,
                      │ netlink        │ smart capture    │  anomaly triage
                      └───────┬────────┴──────────────────┘
                              │
                         SQLite (WAL)
```

Single static binary with the UI embedded. No cgo, no libpcap, no external database.

---

## Configuration

Everything lives in `/etc/orbis/orbis.yaml` (mode `0600`; it holds API keys and private keys).
The Settings page maps one-to-one onto it, so you can drive Orbis from either and keep the file
under version control. Secrets are masked in the API response and never returned.

---

## Notable implementation details

- **The BPF prefilter** is the single most important performance decision. Without it, every byte
  of every stream is copied to userspace. With it, a 4K video costs three or four delivered
  packets in total.
- **QUIC Initial decryption** is what keeps HTTP/3 from being a hole in the filter. The keys come
  from a salt fixed by RFC 9001 and the connection ID sent in the clear, so any on-path observer
  can read the SNI — which is exactly what a filtering resolver needs to do.
- **The nftables ruleset is generated whole and loaded in one transaction.** Incremental rule edits
  are how a firewall ends up in a state nobody can reason about; an atomic replace means the box is
  never briefly open or briefly cut off.
- **Flow orientation is derived from who opened the connection**, not from a sorted tuple. Getting
  this wrong inverts the direction, the service port and the byte counters for roughly half of all
  flows.
- **Conntrack is read over netlink**, because `/proc/net/nf_conntrack` requires a kernel option
  that current Debian, Ubuntu and Proxmox kernels ship disabled.
- **The node locates itself with one DNS query** that asks a public resolver to echo back the
  address it saw. The geolocation then happens against the local database, so the node's position
  is never transmitted. It can be turned off entirely.
- **Tailscale route acceptance is off by default and guarded.** If any tailnet peer advertises a
  prefix covering a network this node is already attached to, accepting it sends locally-destined
  traffic into the tunnel and the node drops off its own LAN — including its management interface.
  Orbis detects the overlap, refuses to enable acceptance, and says which route is the problem.

---

## Security posture

- One administrator, not a user model. **Do not expose port 8080 to the internet** — reach it over
  WireGuard or Tailscale.
- TLS interception is genuinely invasive and off by default, scoped to an explicit host allowlist,
  with banks and pinned apps on a bypass list that always wins. Only the CA certificate is
  downloadable; the private key never leaves the node.
- The assistant cannot change anything unless you turn write access on.
- Every mutating action — UI, API or assistant — is written to an audit log.

---

## Development

```bash
go test ./...            # unit tests
go test -race ./...      # the concurrency ones matter here
go vet ./...

cd web && npm run dev    # UI against a daemon on :8080
go run ./cmd/orbisd -config ./dev.yaml
go run ./cmd/orbisd -print-ruleset   # render nftables without applying
```

---

## Licence

MIT. Blocklists retain their own licences. GeoIP data © DB-IP, CC-BY-4.0.
