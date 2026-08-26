# Running Orbis in Docker

```bash
docker compose up -d
```

Then open `http://<host>:8080` and set an admin password.

## Why host networking is required, not preferred

Orbis reads raw frames off an interface to pull the SNI out of a TLS
ClientHello and the connection ID out of a QUIC Initial. Inside a bridge
network the only frames it would ever see are its own, so capture, DPI, the
flow table, the globe and the topology map would all be empty while appearing
to work.

The same applies to the firewall. Orbis compiles an nftables ruleset for the
host's forwarding path; loaded inside a network namespace it would govern
traffic that does not exist.

There is no bridge-network variant of this that does anything useful. A
container without `network_mode: host` will start, serve its UI, and observe
nothing.

## Capabilities

| Capability | Why |
|---|---|
| `NET_ADMIN` | Load the nftables ruleset, manage routes and interfaces |
| `NET_RAW` | `AF_PACKET` capture |
| `SYS_MODULE` | Load `nft_*` and `nf_conntrack` if the host has not already |

`SYS_MODULE` can be dropped if the host loads the modules itself:

```bash
for m in nf_tables nft_ct nft_chain_nat nf_nat nf_conntrack nf_conntrack_netlink; do
  modprobe $m
done
sysctl -w net.netfilter.nf_conntrack_acct=1   # per-connection byte counters
```

`/dev/net/tun` is only needed for the WireGuard server. Everything else works
without it.

## Volumes

| Path | Holds |
|---|---|
| `/etc/orbis` | `orbis.yaml`. Mode 0600: it carries API keys and private keys |
| `/var/lib/orbis` | SQLite database, the generated CA, GeoIP databases |

Both must persist. Losing `/var/lib/orbis` discards the flow history, the DNS
log, and the CA that every device you onboarded has trusted, which means
reinstalling the certificate everywhere.

## Ports

| Port | Service |
|---|---|
| 8080/tcp | UI and API |
| 53/udp, 53/tcp | Filtering resolver |
| 853/tcp | DNS over TLS (opt-in) |
| 8443/tcp | DNS over HTTPS (opt-in) |
| 3128, 3129/tcp | Filter proxy redirect targets |
| 51820/udp | WireGuard server (opt-in) |

With host networking these bind directly, so anything already using port 53 on
the host has to stop first. `systemd-resolved` is the usual culprit:

```bash
systemctl disable --now systemd-resolved
```

## Building locally

```bash
docker build -t orbis:dev --build-arg VERSION=$(git describe --tags --always) .
```

The UI is built in its own stage and copied in before the Go build, because it
is embedded into the binary. The resulting image is about 44 MB.

## A caveat worth reading before you judge the dashboards

A node that is not on the traffic path records only its own traffic and
broadcast noise. Every screen will look populated and none of it will be about
your network. In Docker this is easy to hit: the container starts, serves the
UI, and observes almost nothing, because the host is not the gateway.

The onboarding wizard measures this directly and tells you. If it reports that
0% of recent flows came from other devices, the placement is the problem, not
the configuration.
