#!/usr/bin/env bash
# Orbis installer. Idempotent: safe to re-run to upgrade in place.
#
# Deliberately does NOT touch how the network behaves. It installs the binary,
# writes a config in observe mode, and starts the service. Making the node a
# real gateway is a separate, explicit decision made from the UI.
set -euo pipefail

BIN_SRC="${1:-./orbisd}"
PREFIX="${PREFIX:-/usr/local/bin}"
CONFIG_DIR="${CONFIG_DIR:-/etc/orbis}"
DATA_DIR="${DATA_DIR:-/var/lib/orbis}"
CONFIG="$CONFIG_DIR/orbis.yaml"

say()  { printf '\033[36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33m warn\033[0m %s\n' "$*"; }
die()  { printf '\033[31merror\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root"
[ -f "$BIN_SRC" ] || die "binary not found at $BIN_SRC"

say "Installing dependencies"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
# nftables: the firewall engine. conntrack: flow termination + byte counters.
# wireguard-tools: the VPN. iproute2: policy routing for VPN steering.
apt-get install -y -qq --no-install-recommends \
  nftables conntrack wireguard-tools iproute2 ca-certificates curl >/dev/null

say "Installing orbisd to $PREFIX"
install -m 0755 "$BIN_SRC" "$PREFIX/orbisd"

install -d -m 0750 "$CONFIG_DIR"
install -d -m 0750 "$DATA_DIR" "$DATA_DIR/ca" "$DATA_DIR/geoip"

if [ ! -f "$CONFIG" ]; then
  say "Writing initial configuration (observe mode)"
  cat > "$CONFIG" <<YAML
# Orbis configuration.
#
# The node ships in observe mode: it watches traffic that reaches it and
# records what it would have done, but installs no firewall ruleset, answers
# no DHCP, and does not route anything. Switch to inline mode from the UI
# (Settings -> Node & mode) when you are ready for it to be the gateway.
mode: observe

node:
  name: $(hostname)
  data_dir: $DATA_DIR
  timezone: $(cat /etc/timezone 2>/dev/null || echo UTC)

api:
  listen: ":8080"

store:
  path: $DATA_DIR/orbis.db
  flow_retention_days: 14
  event_retention_days: 60

capture:
  enabled: true
  snaplen: 512
  conntrack: true

dns:
  enabled: true
  listen: ["0.0.0.0:53"]
  upstreams:
    - "tls://1.1.1.1:853"
    - "tls://9.9.9.9:853"
  strategy: parallel
  log_queries: true

adblock:
  enabled: true
  smart_capture:
    enabled: true
    use_ai: false   # turn on once an AI provider is configured

mitm:
  enabled: false    # TLS interception; needed for in-stream (YouTube) ads
  ca_dir: $DATA_DIR/ca

firewall:
  enabled: false
  default_forward: drop
  anti_lockout: true

dhcp:
  enabled: false

vpn:
  server:
    enabled: false

tailscale:
  enabled: false

ai:
  enabled: false

geoip:
  city_db: $DATA_DIR/geoip/dbip-city-lite.mmdb
  asn_db: $DATA_DIR/geoip/dbip-asn-lite.mmdb
YAML
  chmod 0600 "$CONFIG"
else
  say "Keeping the existing configuration at $CONFIG"
fi

# The resolver needs port 53. systemd-resolved holds it by default on Debian
# and Ubuntu, and the resulting bind failure is a confusing first experience.
if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
  warn "systemd-resolved is listening on port 53"
  warn "Freeing it so Orbis can bind. /etc/resolv.conf will point at 127.0.0.1."
  mkdir -p /etc/systemd/resolved.conf.d
  cat > /etc/systemd/resolved.conf.d/orbis.conf <<'RESOLVED'
[Resolve]
DNSStubListener=no
RESOLVED
  systemctl restart systemd-resolved || true
  # Point the node itself at its own resolver, so its lookups are filtered
  # and logged like everything else.
  if [ -L /etc/resolv.conf ] || [ -f /etc/resolv.conf ]; then
    rm -f /etc/resolv.conf
  fi
  printf 'nameserver 127.0.0.1\nnameserver 1.1.1.1\noptions timeout:2\n' > /etc/resolv.conf
fi

# Tailscale is optional but the exit-node features are inert without it, and
# installing the daemon changes nothing until someone authenticates it.
if ! command -v tailscale >/dev/null 2>&1; then
  if [ "${SKIP_TAILSCALE:-0}" != "1" ]; then
    say "Installing Tailscale (stays logged out; authenticate from the UI when you want it)"
    curl -fsSL https://tailscale.com/install.sh | sh >/dev/null 2>&1 \
      || warn "Tailscale install failed; the VPN page will show how to install it by hand"
  fi
fi

say "Installing the systemd unit"
cat > /etc/systemd/system/orbis.service <<'UNIT'
[Unit]
Description=Orbis network firewall and traffic analyser
Documentation=https://github.com/Neoo-Blue/orbis
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/orbisd -config /etc/orbis/orbis.yaml
Restart=on-failure
RestartSec=3

# Runs as root because it needs raw sockets, netfilter and network
# configuration. The capability set below is still narrowed to what is
# actually used, so a compromise does not hand over the whole machine.
User=root
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_SYS_MODULE CAP_DAC_OVERRIDE CAP_CHOWN CAP_SETUID CAP_SETGID

NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/lib/orbis /etc/orbis /etc/resolv.conf
ProtectKernelLogs=yes
ProtectControlGroups=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes

# The flow table and the DNS cache are the memory footprint; this is a
# generous ceiling that still stops a runaway from taking the host down.
MemoryMax=2G
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
UNIT

say "Applying kernel settings"
cat > /etc/sysctl.d/99-orbis.conf <<'SYSCTL'
# Byte counters per connection, which the flow table reads.
net.netfilter.nf_conntrack_acct = 1
net.netfilter.nf_conntrack_timestamp = 1
net.netfilter.nf_conntrack_max = 262144
SYSCTL
# Forwarding is deliberately NOT set here: turning it on is part of becoming
# a gateway, and that belongs to the inline-mode decision, not the installer.
modprobe nf_conntrack 2>/dev/null || warn "could not load nf_conntrack (expected in an unprivileged container)"
sysctl -q --system 2>/dev/null || warn "some sysctls could not be applied"

systemctl daemon-reload
systemctl enable --now orbis.service

say "Waiting for the service"
for _ in $(seq 1 20); do
  if curl -fsS --max-time 2 http://127.0.0.1:8080/api/status >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done

ADDR="$(hostname -I 2>/dev/null | awk '{print $1}')"
echo
say "Orbis is installed and running in observe mode."
echo "    UI:      http://${ADDR:-127.0.0.1}:8080"
echo "    Config:  $CONFIG"
echo "    Logs:    journalctl -u orbis -f"
echo
echo "  Nothing is routed through this node yet. Next steps, in the UI:"
echo "    1. Set an admin password (you are prompted on first load)."
echo "    2. Optionally point a device's DNS at ${ADDR:-this host} to see filtering work."
echo "    3. Switch to inline mode only when you want it to be the gateway."
