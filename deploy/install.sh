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

install_deps() {
  # nftables: the firewall engine. conntrack: flow termination + byte counters.
  # wireguard-tools: the VPN. iproute2: policy routing for VPN steering.
  if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends \
      nftables conntrack wireguard-tools iproute2 hostapd iw ca-certificates curl >/dev/null
  elif command -v pacman >/dev/null 2>&1; then
    # On Arch a package install is a system update: -Sy alone (refresh, then
    # install against the new database) is the partial upgrade the wiki warns about.
    pacman -Syu --noconfirm --needed \
      nftables conntrack-tools wireguard-tools iproute2 hostapd iw ca-certificates curl >/dev/null
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y \
      nftables conntrack-tools wireguard-tools iproute hostapd iw ca-certificates curl >/dev/null
  elif command -v zypper >/dev/null 2>&1; then
    zypper --non-interactive install \
      nftables conntrack-tools wireguard-tools iproute2 hostapd iw ca-certificates curl >/dev/null
  else
    warn "dependencies were not installed (no apt-get, pacman, dnf or zypper): nftables conntrack wireguard-tools iproute2 hostapd iw ca-certificates curl"
  fi
}

[ "$(id -u)" -eq 0 ] || die "run as root"
[ -f "$BIN_SRC" ] || die "binary not found at $BIN_SRC"

say "Installing dependencies"
install_deps

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

say "Installing the systemd units and the safety net"
# The units come from the binary so the installer, the daemon and the
# settings page all install the same thing: restart on failure, a software
# watchdog fed only while the resolver answers, the lifeboat standby that
# takes over DNS, DHCP and forwarding when the service cannot come back,
# the release step that puts intercepted devices back on the real gateway
# after any stop, and the hardware watchdog where the board has one.
if ! /usr/local/bin/orbisd -install-safety-net -config "$CONFIG"; then
  warn "safety net install failed; writing a plain unit instead"
  cat > /etc/systemd/system/orbis.service <<'UNIT'
[Unit]
Description=Orbis network firewall and traffic analyser
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/orbisd -config /etc/orbis/orbis.yaml
Restart=on-failure
RestartSec=3
User=root
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
UNIT
fi

say "Applying kernel settings"
install -d /etc/sysctl.d /etc/modules-load.d
# The net.netfilter keys only exist once nf_conntrack is loaded, and at boot
# systemd-sysctl runs after systemd-modules-load.
printf 'nf_conntrack\n' > /etc/modules-load.d/orbis.conf
cat > /etc/sysctl.d/99-orbis.conf <<'SYSCTL'
# Byte counters per connection, which the flow table reads.
net.netfilter.nf_conntrack_acct = 1
net.netfilter.nf_conntrack_timestamp = 1
net.netfilter.nf_conntrack_max = 262144
# Loose RPF: strict mode breaks policy routing (VPN steering).
net.ipv4.conf.all.rp_filter = 2
# Lets the transparent proxy redirect to a listener on loopback.
net.ipv4.conf.all.route_localnet = 1
SYSCTL
# Forwarding is deliberately NOT set here: turning it on is part of becoming
# a gateway, and that belongs to the inline-mode decision, not the installer.
modprobe nf_conntrack 2>/dev/null || warn "could not load nf_conntrack (expected in an unprivileged container)"
sysctl -q --system 2>/dev/null || warn "some sysctls could not be applied"

systemctl daemon-reload
systemctl enable --now orbis.service

# api.listen looks like ":8080" or "0.0.0.0:8080".
ui_port=8080
if [ -f "$CONFIG" ]; then
  listen="$(awk '
    $1 == "api:" { inapi=1; next }
    inapi && /^[^[:space:]#]/ { exit }
    inapi && $1 == "listen:" { print $2; exit }
  ' "$CONFIG" 2>/dev/null || true)"
  listen="${listen#[\"\']}"
  listen="${listen%[\"\']}"
  p="${listen##*:}"
  case "$p" in
    ''|*[!0-9]*) ;;
    *) ui_port="$p" ;;
  esac
fi

# The one-liner is the whole setup before the browser; do not claim success
# if the service never answers.
ready=0
for _ in $(seq 1 20); do
  if curl -fs -o /dev/null --max-time 1 "http://127.0.0.1:${ui_port}/api/auth/status" 2>/dev/null; then
    ready=1
    break
  fi
  sleep 1
done
if [ "$ready" -ne 1 ]; then
  echo "Orbis did not start: run journalctl -u orbis -n 50" >&2
  exit 1
fi

addrs="$(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1)" || true
[ -n "$addrs" ] || addrs="$(hostname -I 2>/dev/null || true)"

echo
say "Orbis is up."
ui_printed=0
# Word-split: each token is one address from ip or hostname -I.
# shellcheck disable=SC2086
for a in $addrs; do
  case "$a" in
    *:*) continue ;;
  esac
  if [ "$ui_printed" -eq 0 ]; then
    echo "    UI:      http://${a}:${ui_port}"
    ui_printed=1
  else
    echo "             http://${a}:${ui_port}"
  fi
done
if [ "$ui_printed" -eq 0 ]; then
  echo "    UI:      http://127.0.0.1:${ui_port}"
fi
echo "    Config:  $CONFIG"
echo "    Logs:    journalctl -u orbis -f"
echo
echo "  Open it in a browser. The first screen is a guided setup: it sets a password, names the node, picks what to run, the upstream resolvers and blocklists, and shows you how to point your router at it. About five minutes."
