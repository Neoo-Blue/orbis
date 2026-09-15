#!/usr/bin/env bash
#
# Orbis one-line installer.
#
#   curl -fsSL https://raw.githubusercontent.com/Neoo-Blue/orbis/main/deploy/bootstrap.sh | sudo bash
#
# It figures out where it is and does the rest:
#   - On a Proxmox host, it creates a privileged LXC and installs Orbis inside
#     it, so nothing is installed on the hypervisor itself.
#   - On a Debian/Ubuntu host, VM or existing container, it installs Orbis in
#     place: dependencies, the prebuilt binary for this architecture, a systemd
#     service, and (optionally) the GeoIP databases.
#
# It never changes how the network behaves. The node comes up in observe mode.
#
# Overrides (all optional), e.g.  curl ... | CTID=130 BRIDGE=vmbr0 sudo -E bash
#   CHANNEL=nightly  rolling nightly build (default: latest tagged release)
#   CTID        LXC id on Proxmox (default: next free)
#   HOSTNAME    LXC hostname (default: orbis)
#   BRIDGE      LXC bridge (default: vmbr0)
#   IP          LXC address, CIDR or "dhcp" (default: dhcp)
#   GATEWAY     LXC gateway when IP is static
#   STORAGE     rootfs storage (default: autodetected)
#   CORES/MEM/DISK  LXC sizing (default: 4 / 3072 / 16)
#   SKIP_GEOIP=1    do not download the ~130 MB GeoIP databases
#   FORCE_INPLACE=1 install here even on a Proxmox host

set -euo pipefail

REPO="Neoo-Blue/orbis"
RAW="https://raw.githubusercontent.com/${REPO}/main"
CHANNEL="${CHANNEL:-stable}"

c_say()  { printf '\033[36m==>\033[0m %s\n' "$*"; }
c_warn() { printf '\033[33m warn\033[0m %s\n' "$*"; }
c_die()  { printf '\033[31merror\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || c_die "run as root (pipe into 'sudo bash')"

on_wsl() { grep -qi microsoft /proc/version 2>/dev/null; }

if on_wsl; then
  c_warn "WSL: the node sits behind Windows' virtual network, so it cannot see the LAN's traffic, cannot intercept devices, and other devices cannot reach its resolver unless WSL is in mirrored networking mode and Windows forwards port 53."
  c_warn "systemd must be enabled in /etc/wsl.conf for the service to run. Fine for looking at the interface and filtering the Windows host itself."
  if [ ! -d /run/systemd/system ]; then
    c_die "WSL has no systemd; add [boot] systemd=true to /etc/wsl.conf, then from Windows run wsl --shutdown and start this distro again"
  fi
elif [ ! -d /run/systemd/system ]; then
  c_die "Orbis needs systemd for the service and the safety net; without it, run docker compose up -d with the repo's docker-compose.yml (host networking, NET_ADMIN and NET_RAW)"
fi

arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo amd64 ;;
    aarch64|arm64) echo arm64 ;;
    *) c_die "unsupported architecture: $(uname -m)" ;;
  esac
}

# stable follows GitHub's latest-release redirect; nightly is a rolling tag.
binary_url() {
  local a; a="$(arch)"
  if [ "$CHANNEL" = "stable" ]; then
    echo "https://github.com/${REPO}/releases/latest/download/orbisd-linux-${a}"
  else
    echo "https://github.com/${REPO}/releases/download/${CHANNEL}/orbisd-linux-${a}"
  fi
}

install_deps() {
  if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends \
      nftables conntrack wireguard-tools iproute2 tcpdump hostapd iw ca-certificates curl >/dev/null
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
    c_warn "dependencies were not installed (no apt-get, pacman, dnf or zypper): nftables conntrack wireguard-tools iproute2 tcpdump hostapd iw ca-certificates curl"
  fi
}

# ---- in-place install (host / VM / container) --------------------------------

install_inplace() {
  c_say "Installing Orbis in place ($(arch), ${CHANNEL} channel)"
  install_deps

  local tmp; tmp="$(mktemp -d)"
  trap 'rm -rf "${tmp:-}"' EXIT

  c_say "Downloading orbisd"
  curl -fsSL -o "$tmp/orbisd" "$(binary_url)" \
    || c_die "could not download the binary from $(binary_url)"
  chmod +x "$tmp/orbisd"

  c_say "Fetching the installer"
  curl -fsSL -o "$tmp/install.sh" "${RAW}/deploy/install.sh" \
    || c_die "could not fetch install.sh"
  chmod +x "$tmp/install.sh"

  bash "$tmp/install.sh" "$tmp/orbisd"

  if [ "${SKIP_GEOIP:-0}" != "1" ]; then
    c_say "Fetching GeoIP databases (~130 MB; set SKIP_GEOIP=1 to skip)"
    if curl -fsSL -o "$tmp/geoip.sh" "${RAW}/deploy/fetch-geoip.sh"; then
      bash "$tmp/geoip.sh" || c_warn "GeoIP fetch failed; the globe falls back to region-level placement"
      systemctl restart orbis.service 2>/dev/null || true
    fi
  fi

  local ip; ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  c_say "Done. Open http://${ip:-<this-host>}:8080 and set an admin password."
}

# ---- Proxmox LXC install -----------------------------------------------------

on_proxmox() {
  command -v pct >/dev/null 2>&1 && command -v pveam >/dev/null 2>&1 && [ ! -f /run/systemd/container ]
}

pick_storage() {
  # Prefer a storage that supports container rootfs; fall back to 'local'.
  if [ -n "${STORAGE:-}" ]; then echo "$STORAGE"; return; fi
  pvesm status -content rootdir 2>/dev/null | awk 'NR>1 && $3=="active"{print $1; exit}' \
    || echo local
}

pick_template() {
  # Newest Debian standard template already downloaded, else download one.
  local t
  t="$(pveam list local 2>/dev/null | awk '/debian-1[0-9]-standard/{print $1}' | sort -V | tail -1)"
  if [ -z "$t" ]; then
    c_say "Downloading a Debian LXC template" >&2
    pveam update >/dev/null 2>&1 || true
    local avail
    avail="$(pveam available --section system 2>/dev/null | awk '/debian-1[0-9]-standard/{print $2}' | sort -V | tail -1)"
    [ -n "$avail" ] || c_die "no Debian template available; download one in the Proxmox UI first"
    pveam download local "$avail" >/dev/null
    t="local:vztmpl/$avail"
  fi
  echo "$t"
}

install_lxc() {
  local ctid hostname bridge ipcfg storage template
  ctid="${CTID:-$(pvesh get /cluster/nextid)}"
  hostname="${HOSTNAME:-orbis}"
  bridge="${BRIDGE:-vmbr0}"
  storage="$(pick_storage)"
  template="$(pick_template)"

  if [ "${IP:-dhcp}" = "dhcp" ]; then
    ipcfg="name=eth0,bridge=${bridge},ip=dhcp"
  else
    ipcfg="name=eth0,bridge=${bridge},ip=${IP}"
    [ -n "${GATEWAY:-}" ] && ipcfg="${ipcfg},gw=${GATEWAY}"
  fi

  c_say "Creating LXC ${ctid} (${hostname}) on ${storage} via ${bridge}"
  pct create "$ctid" "$template" \
    --hostname "$hostname" \
    --cores "${CORES:-4}" --memory "${MEM:-3072}" --swap 512 \
    --rootfs "${storage}:${DISK:-16}" \
    --net0 "$ipcfg" \
    --unprivileged 0 --features nesting=1,keyctl=1 \
    --onboot 1 \
    --description "Orbis network firewall. Installed by bootstrap.sh." >/dev/null

  # WireGuard needs /dev/net/tun; the netfilter modules live in the host kernel.
  cat >> "/etc/pve/lxc/${ctid}.conf" <<'LXCCONF'
lxc.cgroup2.devices.allow: c 10:200 rwm
lxc.mount.entry: /dev/net/tun dev/net/tun none bind,create=file
LXCCONF
  for m in nf_tables nft_ct nft_chain_nat nf_nat nf_conntrack nf_conntrack_netlink wireguard tun; do
    modprobe "$m" 2>/dev/null || true
  done
  sysctl -w net.netfilter.nf_conntrack_acct=1 >/dev/null 2>&1 || true

  c_say "Starting the container"
  pct start "$ctid"

  # Wait for the container's network before installing inside it.
  for _ in $(seq 1 30); do
    pct exec "$ctid" -- getent hosts github.com >/dev/null 2>&1 && break
    sleep 2
  done

  c_say "Installing Orbis inside the container (${CHANNEL} channel)"
  pct exec "$ctid" -- bash -c "apt-get update -qq && apt-get install -y -qq curl ca-certificates >/dev/null 2>&1 || true"
  pct exec "$ctid" -- bash -c \
    "curl -fsSL ${RAW}/deploy/bootstrap.sh | CHANNEL='${CHANNEL}' SKIP_GEOIP='${SKIP_GEOIP:-0}' FORCE_INPLACE=1 bash"

  local ip
  ip="$(pct exec "$ctid" -- hostname -I 2>/dev/null | awk '{print $1}')"
  c_say "Done. Orbis is in LXC ${ctid}. Open http://${ip:-<container-ip>}:8080"
}

# ---- dispatch ----------------------------------------------------------------

if [ "${FORCE_INPLACE:-0}" != "1" ] && on_proxmox; then
  c_say "Proxmox host detected"
  install_lxc
else
  install_inplace
fi
