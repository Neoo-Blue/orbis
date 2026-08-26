#!/usr/bin/env bash
# Downloads DB-IP's free City and ASN databases, which need no account and are
# CC-BY-4.0 licensed. Run monthly (a cron entry is installed alongside) to keep
# the globe's placement accurate as address blocks are reallocated.
set -euo pipefail

DEST="${1:-/var/lib/orbis/geoip}"
MONTH="$(date +%Y-%m)"
install -d -m 0755 "$DEST"

fetch() {
  local kind="$1" out="$2"
  local url="https://download.db-ip.com/free/dbip-${kind}-lite-${MONTH}.mmdb.gz"
  echo "==> $kind ($MONTH)"
  if ! curl -fsSL --max-time 180 "$url" -o "$DEST/.tmp.gz"; then
    # Early in the month the new build may not be published yet.
    local prev
    prev="$(date -d '1 month ago' +%Y-%m 2>/dev/null || date -v-1m +%Y-%m)"
    echo "    current month unavailable, trying $prev"
    curl -fsSL --max-time 180 \
      "https://download.db-ip.com/free/dbip-${kind}-lite-${prev}.mmdb.gz" -o "$DEST/.tmp.gz"
  fi
  gunzip -c "$DEST/.tmp.gz" > "$DEST/.tmp.mmdb"
  rm -f "$DEST/.tmp.gz"
  # A truncated or error-page download would leave the resolver silently
  # answering nothing; a real City build is tens of megabytes.
  local size
  size="$(stat -c %s "$DEST/.tmp.mmdb" 2>/dev/null || stat -f %z "$DEST/.tmp.mmdb")"
  if [ "$size" -lt 1000000 ]; then
    rm -f "$DEST/.tmp.mmdb"
    echo "    download looks wrong (${size} bytes); leaving the existing database in place" >&2
    return 1
  fi
  # Swap in atomically so a running daemon never reads a half-written file.
  mv "$DEST/.tmp.mmdb" "$DEST/$out"
  printf "    %s MB -> %s\n" "$((size / 1000000))" "$DEST/$out"
}

fetch city dbip-city-lite.mmdb
fetch asn  dbip-asn-lite.mmdb

if systemctl is-active --quiet orbis 2>/dev/null; then
  echo "==> restarting orbis to pick up the new databases"
  systemctl restart orbis
fi
echo "Done. Data © DB-IP, licensed CC-BY-4.0."
