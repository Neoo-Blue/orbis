#!/usr/bin/env bash
# Print the release notes for a tag: the matching CHANGELOG.md section followed
# by the install snippet. Nightly builds get a one-line heading instead.
#   deploy/release-notes.sh v1.26.2 [channel] [image]
set -euo pipefail
tag="${1:?tag}"
channel="${2:-stable}"
image="${3:-ghcr.io/neoo-blue/orbis}"
cd "$(dirname "$0")/.."

if [ "$channel" = "stable" ]; then
  notes="$(awk -v tag="$tag" '
    $0 == "## " tag { on = 1; next }
    /^## / && on { exit }
    on { print }
  ' CHANGELOG.md | sed -e '1{/^$/d;}' -e '${/^$/d;}')"
  if [ -z "$notes" ]; then
    echo "no CHANGELOG.md section for $tag" >&2
    exit 1
  fi
  echo "Orbis $tag"
  echo
  echo "$notes"
else
  echo "Orbis nightly build from main at $(git rev-parse --short HEAD). Unreleased changes; the stable release is the tested one."
fi

cat <<EOT

---

Install on a Debian/Ubuntu host, VM or LXC:
\`\`\`
curl -fsSL https://raw.githubusercontent.com/Neoo-Blue/orbis/main/deploy/bootstrap.sh | sudo bash
\`\`\`

Docker:
\`\`\`
docker run -d --network host --cap-add NET_ADMIN --cap-add NET_RAW \\
  -v orbis-config:/etc/orbis -v orbis-data:/var/lib/orbis \\
  ${image}:${channel}
\`\`\`

Already running Orbis? It offers this release itself: Settings, About & diagnostics, Update now. Or \`sudo orbisd -update\`.
EOT
