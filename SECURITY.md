# Security

## Reporting

Open a GitHub security advisory on this repository. Please do not open a public issue for
anything exploitable.

## What Orbis assumes

**One administrator, not a user model.** The interface assumes whoever can reach it owns the
network. There are no roles, no per-user scoping and no tenancy. Do not put port 8080 on the
internet; reach it over WireGuard or Tailscale.

**The config file is a secret.** `/etc/orbis/orbis.yaml` is written `0600` and holds the AI API
key, the WireGuard server private key and the Tailscale auth key. Secrets are masked in every API
response and are never returned by `GET /api/config`.

**The interception CA is the sharp edge.** Enabling the in-stream filter generates a root CA whose
private key lives on the node. Any device that trusts it can have its traffic for the intercepted
hosts read by anyone with access to the box. That is why interception is off by default, applies
only to an explicit host allowlist, and honours a bypass list that always wins. Only the public
certificate is downloadable — there is deliberately no PKCS#12 export, because a bundle containing
the key invites installing the CA on a device the operator does not control.

**The assistant cannot act unless you let it.** With write access off, the mutating tools are not
included in the tool list sent to the model. With it on, every call is recorded in the audit log
with its arguments and result.

## Deliberate design choices

- The generated nftables ruleset is validated with `nft -c` and then loaded as a single atomic
  transaction, so a bad rule cannot leave the box half-configured.
- An anti-lockout rule keeps SSH and the web interface reachable. Disabling it is possible and
  clearly labelled as a way to strand yourself.
- Rule names are operator-supplied text that ends up inside nftables comment strings. They are
  stripped of quotes, backslashes, semicolons, braces and non-ASCII before rendering, and there is
  a test that asserts a name cannot escape its string.
- Blocklist entries that would block an entire TLD are ignored unless the operator wrote them
  locally. A parse error in a downloaded list would otherwise take the network off the internet.
- Domains carrying OS updates, time, certificate validation, push notifications and captive-portal
  detection can never be auto-blocked by smart capture, whatever they score.
- Every parser that touches untrusted input (TLS ClientHello, QUIC Initial, HTTP request lines,
  netlink attributes, blocklist files) is bounds-checked, and the QUIC parser has a fuzz-style test
  asserting it cannot be made to panic — a panic there would be a remote denial of service against
  the capture path.

## Data handling

Flow metadata, DNS queries and device identities are stored locally in SQLite and never leave the
node, with two exceptions, both opt-in and both off by default:

1. **The assistant.** When enabled, the specific data a tool returns is sent to the configured
   provider. Point `base_url` at a local Ollama to keep it on-premise.
2. **Smart capture AI escalation.** Sends hostnames and their behavioural evidence — never client
   addresses, which are truncated before they reach the evidence payload.

Public-address discovery, used to place the node on the map, sends one DNS query asking a resolver
to echo back the source address it saw. The geolocation happens against the local database, so the
node's position is never transmitted. It can be turned off entirely, in which case no outbound
query is made and the map falls back to the configured timezone.
