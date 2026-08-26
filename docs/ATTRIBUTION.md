# Attribution

## Map data

`web/src/data/land.json` and `web/src/data/countries.json` are derived from
[Natural Earth](https://www.naturalearthdata.com/) 110m cultural and physical vectors, via
[world-atlas](https://github.com/topojson/world-atlas). Natural Earth data is in the public domain.

The TopoJSON was decoded to flat `[lon, lat]` polylines and quantised to two decimal places
(~1 km at globe scale), which halves the size with no visible difference at any zoom the UI
offers.

## GeoIP

Geolocation is optional and not bundled. `deploy/fetch-geoip.sh` downloads the free
[DB-IP](https://db-ip.com/db/lite.php) City and ASN Lite builds, which require no account and are
licensed **CC-BY-4.0**. If you ship a product using them, the attribution requirement is yours to
honour.

MaxMind GeoLite2 databases work too — the reader is the standard `.mmdb` format. Point
`geoip.city_db` and `geoip.asn_db` at whichever you have.

Without any database, Orbis places destinations at continent resolution from their address block
and labels the accuracy as `region` so the UI can say the position is an estimate.

## Blocklists

Subscriptions are downloaded at runtime and are **not** redistributed with this project. Each
retains its own licence:

| List | Source | Licence |
|---|---|---|
| StevenBlack unified hosts | [StevenBlack/hosts](https://github.com/StevenBlack/hosts) | MIT |
| AdGuard DNS filter | [AdguardTeam](https://github.com/AdguardTeam/HostlistsRegistry) | GPL-3.0 |
| OISD | [oisd.nl](https://oisd.nl) | Free for personal use |
| Peter Lowe's list | [pgl.yoyo.org](https://pgl.yoyo.org/adservers/) | Free for personal use |
| URLhaus | [abuse.ch](https://urlhaus.abuse.ch/) | CC0 |
| Phishing Army | [phishing.army](https://phishing.army/) | CC BY-NC-SA 4.0 |
| Hagezi DNS blocklists | [hagezi/dns-blocklists](https://github.com/hagezi/dns-blocklists) | GPL-3.0 |

## Go dependencies

| Module | Used for | Licence |
|---|---|---|
| `github.com/miekg/dns` | DNS server and client, DoT | BSD-3-Clause |
| `github.com/insomniacslk/dhcp` | DHCPv4 server | BSD-3-Clause |
| `modernc.org/sqlite` | Pure-Go SQLite, so the binary needs no cgo | BSD-3-Clause |
| `github.com/oschwald/maxminddb-golang` | `.mmdb` reader | ISC |
| `golang.zx2c4.com/wireguard/wgctrl` | Reading live WireGuard state | MIT |
| `github.com/go-chi/chi` | HTTP routing | MIT |
| `nhooyr.io/websocket` | The live event stream | ISC |
| `github.com/skip2/go-qrcode` | WireGuard peer enrolment QR codes | MIT |
| `golang.org/x/{crypto,net,sys,text}` | HKDF, BPF assembly, syscalls, IDN | BSD-3-Clause |

## Frontend dependencies

`react`, `react-dom` (MIT) and `three` (MIT). Nothing else at runtime — no component library, no
charting library, no icon package. The charts, icons and the globe are all implemented here,
because each of those dependencies would have cost more than the code it replaced.

## Protocol references

- **RFC 9001** — QUIC-TLS. The initial secrets and the header-protection scheme implemented in
  `internal/dpi/quic.go`.
- **RFC 9000** — QUIC transport. The variable-length integer encoding, tested against the worked
  examples in Appendix A.
- **RFC 8446** — TLS 1.3, for ClientHello structure.
- **RFC 8914** — Extended DNS Errors, used to tell a client *why* a name was filtered.
- **RFC 2131** — DHCP.
- **JA4** — the TLS client fingerprint format, from
  [FoxIO's specification](https://github.com/FoxIO-LLC/ja4).
