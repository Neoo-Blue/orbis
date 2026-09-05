import { useState } from 'react'
import { Drawer, Search } from './ui'

/** Plain definitions for the words the advanced pages use. */
const TERMS: Array<{ term: string; plain: string }> = [
  { term: 'Observe mode', plain: 'Orbis watches and filters DNS but does not route traffic. Nothing depends on it staying up except name resolution.' },
  { term: 'Inline mode', plain: 'Orbis is the gateway. Every packet passes through it and the firewall enforces rules. Needs the firewall on, a WAN interface and a zone.' },
  { term: 'DNS', plain: 'The phone book of the internet: turns names like netflix.com into addresses. Blocking a name here stops the connection before it starts.' },
  { term: 'DoH / DoT', plain: 'DNS over HTTPS / TLS: encrypted lookups. Good for privacy, but apps that use their own encrypted DNS bypass your filter, which is why Orbis can block those servers.' },
  { term: 'Upstream', plain: 'The resolver Orbis asks when it does not know an answer (Cloudflare, Quad9, dns.sb here, over TLS).' },
  { term: 'Blocklist', plain: 'A downloaded list of ad, tracker or malware hostnames. Orbis merges many into one index.' },
  { term: 'Allowlist / denylist', plain: 'Your own exceptions: names that must always work, or must always be blocked, whatever the lists say.' },
  { term: 'CNAME uncloaking', plain: 'Catching a tracker that hides behind a first-party name by following the alias chain to where it really points.' },
  { term: 'Rebind protection', plain: 'Refusing public answers that point at private addresses, a trick used to attack devices inside a home network.' },
  { term: 'SNI', plain: 'The server name a device sends when opening an encrypted connection. It is how Orbis knows a connection is to youtube.com without decrypting anything.' },
  { term: 'QUIC', plain: 'A newer connection protocol over UDP used by Google and others. Orbis can read the name from it; the filter proxy blocks it so apps fall back to TCP, which it can filter.' },
  { term: 'Filter proxy (MITM)', plain: 'Orbis decrypting selected web traffic to remove ads inside pages and streams. Only works on devices that trust the Orbis certificate, and never on apps that pin their certificates.' },
  { term: 'Certificate authority (CA)', plain: 'The certificate a device must install and trust before the filter proxy can inspect its traffic. /setup serves the right file for each platform.' },
  { term: 'Pinned app', plain: 'An app that only accepts its own certificates (YouTube, banking). Orbis notices the rejection and passes the app through untouched.' },
  { term: 'ARP interception', plain: 'Pulling one device’s traffic through Orbis without Orbis being the gateway, by answering the device’s "where is the router" questions. Per device, reversible.' },
  { term: 'conntrack', plain: 'The kernel’s table of open connections. Orbis reads it to count bytes per connection.' },
  { term: 'nftables', plain: 'The Linux firewall. Orbis writes its rules there in inline mode and for interception.' },
  { term: 'Zone', plain: 'A named group of networks with a trust level (LAN, guest, IoT). Firewall rules are written between zones.' },
  { term: 'VLAN', plain: 'A separate virtual network on the same cable, for isolating things like cameras or guests.' },
  { term: 'WireGuard', plain: 'The VPN protocol Orbis uses for inbound peers and outbound tunnels.' },
  { term: 'Tailscale exit node', plain: 'Lets your phone route all its traffic home through Orbis when away, so filtering follows you.' },
  { term: 'Lounge engine', plain: 'Orbis pairing with a TV as a YouTube remote to press skip and mute on ads. No certificate needed.' },
  { term: 'SponsorBlock', plain: 'Community-marked sponsor segments inside videos, which Orbis skips on paired TVs and filtered browsers.' },
  { term: 'Smart capture', plain: 'Watching for hosts that behave like ad servers before any list knows them, and asking the assistant to judge.' },
  { term: 'Policy / profile', plain: 'Per-device filtering: switched-off apps, safe search, schedule, exceptions, or no filtering at all.' },
  { term: 'Anomaly', plain: 'Behaviour the detectors flag: a device calling home on a schedule, a large upload, a scan, suspicious lookups. Most have a mundane cause.' },
  { term: 'Brief', plain: 'The assistant’s periodic note on what happened and whether anything needs you.' },
]

export function GlossaryButton() {
  const [open, setOpen] = useState(false)
  const [q, setQ] = useState('')
  const shown = TERMS.filter((t) => !q.trim() || `${t.term} ${t.plain}`.toLowerCase().includes(q.trim().toLowerCase()))
  return (
    <>
      <button className="btn sm" title="What do these words mean?" aria-label="Glossary" onClick={() => setOpen(true)}>?</button>
      {open && (
        <Drawer title="What the words mean" onClose={() => setOpen(false)}>
          <div style={{ display: 'grid', gap: 12 }}>
            <Search value={q} onChange={setQ} placeholder="Search a term…" />
            {shown.map((t) => (
              <div key={t.term}>
                <div style={{ fontWeight: 600, fontSize: 13.5 }}>{t.term}</div>
                <div className="hint" style={{ lineHeight: 1.6 }}>{t.plain}</div>
              </div>
            ))}
            {shown.length === 0 && <div className="hint">No term matches. Ask the assistant; it knows these too.</div>}
          </div>
        </Drawer>
      )}
    </>
  )
}
