import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react'
import { api } from '../api'
import { usePoll } from '../hooks'
import {
  Banner, Card, CopyButton, Empty, Field, Icons, Loading, Segmented, Switch, useToast,
} from '../ui'
import { bytes, duration } from '../format'
import type { AppConfig, SystemStatus } from '../types'

type Section =
  | 'general' | 'dns' | 'adblock' | 'proxy' | 'firewall' | 'zones'
  | 'dhcp' | 'vpn' | 'tailscale' | 'assistant' | 'capture' | 'storage' | 'security' | 'about'

const SECTIONS: Array<{ id: Section; label: string; group: string; blurb: string }> = [
  { id: 'general', label: 'Node & mode', group: 'System', blurb: 'Name, timezone, and whether Orbis is inline' },
  { id: 'capture', label: 'Traffic capture', group: 'System', blurb: 'Which interfaces are watched and how deeply' },
  { id: 'storage', label: 'Storage & retention', group: 'System', blurb: 'How long history is kept' },
  { id: 'security', label: 'Access', group: 'System', blurb: 'Admin password and API access' },

  { id: 'dns', label: 'DNS resolver', group: 'Filtering', blurb: 'Upstreams, cache, sinkhole behaviour' },
  { id: 'adblock', label: 'Ad blocking', group: 'Filtering', blurb: 'Lists, smart capture, bypass prevention' },
  { id: 'proxy', label: 'In-stream filter', group: 'Filtering', blurb: 'TLS interception for YouTube and app ads' },

  { id: 'firewall', label: 'Firewall', group: 'Network', blurb: 'WAN interface, defaults, offload' },
  { id: 'zones', label: 'Zones', group: 'Network', blurb: 'Group interfaces and set trust levels' },
  { id: 'dhcp', label: 'DHCP', group: 'Network', blurb: 'Scopes, ranges and reservations' },
  { id: 'vpn', label: 'WireGuard', group: 'Network', blurb: 'Server address, port and public endpoint' },
  { id: 'tailscale', label: 'Tailscale', group: 'Network', blurb: 'Exit node, subnet routes, tailnet options' },

  { id: 'assistant', label: 'Assistant', group: 'Intelligence', blurb: 'Provider, model, write access, anomaly detection' },
  { id: 'about', label: 'About & diagnostics', group: 'Intelligence', blurb: 'Versions, health, raw configuration' },
]

export function SettingsPage({ status, onAuthChange }: {
  status: SystemStatus | null
  onAuthChange: () => void
}) {
  const [section, setSection] = useState<Section>('general')
  const { data: config, refresh } = usePoll(() => api.config.get(), 0)
  const { data: ifaces } = usePoll(() => api.config.interfaces(), 0)
  const toast = useToast()

  const save = useCallback(async (patch: Record<string, unknown>) => {
    try {
      await api.config.patch(patch)
      refresh()
      return true
    } catch (e) {
      toast(e instanceof Error ? e.message : 'Could not save that setting', 'err')
      return false
    }
  }, [refresh, toast])

  const grouped = useMemo(() => {
    const out: Array<{ group: string; items: typeof SECTIONS }> = []
    for (const s of SECTIONS) {
      let bucket = out.find((g) => g.group === s.group)
      if (!bucket) {
        bucket = { group: s.group, items: [] }
        out.push(bucket)
      }
      bucket.items.push(s)
    }
    return out
  }, [])

  if (!config) return <Loading what="settings" />

  const props = { config, status, save, refresh, interfaces: ifaces?.interfaces ?? [], toast }

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '218px minmax(0, 1fr)', gap: 18, alignItems: 'start' }}>
      <nav style={{ position: 'sticky', top: 0, display: 'grid', gap: 2 }}>
        {grouped.map((g) => (
          <div key={g.group}>
            <div className="nav-group" style={{ display: 'block', paddingLeft: 9 }}>{g.group}</div>
            {g.items.map((s) => (
              <button key={s.id} className="nav-item" style={{ width: '100%' }}
                aria-current={section === s.id ? 'page' : undefined}
                onClick={() => setSection(s.id)}>
                <span style={{ display: 'block' }}>{s.label}</span>
              </button>
            ))}
          </div>
        ))}
      </nav>

      <div style={{ display: 'grid', gap: 14, minWidth: 0 }}>
        <div>
          <h2 style={{ fontSize: 16 }}>{SECTIONS.find((s) => s.id === section)?.label}</h2>
          <div style={{ color: 'var(--text-faint)', fontSize: 12.5, marginTop: 2 }}>
            {SECTIONS.find((s) => s.id === section)?.blurb}
          </div>
        </div>

        {section === 'general' && <GeneralSection {...props} />}
        {section === 'capture' && <CaptureSection {...props} />}
        {section === 'storage' && <StorageSection {...props} />}
        {section === 'security' && <SecuritySection onAuthChange={onAuthChange} />}
        {section === 'dns' && <DNSSection {...props} />}
        {section === 'adblock' && <AdBlockSection {...props} />}
        {section === 'proxy' && <ProxySection {...props} />}
        {section === 'firewall' && <FirewallSection {...props} />}
        {section === 'zones' && <ZonesSection {...props} />}
        {section === 'dhcp' && <DHCPSection {...props} />}
        {section === 'vpn' && <VPNSection {...props} />}
        {section === 'tailscale' && <TailscaleSection {...props} />}
        {section === 'assistant' && <AssistantSection {...props} />}
        {section === 'about' && <AboutSection {...props} />}
      </div>
    </div>
  )
}

interface SectionProps {
  config: AppConfig
  status: SystemStatus | null
  save: (patch: Record<string, unknown>) => Promise<boolean>
  refresh: () => void
  interfaces: Array<{ name: string; up: boolean; addresses: string[]; virtual: boolean; loopback: boolean }>
  toast: (msg: string, tone?: 'ok' | 'err' | 'info') => void
}

/* ---------- reusable editors ---------- */

/** TextSetting commits on blur rather than per-keystroke: every change writes
 *  the config file, and doing that on each character would be absurd. */
function TextSetting({ label, hint, value, onSave, placeholder, mono, type = 'text' }: {
  label: string; hint?: ReactNode; value: string
  onSave: (v: string) => void; placeholder?: string; mono?: boolean; type?: string
}) {
  const [draft, setDraft] = useState(value)
  useEffect(() => setDraft(value), [value])
  return (
    <Field label={label} hint={hint}>
      <input className={`input${mono ? ' mono' : ''}`} type={type} value={draft} placeholder={placeholder}
        onChange={(e) => setDraft(e.target.value)}
        onBlur={() => draft !== value && onSave(draft)}
        onKeyDown={(e) => { if (e.key === 'Enter') (e.target as HTMLInputElement).blur() }} />
    </Field>
  )
}

function NumberSetting({ label, hint, value, onSave, min, max, suffix }: {
  label: string; hint?: ReactNode; value: number
  onSave: (v: number) => void; min?: number; max?: number; suffix?: string
}) {
  const [draft, setDraft] = useState(String(value))
  useEffect(() => setDraft(String(value)), [value])
  return (
    <Field label={label} hint={hint}>
      <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
        <input className="input mono" type="number" value={draft} min={min} max={max}
          onChange={(e) => setDraft(e.target.value)}
          onBlur={() => {
            const n = Number(draft)
            if (!Number.isNaN(n) && n !== value) onSave(n)
          }} />
        {suffix && <span style={{ color: 'var(--text-faint)', fontSize: 12 }}>{suffix}</span>}
      </div>
    </Field>
  )
}

/** ListSetting edits a string array as one-per-line text, which is far less
 *  fiddly than a row of inputs for things like upstreams and hostnames. */
function ListSetting({ label, hint, value, onSave, placeholder, rows = 4 }: {
  label: string; hint?: ReactNode; value: string[]
  onSave: (v: string[]) => void; placeholder?: string; rows?: number
}) {
  const [draft, setDraft] = useState(value.join('\n'))
  useEffect(() => setDraft(value.join('\n')), [value])
  return (
    <Field label={label} hint={hint}>
      <textarea className="textarea" rows={rows} value={draft} placeholder={placeholder}
        onChange={(e) => setDraft(e.target.value)}
        onBlur={() => {
          const next = draft.split('\n').map((s) => s.trim()).filter(Boolean)
          if (next.join('\n') !== value.join('\n')) onSave(next)
        }} />
    </Field>
  )
}

function SwitchRow({ label, hint, checked, onChange, disabled }: {
  label: string; hint?: ReactNode; checked: boolean
  onChange: (v: boolean) => void; disabled?: boolean
}) {
  return (
    <div style={{ display: 'grid', gap: 4 }}>
      <Switch checked={checked} onChange={onChange} label={label} disabled={disabled} />
      {hint && <div className="hint" style={{ marginLeft: 43 }}>{hint}</div>}
    </div>
  )
}

/* ---------- sections ---------- */

function GeneralSection({ config, status, save, refresh, toast }: SectionProps) {
  const inline = config.mode === 'inline'
  const selfInfo = (status as unknown as { self?: Record<string, unknown> } | null)?.self
  return (
    <>
      <Card title="Operating mode">
        <div style={{ display: 'grid', gap: 13 }}>
          <Segmented
            value={config.mode}
            onChange={async (v) => {
              if (v === 'inline' && !config.firewall.wan_interface) {
                toast('Set a WAN interface under Firewall before switching to inline mode', 'err')
                return
              }
              if (v === 'inline' && !confirm(
                'Inline mode installs an nftables ruleset and starts enforcing policy on traffic ' +
                'that passes through this node. Continue?')) return
              await save({ mode: v })
              toast(v === 'inline' ? 'Now in inline mode' : 'Back to observe mode', 'ok')
            }}
            options={[{ value: 'observe', label: 'Observe' }, { value: 'inline', label: 'Inline' }]}
          />
          <div className="hint" style={{ lineHeight: 1.7 }}>
            <strong style={{ color: 'var(--text)' }}>Observe</strong> watches whatever traffic reaches
            this node and records what it <em>would</em> have done. No ruleset is installed, DHCP
            stays off, and nothing routes through it. This is the install default and it is safe to
            leave here indefinitely.
            <br /><br />
            <strong style={{ color: 'var(--text)' }}>Inline</strong> makes this node a real gateway:
            the firewall ruleset is loaded, NAT and forwarding are enabled, DHCP starts if a scope
            exists, and outbound DNS is redirected to the local resolver.
          </div>
          {inline && (
            <Banner tone="warn">
              Inline mode is active. Devices depend on this node for connectivity — a bad rule or a
              restart will interrupt them.
            </Banner>
          )}
        </div>
      </Card>

      <Card title="Identity">
        <div className="grid c2">
          <TextSetting label="Node name" value={config.node.name}
            hint="Shown on the globe and in generated configs."
            onSave={(v) => save({ 'node.name': v })} />
          <TextSetting label="Timezone" value={config.node.timezone} mono
            placeholder="America/Los_Angeles"
            hint="An IANA zone. Used as the last-resort position on the globe."
            onSave={(v) => save({ 'node.timezone': v })} />
        </div>
      </Card>

      <Card title="Position on the map">
        <div style={{ display: 'grid', gap: 14 }}>
          <SwitchRow label="Find my location automatically" checked={config.node.locate_public_ip}
            hint={<>A node behind NAT has no public address on any interface, so the globe cannot
              place it. With this on, Orbis asks a public resolver to echo back the address it sees
              (one DNS query) and then geolocates that address <em>against the local database</em> —
              the node's position is never sent anywhere. Turn it off to make no outbound query at
              all; the map then falls back to the timezone below.</>}
            onChange={(v) => save({ 'node.locate_public_ip': v })} />

          <div style={{ display: 'flex', gap: 9, alignItems: 'center', flexWrap: 'wrap' }}>
            <button className="btn" onClick={async () => {
              try {
                const r = await api.locateSelf()
                const s2 = r.self as Record<string, unknown>
                toast(s2.city ? `Located: ${s2.city}, ${s2.country}` : 'Public address located', 'ok')
                refresh()
              } catch (e) {
                toast(e instanceof Error ? e.message : 'Could not determine the public address', 'err')
              }
            }}>Detect now</button>
            {selfInfo?.public_ip ? (
              <span className="tag live">
                {String(selfInfo.city || '')}{selfInfo.country ? `, ${String(selfInfo.country)}` : ''}
                {' · '}{String(selfInfo.public_ip)}
              </span>
            ) : (
              <span className="tag">not detected — using the timezone fallback</span>
            )}
          </div>
          {typeof selfInfo?.last_error === 'string' && (
            <div className="hint" style={{ color: 'var(--amber)' }}>{String(selfInfo.last_error)}</div>
          )}

          <div className="grid c2">
            <NumberSetting label="Latitude" value={config.node.latitude} min={-90} max={90}
              hint="Set this to override everything above."
              onSave={(v) => save({ 'node.latitude': v })} />
            <NumberSetting label="Longitude" value={config.node.longitude} min={-180} max={180}
              hint="Leave both at 0 to use automatic detection."
              onSave={(v) => save({ 'node.longitude': v })} />
          </div>
        </div>
      </Card>

      <Card title="Health">
        <dl className="kv">
          <dt>Uptime</dt><dd>{duration(status?.uptime_sec ?? 0)}</dd>
          <dt>Config file</dt><dd>/etc/orbis/orbis.yaml</dd>
          <dt>Database</dt><dd>{config.store.path}</dd>
          <dt>API listening on</dt><dd>{config.api.listen}</dd>
        </dl>
      </Card>
    </>
  )
}

function CaptureSection({ config, status, save, interfaces }: SectionProps) {
  const capture = status?.capture as Record<string, number | boolean> | undefined
  return (
    <>
      <Card title="Packet capture">
        <div style={{ display: 'grid', gap: 14 }}>
          <SwitchRow label="Capture packets" checked={config.capture.enabled}
            hint="Reads frames off the wire to extract TLS SNI, QUIC SNI and HTTP hostnames. Without it, connections show as bare IP addresses."
            onChange={(v) => save({ 'capture.enabled': v })} />

          <Field label="Interfaces"
            hint="Leave all unchecked to watch every physical interface automatically.">
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
              {interfaces.filter((i) => !i.loopback).map((i) => {
                const on = config.capture.interfaces.includes(i.name)
                return (
                  <button key={i.name} className="btn sm"
                    style={on ? { borderColor: 'rgba(78,232,192,.5)', color: 'var(--accent)', background: 'var(--accent-glow)' } : undefined}
                    onClick={() => {
                      const next = on
                        ? config.capture.interfaces.filter((n) => n !== i.name)
                        : [...config.capture.interfaces, i.name]
                      save({ 'capture.interfaces': next })
                    }}>
                    {i.name}{i.virtual ? ' (virtual)' : ''}
                  </button>
                )
              })}
            </div>
          </Field>

          <div className="grid c2">
            <NumberSetting label="Snap length" value={config.capture.snaplen} min={128} max={65535} suffix="bytes"
              hint="Bytes copied per packet. 512 covers a TLS ClientHello with a long SNI plus HTTP headers."
              onSave={(v) => save({ 'capture.snaplen': v })} />
            <div style={{ display: 'grid', gap: 12, alignContent: 'start' }}>
              <SwitchRow label="Read kernel conntrack" checked={config.capture.conntrack}
                hint="Byte counters for traffic the ring buffer does not see. Needs net.netfilter.nf_conntrack_acct=1."
                onChange={(v) => save({ 'capture.conntrack': v })} />
            </div>
          </div>
        </div>
      </Card>

      <Card title="Live capture health">
        {!capture ? <Empty title="No capture statistics yet" /> : (
          <dl className="kv">
            <dt>Interfaces open</dt><dd>{String(capture.interfaces ?? 0)}</dd>
            <dt>Kernel filter</dt>
            <dd>{capture.filter_active ? 'active — only useful packets are copied' : 'not attached'}</dd>
            <dt>Packets seen</dt><dd>{Number(capture.packets ?? 0).toLocaleString()}</dd>
            <dt>Bytes copied</dt><dd>{bytes(Number(capture.bytes ?? 0))}</dd>
            <dt>Kernel drops</dt>
            <dd style={{ color: Number(capture.kernel_drops ?? 0) > 0 ? 'var(--amber)' : undefined }}>
              {Number(capture.kernel_drops ?? 0).toLocaleString()}
            </dd>
            <dt>SNI extracted</dt><dd>{Number(capture.sni_extracted ?? 0).toLocaleString()}</dd>
            <dt>QUIC decrypted</dt><dd>{Number(capture.quic_decrypted ?? 0).toLocaleString()}</dd>
            <dt>Flows at capacity</dt><dd>{Number(capture.capacity_drops ?? 0).toLocaleString()}</dd>
          </dl>
        )}
      </Card>
    </>
  )
}

function StorageSection({ config, save, toast }: SectionProps) {
  const { data: summary } = usePoll(() => api.summary(24), 0)
  return (
    <>
      <Card title="Retention">
        <div className="grid c2">
          <NumberSetting label="Keep connection history" value={config.store.flow_retention_days}
            min={1} max={365} suffix="days"
            hint="Also bounds the DNS query log. Longer means a larger database and slower history queries."
            onSave={(v) => save({ 'store.flow_retention_days': v })} />
          <NumberSetting label="Keep events" value={config.store.event_retention_days}
            min={1} max={730} suffix="days"
            hint="Events and the audit log. These are small; a long window costs little."
            onSave={(v) => save({ 'store.event_retention_days': v })} />
        </div>
        <div className="hint" style={{ marginTop: 12 }}>
          Pruning runs every six hours and reclaims space with a WAL checkpoint. Rows older than the
          window are removed permanently.
        </div>
      </Card>

      <Card title="Current volume">
        <dl className="kv">
          <dt>Connections (24h)</dt><dd>{(summary?.flows ?? 0).toLocaleString()}</dd>
          <dt>DNS queries (24h)</dt><dd>{(summary?.dns_queries ?? 0).toLocaleString()}</dd>
          <dt>Traffic (24h)</dt>
          <dd>{bytes(summary?.bytes_in ?? 0)} in · {bytes(summary?.bytes_out ?? 0)} out</dd>
          <dt>Database</dt><dd>{config.store.path}</dd>
        </dl>
      </Card>

      <Card title="GeoIP databases">
        <div style={{ display: 'grid', gap: 13 }}>
          <TextSetting label="City database" value={config.geoip.city_db} mono
            placeholder="/var/lib/orbis/geoip/dbip-city-lite.mmdb"
            hint="A MaxMind-format .mmdb. DB-IP publishes free monthly City and ASN builds that need no signup."
            onSave={(v) => save({ 'geoip.city_db': v })} />
          <TextSetting label="ASN database" value={config.geoip.asn_db} mono
            placeholder="/var/lib/orbis/geoip/dbip-asn-lite.mmdb"
            hint="Adds the network operator name to every connection."
            onSave={(v) => save({ 'geoip.asn_db': v })} />
          <div className="hint">
            Without a database the globe still works, but destinations are placed at continent
            resolution from their address block rather than a real coordinate.
          </div>
          <div style={{ display: 'flex', gap: 9, alignItems: 'center', flexWrap: 'wrap' }}>
            <button className="btn" onClick={async () => {
              try {
                const r = await api.geoBackfill()
                toast(`Re-located ${r.addresses_resolved} address(es) across ${r.rows_updated} stored connections`, 'ok')
              } catch (e) {
                toast(e instanceof Error ? e.message : 'Backfill failed', 'err')
              }
            }}>Re-check stored history</button>
            <span className="hint" style={{ flex: 1, minWidth: 200 }}>
              Connections recorded before a database was installed keep whatever the coarse fallback
              guessed. This re-resolves them so the history matches the map.
            </span>
          </div>
        </div>
      </Card>
    </>
  )
}

function SecuritySection({ onAuthChange }: { onAuthChange: () => void }) {
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [confirmPw, setConfirmPw] = useState('')
  const [busy, setBusy] = useState(false)
  const { data: authStatus, refresh } = usePoll(() => api.auth.status(), 0)
  const toast = useToast()

  const change = async () => {
    if (next.length < 10) { toast('Password must be at least 10 characters', 'err'); return }
    if (next !== confirmPw) { toast('The two passwords do not match', 'err'); return }
    setBusy(true)
    try {
      await api.auth.setPassword(current, next)
      toast('Password updated', 'ok')
      setCurrent(''); setNext(''); setConfirmPw('')
      refresh(); onAuthChange()
    } catch (e) {
      toast(e instanceof Error ? e.message : 'Could not change the password', 'err')
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      {authStatus?.setup_required && (
        <Banner tone="err">
          No password is set. Anyone who can reach this address has full control of the firewall.
        </Banner>
      )}

      <Card title={authStatus?.setup_required ? 'Set an admin password' : 'Change the admin password'}>
        <div style={{ display: 'grid', gap: 13, maxWidth: 420 }}>
          {!authStatus?.setup_required && (
            <Field label="Current password">
              <input className="input" type="password" value={current} autoComplete="current-password"
                onChange={(e) => setCurrent(e.target.value)} />
            </Field>
          )}
          <Field label="New password" hint="At least 10 characters. There is no recovery path.">
            <input className="input" type="password" value={next} autoComplete="new-password"
              onChange={(e) => setNext(e.target.value)} />
          </Field>
          <Field label="Confirm">
            <input className="input" type="password" value={confirmPw} autoComplete="new-password"
              onChange={(e) => setConfirmPw(e.target.value)} />
          </Field>
          <div>
            <button className="btn primary" onClick={change} disabled={busy || !next}>
              {busy ? 'Saving…' : 'Save password'}
            </button>
          </div>
        </div>
      </Card>

      <Card title="Sessions">
        <div style={{ display: 'grid', gap: 12 }}>
          <div className="hint">
            Sessions are HMAC-signed bearer tokens valid for 30 days, stored in an HttpOnly cookie.
            There is no session table; signing out clears the cookie on this device only.
          </div>
          <div>
            <button className="btn" onClick={async () => {
              await api.auth.logout()
              onAuthChange()
            }}>Sign out</button>
          </div>
        </div>
      </Card>

      <Card title="Notes on exposure">
        <div className="hint" style={{ lineHeight: 1.75 }}>
          Orbis has one administrator, not a user model — the interface assumes whoever reaches it
          is the network owner. Do not expose this port to the internet. If you need remote access,
          reach it over WireGuard or Tailscale rather than a port forward.
        </div>
      </Card>
    </>
  )
}

function DNSSection({ config, status, save, toast }: SectionProps) {
  const dns = status?.dns as Record<string, unknown> | undefined
  return (
    <>
      <Card title="Resolver">
        <div style={{ display: 'grid', gap: 14 }}>
          <SwitchRow label="Run the DNS resolver" checked={config.dns.enabled}
            hint="Listens on port 53. Devices must be pointed at this node (via DHCP, or by hand) for filtering to apply."
            onChange={(v) => save({ 'dns.enabled': v })} />

          <ListSetting label="Upstream resolvers" value={config.dns.upstreams} rows={4}
            placeholder={'tls://1.1.1.1:853\nhttps://dns.quad9.net/dns-query\n9.9.9.9'}
            hint={<>One per line. <code>tls://</code> is DNS-over-TLS, <code>https://</code> is DNS-over-HTTPS,
              a bare address is plain DNS on port 53. Encrypted transports keep your ISP out of the query log.</>}
            onSave={(v) => save({ 'dns.upstreams': v })} />

          <Field label="Upstream strategy"
            hint="Parallel races every healthy upstream and takes the first answer — lower latency, more upstream queries. Sequential tries them in order.">
            <Segmented value={config.dns.strategy === 'sequential' ? 'sequential' : 'parallel'}
              onChange={(v) => save({ 'dns.strategy': v })}
              options={[{ value: 'parallel', label: 'Parallel (fastest wins)' },
                        { value: 'sequential', label: 'Sequential (in order)' }]} />
          </Field>
        </div>
      </Card>

      <Card title="Cache">
        <div className="grid c3">
          <NumberSetting label="Cache size" value={config.dns.cache_size} min={100} max={1000000} suffix="entries"
            onSave={(v) => save({ 'dns.cache_size': v })} />
          <NumberSetting label="Minimum TTL" value={config.dns.min_ttl} min={0} max={86400} suffix="sec"
            hint="Raises short TTLs to cut query volume."
            onSave={(v) => save({ 'dns.min_ttl': v })} />
          <NumberSetting label="Maximum TTL" value={config.dns.max_ttl} min={60} max={604800} suffix="sec"
            hint="Caps long TTLs so a changed record is not stale for days."
            onSave={(v) => save({ 'dns.max_ttl': v })} />
        </div>
        <div style={{ marginTop: 12 }}>
          <button className="btn sm" onClick={async () => {
            const r = await api.dns.flush()
            toast(`Flushed ${r.flushed} entries`, 'ok')
          }}>Flush the cache now</button>
        </div>
      </Card>

      <Card title="Blocked responses">
        <div style={{ display: 'grid', gap: 14 }}>
          <div className="grid c2">
            <TextSetting label="IPv4 sinkhole" value={config.dns.sinkhole_ipv4} mono placeholder="0.0.0.0"
              hint="Returned for blocked names. Leave both empty to answer NXDOMAIN instead."
              onSave={(v) => save({ 'dns.sinkhole_ipv4': v })} />
            <TextSetting label="IPv6 sinkhole" value={config.dns.sinkhole_ipv6} mono placeholder="::"
              onSave={(v) => save({ 'dns.sinkhole_ipv6': v })} />
          </div>
          <SwitchRow label="Explain blocks to clients" checked={config.dns.block_ede}
            hint="Attaches an RFC 8914 Extended DNS Error naming the list that blocked the query. Capable clients show it instead of a generic failure."
            onChange={(v) => save({ 'dns.block_ede': v })} />
        </div>
      </Card>

      <Card title="Local names & logging">
        <div style={{ display: 'grid', gap: 14 }}>
          <TextSetting label="Local domain" value={config.dns.local_domain} mono placeholder="lan"
            hint="DHCP hostnames resolve under this suffix, and reverse lookups return it."
            onSave={(v) => save({ 'dns.local_domain': v })} />
          <SwitchRow label="Log every query" checked={config.dns.log_queries}
            hint="Powers the DNS log and per-device history. On a busy network this is the largest single consumer of database space."
            onChange={(v) => save({ 'dns.log_queries': v })} />
        </div>
      </Card>

      {dns && (
        <Card title="Live resolver state">
          <dl className="kv">
            <dt>Listening</dt><dd>{dns.running ? config.dns.listen.join(', ') : 'not listening'}</dd>
            <dt>Queries</dt><dd>{Number(dns.queries ?? 0).toLocaleString()}</dd>
            <dt>Blocked</dt><dd>{Number(dns.blocked ?? 0).toLocaleString()}</dd>
            <dt>Answered locally</dt><dd>{Number(dns.local ?? 0).toLocaleString()}</dd>
            <dt>Duplicates collapsed</dt><dd>{Number(dns.collapsed ?? 0).toLocaleString()}</dd>
          </dl>
        </Card>
      )}
    </>
  )
}

function AdBlockSection({ config, save }: SectionProps) {
  const sc = config.adblock.smart_capture
  return (
    <>
      <Card title="Blocking">
        <div style={{ display: 'grid', gap: 14 }}>
          <SwitchRow label="Block ads and trackers" checked={config.adblock.enabled}
            onChange={(v) => save({ 'adblock.enabled': v })} />
          <SwitchRow label="Follow CNAME chains" checked={config.adblock.cname_uncloak}
            hint="Re-checks every hop of a CNAME chain. First-party CNAME cloaking is now the dominant tracker evasion, and this is the only thing that catches it."
            onChange={(v) => save({ 'adblock.cname_uncloak': v })} />
          <SwitchRow label="Block by TLS/QUIC SNI" checked={config.adblock.sni_blocking}
            hint="Terminates connections whose SNI matches a rule, catching apps that hardcode IP addresses and never ask this resolver."
            onChange={(v) => save({ 'adblock.sni_blocking': v })} />
          <SwitchRow label="Prevent DNS bypass" checked={config.adblock.block_dns_bypass}
            hint="Sinkholes the bootstrap names of public DoH resolvers, so a browser cannot silently route around this filter."
            onChange={(v) => save({ 'adblock.block_dns_bypass': v })} />
          <SwitchRow label="Block streaming-device ads and viewing telemetry" checked={config.adblock.streaming_ads}
            hint="A built-in list of the hosts smart TVs, streaming sticks and media apps use only to fetch ads or report what you watch: Samsung, LG, Roku, Fire TV, Vizio, the ACR vendors, CTV ad exchanges. Nothing a stream needs is on it."
            onChange={(v) => save({ 'adblock.streaming_ads': v })} />
          <NumberSetting label="Refresh lists every" value={config.adblock.update_interval_hours}
            min={1} max={720} suffix="hours"
            onSave={(v) => save({ 'adblock.update_interval_hours': v })} />
        </div>
      </Card>

      <Card title="Smart capture">
        <div style={{ display: 'grid', gap: 14 }}>
          <div className="hint" style={{ lineHeight: 1.7 }}>
            Watches which hostnames devices reach that no list covers, scores them on how they
            behave — third-party referrer ratio, response size, request breadth, name shape — and
            promotes the confident ones. Anything ambiguous goes to the review queue instead.
          </div>
          <SwitchRow label="Discover new ad domains" checked={sc.enabled}
            onChange={(v) => save({ 'adblock.smart_capture.enabled': v })} />
          <SwitchRow label="Ask the model about ambiguous cases" checked={sc.use_ai}
            hint="Only domains the heuristics could not decide are sent, a few dozen a day at most. Requires a configured provider."
            onChange={(v) => save({ 'adblock.smart_capture.use_ai': v })} />

          <div className="grid c2">
            <Field label={`Auto-block above ${Math.round(sc.auto_block_score * 100)}`}
              hint="Higher means fewer automatic blocks and more items in the review queue.">
              <input type="range" min={0.5} max={1} step={0.01} value={sc.auto_block_score}
                onChange={(e) => save({ 'adblock.smart_capture.auto_block_score': Number(e.target.value) })} />
            </Field>
            <Field label={`Surface for review above ${Math.round(sc.review_score * 100)}`}
              hint="Below this, a candidate is dismissed quietly.">
              <input type="range" min={0.2} max={0.95} step={0.01} value={sc.review_score}
                onChange={(e) => save({ 'adblock.smart_capture.review_score': Number(e.target.value) })} />
            </Field>
          </div>

          <div className="grid c3">
            <NumberSetting label="Minimum sightings" value={sc.min_observations} min={2} max={1000}
              hint="Before a domain is scored at all."
              onSave={(v) => save({ 'adblock.smart_capture.min_observations': v })} />
            <NumberSetting label="Scoring interval" value={sc.interval_minutes} min={1} max={1440} suffix="min"
              onSave={(v) => save({ 'adblock.smart_capture.interval_minutes': v })} />
            <NumberSetting label="Daily auto-block cap" value={sc.max_auto_blocks_per_day} min={0} max={10000}
              hint="A safety valve. Hitting it sends the rest to review."
              onSave={(v) => save({ 'adblock.smart_capture.max_auto_blocks_per_day': v })} />
          </div>
        </div>
      </Card>

      <Card title="Global overrides">
        <div style={{ display: 'grid', gap: 14 }}>
          <ListSetting label="Always allow" value={config.adblock.allowlist} rows={4}
            placeholder={'analytics.mycompany.com\n*.internal.example'}
            hint="One per line. Beats every subscribed list. Prefix with *. to include subdomains."
            onSave={(v) => save({ 'adblock.allowlist': v })} />
          <ListSetting label="Always block" value={config.adblock.denylist} rows={4}
            placeholder={'*.tracker.example\nads.example.com'}
            onSave={(v) => save({ 'adblock.denylist': v })} />
          <div className="hint">
            Rules added from the Ad blocking page are stored separately and shown there; these two
            lists live in the config file, which makes them easy to keep under version control.
          </div>
        </div>
      </Card>
    </>
  )
}

function ProxySection({ config, status, save, toast }: SectionProps) {
  const proxy = status?.filter_proxy as Record<string, unknown> | undefined
  const running = Boolean(proxy?.running)
  return (
    <>
      <Banner tone="warn">
        <strong style={{ display: 'block', marginBottom: 3 }}>This decrypts traffic</strong>
        The filter proxy terminates TLS for the hosts listed below using a certificate authority
        generated on this node. It is the only way to remove ads that share a hostname with content
        (YouTube), and it is a real trade-off: anyone with access to this box can read that traffic.
        Only intercept what you need to.
      </Banner>

      <Card title="Interception" actions={
        <button className={`btn sm ${running ? 'danger' : 'primary'}`} onClick={async () => {
          try {
            await api.proxy.action(running ? 'stop' : 'start')
            toast(running ? 'Stopped' : 'Started', 'ok')
          } catch (e) {
            toast(e instanceof Error ? e.message : 'Could not change state', 'err')
          }
        }}>{running ? 'Stop' : 'Start'}</button>
      }>
        <div style={{ display: 'grid', gap: 14 }}>
          <SwitchRow label="Enable the filter proxy" checked={config.mitm.enabled}
            hint="In inline mode, matching ports are transparently redirected here by the firewall ruleset."
            onChange={(v) => save({ 'mitm.enabled': v })} />

          <ListSetting label="Intercept these hosts" value={config.mitm.intercept_hosts} rows={6}
            hint="Glob patterns. Narrow by default on purpose — intercepting everything breaks pinned apps and is far more invasive than it needs to be."
            onSave={(v) => save({ 'mitm.intercept_hosts': v })} />

          <ListSetting label="Never intercept" value={config.mitm.bypass_hosts} rows={5}
            hint="Always wins over the list above. Keep banks, health, and anything with certificate pinning here."
            onSave={(v) => save({ 'mitm.bypass_hosts': v })} />

          <ListSetting label="Only these clients" value={config.mitm.only_clients} rows={3}
            placeholder={'192.168.1.42\n192.168.5.0/24'}
            hint="Leave empty to filter every device whose traffic is redirected here. Useful for trying it on one TV first."
            onSave={(v) => save({ 'mitm.only_clients': v })} />
        </div>
      </Card>

      <Card title="Filters">
        <div style={{ display: 'grid', gap: 14 }}>
          <SwitchRow label="Strip YouTube ad slots" checked={config.mitm.filters.youtube}
            hint="Removes adPlacements, playerAds and adSlots from the InnerTube player response, and drops ad-tracking pings. Works on web and the native apps; does not touch server-side stitched ads."
            onChange={(v) => save({ 'mitm.filters.youtube': v })} />
          <SwitchRow label="YouTube in-page engine" checked={config.mitm.filters.youtube_in_page}
            hint="Injects a small script into YouTube pages that removes ad structures inside the client and drives the player past any ad break that still starts. It matches behaviour rather than field names, so it keeps working the week YouTube renames something."
            onChange={(v) => save({ 'mitm.filters.youtube_in_page': v })} />
          <SwitchRow label="SponsorBlock in the browser" checked={config.mitm.filters.youtube_sponsorblock}
            hint="The in-page engine also skips and mutes SponsorBlock segments, using the categories chosen on the YouTube page. The browser asks Orbis for segments; it never talks to SponsorBlock itself."
            onChange={(v) => save({ 'mitm.filters.youtube_sponsorblock': v })} />
          <SwitchRow label="Drop tracker beacons" checked={config.mitm.filters.tracker_beacons}
            hint="Answers analytics endpoints with a 204 or a transparent pixel instead of forwarding the request. Saves the round trip and the data."
            onChange={(v) => save({ 'mitm.filters.tracker_beacons': v })} />
          <SwitchRow label="Strip ad payloads from app APIs" checked={config.mitm.filters.generic_json_ads}
            hint="Removes common ad keys from JSON responses. Apps render the slot as unfilled, which they all handle."
            onChange={(v) => save({ 'mitm.filters.generic_json_ads': v })} />
          <SwitchRow label="Inject element-hiding CSS" checked={config.mitm.filters.html_cosmetic}
            hint="Hides ad containers that survive network blocking. Conservative selectors only — broad ones break layouts."
            onChange={(v) => save({ 'mitm.filters.html_cosmetic': v })} />
        </div>
      </Card>

      <Card title="Listeners">
        <dl className="kv">
          <dt>HTTP</dt><dd>{config.mitm.listen_http}</dd>
          <dt>TLS</dt><dd>{config.mitm.listen_tls}</dd>
          <dt>CA directory</dt><dd>{config.mitm.ca_dir}</dd>
          <dt>Certificate</dt><dd><a href="/orbis-ca.crt" download>orbis-ca.crt</a></dd>
        </dl>
        <div className="hint" style={{ marginTop: 10 }}>
          Ports are config-file only; changing them requires editing orbis.yaml and restarting, because
          the firewall redirect rules are generated from them.
        </div>
      </Card>
    </>
  )
}

function FirewallSection({ config, status, save, interfaces, toast }: SectionProps) {
  const { data: sysctl, refresh: refreshSysctl } = usePoll(() => api.firewall.sysctl(), 0)
  const fw = status?.firewall as Record<string, unknown> | undefined

  return (
    <>
      <Card title="Firewall">
        <div style={{ display: 'grid', gap: 14 }}>
          <SwitchRow label="Manage the firewall" checked={config.firewall.enabled}
            hint="Generates and loads an nftables ruleset. Takes effect only in inline mode."
            onChange={(v) => save({ 'firewall.enabled': v })} />

          <Field label="WAN interface"
            hint="The internet-facing interface. NAT is applied on the way out of it.">
            <select className="select" value={config.firewall.wan_interface}
              onChange={(e) => save({ 'firewall.wan_interface': e.target.value })}>
              <option value="">Not set</option>
              {interfaces.filter((i) => !i.loopback).map((i) => (
                <option key={i.name} value={i.name}>
                  {i.name}{i.addresses.length ? ` — ${i.addresses[0]}` : ''}
                </option>
              ))}
            </select>
          </Field>

          <Field label="Default for traffic between zones"
            hint="Applied when no rule matches. Drop is the correct default; accept turns the firewall into a router with logging.">
            <Segmented value={config.firewall.default_forward}
              onChange={(v) => save({ 'firewall.default_forward': v })}
              options={[{ value: 'drop', label: 'Drop' }, { value: 'accept', label: 'Accept' }]} />
          </Field>

          <SwitchRow label="Log dropped packets" checked={config.firewall.log_dropped}
            hint="Rate-limited to 10/second so a scan cannot flood the log."
            onChange={(v) => save({ 'firewall.log_dropped': v })} />
          <SwitchRow label="Filter IPv6 as well" checked={config.firewall.ipv6}
            onChange={(v) => save({ 'firewall.ipv6': v })} />
          <SwitchRow label="Never lock myself out" checked={config.firewall.anti_lockout}
            hint="Keeps SSH and this web interface permanently reachable. Turning this off means one bad rule can strand you outside your own firewall."
            onChange={(v) => save({ 'firewall.anti_lockout': v })} />
          <SwitchRow label="Hardware/software flow offload" checked={config.firewall.flow_offload}
            hint="Fast-paths established connections in the kernel. Large throughput win, but offloaded packets skip inspection — the flow table will undercount them."
            onChange={(v) => save({ 'firewall.flow_offload': v })} />
        </div>
      </Card>

      <Card title="Kernel settings" actions={
        <button className="btn sm" onClick={async () => {
          const r = await api.firewall.applySysctl()
          const bad = r.sysctl.filter((s) => !s.ok)
          toast(bad.length ? `${bad.length} could not be set` : 'Applied', bad.length ? 'err' : 'ok')
          refreshSysctl()
        }}>Apply recommended</button>
      }>
        {!sysctl ? <Loading what="kernel settings" /> : (
          <div style={{ display: 'grid', gap: 9 }}>
            {sysctl.sysctl.map((s) => (
              <div key={s.key} style={{ display: 'flex', gap: 10, alignItems: 'flex-start' }}>
                <span className={`dot ${s.ok ? 'on' : s.critical ? 'err' : 'warn'}`} style={{ marginTop: 5 }} />
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div className="mono" style={{ fontSize: 11.5 }}>
                    {s.key} = {s.current || '?'}
                    {!s.ok && <span style={{ color: 'var(--amber)' }}> (want {s.want})</span>}
                  </div>
                  <div style={{ fontSize: 11, color: 'var(--text-faint)' }}>{s.why}</div>
                  {s.error && <div style={{ fontSize: 11, color: 'var(--red)' }}>{s.error}</div>}
                </div>
              </div>
            ))}
            <div className="hint" style={{ marginTop: 4 }}>
              These are reported rather than forced. In a container they may be owned by the host,
              in which case set them there instead.
            </div>
          </div>
        )}
      </Card>

      {fw && (
        <Card title="Ruleset state">
          <dl className="kv">
            <dt>nft</dt><dd>{String(fw.version || 'not available')}</dd>
            <dt>Applied</dt><dd>{fw.applied ? 'yes' : 'no'}</dd>
            {fw.last_error ? <><dt>Last message</dt><dd>{String(fw.last_error)}</dd></> : null}
          </dl>
        </Card>
      )}
    </>
  )
}

function ZonesSection({ config, save, interfaces, toast }: SectionProps) {
  const [zones, setZones] = useState(config.firewall.zones)
  useEffect(() => setZones(config.firewall.zones), [config.firewall.zones])

  const commit = async (next: typeof zones) => {
    setZones(next)
    if (await save({ 'firewall.zones': next })) toast('Zones updated', 'ok')
  }

  return (
    <>
      <Card title="Zones">
        <div className="hint" style={{ marginBottom: 14, lineHeight: 1.7 }}>
          A zone groups interfaces and gives them a trust level. Rules can then say "guest cannot
          reach lan" instead of enumerating addresses. The trust level also drives the defaults:
          <strong style={{ color: 'var(--text)' }}> guest</strong> and
          <strong style={{ color: 'var(--text)' }}> iot</strong> zones are isolated from every other
          local zone automatically, while <strong style={{ color: 'var(--text)' }}>lan</strong> and
          <strong style={{ color: 'var(--text)' }}> vpn</strong> reach the internet freely.
        </div>

        <div style={{ display: 'grid', gap: 12 }}>
          {zones.map((z, i) => (
            <div key={i} style={{ border: '1px solid var(--line-soft)', borderRadius: 8, padding: 12 }}>
              <div className="grid c3" style={{ gap: 11 }}>
                <Field label="Name">
                  <input className="input" value={z.name}
                    onChange={(e) => {
                      const next = [...zones]
                      next[i] = { ...z, name: e.target.value }
                      setZones(next)
                    }}
                    onBlur={() => commit(zones)} />
                </Field>
                <Field label="Trust level">
                  <select className="select" value={z.trust}
                    onChange={(e) => {
                      const next = [...zones]
                      next[i] = { ...z, trust: e.target.value }
                      commit(next)
                    }}>
                    <option value="wan">wan — the internet side</option>
                    <option value="lan">lan — trusted local</option>
                    <option value="guest">guest — internet only</option>
                    <option value="iot">iot — internet only, isolated</option>
                    <option value="dmz">dmz — exposed services</option>
                    <option value="vpn">vpn — remote clients</option>
                  </select>
                </Field>
                <Field label="Subnets" hint="Comma-separated CIDRs">
                  <input className="input mono" value={z.subnets.join(', ')}
                    onChange={(e) => {
                      const next = [...zones]
                      next[i] = { ...z, subnets: e.target.value.split(',').map((s) => s.trim()).filter(Boolean) }
                      setZones(next)
                    }}
                    onBlur={() => commit(zones)} />
                </Field>
              </div>

              <Field label="Interfaces">
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                  {interfaces.filter((iface) => !iface.loopback).map((iface) => {
                    const on = z.interfaces.includes(iface.name)
                    return (
                      <button key={iface.name} className="btn sm"
                        style={on ? { borderColor: 'rgba(78,232,192,.5)', color: 'var(--accent)', background: 'var(--accent-glow)' } : undefined}
                        onClick={() => {
                          const next = [...zones]
                          next[i] = {
                            ...z,
                            interfaces: on
                              ? z.interfaces.filter((n) => n !== iface.name)
                              : [...z.interfaces, iface.name],
                          }
                          commit(next)
                        }}>{iface.name}</button>
                    )
                  })}
                </div>
              </Field>

              <div style={{ marginTop: 10 }}>
                <button className="btn sm danger" onClick={() => commit(zones.filter((_, j) => j !== i))}>
                  <Icons.trash size={12} /> Remove zone
                </button>
              </div>
            </div>
          ))}

          <div>
            <button className="btn" onClick={() =>
              commit([...zones, { name: `zone${zones.length + 1}`, interfaces: [], subnets: [], trust: 'lan' }])}>
              <Icons.plus size={13} /> Add a zone
            </button>
          </div>
        </div>
      </Card>
    </>
  )
}

function DHCPSection({ config, save, interfaces, toast }: SectionProps) {
  const [scopes, setScopes] = useState(config.dhcp.scopes)
  const [statics, setStatics] = useState(config.dhcp.static)
  useEffect(() => setScopes(config.dhcp.scopes), [config.dhcp.scopes])
  useEffect(() => setStatics(config.dhcp.static), [config.dhcp.static])

  const commitScopes = async (next: typeof scopes) => {
    setScopes(next)
    if (await save({ 'dhcp.scopes': next })) toast('Scopes updated', 'ok')
  }
  const commitStatics = async (next: typeof statics) => {
    setStatics(next)
    if (await save({ 'dhcp.static': next })) toast('Reservations updated', 'ok')
  }

  return (
    <>
      <Card title="DHCP server">
        <div style={{ display: 'grid', gap: 12 }}>
          <SwitchRow label="Hand out addresses" checked={config.dhcp.enabled}
            hint="Only starts in inline mode. Running a second DHCP server on a network that already has one causes address conflicts, so this stays off until you are genuinely the gateway."
            onChange={(v) => save({ 'dhcp.enabled': v })} />
        </div>
      </Card>

      <Card title="Scopes">
        <div style={{ display: 'grid', gap: 12 }}>
          {scopes.length === 0 && <Empty title="No scopes yet">Add one to define a pool.</Empty>}
          {scopes.map((s, i) => (
            <div key={i} style={{ border: '1px solid var(--line-soft)', borderRadius: 8, padding: 12 }}>
              <div className="grid c2" style={{ gap: 11 }}>
                <Field label="Name">
                  <input className="input" value={s.name}
                    onChange={(e) => { const n = [...scopes]; n[i] = { ...s, name: e.target.value }; setScopes(n) }}
                    onBlur={() => commitScopes(scopes)} />
                </Field>
                <Field label="Interface">
                  <select className="select" value={s.interface}
                    onChange={(e) => { const n = [...scopes]; n[i] = { ...s, interface: e.target.value }; commitScopes(n) }}>
                    <option value="">Choose…</option>
                    {interfaces.filter((iface) => !iface.loopback).map((iface) => (
                      <option key={iface.name} value={iface.name}>{iface.name}</option>
                    ))}
                  </select>
                </Field>
              </div>
              <div className="grid c3" style={{ gap: 11 }}>
                <Field label="Subnet">
                  <input className="input mono" value={s.subnet} placeholder="192.168.1.0/24"
                    onChange={(e) => { const n = [...scopes]; n[i] = { ...s, subnet: e.target.value }; setScopes(n) }}
                    onBlur={() => commitScopes(scopes)} />
                </Field>
                <Field label="Range start">
                  <input className="input mono" value={s.range_start} placeholder="192.168.1.100"
                    onChange={(e) => { const n = [...scopes]; n[i] = { ...s, range_start: e.target.value }; setScopes(n) }}
                    onBlur={() => commitScopes(scopes)} />
                </Field>
                <Field label="Range end">
                  <input className="input mono" value={s.range_end} placeholder="192.168.1.250"
                    onChange={(e) => { const n = [...scopes]; n[i] = { ...s, range_end: e.target.value }; setScopes(n) }}
                    onBlur={() => commitScopes(scopes)} />
                </Field>
              </div>
              <div className="grid c3" style={{ gap: 11 }}>
                <Field label="Gateway">
                  <input className="input mono" value={s.gateway} placeholder="192.168.1.1"
                    onChange={(e) => { const n = [...scopes]; n[i] = { ...s, gateway: e.target.value }; setScopes(n) }}
                    onBlur={() => commitScopes(scopes)} />
                </Field>
                <Field label="DNS servers" hint="Comma-separated. Point at this node to enforce filtering.">
                  <input className="input mono" value={s.dns.join(', ')} placeholder="192.168.1.1"
                    onChange={(e) => {
                      const n = [...scopes]
                      n[i] = { ...s, dns: e.target.value.split(',').map((x) => x.trim()).filter(Boolean) }
                      setScopes(n)
                    }}
                    onBlur={() => commitScopes(scopes)} />
                </Field>
                <Field label="Lease hours">
                  <input className="input mono" type="number" value={s.lease_hours}
                    onChange={(e) => { const n = [...scopes]; n[i] = { ...s, lease_hours: Number(e.target.value) }; setScopes(n) }}
                    onBlur={() => commitScopes(scopes)} />
                </Field>
              </div>
              <button className="btn sm danger" onClick={() => commitScopes(scopes.filter((_, j) => j !== i))}>
                <Icons.trash size={12} /> Remove scope
              </button>
            </div>
          ))}
          <div>
            <button className="btn" onClick={() => commitScopes([...scopes, {
              name: `scope${scopes.length + 1}`, interface: '', subnet: '', range_start: '',
              range_end: '', gateway: '', dns: [], domain: config.dns.local_domain,
              lease_hours: 12, mtu: 0, ntp: [],
            }])}><Icons.plus size={13} /> Add a scope</button>
          </div>
        </div>
      </Card>

      <Card title="Reservations">
        <div className="hint" style={{ marginBottom: 12 }}>
          Pin a device to a fixed address by MAC. Reservations survive lease expiry and are never
          handed to anything else.
        </div>
        <div style={{ display: 'grid', gap: 9 }}>
          {statics.map((s, i) => (
            <div key={i} style={{ display: 'flex', gap: 9, alignItems: 'center' }}>
              <input className="input mono" style={{ flex: 1 }} value={s.mac} placeholder="aa:bb:cc:dd:ee:ff"
                onChange={(e) => { const n = [...statics]; n[i] = { ...s, mac: e.target.value }; setStatics(n) }}
                onBlur={() => commitStatics(statics)} />
              <input className="input mono" style={{ flex: 1 }} value={s.ip} placeholder="192.168.1.50"
                onChange={(e) => { const n = [...statics]; n[i] = { ...s, ip: e.target.value }; setStatics(n) }}
                onBlur={() => commitStatics(statics)} />
              <input className="input" style={{ flex: 1 }} value={s.hostname} placeholder="hostname"
                onChange={(e) => { const n = [...statics]; n[i] = { ...s, hostname: e.target.value }; setStatics(n) }}
                onBlur={() => commitStatics(statics)} />
              <button className="btn icon" onClick={() => commitStatics(statics.filter((_, j) => j !== i))}>
                <Icons.trash size={13} />
              </button>
            </div>
          ))}
          <div>
            <button className="btn sm" onClick={() => setStatics([...statics, { mac: '', ip: '', hostname: '' }])}>
              <Icons.plus size={12} /> Add a reservation
            </button>
          </div>
        </div>
      </Card>
    </>
  )
}

function VPNSection({ config, save, toast }: SectionProps) {
  const { data: status } = usePoll(() => api.vpn.status(), 0)
  const s = (status?.status ?? {}) as Record<string, unknown>
  return (
    <>
      <Card title="WireGuard server">
        <div style={{ display: 'grid', gap: 14 }}>
          <SwitchRow label="Run the server" checked={config.vpn.server.enabled}
            hint="Lets remote devices join this network. They get the same DNS filtering and firewall policy as anything on the LAN."
            onChange={(v) => save({ 'vpn.server.enabled': v })} />

          <div className="grid c2">
            <NumberSetting label="Listen port" value={config.vpn.server.listen_port} min={1} max={65535}
              hint="UDP. Forward this port to the node if it is behind another router."
              onSave={(v) => save({ 'vpn.server.listen_port': v })} />
            <TextSetting label="Tunnel subnet" value={config.vpn.server.address} mono placeholder="10.66.0.1/24"
              hint="The server's address inside the tunnel. Peers get the next free address in this range."
              onSave={(v) => save({ 'vpn.server.address': v })} />
          </div>

          <TextSetting label="Public endpoint" value={config.vpn.server.endpoint} mono
            placeholder="vpn.example.com:51820"
            hint="Where peers connect from outside — a hostname or public IP with the port. Generated configs are useless without it."
            onSave={(v) => save({ 'vpn.server.endpoint': v })} />

          <ListSetting label="DNS servers for peers" value={config.vpn.server.dns} rows={2}
            hint="Leave empty to hand peers this node's tunnel address, so remote devices get the same filtering."
            onSave={(v) => save({ 'vpn.server.dns': v })} />

          <NumberSetting label="MTU" value={config.vpn.server.mtu} min={576} max={1500}
            hint="1420 suits most links. Lower it if large packets stall over the tunnel."
            onSave={(v) => save({ 'vpn.server.mtu': v })} />
        </div>
      </Card>

      <Card title="Server key">
        {typeof s.server_pubkey === 'string' && s.server_pubkey ? (
          <div style={{ display: 'grid', gap: 10 }}>
            <Field label="Public key">
              <div className="mono" style={{ fontSize: 11, wordBreak: 'break-all', color: 'var(--text-dim)' }}>
                {String(s.server_pubkey)}
              </div>
            </Field>
            <div><CopyButton text={String(s.server_pubkey)} label="Copy public key" /></div>
            <div className="hint">
              The private key lives in the config file and is never exposed through the API.
            </div>
          </div>
        ) : (
          <div style={{ display: 'grid', gap: 10 }}>
            <div className="hint">No key pair yet. One is generated the first time the server starts.</div>
            <div>
              <button className="btn" onClick={async () => {
                await api.vpn.serverAction('keys')
                toast('Key pair generated', 'ok')
              }}>Generate now</button>
            </div>
          </div>
        )}
      </Card>

      <Card title="Outbound tunnels">
        <div className="hint" style={{ lineHeight: 1.7 }}>
          Orbis can also act as a WireGuard <em>client</em>, routing selected LAN devices out
          through a provider with a kill switch. These are configured in
          <code> /etc/orbis/orbis.yaml</code> under <code>vpn.clients</code> — they need a private
          key and peer details that do not belong in a web form. Once defined they appear on the
          VPN page and can be started and stopped from there.
        </div>
      </Card>
    </>
  )
}

function TailscaleSection({ config, save, refresh, toast }: SectionProps) {
  const { data } = usePoll(() => api.tailscale.status(), 8000)
  const st = data?.status
  const overlap = data?.overlapping_routes ?? []
  const [authKey, setAuthKey] = useState('')

  return (
    <>
      {st && !st.available && (
        <Banner tone="warn">
          Tailscale is not installed on this node. Install it, then reload:
          <pre style={{ background: 'var(--bg-2)', borderRadius: 6, padding: '7px 10px', marginTop: 7, fontSize: 11.5 }}>
            curl -fsSL https://tailscale.com/install.sh | sh
          </pre>
        </Banner>
      )}

      <Card title="Tailnet">
        <div style={{ display: 'grid', gap: 14 }}>
          <SwitchRow label="Use Tailscale" checked={config.tailscale.enabled}
            hint="Brings the node up on your tailnet at boot and re-applies these settings."
            onChange={(v) => save({ 'tailscale.enabled': v })} />

          <TextSetting label="Hostname" value={config.tailscale.hostname} mono
            placeholder={config.node.name}
            hint="How this node appears in the tailnet. Leave empty to use the system hostname."
            onSave={(v) => save({ 'tailscale.hostname': v })} />

          <Field label="Auth key"
            hint="An ephemeral or reusable key for unattended enrolment. Leave empty to log in via a browser URL instead. Stored in the config file and never returned by the API.">
            <div style={{ display: 'flex', gap: 8 }}>
              <input className="input mono" type="password" value={authKey} placeholder="tskey-auth-…"
                onChange={(e) => setAuthKey(e.target.value)} />
              <button className="btn" disabled={!authKey} onClick={async () => {
                await api.tailscale.up({ auth_key: authKey })
                setAuthKey('')
                toast('Enrolling with the auth key', 'ok')
              }}>Enrol</button>
            </div>
          </Field>

          <TextSetting label="Login server" value={config.tailscale.login_server} mono
            placeholder="https://controlplane.tailscale.com"
            hint="Point at a Headscale instance to use a self-hosted coordination server."
            onSave={(v) => save({ 'tailscale.login_server': v })} />
        </div>
      </Card>

      <Card title="Exit node">
        <div style={{ display: 'grid', gap: 14 }}>
          <SwitchRow label="Offer this network as an exit node" checked={config.tailscale.advertise_exit_node}
            hint={<>Tailnet devices can route all their internet traffic through here, inheriting this
              node's ad blocking and firewall rules. Tailscale requires an admin to approve the offer
              before it carries any traffic.
              {st?.advertising_exit_node && !st?.exit_node_approved && (
                <strong style={{ color: 'var(--amber)', display: 'block', marginTop: 5 }}>
                  Advertised but not approved yet — approve it under Machines in the Tailscale console.
                </strong>
              )}</>}
            onChange={(v) => save({ 'tailscale.advertise_exit_node': v })} />

          <Field label="Use another node as this network's exit"
            hint="Sends egress out through the chosen peer instead of the WAN.">
            <select className="select" value={config.tailscale.exit_node}
              onChange={(e) => save({ 'tailscale.exit_node': e.target.value })}>
              <option value="">None</option>
              {(st?.available_exit_nodes ?? []).map((n) => (
                <option key={n.id} value={n.dns_name || n.name}>{n.name}</option>
              ))}
              {config.tailscale.exit_node &&
                !(st?.available_exit_nodes ?? []).some((n) => (n.dns_name || n.name) === config.tailscale.exit_node) && (
                <option value={config.tailscale.exit_node}>{config.tailscale.exit_node} (not currently offered)</option>
              )}
            </select>
          </Field>

          <SwitchRow label="Keep the local network reachable" checked={config.tailscale.exit_node_allow_lan}
            hint="Without this, selecting an exit node cuts off LAN access — including this interface."
            onChange={(v) => save({ 'tailscale.exit_node_allow_lan': v })} />

          <ListSetting label="Devices to steer through the exit node"
            value={config.tailscale.steer_clients} rows={4}
            placeholder={'192.168.1.42\n192.168.5.0/24'}
            hint="Addresses or CIDRs, one per line. Choosing an exit node alone only moves this node's own traffic; LAN clients have to be listed here to be policy-routed into the tunnel."
            onSave={(v) => save({ 'tailscale.steer_clients': v })} />
        </div>
      </Card>

      <Card title="Subnet routing & options">
        <div style={{ display: 'grid', gap: 14 }}>
          <ListSetting label="Advertise these subnets" value={config.tailscale.advertise_routes} rows={3}
            placeholder="192.168.1.0/24"
            hint="Makes this node a subnet router, so tailnet devices reach the LAN without installing a client on every host. Needs approval in the admin console."
            onSave={(v) => save({ 'tailscale.advertise_routes': v })} />

          <SwitchRow label="Accept routes from other nodes" checked={config.tailscale.accept_routes}
            disabled={overlap.length > 0}
            hint={overlap.length > 0
              ? <strong style={{ color: 'var(--amber)' }}>
                  A peer advertises {overlap.join(', ')}, which covers this node's own network.
                  Accepting it would send local traffic into the tunnel and take this node off the
                  LAN — including this page. Stop advertising that route first.
                </strong>
              : "Lets this node reach subnets other machines advertise. Safe unless a peer advertises a prefix covering a network this node is already on."}
            onChange={async (v) => {
              try {
                await api.tailscale.acceptRoutes(v)
                refresh()
              } catch (e) {
                toast(e instanceof Error ? e.message : 'Could not change route acceptance', 'err')
              }
            }} />

          <SwitchRow label="Accept the tailnet's DNS" checked={config.tailscale.accept_dns}
            hint="Off by default on purpose: accepting it would override the filtering resolver this node runs, for its own lookups."
            onChange={(v) => save({ 'tailscale.accept_dns': v })} />

          <SwitchRow label="Enable Tailscale SSH" checked={config.tailscale.ssh}
            hint="Allows SSH into this node over the tailnet with tailnet identity, no keys to manage."
            onChange={(v) => save({ 'tailscale.ssh': v })} />
        </div>
      </Card>
    </>
  )
}

function AssistantSection({ config, save, toast }: SectionProps) {
  const [apiKey, setApiKey] = useState('')
  const provider = config.ai.provider || 'anthropic'

  return (
    <>
      <Card title="Provider">
        <div style={{ display: 'grid', gap: 14 }}>
          <SwitchRow label="Enable the assistant" checked={config.ai.enabled}
            onChange={(v) => save({ 'ai.enabled': v })} />

          <Field label="Provider">
            <select className="select" value={provider} onChange={(e) => save({ 'ai.provider': e.target.value })}>
              <option value="anthropic">Anthropic</option>
              <option value="openai">OpenAI</option>
              <option value="openrouter">OpenRouter</option>
              <option value="ollama">Ollama (local)</option>
            </select>
          </Field>

          <Field label="API key"
            hint="Stored in the config file with 0600 permissions and never returned by the API.">
            <div style={{ display: 'flex', gap: 8 }}>
              <input className="input mono" type="password" value={apiKey}
                placeholder={config.ai.api_key ? '•••••••• (set)' : 'sk-…'}
                onChange={(e) => setApiKey(e.target.value)} />
              <button className="btn" disabled={!apiKey} onClick={async () => {
                if (await save({ 'ai.api_key': apiKey })) {
                  setApiKey('')
                  toast('API key saved', 'ok')
                }
              }}>Save</button>
            </div>
          </Field>

          <TextSetting label="Base URL" value={config.ai.base_url} mono
            placeholder={provider === 'ollama' ? 'http://127.0.0.1:11434/v1' : 'leave empty for the default'}
            hint="Override for a proxy, a gateway, or a local runtime."
            onSave={(v) => save({ 'ai.base_url': v })} />

          <div className="grid c2">
            <TextSetting label="Model" value={config.ai.model} mono
              hint="Used for chat and reasoning."
              onSave={(v) => save({ 'ai.model': v })} />
            <TextSetting label="Fast model" value={config.ai.fast_model} mono
              hint="High-volume classification: ad-domain scoring and anomaly triage. A smaller model is the right choice here."
              onSave={(v) => save({ 'ai.fast_model': v })} />
          </div>

          <NumberSetting label="Max response tokens" value={config.ai.max_tokens} min={256} max={64000}
            onSave={(v) => save({ 'ai.max_tokens': v })} />
        </div>
      </Card>

      <Card title="Permissions">
        <div style={{ display: 'grid', gap: 14 }}>
          <SwitchRow label="Let the assistant make changes" checked={config.ai.allow_write}
            hint="With this off, the mutating tools are not offered to the model at all — it can inspect and propose, but every change needs a click. With it on, it can add firewall rules, block domains and devices, and apply the ruleset. Everything it does lands in the audit log."
            onChange={async (v) => {
              if (v && !confirm(
                'The assistant will be able to change firewall rules, blocklists and device ' +
                'access on this live network. Continue?')) return
              save({ 'ai.allow_write': v })
            }} />
          {config.ai.allow_write && (
            <Banner tone="warn">
              Write access is on. The assistant acts on the live network as soon as it decides to.
            </Banner>
          )}
        </div>
      </Card>

      <Card title="Anomaly detection">
        <div style={{ display: 'grid', gap: 14 }}>
          <div className="hint" style={{ lineHeight: 1.7 }}>
            Statistical detectors run on a timer regardless of whether a model is configured:
            beaconing (connections at a suspiciously regular interval), large one-sided uploads,
            port and host sweeps, and DGA-style failed lookups. The model, when enabled, only
            triages what they surface.
          </div>
          <SwitchRow label="Run detectors" checked={config.ai.anomaly.enabled}
            onChange={(v) => save({ 'ai.anomaly.enabled': v })} />
          <SwitchRow label="Alert on new devices" checked={config.ai.anomaly.new_device_alert}
            hint="Raises an event the first time a device is seen on the network."
            onChange={(v) => save({ 'ai.anomaly.new_device_alert': v })} />
          <SwitchRow label="Triage findings with the model" checked={config.ai.anomaly.use_ai}
            hint="Most anomalies on a normal network have a mundane explanation. Triage adds an assessment and drops the routine ones to info level rather than alerting on everything."
            onChange={(v) => save({ 'ai.anomaly.use_ai': v })} />
          <NumberSetting label="Sweep interval" value={config.ai.anomaly.interval_minutes} min={1} max={1440} suffix="min"
            onSave={(v) => save({ 'ai.anomaly.interval_minutes': v })} />
        </div>
      </Card>
    </>
  )
}

function AboutSection({ config, status }: SectionProps) {
  const [showRaw, setShowRaw] = useState(false)
  return (
    <>
      <Card title="Node">
        <dl className="kv">
          <dt>Name</dt><dd>{config.node.name}</dd>
          <dt>Mode</dt><dd>{config.mode}</dd>
          <dt>Uptime</dt><dd>{duration(status?.uptime_sec ?? 0)}</dd>
          <dt>nftables</dt>
          <dd>{String((status?.firewall as Record<string, unknown>)?.version || 'not available')}</dd>
          <dt>GeoIP</dt>
          <dd>{String((status?.geoip as Record<string, unknown>)?.accuracy || 'unknown')}</dd>
          <dt>Tailscale</dt>
          <dd>{status?.tailscale?.available
            ? `${status.tailscale.version || 'installed'}${status.tailscale.tailnet_name ? ` · ${status.tailscale.tailnet_name}` : ''}`
            : 'not installed'}</dd>
          <dt>Event stream</dt>
          <dd>{Number((status?.bus as Record<string, number>)?.subscribers ?? 0)} subscriber(s),
            {' '}{Number((status?.bus as Record<string, number>)?.dropped ?? 0).toLocaleString()} dropped</dd>
        </dl>
      </Card>

      <Card title="Raw configuration" actions={
        <button className="btn sm" onClick={() => setShowRaw((v) => !v)}>{showRaw ? 'Hide' : 'Show'}</button>
      }>
        <div className="hint">
          Everything on this page maps to <code>/etc/orbis/orbis.yaml</code>. Secrets are masked here
          and in the API response; they exist only in the file itself.
        </div>
        {showRaw && (
          <pre style={{
            marginTop: 12, background: 'var(--bg-2)', border: '1px solid var(--line-soft)',
            borderRadius: 8, padding: 12, fontSize: 11, overflow: 'auto', maxHeight: 460,
          }}>{JSON.stringify(config, null, 2)}</pre>
        )}
      </Card>

      <Card title="Orbis">
        <div className="hint" style={{ lineHeight: 1.75 }}>
          An AI-assisted network firewall, filtering resolver and traffic analyser in one binary.
          Source and issues: <a href="https://github.com/Neoo-Blue/orbis" target="_blank" rel="noreferrer">
            github.com/Neoo-Blue/orbis</a>.
        </div>
      </Card>
    </>
  )
}
