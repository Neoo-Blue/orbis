import { lazy, Suspense, useMemo, useRef, useState } from 'react'
import { api } from '../api'
import { usePoll } from '../hooks'
import { useLiveBatch } from '../live'
import { OrbitChart, type OrbitDevice, type OrbitFlow, type OrbitHandle } from '../orbit/OrbitChart'
import { Card, Dot, Empty, Icons, Loading, Sparkline } from '../ui'
import { ago, bits, bytes, clientName, compact, duration, num, pct } from '../format'
import type { Client, DNSQuery, EventItem, Flow, Health, Summary, SystemStatus, NodeResources } from '../types'

type Nav = 'globe' | 'clients' | 'flows' | 'adblock' | 'events' | 'firewall' | 'settings' | 'dnstools' | 'problems' | 'health'

interface Props {
  status: SystemStatus | null
  summary: Summary | null
  onNavigate: (r: Nav, sub?: string) => void
}

/** Things that stay put go on the inner orbit, things people carry on the outer. */
export const FIXED_TYPES = /server|storage|nas|tv|speaker|camera|iot|printer|console|appliance|router|switch|access/i

export function orbitDevices(clients: Client[]): OrbitDevice[] {
  return clients.map((c) => ({
    id: c.id, name: clientName(c), rate: c.rate_in + c.rate_out, flows: c.active_flows, paused: c.blocked,
    ring: FIXED_TYPES.test(c.device_type ?? '') ? 0 : 1,
  }))
}

export function orbitFlows(flows: Flow[]): OrbitFlow[] {
  return flows.filter((f) => f.client_id).map((f) => ({
    client: f.client_id as string, lon: f.lat || f.lon ? f.lon : null,
    blocked: f.verdict === 'block', bytes: f.bytes_in + f.bytes_out,
  }))
}

interface Attention { key: string; level: 'problem' | 'attention' | 'notice'; title: string; threat?: boolean; go: () => void }
type Tone = 'ok' | 'attention' | 'problem'

/** Vermilion is for something stopped or a threat. A fault is amber, however bad. */
const THREAT_EVENTS = new Set(['threat', 'ids'])

interface Tick { rate_in: number; rate_out: number; flows_active: number }

const ClientDrawer = lazy(() => import('./Clients').then((m) => ({ default: m.ClientDrawer })))

export function Dashboard({ status, summary, onNavigate }: Props) {
  const [openDevice, setOpenDevice] = useState<string | null>(null)
  const { data: health } = usePoll<Health>(() => api.simple.health(), 15000)
  const { data: clients } = usePoll(() => api.clients.list(), 12000)
  const { data: active } = usePoll(() => api.flows.active(160), 8000)
  const { data: internet } = usePoll(() => api.netwatch.status(), 15000)
  const { data: recentEvents } = usePoll(() => api.events.list({ hours: 24, limit: 8 }), 20000)
  const { data: topBlocked } = usePoll(() => api.adblock.topBlocked(24, 8), 30000)
  const { data: topDest } = usePoll(() => api.flows.list({ hours: 24, order: 'bytes', limit: 8 }), 30000)
  const { data: blockedSeries } = usePoll(() => api.series('dns_blocked_total', 24, 48), 60000)
  const { data: blockedLog } = usePoll(() => api.dns.log({ hours: 2, blocked_only: true, limit: 6 }), 0)

  const orbit = useRef<OrbitHandle>(null)
  const [tick, setTick] = useState<Tick | null>(null)
  const [stopped, setStopped] = useState<DNSQuery[] | null>(null)
  useLiveBatch(['stats.tick'], (batch) => {
    const d = batch[batch.length - 1].data as Tick
    setTick((t) => (t && t.rate_in === d.rate_in && t.rate_out === d.rate_out && t.flows_active === d.flows_active ? t : d))
  })
  useLiveBatch(['dns.query'], (batch) => {
    const fresh: DNSQuery[] = []
    for (const ev of batch) {
      const q = ev.data as DNSQuery
      if (q?.blocked) { fresh.push(q); if (q.client_id) orbit.current?.strike(q.client_id, q.name) }
    }
    if (fresh.length) setStopped((prev) => [...fresh.reverse(), ...(prev ?? blockedLog?.queries ?? [])].slice(0, 6))
  })
  useLiveBatch(['flow.new'], (batch) => {
    for (const ev of batch) { const f = ev.data as Flow; if (f?.client_id) orbit.current?.arrive(f.client_id, f.lat || f.lon ? f.lon : null) }
  })

  const online = useMemo(
    () => (clients?.clients ?? []).filter((c) => c.online).sort((a, b) => (b.rate_in + b.rate_out) - (a.rate_in + a.rate_out)),
    [clients],
  )
  const devices = useMemo(() => orbitDevices(online), [online])
  const flows = useMemo(() => orbitFlows(active?.flows ?? []), [active])
  const blockedPoints = useMemo(() => (blockedSeries?.points ?? []).map((p) => p.v), [blockedSeries])
  const names = useMemo(() => new Map((clients?.clients ?? []).map((c) => [c.id, clientName(c)])), [clients])

  if (!summary) return <Loading what="overview" />

  const capture = status?.capture as Record<string, number | boolean> | undefined
  const level = health?.level ?? 'ok'
  const netFault = internet && internet.story !== 'ok' ? internet : null
  const verdict = !health ? 'Checking your network'
    : level !== 'ok' ? health.headline.replace(/\.$/, '')
    : !health.protection_on ? 'Filtering is switched off'
    : netFault ? 'Protected, but the internet is unwell'
    : status?.mode === 'inline' ? 'Your network is protected' : 'Protected by DNS filtering'
  // One tone for the sentence, its mark and the chart, so a fault can never sit
  // on the safe colour.
  const tone: Tone = !health ? 'attention'
    : level !== 'ok' ? level
    : !health.protection_on ? 'problem'
    : netFault ? 'attention' : 'ok'
  const quiet = (health?.points ?? []).filter((p) => p.level === 'ok').slice(0, 3)
  const stoppedList = stopped ?? blockedLog?.queries ?? []

  // Everything that needs the owner, in one place, most serious first.
  const attention: Attention[] = []
  for (const p of health?.points ?? []) {
    if (p.level !== 'ok') attention.push({ key: p.text, level: p.level, title: p.text, go: () => onNavigate(p.page === 'settings' || p.page === 'firewall' ? p.page : 'events') })
  }
  if (netFault) attention.push({ key: 'internet', level: netFault.state === 'down' ? 'problem' : 'attention', title: netFault.headline, go: () => onNavigate('health') })
  if (capture && capture.interfaces === 0) attention.push({ key: 'capture', level: 'attention', title: 'Packet capture opened no interfaces, so names and sites will be missing from connections.', go: () => onNavigate('settings') })
  for (const e of (recentEvents?.events ?? []).filter((e) => !e.acknowledged && (e.severity === 'warning' || e.severity === 'critical')).slice(0, 3)) {
    attention.push({ key: e.id, level: e.severity === 'critical' ? 'problem' : 'attention', title: e.title, threat: THREAT_EVENTS.has(e.category), go: () => onNavigate('events') })
  }
  if (summary.ad_candidates > 0) attention.push({ key: 'ads', level: 'notice', title: `${summary.ad_candidates} new ${summary.ad_candidates === 1 ? 'host looks' : 'hosts look'} like ads`, go: () => onNavigate('adblock') })
  const order = { problem: 0, attention: 1, notice: 2 }
  attention.sort((x, y) => order[x.level] - order[y.level])

  return (
    <div style={{ display: 'grid', gap: 14 }}>
      <section className="plate">
        <div className="plate-state">
          <h2 className={`verdict-line ${tone}`}>{verdict}</h2>
          <ul className="plate-points">
            {status?.mode === 'observe' && (
              <li>Filtering every device that uses this resolver. Firewall rules are not enforced in observe mode.</li>
            )}
            {quiet.map((p) => <li key={p.text}>{p.text}</li>)}
          </ul>
          {status && health && (
            <dl className="plate-ledger">
              {protectionLayers(status, health).map((l) => (
                <div key={l.name}><dt>{l.name}</dt><dd className={l.on ? 'on' : undefined}>{l.state}</dd></div>
              ))}
            </dl>
          )}
          <div className="plate-stopped">
            <div className="plate-caption"><b className="plate-figure">{compact(summary.dns_blocked)}</b> stopped today, {pct(summary.block_rate, 0)} of lookups</div>
            {blockedPoints.length > 1 && (
              <>
                <Sparkline points={blockedPoints} tone="red" height={96} />
                <div className="plate-axis"><span>24h ago</span><span>now</span></div>
              </>
            )}
          </div>
          <dl className="plate-facts">
            <div><dt>Devices online</dt><dd>{clients ? online.length : summary.clients_online} of {clients?.clients.length ?? summary.clients}</dd></div>
            <div><dt>Connections</dt><dd>{num(tick?.flows_active ?? summary.active_flows)}</dd></div>
            <div><dt>Down</dt><dd>{bits(tick?.rate_in ?? 0)}</dd></div>
            <div><dt>Up</dt><dd>{bits(tick?.rate_out ?? 0)}</dd></div>
          </dl>
        </div>

        <div className="plate-chart">
          <OrbitChart ref={orbit} devices={devices} flows={flows} title={status?.node} tone={tone}
            onSelect={setOpenDevice} onStrike={(name) => onNavigate('dnstools', name)}
            label={`${devices.length} devices online with ${flows.length} connections. Every device is listed under Devices.`} />
        </div>

        <div className="plate-side">
          <h3>Needs you</h3>
          {attention.length === 0 ? (
            <p className="plate-clear">Nothing right now.</p>
          ) : (
            <ul className="plate-list">
              {attention.slice(0, 5).map((a) => (
                <li key={a.key}>
                  <button type="button" className="row-btn needs" onClick={a.go}>
                    <span className={`issue-sev ${a.threat ? 'critical' : a.level === 'notice' ? 'notice' : 'warning'}`} />
                    <span className="needs-title">{a.title}</span>
                  </button>
                </li>
              ))}
            </ul>
          )}

          <h3>Stopped just now</h3>
          {stoppedList.length === 0 ? (
            <p className="plate-clear">Nothing blocked in the last two hours.</p>
          ) : (
            <ul className="plate-list">
              {stoppedList.map((q, i) => (
                <li key={`${q.ts}|${q.name}|${i}`}>
                  <button type="button" className="row-btn" title="See why" onClick={() => onNavigate('dnstools', q.name)}>
                    <span className="plate-row-title mono"><i className="struck" />{q.name}</span>
                    {q.client_id && names.get(q.client_id)
                      ? <span className="plate-row-meta">{names.get(q.client_id)}</span>
                      : <span className="plate-row-meta mono">{q.client_ip}</span>}
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      </section>

      {openDevice && (
        <Suspense fallback={null}>
          <ClientDrawer id={openDevice} onClose={() => setOpenDevice(null)} onChanged={() => undefined} />
        </Suspense>
      )}

      <div className="grid c3">
        <Card title="Busiest devices"
          actions={<button className="btn sm" onClick={() => onNavigate('clients')}>All devices</button>}>
          {online.length === 0 ? (
            <Empty title="No devices seen yet">
              Devices appear as soon as traffic from them reaches this node.
            </Empty>
          ) : (
            <div style={{ display: 'grid', gap: 9 }}>
              {online.slice(0, 6).map((c) => (
                <ClientRow key={c.id} client={c} peak={online[0]} onOpen={() => onNavigate('clients', c.id)} />
              ))}
            </div>
          )}
        </Card>

        <Card title="Most blocked"
          actions={<button className="btn sm" onClick={() => onNavigate('adblock')}>Ad blocking</button>}>
          {!topBlocked?.domains.length ? (
            <Empty title="Nothing blocked yet">
              Either the lists have not finished downloading, or nothing has asked for a
              blocked name in the last day.
            </Empty>
          ) : (
            <div style={{ display: 'grid', gap: 7 }}>
              {topBlocked.domains.map((d) => (
                <button type="button" key={d.domain} className="row-btn"
                  onClick={() => onNavigate('dnstools', d.domain)}
                  style={{ display: 'flex', gap: 10, alignItems: 'baseline', fontSize: 12.5, padding: '2px 4px' }}>
                  <span className="truncate mono" style={{ flex: 1 }} title={d.domain}>{d.domain}</span>
                  <span className="num" style={{ color: 'var(--red)' }}>{compact(d.count)}</span>
                </button>
              ))}
            </div>
          )}
        </Card>

        <Card title="Subsystems" actions={<span className="tag">up {duration(summary.uptime_seconds)}</span>}>
          <SubsystemList status={status} />
        </Card>
      </div>

      <div className="grid c2">
        <Card title="Heaviest connections (24h)"
          actions={<button className="btn sm" onClick={() => onNavigate('flows')}>All connections</button>}>
          <TopFlows flows={topDest?.flows ?? []} onOpen={() => onNavigate('flows')} />
        </Card>

        <Card title="Recent events"
          actions={<button className="btn sm" onClick={() => onNavigate('events')}>All events</button>}>
          <EventList events={recentEvents?.events ?? []} onOpen={() => onNavigate('events')} />
        </Card>
      </div>
    </div>
  )
}

function SubsystemList({ status }: { status: SystemStatus | null }) {
  if (!status) return <Loading what="status" />

  const rows: Array<{ name: string; on: boolean; detail: string; warn?: boolean }> = [
    {
      name: 'Packet capture',
      on: Number(status.capture?.interfaces ?? 0) > 0,
      detail: `${status.capture?.interfaces ?? 0} ${status.capture?.interfaces === 1 ? 'interface' : 'interfaces'} · ${compact(Number(status.capture?.packets ?? 0))} packets`,
      warn: Number(status.capture?.kernel_drops ?? 0) > 1000,
    },
    {
      name: 'DNS resolver',
      on: Boolean((status.dns as Record<string, unknown>)?.running),
      detail: `${compact(Number((status.dns as Record<string, number>)?.queries ?? 0))} queries · ` +
        `${pct(Number(((status.dns as Record<string, Record<string, number>>)?.cache)?.hit_rate ?? 0), 0)} cached`,
    },
    {
      name: 'Ad blocking',
      on: Number((status.adblock as Record<string, number>)?.entries ?? 0) > 0,
      detail: `${compact(Number((status.adblock as Record<string, number>)?.entries ?? 0))} rules indexed`,
    },
    {
      name: 'Filter proxy',
      on: Boolean((status.filter_proxy as Record<string, unknown>)?.running),
      detail: (status.filter_proxy as Record<string, unknown>)?.running
        ? `${compact(Number((status.filter_proxy as Record<string, number>)?.ads_stripped ?? 0))} ads stripped`
        : 'off, required for in-stream (YouTube) ad removal',
    },
    {
      name: 'Firewall',
      on: Boolean((status.firewall as Record<string, unknown>)?.applied),
      detail: firewallDetail(String((status.firewall as Record<string, unknown>)?.last_error ?? '')),
    },
    {
      name: 'DHCP',
      on: Boolean((status.dhcp as Record<string, unknown>)?.running),
      detail: `${Number((status.dhcp as Record<string, number>)?.leases ?? 0)} leases`,
    },
    {
      name: 'WireGuard',
      on: Boolean((status.vpn as Record<string, unknown>)?.server_up),
      detail: (status.vpn as Record<string, unknown>)?.server_up ? 'server running' : 'off',
    },
    {
      name: 'Tailscale',
      on: Boolean(status.tailscale?.running),
      detail: !status.tailscale?.available ? 'not installed'
        : status.tailscale.exit_node_in_use ? `via exit node ${status.tailscale.exit_node_in_use}`
        : status.tailscale.advertising_exit_node
          ? (status.tailscale.exit_node_approved ? 'exit node (approved)' : 'exit node awaiting approval')
          : status.tailscale.backend_state || 'off',
      warn: Boolean(status.tailscale?.advertising_exit_node && !status.tailscale?.exit_node_approved),
    },
    {
      name: 'Assistant',
      on: Boolean((status.ai as Record<string, unknown>)?.configured),
      detail: (status.ai as Record<string, unknown>)?.configured
        ? `${(status.ai as Record<string, string>).model}${(status.ai as Record<string, boolean>).allow_write ? ' · can make changes' : ' · read-only'}`
        : 'no provider configured',
    },
    ...(status.resources ? resourceRows(status.resources, status.version) : []),
  ]

  return (
    <div style={{ display: 'grid', gap: 8, gridTemplateColumns: 'minmax(0, 1fr)' }}>
      {rows.map((r) => (
        <div key={r.name} style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <Dot state={r.warn ? 'warn' : r.on ? 'on' : 'off'} />
          <span style={{ minWidth: 108, fontSize: 12.5 }}>{r.name}</span>
          <span className="truncate" style={{ flex: 1, color: 'var(--text-faint)', fontSize: 11.5 }} title={r.detail}>
            {r.detail}
          </span>
        </div>
      ))}
    </div>
  )
}

function ClientRow({ client, peak, onOpen }: { client: Client; peak: Client; onOpen: () => void }) {
  const total = client.rate_in + client.rate_out
  const max = Math.max(peak.rate_in + peak.rate_out, 1)
  return (
    <button type="button" className="row-btn" onClick={onOpen} aria-label={`${clientName(client)}, ${bits(total)}`}>
      <div style={{ display: 'flex', gap: 9, alignItems: 'baseline', marginBottom: 3 }}>
        <span className="truncate" style={{ flex: 1, fontSize: 12.5 }} title={client.ip}>
          {clientName(client)}
        </span>
        <span className="num" style={{ fontSize: 11.5, color: 'var(--text-dim)' }}>{bits(total)}</span>
      </div>
      <div className="bar"><i style={{ width: `${Math.min(100, (total / max) * 100)}%` }} /></div>
    </button>
  )
}

function TopFlows({ flows, onOpen }: { flows: Flow[]; onOpen: () => void }) {
  if (!flows.length) {
    return <Empty title="No traffic recorded yet">Connections appear once devices use the internet through this node.</Empty>
  }
  return (
    <div className="table-wrap">
      <table className="t">
        <thead>
          <tr><th>Destination</th><th>App</th><th className="num">Down</th><th className="num">Up</th></tr>
        </thead>
        <tbody>
          {flows.map((f) => (
            <tr key={f.id} className="clickable" tabIndex={0} role="button"
              onClick={onOpen}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onOpen() }
              }}>
              <td className="truncate" title={f.hostname || f.sni || f.dst_ip}>
                {f.country && <span className="mono" style={{ marginRight: 6, color: 'var(--text-faint)' }}>{f.country}</span>}
                {f.hostname || f.sni || f.dst_ip}
              </td>
              <td style={{ color: 'var(--text-dim)' }}>{f.app || f.as_org || '-'}</td>
              <td className="num">{bytes(f.bytes_in)}</td>
              <td className="num">{bytes(f.bytes_out)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function EventList({ events, onOpen }: { events: EventItem[]; onOpen: () => void }) {
  if (!events.length) {
    return <Empty title="Nothing to report">No events in the last 24 hours.</Empty>
  }
  return (
    <div style={{ display: 'grid', gap: 9 }}>
      {events.map((e) => (
        <button type="button" key={e.id} className="row-btn" onClick={onOpen}
          style={{ display: 'flex', gap: 9, alignItems: 'flex-start', padding: '2px 4px' }}>
          <span className={`tag ${e.severity === 'critical' || e.severity === 'warning' ? 'warn' : 'info'}`}
            style={{ marginTop: 1 }}>
            {e.severity === 'critical' ? <Icons.alert size={11} /> : null}
            {e.severity}
          </span>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div className="truncate" style={{ fontSize: 12.5 }} title={e.title}>{e.title}</div>
            <div style={{ fontSize: 11, color: 'var(--text-faint)' }}>{ago(e.ts)}</div>
          </div>
        </button>
      ))}
    </div>
  )
}


/**
 * What the node itself is spending. The daemon's CPU is a share of one core,
 * the host's of all cores; memory is the daemon's resident set against the
 * machine. A Pi's firmware throttle word is decoded when present, since
 * under-voltage is the usual reason a Pi "feels slow".
 */
function resourceRows(r: NodeResources, version?: string) {
  const gb = (b: number) => (b / (1024 ** 3)).toFixed(b >= 10 * 1024 ** 3 ? 0 : 1) + ' GB'
  const memPct = r.mem_total_bytes > 0 ? Math.round((r.rss_bytes / r.mem_total_bytes) * 100) : 0
  const throttled = Boolean(r.throttled) && r.throttled !== 'ok'
  return [
    {
      name: 'CPU', on: true, warn: r.process_cpu_percent > 150,
      detail: `${Math.round(r.process_cpu_percent)}% of one core · host ${Math.round(r.host_cpu_percent)}% of ${r.cores} · load ${r.load1.toFixed(2)}`,
    },
    {
      name: 'Memory', on: true, warn: memPct > 60,
      detail: `${gb(r.rss_bytes)}, ${memPct}% of ${gb(r.mem_total_bytes)} · heap ${gb(r.heap_bytes)}`,
    },
    {
      name: 'Temperature', on: Boolean(r.temp_c), warn: (r.temp_c ?? 0) >= 75 || throttled,
      detail: `${r.temp_c ? `${Math.round(r.temp_c)} °C` : 'no sensor'}${r.throttled ? ` · ${r.throttled}` : ''}`,
    },
    {
      name: 'Orbis', on: true,
      detail: `${version ?? 'dev'} · up ${duration(r.uptime_seconds)} · ${num(r.goroutines)} goroutines`,
    },
  ]
}

/** What each layer of protection is doing now, in the words it would be judged by. */
function protectionLayers(status: SystemStatus, health: Health) {
  const inline = status.mode === 'inline'
  const applied = Boolean((status.firewall as Record<string, unknown>)?.applied)
  const proxy = Boolean((status.filter_proxy as Record<string, unknown>)?.running)
  const threat = Boolean((status.threat as Record<string, unknown> | undefined)?.enabled)
  return [
    { name: 'DNS filtering', on: health.protection_on, state: health.protection_on ? 'On' : 'Off' },
    { name: 'Firewall', on: inline && applied, state: !inline ? 'Not enforced' : applied ? 'Enforced' : 'Not applied' },
    { name: 'In-stream ads', on: proxy, state: proxy ? 'Removed' : 'Off' },
    { name: 'Threat feeds', on: threat, state: threat ? 'On' : 'Off' },
  ]
}

function firewallDetail(error: string) {
  if (!error) return 'ruleset applied'
  return error.includes('executable file not found') ? 'nft not installed' : error
}
