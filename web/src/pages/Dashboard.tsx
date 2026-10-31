import { useMemo, useRef, useState } from 'react'
import { api } from '../api'
import { usePoll } from '../hooks'
import { useLiveBatch } from '../live'
import { OrbitChart, type OrbitDevice, type OrbitFlow, type OrbitHandle } from '../orbit/OrbitChart'
import { Banner, Card, Dot, Empty, Icons, Loading, Sparkline, Stat } from '../ui'
import { ago, bits, bytes, clientName, compact, duration, num, pct, countryFlag } from '../format'
import type { Client, DNSQuery, EventItem, Flow, Health, Summary, SystemStatus, NodeResources } from '../types'

type Nav = 'globe' | 'clients' | 'flows' | 'adblock' | 'events' | 'firewall' | 'settings' | 'dnstools' | 'problems'

interface Props {
  status: SystemStatus | null
  summary: Summary | null
  onNavigate: (r: Nav, sub?: string) => void
}

interface Tick { rate_in: number; rate_out: number; flows_active: number }

export function Dashboard({ status, summary, onNavigate }: Props) {
  const { data: health } = usePoll<Health>(() => api.simple.health(), 15000)
  const { data: clients } = usePoll(() => api.clients.list(), 12000)
  const { data: active } = usePoll(() => api.flows.active(160), 8000)
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
      if (q?.blocked) { fresh.push(q); if (q.client_id) orbit.current?.spark(q.client_id) }
    }
    if (fresh.length) setStopped((prev) => [...fresh.reverse(), ...(prev ?? blockedLog?.queries ?? [])].slice(0, 6))
  })
  useLiveBatch(['flow.new'], (batch) => {
    for (const ev of batch) { const f = ev.data as Flow; if (f?.id) orbit.current?.arrive(f.id) }
  })

  const online = useMemo(
    () => (clients?.clients ?? []).filter((c) => c.online).sort((a, b) => (b.rate_in + b.rate_out) - (a.rate_in + a.rate_out)),
    [clients],
  )
  const devices = useMemo<OrbitDevice[]>(() => online.map((c) => ({
    id: c.id, name: clientName(c), rate: c.rate_in + c.rate_out, flows: c.active_flows, paused: c.blocked,
  })), [online])
  const flows = useMemo<OrbitFlow[]>(() => (active?.flows ?? []).filter((f) => f.client_id && (f.lat || f.lon)).map((f) => ({
    id: f.id, client: f.client_id as string, lon: f.lon, blocked: f.verdict === 'block', bytes: f.bytes_in + f.bytes_out,
  })), [active])
  const blockedPoints = useMemo(() => (blockedSeries?.points ?? []).map((p) => p.v), [blockedSeries])
  const names = useMemo(() => new Map((clients?.clients ?? []).map((c) => [c.id, clientName(c)])), [clients])

  if (!summary) return <Loading what="overview" />

  const capture = status?.capture as Record<string, number | boolean> | undefined
  const captureOff = capture && capture.interfaces === 0
  const sysctlIssues = (status?.sysctl ?? []).filter((s) => s.critical && !s.ok)
  const level = health?.level ?? 'ok'
  const verdict = !health ? 'Checking your network'
    : level !== 'ok' ? health.headline.replace(/\.$/, '')
    : health.protection_on ? 'Your network is protected' : 'Filtering is switched off'
  const issues = (health?.points ?? []).filter((p) => p.level !== 'ok')
  const quiet = (health?.points ?? []).filter((p) => p.level === 'ok').slice(0, 3)
  const review = (recentEvents?.events ?? []).filter((e) => !e.acknowledged && (e.severity === 'warning' || e.severity === 'critical')).slice(0, 3)
  const stoppedList = stopped ?? blockedLog?.queries ?? []

  return (
    <div style={{ display: 'grid', gap: 14 }}>
      {captureOff && (
        <Banner tone="warn">
          Packet capture opened no interfaces. Without <code>CAP_NET_RAW</code> the flow table
          only sees what conntrack reports, so hostnames and SNI will be missing.
        </Banner>
      )}
      {sysctlIssues.length > 0 && status?.mode === 'inline' && (
        <Banner tone="err" action={<button className="btn sm" onClick={() => onNavigate('firewall')}>Fix</button>}>
          {sysctlIssues.map((s) => s.key).join(', ')} {sysctlIssues.length === 1 ? 'is' : 'are'} not set
          correctly, routing will not work as configured.
        </Banner>
      )}

      <section className="plate">
        <div className="plate-state">
          <h2 className={`verdict-line ${level}`}>{verdict}</h2>
          <ul className="plate-points">
            {(issues.length ? issues : quiet).map((p) => (
              <li key={p.text} className={p.level}>{p.text}</li>
            ))}
            {status?.mode === 'observe' && (
              <li className="ok">Filtering every device that uses this resolver. Firewall rules are not enforced in observe mode.</li>
            )}
          </ul>
          <div className="plate-stopped">
            <div className="plate-figure">{compact(summary.dns_blocked)}</div>
            <div className="plate-caption">stopped today, {pct(summary.block_rate, 0)} of lookups</div>
            {blockedPoints.length > 1 && <Sparkline points={blockedPoints} tone="red" height={40} />}
          </div>
          <dl className="plate-facts">
            <div><dt>Devices online</dt><dd>{summary.clients_online} of {summary.clients}</dd></div>
            <div><dt>Connections</dt><dd>{num(tick?.flows_active ?? summary.active_flows)}</dd></div>
            <div><dt>Down</dt><dd>{bits(tick?.rate_in ?? 0)}</dd></div>
            <div><dt>Up</dt><dd>{bits(tick?.rate_out ?? 0)}</dd></div>
          </dl>
        </div>

        <div className="plate-chart">
          <OrbitChart ref={orbit} devices={devices} flows={flows} onSelect={(id) => onNavigate('clients', id)}
            label={`${devices.length} devices online with ${flows.length} connections drawn. The same devices are listed under Busiest devices.`} />
        </div>

        <div className="plate-side">
          <h3>Needs you</h3>
          {review.length === 0 && !summary.ad_candidates ? (
            <p className="plate-clear">Nothing right now.</p>
          ) : (
            <ul className="plate-list">
              {review.map((e) => (
                <li key={e.id}>
                  <button type="button" className="row-btn" onClick={() => onNavigate('events')}>
                    <span className={`issue-sev ${e.severity}`} /><span className="plate-row-title">{e.title}</span>
                    <span className="plate-row-meta">{ago(e.ts)}</span>
                  </button>
                </li>
              ))}
              {summary.ad_candidates > 0 && (
                <li>
                  <button type="button" className="row-btn" onClick={() => onNavigate('adblock')}>
                    <span className="issue-sev notice" /><span className="plate-row-title">{summary.ad_candidates} new {summary.ad_candidates === 1 ? 'host looks' : 'hosts look'} like ads</span>
                    <span className="plate-row-meta">Review</span>
                  </button>
                </li>
              )}
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
                    <span className="plate-row-title mono">{q.name}</span>
                    <span className="plate-row-meta">{(q.client_id && names.get(q.client_id)) || q.client_ip}</span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      </section>

      {status?.resources && <NodeResourcesRow r={status.resources} version={status.version} />}

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
      detail: `${status.capture?.interfaces ?? 0} interface(s) · ${compact(Number(status.capture?.packets ?? 0))} packets`,
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
      detail: String((status.firewall as Record<string, unknown>)?.last_error || 'ruleset applied'),
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
          : status.tailscale.backend_state,
      warn: Boolean(status.tailscale?.advertising_exit_node && !status.tailscale?.exit_node_approved),
    },
    {
      name: 'Assistant',
      on: Boolean((status.ai as Record<string, unknown>)?.configured),
      detail: (status.ai as Record<string, unknown>)?.configured
        ? `${(status.ai as Record<string, string>).model}${(status.ai as Record<string, boolean>).allow_write ? ' · can make changes' : ' · read-only'}`
        : 'no provider configured',
    },
  ]

  return (
    <div style={{ display: 'grid', gap: 8 }}>
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
                {f.country && <span style={{ marginRight: 6 }}>{countryFlag(f.country)}</span>}
                {f.hostname || f.sni || f.dst_ip}
              </td>
              <td style={{ color: 'var(--text-dim)' }}>{f.app || f.as_org || '—'}</td>
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
function NodeResourcesRow({ r, version }: { r: NodeResources; version?: string }) {
  const gb = (b: number) => (b / (1024 ** 3)).toFixed(b >= 10 * 1024 ** 3 ? 0 : 1) + ' GB'
  const memPct = r.mem_total_bytes > 0 ? Math.round((r.rss_bytes / r.mem_total_bytes) * 100) : 0
  const hostUsed = r.mem_total_bytes > 0 ? Math.round(((r.mem_total_bytes - r.mem_available_bytes) / r.mem_total_bytes) * 100) : 0
  const hot = (r.temp_c ?? 0) >= 75
  const throttledNow = (r.throttled ?? '').startsWith('now')
  return (
    <div className="grid c4">
      <Stat label="Orbis CPU" tone={r.process_cpu_percent > 150 ? 'amber' : undefined}
        value={`${Math.round(r.process_cpu_percent)}%`}
        sub={`of one core · host ${Math.round(r.host_cpu_percent)}% of ${r.cores} · load ${r.load1.toFixed(2)}`} />
      <Stat label="Orbis memory" tone={memPct > 60 ? 'amber' : undefined}
        value={gb(r.rss_bytes)}
        sub={`${memPct}% of ${gb(r.mem_total_bytes)} · host ${hostUsed}% used · heap ${gb(r.heap_bytes)}`} />
      <Stat label="Temperature" tone={hot || throttledNow ? 'red' : (r.throttled ?? 'ok') !== 'ok' && r.throttled ? 'amber' : undefined}
        value={r.temp_c ? `${Math.round(r.temp_c)} °C` : 'n/a'}
        sub={r.throttled ? r.throttled : 'no throttle data on this platform'} />
      <Stat label="Uptime"
        value={duration(r.uptime_seconds)}
        sub={`${version ? `Orbis ${version} · ` : ''}${num(r.goroutines)} goroutines`} />
    </div>
  )
}
