import { useEffect, useMemo, useState } from 'react'
import { api } from '../api'
import { usePoll, type LiveEvent } from '../hooks'
import { Banner, Card, Dot, Empty, Icons, Loading, Stat } from '../ui'
import { ago, bits, bytes, clientName, compact, duration, num, pct, countryFlag } from '../format'
import type { Client, EventItem, Flow, Summary, SystemStatus } from '../types'

interface Props {
  status: SystemStatus | null
  summary: Summary | null
  events: LiveEvent[]
  onNavigate: (r: 'globe' | 'clients' | 'flows' | 'adblock' | 'events' | 'firewall' | 'settings') => void
}

export function Dashboard({ status, summary, events, onNavigate }: Props) {
  const { data: clients } = usePoll(() => api.clients.list(), 12000)
  const { data: recentEvents } = usePoll(() => api.events.list({ hours: 24, limit: 8 }), 20000)
  const { data: topBlocked } = usePoll(() => api.adblock.topBlocked(24, 8), 30000)
  const { data: topDest } = usePoll(() => api.flows.list({ hours: 24, order: 'bytes', limit: 8 }), 30000)
  const { data: throughput } = usePoll(() => api.series('throughput_out', 3), 30000)
  const { data: dnsSeries } = usePoll(() => api.series('dns_queries_total', 6), 60000)

  // Live counters derived from the socket, so the headline numbers move
  // between polls instead of stepping every fifteen seconds.
  const [liveRate, setLiveRate] = useState({ in: 0, out: 0, flows: 0 })
  useEffect(() => {
    for (let i = events.length - 1; i >= 0; i--) {
      if (events[i].type === 'stats.tick') {
        const d = events[i].data as { rate_in: number; rate_out: number; flows_active: number }
        setLiveRate({ in: d.rate_in, out: d.rate_out, flows: d.flows_active })
        break
      }
    }
  }, [events])

  const onlineClients = useMemo(
    () => (clients?.clients ?? []).filter((c) => c.online).sort((a, b) => (b.rate_in + b.rate_out) - (a.rate_in + a.rate_out)),
    [clients],
  )
  const throughputPoints = useMemo(() => (throughput?.points ?? []).map((p) => p.v), [throughput])
  const dnsPoints = useMemo(() => (dnsSeries?.points ?? []).map((p) => p.v), [dnsSeries])

  if (!summary) return <Loading what="dashboard" />

  const capture = status?.capture as Record<string, number | boolean> | undefined
  const captureOff = capture && capture.interfaces === 0
  const sysctlIssues = (status?.sysctl ?? []).filter((s) => s.critical && !s.ok)

  return (
    <div style={{ display: 'grid', gap: 14 }}>
      {status?.mode === 'observe' && (
        <Banner tone="info" action={<button className="btn sm" onClick={() => onNavigate('settings')}>Configure</button>}>
          <strong style={{ display: 'block', marginBottom: 2 }}>Observe mode</strong>
          Orbis is watching traffic that reaches it, but nothing is routed through this node and
          no firewall ruleset is installed. Blocked verdicts are recorded, not enforced.
        </Banner>
      )}
      {captureOff && (
        <Banner tone="warn">
          Packet capture opened no interfaces. Without <code>CAP_NET_RAW</code> the flow table
          only sees what conntrack reports, so hostnames and SNI will be missing.
        </Banner>
      )}
      {sysctlIssues.length > 0 && status?.mode === 'inline' && (
        <Banner tone="err" action={<button className="btn sm" onClick={() => onNavigate('firewall')}>Fix</button>}>
          {sysctlIssues.map((s) => s.key).join(', ')} {sysctlIssues.length === 1 ? 'is' : 'are'} not set
          correctly — routing will not work as configured.
        </Banner>
      )}

      <div className="grid c4">
        <Stat label="Throughput out" tone="accent" spark={throughputPoints}
          value={bits(liveRate.out || 0)}
          sub={`${bits(liveRate.in || 0)} inbound`} />
        <Stat label="Active connections" tone="blue"
          value={num(liveRate.flows || summary.active_flows)}
          sub={`${compact(summary.flows)} in 24h`} />
        <Stat label="DNS blocked" tone={summary.block_rate > 0.35 ? 'amber' : 'accent'} spark={dnsPoints}
          value={pct(summary.block_rate, 0)}
          sub={`${compact(summary.dns_blocked)} of ${compact(summary.dns_queries)} queries`} />
        <Stat label="Devices online"
          value={`${summary.clients_online}`}
          sub={`${summary.clients} known · ${compact(summary.blocklist_entries)} block entries`} />
      </div>

      <div className="grid c3">
        <Card title="Subsystems" actions={<span className="tag">up {duration(summary.uptime_seconds)}</span>}>
          <SubsystemList status={status} />
        </Card>

        <Card title="Busiest devices"
          actions={<button className="btn sm" onClick={() => onNavigate('clients')}>All devices</button>}>
          {onlineClients.length === 0 ? (
            <Empty title="No devices seen yet">
              Devices appear as soon as traffic from them reaches this node.
            </Empty>
          ) : (
            <div style={{ display: 'grid', gap: 9 }}>
              {onlineClients.slice(0, 6).map((c) => <ClientRow key={c.id} client={c} peak={onlineClients[0]} />)}
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
                <div key={d.domain} style={{ display: 'flex', gap: 10, alignItems: 'baseline', fontSize: 12.5 }}>
                  <span className="truncate mono" style={{ flex: 1 }} title={d.domain}>{d.domain}</span>
                  <span className="num" style={{ color: 'var(--red)' }}>{compact(d.count)}</span>
                </div>
              ))}
            </div>
          )}
        </Card>
      </div>

      <div className="grid c2">
        <Card title="Heaviest connections (24h)"
          actions={<button className="btn sm" onClick={() => onNavigate('flows')}>All connections</button>}>
          <TopFlows flows={topDest?.flows ?? []} />
        </Card>

        <Card title="Recent events"
          actions={<button className="btn sm" onClick={() => onNavigate('events')}>All events</button>}>
          <EventList events={recentEvents?.events ?? []} />
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
        : 'off — required for in-stream (YouTube) ad removal',
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

function ClientRow({ client, peak }: { client: Client; peak: Client }) {
  const total = client.rate_in + client.rate_out
  const max = Math.max(peak.rate_in + peak.rate_out, 1)
  return (
    <div>
      <div style={{ display: 'flex', gap: 9, alignItems: 'baseline', marginBottom: 3 }}>
        <span className="truncate" style={{ flex: 1, fontSize: 12.5 }} title={client.ip}>
          {clientName(client)}
        </span>
        <span className="num" style={{ fontSize: 11.5, color: 'var(--text-dim)' }}>{bits(total)}</span>
      </div>
      <div className="bar"><i style={{ width: `${Math.min(100, (total / max) * 100)}%` }} /></div>
    </div>
  )
}

function TopFlows({ flows }: { flows: Flow[] }) {
  if (!flows.length) return <Empty title="No traffic recorded yet" />
  return (
    <div className="table-wrap">
      <table className="t">
        <thead>
          <tr><th>Destination</th><th>App</th><th className="num">Down</th><th className="num">Up</th></tr>
        </thead>
        <tbody>
          {flows.map((f) => (
            <tr key={f.id}>
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

function EventList({ events }: { events: EventItem[] }) {
  if (!events.length) {
    return <Empty title="Nothing to report">No events in the last 24 hours.</Empty>
  }
  return (
    <div style={{ display: 'grid', gap: 9 }}>
      {events.map((e) => (
        <div key={e.id} style={{ display: 'flex', gap: 9, alignItems: 'flex-start' }}>
          <span className={`tag ${e.severity === 'critical' || e.severity === 'warning' ? 'warn' : 'info'}`}
            style={{ marginTop: 1 }}>
            {e.severity === 'critical' ? <Icons.alert size={11} /> : null}
            {e.severity}
          </span>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div className="truncate" style={{ fontSize: 12.5 }} title={e.title}>{e.title}</div>
            <div style={{ fontSize: 11, color: 'var(--text-faint)' }}>{ago(e.ts)}</div>
          </div>
        </div>
      ))}
    </div>
  )
}
