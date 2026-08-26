import { useEffect, useMemo, useState } from 'react'
import { api } from '../api'
import { usePoll, useDebounced, useLocalStorage, type LiveEvent } from '../hooks'
import { Card, Empty, Icons, Loading, Search, Segmented, useToast } from '../ui'
import { ago, bytes, clientName, clock, countryFlag, flowTarget, riskColor } from '../format'
import type { Client, Flow } from '../types'

type View = 'live' | 'history'

/** The connection log. Little Snitch's list view, but for the whole network:
 *  every row is one connection with who asked for it and where it went. */
export function FlowsPage({ events }: { events: LiveEvent[] }) {
  const [view, setView] = useLocalStorage<View>('orbis.flows.view', 'live')
  const [query, setQuery] = useState('')
  const [verdict, setVerdict] = useLocalStorage<string>('orbis.flows.verdict', '')
  const [clientId, setClientId] = useState('')
  const [hours, setHours] = useLocalStorage<number>('orbis.flows.hours', 24)
  const [paused, setPaused] = useState(false)
  const [selected, setSelected] = useState<Flow | null>(null)
  const debounced = useDebounced(query, 250)
  const toast = useToast()

  const { data: clients } = usePoll(() => api.clients.list(), 20000)
  const { data: historyData, refresh } = usePoll(
    () => api.flows.list({ hours, q: debounced || undefined, verdict: verdict || undefined, client_id: clientId || undefined, limit: 400 }),
    view === 'history' ? 15000 : 0,
    [hours, debounced, verdict, clientId, view],
  )
  const { data: activeData } = usePoll(
    () => api.flows.active(600),
    view === 'live' && !paused ? 3000 : 0,
    [view, paused],
  )

  // Live rows arriving over the socket are merged in so the list updates
  // between polls; pausing freezes it so a row can actually be read.
  const [liveFlows, setLiveFlows] = useState<Map<string, Flow>>(new Map())
  useEffect(() => {
    if (view !== 'live' || paused) return
    let changed = false
    const next = new Map(liveFlows)
    for (const ev of events.slice(-120)) {
      if (ev.type === 'flow.new' || ev.type === 'flow.update') {
        const f = ev.data as Flow
        if (f?.id) { next.set(f.id, f); changed = true }
      } else if (ev.type === 'flow.close') {
        const f = ev.data as Flow
        if (f?.id && next.has(f.id)) { next.set(f.id, f); changed = true }
      }
    }
    if (changed) {
      // Bound the map so a long session does not accumulate every flow ever.
      if (next.size > 1500) {
        const trimmed = [...next.entries()].slice(-1000)
        setLiveFlows(new Map(trimmed))
      } else {
        setLiveFlows(next)
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [events, view, paused])

  const rows = useMemo(() => {
    if (view === 'history') return historyData?.flows ?? []
    const merged = new Map<string, Flow>()
    for (const f of activeData?.flows ?? []) merged.set(f.id, f)
    for (const [id, f] of liveFlows) merged.set(id, f)
    let list = [...merged.values()]
    const q = debounced.toLowerCase()
    if (q) {
      list = list.filter((f) =>
        [f.hostname, f.sni, f.dst_ip, f.as_org, f.app, f.src_ip].filter(Boolean).join(' ').toLowerCase().includes(q))
    }
    if (verdict) list = list.filter((f) => f.verdict === verdict)
    if (clientId) list = list.filter((f) => f.client_id === clientId)
    return list.sort((a, b) => new Date(b.last_seen).getTime() - new Date(a.last_seen).getTime()).slice(0, 500)
  }, [view, historyData, activeData, liveFlows, debounced, verdict, clientId])

  const clientMap = useMemo(() => {
    const m = new Map<string, Client>()
    for (const c of clients?.clients ?? []) m.set(c.id, c)
    return m
  }, [clients])

  const block = async (flow: Flow) => {
    try {
      await api.flows.block(flow.id)
      toast(`Blocked ${flowTarget(flow)}`, 'ok')
    } catch (e) {
      toast(e instanceof Error ? e.message : 'Could not block', 'err')
    }
  }

  return (
    <>
      <div className="toolbar">
        <Segmented value={view} onChange={setView}
          options={[{ value: 'live', label: 'Live' }, { value: 'history', label: 'History' }]} />
        <Search value={query} onChange={setQuery} placeholder="Search host, IP, app or network…" />
        <select className="select" style={{ width: 130 }} value={verdict} onChange={(e) => setVerdict(e.target.value)}>
          <option value="">Any verdict</option>
          <option value="allow">Allowed</option>
          <option value="block">Blocked</option>
          <option value="filtered">Filtered</option>
        </select>
        <select className="select" style={{ width: 180 }} value={clientId} onChange={(e) => setClientId(e.target.value)}>
          <option value="">All devices</option>
          {(clients?.clients ?? []).map((c) => <option key={c.id} value={c.id}>{clientName(c)}</option>)}
        </select>
        {view === 'history' && (
          <Segmented value={String(hours)} onChange={(v) => setHours(Number(v))}
            options={[{ value: '1', label: '1h' }, { value: '24', label: '24h' },
                      { value: '168', label: '7d' }, { value: '720', label: '30d' }]} />
        )}
        <div style={{ flex: 1 }} />
        {view === 'live' ? (
          <button className="btn sm" onClick={() => setPaused((p) => !p)}>
            {paused ? 'Resume' : 'Pause'}
          </button>
        ) : (
          <button className="btn sm" onClick={refresh}><Icons.refresh size={13} /> Refresh</button>
        )}
        <span className="tag">{rows.length} shown</span>
      </div>

      <Card flush>
        {!historyData && !activeData ? <Loading what="connections" /> : rows.length === 0 ? (
          <Empty title="No connections match">
            {view === 'live'
              ? 'Nothing is open right now that matches these filters.'
              : 'Try widening the time window or clearing the filters.'}
          </Empty>
        ) : (
          <div className="table-wrap" style={{ maxHeight: 'calc(100vh - 210px)' }}>
            <table className="t">
              <thead>
                <tr>
                  <th style={{ width: 62 }}>Time</th>
                  <th>Device</th>
                  <th>Destination</th>
                  <th>App</th>
                  <th className="num">Port</th>
                  <th className="num">Down</th>
                  <th className="num">Up</th>
                  <th style={{ width: 78 }}>Verdict</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((f) => {
                  const c = f.client_id ? clientMap.get(f.client_id) : undefined
                  return (
                    <tr key={f.id} className="clickable" onClick={() => setSelected(f)}>
                      <td className="mono" style={{ fontSize: 11, color: 'var(--text-faint)' }}>
                        {clock(f.started_at)}
                      </td>
                      <td className="truncate" style={{ maxWidth: 150 }}>
                        {c ? clientName(c) : f.src_ip}
                      </td>
                      <td className="truncate" style={{ maxWidth: 260 }} title={`${flowTarget(f)} (${f.dst_ip})`}>
                        {f.country && <span style={{ marginRight: 6 }}>{countryFlag(f.country)}</span>}
                        {flowTarget(f)}
                        {f.risk > 0.4 && (
                          <span style={{ marginLeft: 6, color: riskColor(f.risk), fontSize: 10 }}>●</span>
                        )}
                      </td>
                      <td className="truncate" style={{ maxWidth: 130, color: 'var(--text-dim)' }}>
                        {f.app || f.as_org || '—'}
                      </td>
                      <td className="num" style={{ color: 'var(--text-faint)' }}>{f.dst_port}</td>
                      <td className="num">{bytes(f.bytes_in)}</td>
                      <td className="num">{bytes(f.bytes_out)}</td>
                      <td>
                        <span className={`tag ${f.verdict}`}>{f.verdict}</span>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {selected && (
        <FlowDetail
          flow={selected}
          client={selected.client_id ? clientMap.get(selected.client_id) : undefined}
          onClose={() => setSelected(null)}
          onBlock={() => block(selected)}
        />
      )}
    </>
  )
}

function FlowDetail({ flow, client, onClose, onBlock }: {
  flow: Flow; client?: Client; onClose: () => void; onBlock: () => void
}) {
  const [check, setCheck] = useState<string | null>(null)
  const host = flow.hostname || flow.sni

  useEffect(() => {
    if (!host) return
    api.adblock.check(host).then((r) => setCheck(r.explanation)).catch(() => setCheck(null))
  }, [host])

  return (
    <>
      <div className="scrim" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-modal="true">
        <header className="drawer-head">
          <span className={`tag ${flow.verdict}`}>{flow.verdict}</span>
          <h2 style={{ flex: 1, fontSize: 13.5 }} className="truncate">{flowTarget(flow)}</h2>
          <button className="btn icon" onClick={onClose} aria-label="Close"><Icons.close /></button>
        </header>
        <div className="drawer-body" style={{ display: 'grid', gap: 14 }}>
          <dl className="kv">
            <dt>Device</dt><dd>{client ? clientName(client) : flow.src_ip}</dd>
            <dt>Source</dt><dd>{flow.src_ip}:{flow.src_port}</dd>
            <dt>Destination</dt><dd>{flow.dst_ip}:{flow.dst_port}</dd>
            {flow.hostname && <><dt>Hostname</dt><dd>{flow.hostname}</dd></>}
            {flow.sni && flow.sni !== flow.hostname && <><dt>TLS SNI</dt><dd>{flow.sni}</dd></>}
            <dt>Protocol</dt><dd>{flow.proto}</dd>
            {flow.app && <><dt>Application</dt><dd>{flow.app}</dd></>}
            {flow.as_org && <><dt>Network</dt><dd>AS{flow.asn} {flow.as_org}</dd></>}
            {flow.country && (
              <><dt>Location</dt><dd>{countryFlag(flow.country)} {flow.city || ''} {flow.country}</dd></>
            )}
            {flow.ja4 && <><dt>TLS fingerprint</dt><dd style={{ fontSize: 11 }}>{flow.ja4}</dd></>}
            <dt>Started</dt><dd>{ago(flow.started_at)}</dd>
            <dt>Status</dt><dd>{flow.ended_at ? `closed ${ago(flow.ended_at)}` : 'open'}</dd>
            <dt>Transferred</dt>
            <dd>{bytes(flow.bytes_in)} down · {bytes(flow.bytes_out)} up
              ({flow.packets_in + flow.packets_out} packets)</dd>
            {flow.reason && <><dt>Reason</dt><dd>{flow.reason}</dd></>}
            {flow.risk > 0 && <><dt>Risk</dt><dd style={{ color: riskColor(flow.risk) }}>{flow.risk.toFixed(2)}</dd></>}
          </dl>

          {check && (
            <Card title="Filter status">
              <div style={{ fontSize: 12.5, color: 'var(--text-dim)' }}>{check}</div>
            </Card>
          )}

          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            {!flow.ended_at && flow.verdict === 'allow' && (
              <button className="btn danger" onClick={onBlock}>Kill this connection</button>
            )}
            {host && (
              <button className="btn" onClick={async () => {
                await api.adblock.addRule({ domain: host, action: 'block', wildcard: true, note: 'from connection detail' })
                await api.dns.flush(host)
              }}>
                Block {host}
              </button>
            )}
            {host && (
              <button className="btn" onClick={async () => {
                await api.adblock.addRule({ domain: host, action: 'allow', note: 'from connection detail' })
                await api.dns.flush(host)
              }}>
                Always allow {host}
              </button>
            )}
          </div>
        </div>
      </aside>
    </>
  )
}
