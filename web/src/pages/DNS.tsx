import { useEffect, useMemo, useState } from 'react'
import { api } from '../api'
import { usePoll, useDebounced, type LiveEvent } from '../hooks'
import { Banner, Card, Empty, Icons, Loading, Search, Segmented, Stat, useToast } from '../ui'
import { clientName, clock, compact, pct } from '../format'
import type { Client, DNSQuery } from '../types'

export function DNSPage({ events }: { events: LiveEvent[] }) {
  const [query, setQuery] = useState('')
  const [blockedOnly, setBlockedOnly] = useState(false)
  const [clientId, setClientId] = useState('')
  const [paused, setPaused] = useState(false)
  const [lookup, setLookup] = useState('')
  const [lookupResult, setLookupResult] = useState<Awaited<ReturnType<typeof api.adblock.check>> | null>(null)
  const debounced = useDebounced(query, 250)
  const toast = useToast()

  const { data: stats } = usePoll(() => api.dns.stats(), 8000)
  const { data: clients } = usePoll(() => api.clients.list(), 20000)
  const { data: log, refresh } = usePoll(
    () => api.dns.log({ hours: 2, q: debounced || undefined, blocked_only: blockedOnly, client_id: clientId || undefined, limit: 300 }),
    paused ? 0 : 6000,
    [debounced, blockedOnly, clientId, paused],
  )

  // Live queries from the socket, prepended so the log feels immediate.
  const [live, setLive] = useState<DNSQuery[]>([])
  useEffect(() => {
    if (paused) return
    const additions: DNSQuery[] = []
    for (const ev of events.slice(-60)) {
      if (ev.type !== 'dns.query') continue
      const q = ev.data as DNSQuery
      if (!q?.name) continue
      if (blockedOnly && !q.blocked) continue
      if (clientId && q.client_id !== clientId) continue
      if (debounced && !q.name.toLowerCase().includes(debounced.toLowerCase())) continue
      additions.push(q)
    }
    if (additions.length) setLive((prev) => [...additions.reverse(), ...prev].slice(0, 200))
  }, [events, paused, blockedOnly, clientId, debounced])

  const rows = useMemo(() => {
    const seen = new Set<string>()
    const out: DNSQuery[] = []
    for (const q of [...live, ...(log?.queries ?? [])]) {
      const key = `${q.id || ''}|${q.ts}|${q.name}|${q.client_ip}`
      if (seen.has(key)) continue
      seen.add(key)
      out.push(q)
    }
    return out.slice(0, 400)
  }, [live, log])

  const clientMap = useMemo(() => {
    const m = new Map<string, Client>()
    for (const c of clients?.clients ?? []) m.set(c.id, c)
    return m
  }, [clients])

  const upstreams = (stats?.upstreams as Array<Record<string, unknown>>) ?? []
  const cache = (stats?.cache as Record<string, number>) ?? {}
  const total = Number(stats?.queries ?? 0)
  const blocked = Number(stats?.blocked ?? 0)

  const runLookup = async () => {
    if (!lookup.trim()) return
    try {
      setLookupResult(await api.adblock.check(lookup.trim()))
    } catch (e) {
      toast(e instanceof Error ? e.message : 'Lookup failed', 'err')
    }
  }

  return (
    <div style={{ display: 'grid', gap: 14 }}>
      {!stats?.running && (
        <Banner tone="warn">
          The resolver is not listening. Either DNS is disabled in settings, or binding port 53
          failed — another resolver (systemd-resolved, dnsmasq) is usually the cause.
        </Banner>
      )}

      <div className="grid c4">
        <Stat label="Queries handled" value={compact(total)} tone="blue"
          sub={`${compact(Number(stats?.local ?? 0))} answered locally`} />
        <Stat label="Blocked" value={compact(blocked)} tone={blocked > 0 ? 'amber' : undefined}
          sub={total > 0 ? `${pct(blocked / total, 1)} of all queries` : '—'} />
        <Stat label="Cache hit rate" value={pct(cache.hit_rate ?? 0, 0)} tone="accent"
          sub={`${compact(cache.size ?? 0)} of ${compact(cache.capacity ?? 0)} entries`} />
        <Stat label="Collapsed" value={compact(Number(stats?.collapsed ?? 0))}
          sub="duplicate in-flight queries merged" />
      </div>

      <div className="grid c2">
        <Card title="Upstream resolvers" actions={
          <button className="btn sm" onClick={async () => {
            const n = await api.dns.flush()
            toast(`Flushed ${n.flushed} cached entries`, 'ok')
          }}>Flush cache</button>
        }>
          {upstreams.length === 0 ? <Empty title="No upstreams configured" /> : (
            <div style={{ display: 'grid', gap: 9 }}>
              {upstreams.map((u, i) => (
                <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <span className={`dot ${u.healthy ? 'on' : 'err'}`} />
                  <span className="mono truncate" style={{ flex: 1, fontSize: 12 }}>{String(u.spec)}</span>
                  <span className="tag">{String(u.kind)}</span>
                  <span className="num" style={{ fontSize: 11.5, color: 'var(--text-dim)', minWidth: 60, textAlign: 'right' }}>
                    {Number(u.latency_ms).toFixed(1)} ms
                  </span>
                  <span className="num" style={{ fontSize: 11, color: 'var(--text-faint)', minWidth: 60, textAlign: 'right' }}>
                    {compact(Number(u.queries))}
                  </span>
                </div>
              ))}
            </div>
          )}
        </Card>

        <Card title="Why is this domain blocked?">
          <div style={{ display: 'flex', gap: 8 }}>
            <input className="input" value={lookup} placeholder="example.com"
              onChange={(e) => setLookup(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && runLookup()} />
            <button className="btn" onClick={runLookup}>Check</button>
          </div>
          {lookupResult && (
            <div style={{ marginTop: 12 }}>
              <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 8 }}>
                <span className={`tag ${lookupResult.blocked ? 'block' : lookupResult.allowed ? 'allow' : ''}`}>
                  {lookupResult.blocked ? 'blocked' : lookupResult.allowed ? 'explicitly allowed' : 'not filtered'}
                </span>
                <span className="mono" style={{ fontSize: 12 }}>{lookupResult.domain}</span>
              </div>
              <div style={{ fontSize: 12.5, color: 'var(--text-dim)', marginBottom: 10 }}>
                {lookupResult.explanation}
              </div>
              <div style={{ display: 'flex', gap: 7 }}>
                {lookupResult.blocked && (
                  <button className="btn sm" onClick={async () => {
                    await api.adblock.addRule({ domain: lookupResult.domain, action: 'allow', note: 'unblocked from DNS page' })
                    await api.dns.flush(lookupResult.domain)
                    toast('Allowed. Try again now.', 'ok')
                    setLookupResult(await api.adblock.check(lookupResult.domain))
                  }}>Allow it</button>
                )}
                {!lookupResult.blocked && (
                  <button className="btn sm danger" onClick={async () => {
                    await api.adblock.addRule({ domain: lookupResult.domain, action: 'block', wildcard: true, note: 'blocked from DNS page' })
                    await api.dns.flush(lookupResult.domain)
                    toast('Blocked', 'ok')
                    setLookupResult(await api.adblock.check(lookupResult.domain))
                  }}>Block it</button>
                )}
              </div>
            </div>
          )}
        </Card>
      </div>

      <div className="toolbar" style={{ marginBottom: 0 }}>
        <Search value={query} onChange={setQuery} placeholder="Filter by domain…" />
        <Segmented value={blockedOnly ? 'blocked' : 'all'}
          onChange={(v) => setBlockedOnly(v === 'blocked')}
          options={[{ value: 'all', label: 'All' }, { value: 'blocked', label: 'Blocked only' }]} />
        <select className="select" style={{ width: 180 }} value={clientId} onChange={(e) => setClientId(e.target.value)}>
          <option value="">All devices</option>
          {(clients?.clients ?? []).map((c) => <option key={c.id} value={c.id}>{clientName(c)}</option>)}
        </select>
        <div style={{ flex: 1 }} />
        <button className="btn sm" onClick={() => setPaused((p) => !p)}>{paused ? 'Resume' : 'Pause'}</button>
        <button className="btn sm" onClick={refresh}><Icons.refresh size={13} /></button>
      </div>

      <Card flush>
        {!log ? <Loading what="queries" /> : rows.length === 0 ? (
          <Empty title="No lookups match">
            Query logging can be turned off in settings; if it is on and this is empty, nothing
            on the network is using this resolver yet.
          </Empty>
        ) : (
          <div className="table-wrap" style={{ maxHeight: 'calc(100vh - 520px)', minHeight: 240 }}>
            <table className="t">
              <thead>
                <tr>
                  <th style={{ width: 62 }}>Time</th>
                  <th>Device</th>
                  <th>Domain</th>
                  <th style={{ width: 52 }}>Type</th>
                  <th>Answer</th>
                  <th style={{ width: 88 }}>Result</th>
                  <th className="num" style={{ width: 64 }}>Latency</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((q, i) => {
                  const c = q.client_id ? clientMap.get(q.client_id) : undefined
                  return (
                    <tr key={`${q.id}-${i}`}>
                      <td className="mono" style={{ fontSize: 11, color: 'var(--text-faint)' }}>{clock(q.ts)}</td>
                      <td className="truncate" style={{ maxWidth: 140 }}>{c ? clientName(c) : q.client_ip}</td>
                      <td className="truncate mono" style={{ maxWidth: 300, fontSize: 11.5 }} title={q.name}>
                        {q.name}
                        {q.cname_chain && q.cname_chain.length > 0 && (
                          <span className="tag" style={{ marginLeft: 6 }} title={q.cname_chain.join(' → ')}>
                            CNAME
                          </span>
                        )}
                      </td>
                      <td style={{ color: 'var(--text-faint)', fontSize: 11 }}>{q.qtype}</td>
                      <td className="truncate mono" style={{ maxWidth: 200, fontSize: 11, color: 'var(--text-dim)' }}>
                        {q.answer?.slice(0, 2).join(', ') || '—'}
                      </td>
                      <td>
                        {q.blocked
                          ? <span className="tag block" title={q.block_source}>blocked</span>
                          : q.cached
                            ? <span className="tag" style={{ opacity: .65 }}>cached</span>
                            : <span className="tag" style={{ opacity: .65 }}>{q.rcode || 'ok'}</span>}
                      </td>
                      <td className="num" style={{ fontSize: 11, color: 'var(--text-faint)' }}>
                        {q.latency_ms ? `${q.latency_ms.toFixed(0)}ms` : '—'}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  )
}
