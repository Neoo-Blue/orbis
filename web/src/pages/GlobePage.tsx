import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { api } from '../api'
import { usePoll, useLocalStorage, type LiveEvent } from '../hooks'
import { Globe } from '../globe/Globe'
import { FlatMap } from '../globe/FlatMap'
import { Banner, Icons, Segmented, useToast } from '../ui'
import { bytes, clientName, countryFlag, compact, flowTarget } from '../format'
import type { Client, Flow, GlobeArc } from '../types'

type ViewMode = 'live' | 'history'
type Projection = 'globe' | 'flat'

/**
 * The globe view. This is the page the product is built around: every arc is
 * one connection leaving (or entering) the network, coloured by verdict, and
 * the ticker underneath is the running log of what just happened.
 */
export function GlobePage({ events }: { events: LiveEvent[] }) {
  const [mode, setMode] = useLocalStorage<ViewMode>('orbis.globe.mode', 'live')
  const [hours, setHours] = useLocalStorage<number>('orbis.globe.hours', 24)
  const [clientFilter, setClientFilter] = useState<string>('')
  const [projection, setProjection] = useLocalStorage<Projection>('orbis.globe.projection', 'globe')
  const [autoRotate, setAutoRotate] = useState(true)
  const [selected, setSelected] = useState<GlobeArc | null>(null)
  const [focus, setFocus] = useState<{ lat: number; lng: number } | null>(null)
  const toast = useToast()

  const { data: globeData } = usePoll(
    () => api.flows.globe({ mode, hours, limit: 500, client_id: clientFilter || undefined }),
    mode === 'live' ? 4000 : 30000,
    [mode, hours, clientFilter],
  )
  const { data: clients } = usePoll(() => api.clients.list({ online_only: true }), 20000)

  // Live arcs: new flows arriving on the socket are rendered immediately
  // rather than waiting for the next poll, which is what makes the view feel
  // like an instrument instead of a dashboard.
  const [liveArcs, setLiveArcs] = useState<GlobeArc[]>([])
  const [ticker, setTicker] = useState<Array<{ id: string; text: string; verdict: string }>>([])
  const homeRef = useRef(globeData?.home)
  homeRef.current = globeData?.home ?? homeRef.current
  const seenIds = useRef(new Set<string>())

  useEffect(() => {
    if (mode !== 'live') return
    const home = homeRef.current
    if (!home) return

    const additions: GlobeArc[] = []
    const tickerAdds: Array<{ id: string; text: string; verdict: string }> = []
    const closedIds: string[] = []

    for (const ev of events.slice(-80)) {
      if (ev.type === 'flow.close') {
        const f = ev.data as Flow
        closedIds.push(f.id)
        continue
      }
      if (ev.type !== 'flow.new' && ev.type !== 'flow.update') continue
      const f = ev.data as Flow
      if (!f || (!f.lat && !f.lon)) continue
      if (clientFilter && f.client_id !== clientFilter) continue

      additions.push({
        id: f.id, client_id: f.client_id,
        start_lat: home.lat, start_lng: home.lng,
        end_lat: f.lat, end_lng: f.lon,
        label: flowTarget(f), app: f.app, country: f.country, city: f.city,
        org: f.as_org, verdict: f.verdict, bytes: f.bytes_in + f.bytes_out,
        port: f.dst_port, proto: f.proto, risk: f.risk,
        direction: f.direction, bytes_in: f.bytes_in, bytes_out: f.bytes_out,
        started: Math.floor(new Date(f.started_at).getTime() / 1000),
        active: !f.ended_at, src: f.src_ip, dst: f.dst_ip,
      })
      if (ev.type === 'flow.new' && !seenIds.current.has(f.id)) {
        seenIds.current.add(f.id)
        tickerAdds.push({ id: f.id, text: `${flowTarget(f)}:${f.dst_port}`, verdict: f.verdict })
      }
    }

    if (additions.length || closedIds.length) {
      setLiveArcs((prev) => {
        const map = new Map(prev.map((a) => [a.id, a]))
        for (const a of additions) map.set(a.id, a)
        for (const id of closedIds) map.delete(id)
        // Bound the live overlay: beyond a few hundred arcs the globe is a
        // solid ball of light and tells you nothing.
        const arr = [...map.values()]
        return arr.length > 600 ? arr.slice(-500) : arr
      })
    }
    if (tickerAdds.length) {
      setTicker((prev) => [...prev, ...tickerAdds].slice(-40))
    }
    // Keep the id set from growing without bound over a long session.
    if (seenIds.current.size > 5000) seenIds.current = new Set()
  }, [events, mode, clientFilter])

  useEffect(() => {
    // Switching to history clears the live overlay so the two never blend.
    if (mode === 'history') {
      setLiveArcs([])
      setTicker([])
    }
  }, [mode])

  const arcs = globeData?.arcs ?? []
  const stats = useMemo(() => {
    const all = mode === 'live' ? [...arcs, ...liveArcs] : arcs
    const uniq = new Map(all.map((a) => [a.id, a]))
    const list = [...uniq.values()]
    const countries = new Set(list.map((a) => a.country).filter(Boolean))
    const blocked = list.filter((a) => a.verdict === 'block').length
    const totalBytes = list.reduce((sum, a) => sum + a.bytes, 0)
    return { count: list.length, countries: countries.size, blocked, totalBytes }
  }, [arcs, liveArcs, mode])

  // A node behind NAT cannot know where it is from its own interfaces. When
  // the home point is still the timezone fallback, say so rather than quietly
  // drawing every arc from the wrong continent.
  const { data: status, refresh: refreshStatus } = usePoll(() => api.status(), 30000)
  const [locating, setLocating] = useState(false)
  const self = (status as unknown as { self?: Record<string, unknown> } | null)?.self
  const homeIsGuessed = Boolean(status) && !self?.public_ip

  const locateSelf = async () => {
    setLocating(true)
    try {
      const r = await api.locateSelf()
      const s = r.self as Record<string, unknown>
      toast(s.city ? `Located: ${s.city}, ${s.country}` : 'Public address located', 'ok')
      refreshStatus()
    } catch (e) {
      toast(e instanceof Error ? e.message : 'Could not determine the public address', 'err')
    } finally {
      setLocating(false)
    }
  }

  const onSelect = useCallback((arc: GlobeArc | null) => {
    setSelected(arc)
    if (arc) setAutoRotate(false)
  }, [])

  const blockFlow = async (arc: GlobeArc) => {
    try {
      await api.flows.block(arc.id)
      toast(`Blocked the connection to ${arc.label}`, 'ok')
    } catch (e) {
      toast(e instanceof Error ? e.message : 'Could not block that connection', 'err')
    }
  }

  return (
    <div className="globe-stage">
      {projection === 'globe' ? (
        <Globe
          data={globeData ?? null}
          liveArcs={mode === 'live' ? liveArcs : []}
          onSelect={onSelect}
          focus={focus}
          autoRotate={autoRotate}
        />
      ) : (
        <FlatMap
          data={globeData ?? null}
          liveArcs={mode === 'live' ? liveArcs : []}
          onSelect={onSelect}
          autoAnimate={autoRotate}
        />
      )}

      <div className="globe-overlay">
        {homeIsGuessed && (
          <div style={{ maxWidth: 520, marginBottom: 10, flex: 'none' }}>
            <Banner tone="info" action={
              <button className="btn sm" onClick={locateSelf} disabled={locating}>
                {locating ? 'Locating…' : 'Locate me'}
              </button>
            }>
              This node is placed from its timezone, not its real position. Let Orbis look up its
              own public address to fix that, or set coordinates in Settings.
            </Banner>
          </div>
        )}
        <div style={{ display: 'flex', gap: 10, alignItems: 'flex-start', flexWrap: 'wrap', flex: 'none' }}>
          <div className="globe-legend">
            <span><i style={{ background: 'var(--accent)' }} />allowed</span>
            <span><i style={{ background: 'var(--red)' }} />blocked</span>
            <span><i style={{ background: 'var(--violet)' }} />filtered</span>
            <span><i style={{ background: 'var(--blue)' }} />this network</span>
            <span><i style={{ background: 'var(--amber)' }} />inbound</span>
          </div>
        </div>

        <div className="globe-hud">
          <Segmented
            value={projection}
            onChange={(v) => setProjection(v)}
            options={[{ value: 'globe', label: 'Globe' }, { value: 'flat', label: 'Flat' }]}
          />
          <Segmented
            value={mode}
            onChange={(v) => setMode(v)}
            options={[{ value: 'live', label: 'Live' }, { value: 'history', label: 'History' }]}
          />
          {mode === 'history' && (
            <Segmented
              value={String(hours)}
              onChange={(v) => setHours(Number(v))}
              options={[
                { value: '1', label: '1h' }, { value: '24', label: '24h' },
                { value: '168', label: '7d' }, { value: '720', label: '30d' },
              ]}
            />
          )}
          <select className="select" style={{ width: 190 }} value={clientFilter}
            onChange={(e) => setClientFilter(e.target.value)}>
            <option value="">All devices</option>
            {(clients?.clients ?? []).map((c: Client) => (
              <option key={c.id} value={c.id}>{clientName(c)}</option>
            ))}
          </select>
          <div style={{ display: 'flex', gap: 6 }}>
            <button className="btn sm" onClick={() => setAutoRotate((v) => !v)}
              title={projection === 'globe'
                ? (autoRotate ? 'Pause rotation' : 'Resume rotation')
                : (autoRotate ? 'Pause the animation' : 'Resume the animation')}>
              {autoRotate ? 'Pause' : projection === 'globe' ? 'Rotate' : 'Animate'}
            </button>
            <button className="btn sm" onClick={() => { setFocus(null); setSelected(null); setAutoRotate(true) }}>
              Reset
            </button>
          </div>

          <div className="globe-legend" style={{ flexDirection: 'column', alignItems: 'flex-end', gap: 2 }}>
            <span>{compact(stats.count)} connections</span>
            <span>{stats.countries} countries</span>
            <span>{bytes(stats.totalBytes)} moved</span>
            {stats.blocked > 0 && <span style={{ color: 'var(--red)' }}>{stats.blocked} blocked</span>}
          </div>
        </div>

        {mode === 'live' && ticker.length > 0 && (
          <div className="globe-ticker">
            {ticker.slice().reverse().map((t) => (
              <div key={t.id} className="ticker-row">
                <span className={`dot ${t.verdict === 'block' ? 'err' : 'on'}`} />
                <span className="truncate">{t.text}</span>
              </div>
            ))}
          </div>
        )}

        {globeData?.countries && globeData.countries.length > 0 && (
          <CountryPanel
            countries={globeData.countries}
            onFocus={(lat, lng) => { setFocus({ lat, lng }); setAutoRotate(false) }}
          />
        )}
      </div>

      {selected && (
        <ArcDetail arc={selected} onClose={() => setSelected(null)} onBlock={() => blockFlow(selected)} />
      )}
    </div>
  )
}

function CountryPanel({ countries, onFocus }: {
  countries: Array<{ country: string; connections: number; bytes: number; blocked: number; lat: number; lon: number }>
  onFocus: (lat: number, lng: number) => void
}) {
  const top = countries.slice(0, 8)
  const max = Math.max(...top.map((c) => c.bytes), 1)
  return (
    <div className="globe-country-panel">
      <div style={{
        fontSize: 10, letterSpacing: '.11em', textTransform: 'uppercase',
        color: 'var(--text-faint)', fontWeight: 600, marginBottom: 8,
      }}>
        Where traffic goes
      </div>
      <div style={{ display: 'grid', gap: 7 }}>
        {top.map((c) => (
          <button key={c.country} onClick={() => onFocus(c.lat, c.lon)}
            style={{ background: 'none', border: 0, padding: 0, cursor: 'pointer', textAlign: 'left', color: 'inherit' }}>
            <div style={{ display: 'flex', gap: 7, alignItems: 'baseline', fontSize: 11.5, marginBottom: 2 }}>
              <span>{countryFlag(c.country)}</span>
              <span style={{ flex: 1 }}>{c.country}</span>
              <span className="num" style={{ color: 'var(--text-dim)', fontSize: 10.5 }}>{bytes(c.bytes)}</span>
            </div>
            <div className="bar" style={{ height: 3 }}>
              <i className={c.blocked > c.connections * 0.3 ? 'red' : undefined}
                style={{ width: `${(c.bytes / max) * 100}%` }} />
            </div>
          </button>
        ))}
      </div>
    </div>
  )
}

function ArcDetail({ arc, onClose, onBlock }: { arc: GlobeArc; onClose: () => void; onBlock: () => void }) {
  return (
    <div className="globe-detail">
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '10px 13px', borderBottom: '1px solid var(--line-soft)' }}>
        <span className={`tag ${arc.verdict}`}>{arc.verdict}</span>
        <span className={`tag ${arc.direction === 'in' ? 'warn' : ''}`}>
          {arc.direction === 'in' ? '← inbound' : '→ outbound'}
        </span>
        <div className="spacer" style={{ flex: 1 }} />
        <button className="btn icon" onClick={onClose} aria-label="Close"><Icons.close /></button>
      </div>
      <div style={{ padding: 13 }}>
        <div className="mono" style={{ color: 'var(--accent)', wordBreak: 'break-all', marginBottom: 9 }}>
          {arc.label}
        </div>
        <dl className="kv">
          <dt>Address</dt><dd>{arc.dst}:{arc.port}</dd>
          <dt>Protocol</dt><dd>{arc.proto}</dd>
          {arc.app && <><dt>Application</dt><dd>{arc.app}</dd></>}
          {arc.org && <><dt>Network</dt><dd>{arc.org}</dd></>}
          {arc.country && (
            <><dt>Location</dt><dd>{countryFlag(arc.country)} {arc.city || arc.country}</dd></>
          )}
          <dt>Received</dt><dd>{bytes(arc.bytes_in ?? 0)}</dd>
          <dt>Sent</dt><dd>{bytes(arc.bytes_out ?? 0)}</dd>
          <dt>From</dt><dd>{arc.src}</dd>
        </dl>
        {arc.active && arc.verdict === 'allow' && (
          <button className="btn danger sm" style={{ marginTop: 12, width: '100%' }} onClick={onBlock}>
            Block this connection
          </button>
        )}
      </div>
    </div>
  )
}
