import { useEffect, useMemo, useRef, useState } from 'react'
import { api } from '../api'
import { usePoll } from '../hooks'
import { Banner, Card, Dot, Empty, Icons, Loading } from '../ui'
import type {
  NetwatchIncident,
  NetwatchPoint,
  NetwatchState,
  NetwatchTarget,
} from '../types'
import './InternetHealth.css'

type WindowHours = 1 | 6 | 24

const WINDOW_OPTIONS: Array<{ hours: WindowHours; label: string }> = [
  { hours: 1, label: '1 h' },
  { hours: 6, label: '6 h' },
  { hours: 24, label: '24 h' },
]

export function InternetHealthPage() {
  const [windowHours, setWindowHours] = useState<WindowHours>(1)

  const {
    data: status,
    error: statusError,
    loading: statusLoading,
    refresh: refreshStatus,
  } = usePoll(() => api.netwatch.status(), 10000)

  const {
    data: history,
    error: historyError,
    refresh: refreshHistory,
  } = usePoll(() => api.netwatch.history(windowHours), 10000, [windowHours])

  const refreshAll = () => {
    refreshStatus()
    refreshHistory()
  }

  const seriesByTarget = useMemo(() => {
    const map = new Map<string, NetwatchPoint[]>()
    for (const s of history?.targets ?? []) {
      map.set(s.id, s.points ?? [])
    }
    return map
  }, [history])

  if (!status && statusLoading) {
    return (
      <div className="nw-page">
        <Card title="Internet health">
          <Loading what="internet health probes" />
          <p className="nw-teach-note">
            Orbis probes your local default gateway and three independent public networks
            (1.1.1.1, 8.8.8.8, and 9.9.9.9) every 10 seconds. Comparing your router against
            outside targets separates LAN trouble from an internet provider outage.
          </p>
        </Card>
      </div>
    )
  }

  const errMsg = statusError || historyError
  if (!status) {
    return (
      <div className="nw-page">
        {errMsg && (
          <Banner
            tone="err"
            action={
              <button type="button" className="btn sm nw-refresh-btn" onClick={refreshAll}>
                <Icons.refresh size={14} /> Retry
              </button>
            }
          >
            Could not load internet health status: {errMsg}. If this node is on your LAN,
            check the local connection between your browser and Orbis.
          </Banner>
        )}
        <Card title="Internet health">
          <Empty title="Waiting for health monitor">
            Orbis tests your default gateway and Cloudflare, Google, and Quad9 every 10 seconds
            once the background monitor answers.
          </Empty>
        </Card>
      </div>
    )
  }

  const warmingUp = status.rounds === 0
  const targets = status.targets ?? []
  const incidents = status.incidents ?? []
  const windowIncidents = history?.incidents ?? incidents
  const nowSec = Math.floor(Date.now() / 1000)
  const fromSec = history?.from ?? nowSec - windowHours * 3600
  const toSec = history?.to ?? nowSec
  const gw = targets.find((t) => t.role === 'gateway')

  return (
    <div className="nw-page">
      {errMsg && (
        <Banner
          tone="err"
          action={
            <button type="button" className="btn sm nw-refresh-btn" onClick={refreshAll}>
              <Icons.refresh size={14} /> Retry
            </button>
          }
        >
          Live refresh failed ({errMsg}). Showing the last snapshot received from this node.
        </Banner>
      )}

      <section className={`nw-verdict ${status.state}`} aria-live="polite">
        <div className="nw-verdict-main">
          <div className="nw-verdict-title-row">
            <Dot state={dotForState(status.state)} label={stateLabel(status.state)} />
            <h2 className="nw-verdict-sentence">{status.headline}</h2>
            <span className={`nw-blame-pill ${status.state}`}>
              {status.blame ? `Fault: ${status.blame}` : `Every ${status.interval_seconds}s`}
            </span>
          </div>
          <p className="nw-verdict-detail">{status.detail}</p>
        </div>

        <div className="nw-controls">
          <div className="nw-window-group" role="group" aria-label="Timeline window">
            {WINDOW_OPTIONS.map((opt) => (
              <button
                key={opt.hours}
                type="button"
                className="nw-window-btn"
                aria-pressed={windowHours === opt.hours}
                onClick={() => setWindowHours(opt.hours)}
              >
                {opt.label}
              </button>
            ))}
          </div>
          <button
            type="button"
            className="btn icon nw-refresh-btn"
            onClick={refreshAll}
            aria-label="Refresh internet health"
            title="Refresh now"
          >
            <Icons.refresh size={15} />
          </button>
        </div>
      </section>

      {warmingUp && (
        <Banner tone="info">
          First 10-second probe round is running. Latency, jitter, and packet loss appear as
          soon as the first replies return, and each target builds its own 24-hour baseline
          automatically.
        </Banner>
      )}

      <Card
        title="Targets"
        flush
        actions={
          <div className="nw-legend" aria-hidden="true">
            <span className="nw-legend-item">
              <i className="nw-legend-swatch" /> latency
            </span>
            <span className="nw-legend-item">
              <i className="nw-legend-swatch loss" /> packet loss
            </span>
            <span className="nw-legend-item">
              <i className="nw-legend-swatch incident" /> outage
            </span>
          </div>
        }
      >
        {targets.length === 0 ? (
          <Empty title="No probe targets configured">
            Orbis monitors your kernel default gateway alongside 1.1.1.1, 8.8.8.8, and 9.9.9.9
            every 10 seconds to isolate where packets stop.
          </Empty>
        ) : (
          <div className="nw-targets">
            {targets.map((target) => (
              <TargetRow
                key={target.id}
                target={target}
                points={seriesByTarget.get(target.id) ?? []}
                incidents={windowIncidents}
                from={fromSec}
                to={toSec}
                windowHours={windowHours}
                warmingUp={warmingUp}
              />
            ))}
          </div>
        )}
      </Card>

      <Card
        title="Outage incidents"
        flush
        actions={
          incidents.length > 0 ? (
            <span className="nw-role-tag">{incidents.length} recorded</span>
          ) : undefined
        }
      >
        {incidents.length === 0 ? (
          <Empty title="No outages recorded">
            An outage incident opens only when Cloudflare, Google, and Quad9 all fail for three
            consecutive 10-second rounds (30 seconds), and closes on the first reply. Isolated
            single-target drops appear as marks on that target&apos;s timeline above without
            triggering a false alarm.
          </Empty>
        ) : (
          <div className="nw-incidents">
            {incidents.map((inc) => (
              <IncidentRow key={inc.id} incident={inc} />
            ))}
          </div>
        )}
      </Card>
    </div>
  )
}

function TargetRow({
  target,
  points,
  incidents,
  from,
  to,
  windowHours,
  warmingUp,
}: {
  target: NetwatchTarget
  points: NetwatchPoint[]
  incidents: NetwatchIncident[]
  from: number
  to: number
  windowHours: WindowHours
  warmingUp: boolean
}) {
  const hasSamples = !warmingUp && target.samples_24h > 0
  const addrLabel =
    target.role === 'gateway'
      ? target.address
        ? target.interface
          ? `${target.address} via ${target.interface}`
          : target.address
        : 'no default route'
      : target.address

  const latencyTone = !hasSamples
    ? ''
    : !target.last_ok || target.state === 'down'
      ? 'bad'
      : target.state === 'degraded' && target.loss_percent <= 2
        ? 'warn'
        : 'good'

  const lossTone = !hasSamples
    ? ''
    : target.loss_percent >= 100 || target.state === 'down'
      ? 'bad'
      : target.loss_percent > 2
        ? 'warn'
        : ''

  return (
    <div className="nw-target-row">
      <div className="nw-target-ident">
        <div className="nw-target-name-line">
          <Dot state={dotForState(target.state)} label={`${target.name}: ${stateLabel(target.state)}`} />
          <span className="nw-target-name">{target.name}</span>
          <span className="nw-role-tag">{target.role === 'gateway' ? 'LAN hop' : 'Public'}</span>
        </div>
        <div className="nw-target-addr" title={addrLabel}>
          {addrLabel}
        </div>
      </div>

      <div className="nw-metrics">
        <div className="nw-metric">
          <span className="nw-metric-label">Latency</span>
          <span className={`nw-metric-val ${latencyTone}`}>
            {!hasSamples ? '--' : target.last_ok ? formatMS(target.current_ms) : 'Lost'}
          </span>
          <span className="nw-metric-sub">
            {hasSamples && target.p50_ms > 0
              ? `p50 ${formatMS(target.p50_ms)}`
              : '5m median'}
          </span>
        </div>

        <div className="nw-metric">
          <span className="nw-metric-label">Jitter</span>
          <span className="nw-metric-val">
            {!hasSamples ? '--' : formatMS(target.jitter_ms)}
          </span>
          <span className="nw-metric-sub">
            {hasSamples && target.median_24h_ms > 0
              ? `24h ${formatMS(target.median_24h_ms)}`
              : '5m mean diff'}
          </span>
        </div>

        <div className="nw-metric">
          <span className="nw-metric-label">Loss</span>
          <span className={`nw-metric-val ${lossTone}`}>
            {!hasSamples ? '--' : formatPct(target.loss_percent)}
          </span>
          <span className="nw-metric-sub">last 5m</span>
        </div>
      </div>

      <TargetTimelineCanvas
        targetName={target.name}
        state={target.state}
        median24h={target.median_24h_ms}
        points={points}
        incidents={incidents}
        from={from}
        to={to}
        windowHours={windowHours}
      />
    </div>
  )
}

function TargetTimelineCanvas({
  targetName,
  state,
  median24h,
  points,
  incidents,
  from,
  to,
  windowHours,
}: {
  targetName: string
  state: NetwatchState
  median24h: number
  points: NetwatchPoint[]
  incidents: NetwatchIncident[]
  from: number
  to: number
  windowHours: WindowHours
}) {
  const boxRef = useRef<HTMLDivElement>(null)
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const drawnSigRef = useRef<string>('')
  const [size, setSize] = useState<{ w: number; h: number }>({ w: 0, h: 0 })

  useEffect(() => {
    const el = boxRef.current
    if (!el) return
    const update = () => {
      const rect = el.getBoundingClientRect()
      const w = Math.round(rect.width)
      const h = Math.round(rect.height)
      setSize((prev) => (prev.w === w && prev.h === h ? prev : { w, h }))
    }
    update()
    if (typeof ResizeObserver === 'undefined') return
    const ro = new ResizeObserver(update)
    ro.observe(el)
    return () => ro.disconnect()
  }, [])

  const peakMS = useMemo(() => {
    let peak = 0
    for (const p of points) {
      if (p.ms > peak) peak = p.ms
    }
    return peak
  }, [points])

  const dataSig = useMemo(() => {
    let ptsHash = `${points.length}:`
    for (let i = 0; i < points.length; i++) {
      const p = points[i]
      ptsHash += `${p.t},${p.ms},${p.loss ? 1 : 0};`
    }
    let incHash = `${incidents.length}:`
    for (let i = 0; i < incidents.length; i++) {
      const inc = incidents[i]
      incHash += `${inc.id},${inc.started_at},${inc.ended_at ?? ''};`
    }
    return `${from}|${to}|${state}|${median24h}|${ptsHash}|${incHash}`
  }, [from, to, state, median24h, points, incidents])

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas || size.w <= 0 || size.h <= 0) return

    const dpr = Math.min(2, window.devicePixelRatio || 1)
    const sig = `${size.w}x${size.h}@${dpr}|${dataSig}`
    if (drawnSigRef.current === sig) return
    drawnSigRef.current = sig

    const bw = Math.round(size.w * dpr)
    const bh = Math.round(size.h * dpr)
    if (canvas.width !== bw || canvas.height !== bh) {
      canvas.width = bw
      canvas.height = bh
    }

    const ctx = canvas.getContext('2d')
    if (!ctx) return

    ctx.setTransform(1, 0, 0, 1, 0, 0)
    ctx.clearRect(0, 0, bw, bh)
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0)

    const cs = getComputedStyle(canvas)
    const colLine = cs.getPropertyValue('--line').trim()
    const colTextDim = cs.getPropertyValue('--text-dim').trim()
    const colAccent = cs.getPropertyValue('--accent').trim()
    const colGreen = cs.getPropertyValue('--green').trim() || colAccent
    const colAmber = cs.getPropertyValue('--amber').trim()
    const colRed = cs.getPropertyValue('--red').trim()

    const W = size.w
    const H = size.h
    const padX = 2
    const padTop = 6
    const padBottom = 6
    const plotW = Math.max(8, W - padX * 2)
    const plotH = Math.max(8, H - padTop - padBottom)
    const span = Math.max(1, to - from)
    const scaleMax = Math.max(10, median24h * 2.2, peakMS * 1.15)

    const xOf = (tSec: number) => {
      const clamped = Math.max(from, Math.min(to, tSec))
      return padX + ((clamped - from) / span) * plotW
    }
    const yOf = (ms: number) => {
      const clamped = Math.max(0, Math.min(scaleMax, ms))
      return padTop + (1 - clamped / scaleMax) * plotH
    }

    // 1. Shaded incident spans across the window.
    for (const inc of incidents) {
      const t0 = Math.floor(Date.parse(inc.started_at) / 1000)
      const t1 = inc.ended_at ? Math.ceil(Date.parse(inc.ended_at) / 1000) : to
      if (!Number.isFinite(t0) || !Number.isFinite(t1) || t1 < from || t0 > to) continue
      const x0 = xOf(t0)
      const x1 = Math.max(x0 + 2, xOf(t1))
      ctx.fillStyle = colRed
      ctx.globalAlpha = 0.14
      ctx.fillRect(x0, 0, x1 - x0, H)
      ctx.globalAlpha = 0.45
      ctx.fillRect(x0, 0, x1 - x0, 2)
    }

    // 2. Subtle reference line and 24-hour median baseline.
    ctx.strokeStyle = colLine
    ctx.lineWidth = 1
    ctx.globalAlpha = 0.65
    ctx.beginPath()
    const midY = Math.round(padTop + plotH * 0.5) + 0.5
    ctx.moveTo(0, midY)
    ctx.lineTo(W, midY)
    ctx.stroke()

    if (median24h > 0 && median24h < scaleMax) {
      const baseY = Math.round(yOf(median24h)) + 0.5
      ctx.strokeStyle = colTextDim
      ctx.globalAlpha = 0.35
      ctx.setLineDash([3, 3])
      ctx.beginPath()
      ctx.moveTo(0, baseY)
      ctx.lineTo(W, baseY)
      ctx.stroke()
      ctx.setLineDash([])
    }

    // 3. Latency polyline and soft area fill, split across full-loss gaps.
    const traceCol =
      state === 'down' ? colRed : state === 'degraded' ? colAmber : colGreen

    let segStart = -1
    const drawSegment = (lo: number, hi: number) => {
      const count = hi - lo
      if (count <= 0) return
      if (count === 1) {
        const p = points[lo]
        ctx.fillStyle = traceCol
        ctx.globalAlpha = 0.95
        ctx.beginPath()
        ctx.arc(xOf(p.t), yOf(p.ms), 2.2, 0, Math.PI * 2)
        ctx.fill()
        return
      }

      ctx.beginPath()
      for (let i = lo; i < hi; i++) {
        const p = points[i]
        const px = xOf(p.t)
        const py = yOf(p.ms)
        if (i === lo) ctx.moveTo(px, py)
        else ctx.lineTo(px, py)
      }
      ctx.strokeStyle = traceCol
      ctx.lineWidth = 1.6
      ctx.lineJoin = 'round'
      ctx.lineCap = 'round'
      ctx.globalAlpha = 0.95
      ctx.stroke()

      ctx.lineTo(xOf(points[hi - 1].t), H - padBottom)
      ctx.lineTo(xOf(points[lo].t), H - padBottom)
      ctx.closePath()
      ctx.fillStyle = traceCol
      ctx.globalAlpha = 0.12
      ctx.fill()
    }

    for (let i = 0; i < points.length; i++) {
      if (points[i].ms >= 0) {
        if (segStart < 0) segStart = i
      } else if (segStart >= 0) {
        drawSegment(segStart, i)
        segStart = -1
      }
    }
    if (segStart >= 0) {
      drawSegment(segStart, points.length)
    }

    // 4. Loss marks drawn distinctly so single drops remain visible at 6h and 24h.
    ctx.strokeStyle = colRed
    ctx.fillStyle = colRed
    ctx.lineWidth = 1.5
    for (let i = 0; i < points.length; i++) {
      if (!points[i].loss) continue
      const lx = Math.round(xOf(points[i].t)) + 0.5
      ctx.globalAlpha = 0.85
      ctx.beginPath()
      ctx.moveTo(lx, 2)
      ctx.lineTo(lx, H - 2)
      ctx.stroke()
      ctx.globalAlpha = 1
      ctx.beginPath()
      ctx.arc(lx, 4, 2, 0, Math.PI * 2)
      ctx.fill()
    }

    ctx.globalAlpha = 1
  }, [size, dataSig, from, to, state, median24h, peakMS, points, incidents])

  const ceilMS = Math.round(Math.max(10, median24h * 2.2, peakMS * 1.15))

  return (
    <div className="nw-timeline-wrap">
      <div className="nw-canvas-box" ref={boxRef}>
        <canvas
          ref={canvasRef}
          className="nw-canvas"
          role="img"
          aria-label={`${targetName} latency and packet loss over the last ${windowHours} ${windowHours === 1 ? 'hour' : 'hours'}`}
        />
        {points.length === 0 && (
          <div className="nw-canvas-empty">
            First 10s samples will plot here as replies arrive
          </div>
        )}
      </div>
      <div className="nw-axis">
        <span>{windowHours}h ago</span>
        <span>{points.length > 0 ? `scale 0-${ceilMS} ms` : '10s cadence'}</span>
        <span>now</span>
      </div>
    </div>
  )
}

function IncidentRow({ incident }: { incident: NetwatchIncident }) {
  const failed = incident.failed ?? []
  const causeText =
    incident.cause === 'network' ? 'Your network' : 'Your internet provider'

  return (
    <div className={`nw-incident-row${incident.ongoing ? ' ongoing' : ''}`}>
      <div>
        <div className="nw-inc-start">
          <Dot
            state={incident.ongoing ? 'err' : 'warn'}
            label={incident.ongoing ? 'Ongoing outage' : 'Resolved outage'}
          />
          <span>{formatStamp(incident.started_at)}</span>
        </div>
        <span className="nw-inc-ago">{formatRelative(incident.started_at)}</span>
      </div>

      <div className="nw-inc-duration">
        <span>{formatDuration(incident.duration_seconds)}</span>
        {incident.ongoing && <span className="nw-inc-live">ongoing</span>}
      </div>

      <div className="nw-inc-what">
        <div className="nw-inc-summary">
          <strong>{causeText}:</strong> {incident.summary}
        </div>
        {failed.length > 0 && (
          <div className="nw-inc-failed-list">
            {failed.map((target) => (
              <span key={target} className="nw-failed-chip">
                {target}
              </span>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

function dotForState(state: NetwatchState): 'on' | 'warn' | 'err' {
  if (state === 'down') return 'err'
  if (state === 'degraded') return 'warn'
  return 'on'
}

function stateLabel(state: NetwatchState): string {
  if (state === 'down') return 'Down'
  if (state === 'degraded') return 'Degraded'
  return 'Good'
}

function formatMS(ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) return '--'
  if (ms > 0 && ms < 1) return `${ms.toFixed(2)} ms`
  if (ms < 10) return `${ms.toFixed(1)} ms`
  return `${Math.round(ms)} ms`
}

function formatPct(pct: number): string {
  if (!Number.isFinite(pct) || pct <= 0) return '0%'
  if (pct < 10) return `${pct.toFixed(1)}%`
  return `${Math.round(pct)}%`
}

function formatDuration(seconds: number): string {
  const s = Math.max(0, Math.floor(seconds))
  if (s < 60) return `${s}s`
  const m = Math.floor(s / 60)
  const remS = s % 60
  if (m < 60) return remS === 0 ? `${m}m` : `${m}m ${remS}s`
  const h = Math.floor(m / 60)
  const remM = m % 60
  if (h < 24) return `${h}h ${remM}m`
  const d = Math.floor(h / 24)
  return `${d}d ${h % 24}h`
}

function formatStamp(iso?: string): string {
  if (!iso) return '--'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return '--'
  return d.toLocaleString([], {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  })
}

function formatRelative(iso?: string): string {
  if (!iso) return ''
  const t = Date.parse(iso)
  if (Number.isNaN(t)) return ''
  const diff = Math.floor((Date.now() - t) / 1000)
  if (diff < 10) return 'just now'
  if (diff < 60) return `${diff}s ago`
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`
  return `${Math.floor(diff / 86400)}d ago`
}

export default InternetHealthPage
