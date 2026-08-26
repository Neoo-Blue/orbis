import { useCallback, useEffect, useRef, useState } from 'react'
import landRings from '../data/land.json'
import countryShapes from '../data/countries.json'
import type { GlobeArc, GlobeData } from '../types'

/** One ring of one country, tagged with its ISO 3166-1 alpha-2 code. */
interface CountryShape { c: string; n: string; r: number[] }
import { bytes, countryFlag } from '../format'

/**
 * The flat (equirectangular) view of the same data the globe shows.
 *
 * A globe is better at conveying "these are real distances across a round
 * world"; a flat map is better at comparing everything at once, because
 * nothing is hidden on the far side. Both read from the same arc set.
 *
 * Rendered on a 2D canvas rather than as SVG: several hundred arcs plus their
 * travelling markers is a few hundred DOM nodes mutating every frame, which
 * SVG handles badly.
 */

interface Props {
  data: GlobeData | null
  liveArcs?: GlobeArc[]
  onSelect?: (arc: GlobeArc | null) => void
  autoAnimate?: boolean
}

const COLORS = {
  inbound: '#ffc266',
  allow: '#4ee8c0',
  block: '#ff6b7a',
  filtered: '#a98bff',
  pending: '#ffc266',
  home: '#7fd3ff',
  land: '#1d3550',
  border: '#152740',
  graticule: '#0e1a2b',
  // Crest of the travelling gradient: cool outbound, warm inbound.
  flowOut: '#eafffb',
  flowIn: '#ffd9a0',
}

function verdictColor(v: string): string {
  return (COLORS as Record<string, string>)[v] ?? COLORS.allow
}

/** Verdict stays the primary colour encoding; inbound arcs are tinted toward
 *  the inbound hue so direction is readable with the animation paused. */
function arcColor(a: { verdict: string; direction?: string }): string {
  if (a.direction !== 'in') return verdictColor(a.verdict)
  return mix(verdictColor(a.verdict), COLORS.inbound, 0.45)
}

function mix(a: string, b: string, t: number): string {
  const pa = parseInt(a.slice(1), 16)
  const pb = parseInt(b.slice(1), 16)
  const ch = (shift: number) => {
    const va = (pa >> shift) & 0xff
    const vb = (pb >> shift) & 0xff
    return Math.round(va + (vb - va) * t)
  }
  return `rgb(${ch(16)},${ch(8)},${ch(0)})`
}

interface View {
  zoom: number
  offsetX: number
  offsetY: number
}

export function FlatMap({ data, liveArcs, onSelect, autoAnimate = true }: Props) {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const wrapRef = useRef<HTMLDivElement>(null)
  const [hover, setHover] = useState<{ arc: GlobeArc; x: number; y: number } | null>(null)

  // View state lives in a ref so panning does not re-render React on every
  // pointer move; the canvas redraws itself from the animation loop.
  const view = useRef<View>({ zoom: 1, offsetX: 0, offsetY: 0 })
  const arcsRef = useRef<GlobeArc[]>([])
  const homeRef = useRef<{ lat: number; lng: number; label: string } | null>(null)
  const countryLoadRef = useRef<Map<string, { intensity: number; blocked: boolean }>>(new Map())
  const hoverRef = useRef<GlobeArc | null>(null)
  const pointerRef = useRef<{ x: number; y: number } | null>(null)
  const dragRef = useRef<{ x: number; y: number } | null>(null)
  const sizeRef = useRef({ w: 0, h: 0, dpr: 1 })

  // Merge the polled and live sets, exactly as the globe does.
  useEffect(() => {
    const map = new Map<string, GlobeArc>()
    for (const a of data?.arcs ?? []) map.set(a.id, a)
    for (const a of liveArcs ?? []) map.set(a.id, a)
    arcsRef.current = [...map.values()].filter((a) => a.end_lat !== 0 || a.end_lng !== 0)
    homeRef.current = data?.home ?? homeRef.current

    // Per-country intensity, scaled against the busiest country so the map
    // adapts to this network rather than to an absolute byte count.
    const loads = new Map<string, { intensity: number; blocked: boolean }>()
    const rows = data?.countries ?? []
    let peak = 0
    for (const r of rows) peak = Math.max(peak, r.connections)
    if (peak > 0) {
      for (const r of rows) {
        if (!r.country) continue
        // Log scale, or one busy country flattens every other to nothing.
        const share = Math.log10(1 + r.connections) / Math.log10(1 + peak)
        loads.set(r.country.toUpperCase(), {
          intensity: Math.max(0.18, Math.min(0.9, 0.18 + share * 0.72)),
          blocked: r.blocked > 0 && r.blocked >= r.connections * 0.4,
        })
      }
    }
    countryLoadRef.current = loads
  }, [data, liveArcs])

  /** project maps a coordinate to canvas pixels under the current view. */
  const project = useCallback((lat: number, lng: number): [number, number] => {
    const { w, h } = sizeRef.current
    const v = view.current
    const x = ((lng + 180) / 360) * w * v.zoom + v.offsetX
    const y = ((90 - lat) / 180) * h * v.zoom + v.offsetY
    return [x, y]
  }, [])

  useEffect(() => {
    const canvas = canvasRef.current
    const wrap = wrapRef.current
    if (!canvas || !wrap) return
    const ctx = canvas.getContext('2d', { alpha: true })
    if (!ctx) return

    const resize = () => {
      const dpr = Math.min(window.devicePixelRatio || 1, 2)
      const w = wrap.clientWidth
      const h = wrap.clientHeight
      if (!w || !h) return
      canvas.width = w * dpr
      canvas.height = h * dpr
      canvas.style.width = `${w}px`
      canvas.style.height = `${h}px`
      sizeRef.current = { w, h, dpr }
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
    }
    resize()
    const ro = new ResizeObserver(resize)
    ro.observe(wrap)

    let raf = 0
    const start = performance.now()

    const drawRings = (rings: number[][], color: string, alpha: number, width: number) => {
      ctx.strokeStyle = color
      ctx.globalAlpha = alpha
      ctx.lineWidth = width
      ctx.beginPath()
      for (const flat of rings) {
        // Skip a segment that wraps the antimeridian, or it draws a line
        // straight across the whole map.
        let prevX: number | null = null
        for (let i = 0; i + 1 < flat.length; i += 2) {
          const [x, y] = project(flat[i + 1], flat[i])
          if (prevX !== null && Math.abs(x - prevX) > sizeRef.current.w * view.current.zoom * 0.5) {
            ctx.moveTo(x, y)
          } else if (i === 0) {
            ctx.moveTo(x, y)
          } else {
            ctx.lineTo(x, y)
          }
          prevX = x
        }
      }
      ctx.stroke()
      ctx.globalAlpha = 1
    }

    const draw = (now: number) => {
      raf = requestAnimationFrame(draw)
      const { w, h } = sizeRef.current
      if (!w || !h) return
      const t = (now - start) / 1000

      ctx.clearRect(0, 0, w, h)

      // Graticule every 30 degrees, for orientation.
      ctx.strokeStyle = COLORS.graticule
      ctx.lineWidth = 1
      ctx.globalAlpha = 0.6
      ctx.beginPath()
      for (let lat = -60; lat <= 60; lat += 30) {
        const [, y] = project(lat, 0)
        ctx.moveTo(0, y)
        ctx.lineTo(w, y)
      }
      for (let lng = -150; lng <= 150; lng += 30) {
        const [x] = project(0, lng)
        ctx.moveTo(x, 0)
        ctx.lineTo(x, h)
      }
      ctx.stroke()
      ctx.globalAlpha = 1

      // Lit countries first, as a filled wash under the borders, so a country
      // this network is talking to reads at a glance without hiding its outline.
      const loads = countryLoadRef.current
      if (loads.size) {
        for (const shape of countryShapes as CountryShape[]) {
          const load = loads.get(shape.c)
          if (!load) continue
          ctx.beginPath()
          const flat = shape.r
          for (let i = 0; i + 1 < flat.length; i += 2) {
            const [x, y] = project(flat[i + 1], flat[i])
            if (i === 0) ctx.moveTo(x, y)
            else ctx.lineTo(x, y)
          }
          ctx.closePath()
          ctx.fillStyle = load.blocked ? COLORS.block : COLORS.allow
          ctx.globalAlpha = load.intensity * 0.16
          ctx.fill()
          ctx.strokeStyle = load.blocked ? COLORS.block : COLORS.allow
          ctx.globalAlpha = load.intensity * 0.55
          ctx.lineWidth = 1
          ctx.stroke()
        }
        ctx.globalAlpha = 1
      }

      drawRings((countryShapes as CountryShape[]).map((c) => c.r), COLORS.border, 0.42, 1)
      drawRings(landRings as number[][], COLORS.land, 0.85, 1.1)

      const home = homeRef.current
      const arcs = arcsRef.current
      if (!home) return
      const [hx, hy] = project(home.lat, home.lng)

      // Arcs first, then markers, so a marker is never hidden under a line.
      ctx.lineCap = 'round'
      for (const a of arcs) {
        const [ex, ey] = project(a.end_lat, a.end_lng)
        // The control point lifts the curve perpendicular to the chord, so
        // many arcs to nearby destinations stay visually distinguishable.
        const mx = (hx + ex) / 2
        const my = (hy + ey) / 2
        const dx = ex - hx
        const dy = ey - hy
        const dist = Math.hypot(dx, dy)
        const lift = Math.min(dist * 0.22, 120)
        const cx = mx - (dy / (dist || 1)) * lift
        const cy = my + (dx / (dist || 1)) * lift

        const weight = Math.min(1, Math.log10(Math.max(a.bytes, 1)) / 8)
        const isHovered = hoverRef.current?.id === a.id
        ctx.strokeStyle = arcColor(a)
        ctx.globalAlpha = isHovered ? 0.95 : 0.16 + weight * 0.4
        ctx.lineWidth = isHovered ? 2.2 : 0.7 + weight * 1.1
        ctx.beginPath()
        ctx.moveTo(hx, hy)
        ctx.quadraticCurveTo(cx, cy, ex, ey)
        ctx.stroke()

        if (autoAnimate && a.active) {
          // A crest that runs along the arc, rather than a dot riding it. The
          // direction of travel is the encoding: outbound runs home → remote,
          // inbound runs the other way, so an unsolicited inbound connection
          // is visible without reading a legend.
          const phase = hashPhase(a.id)
          const speed = 0.2 + Math.min(0.3, a.bytes / 5_000_000)
          const inbound = a.direction === 'in'
          const head = ((t * speed + phase) % 1 + 1) % 1
          const crest = inbound ? COLORS.flowIn : COLORS.flowOut

          // Canvas has no shader, so the comet is drawn as a short run of
          // segments whose alpha falls off behind the crest. Twelve is enough
          // to read as continuous without costing a full re-stroke per arc.
          const steps = 12
          const span = 0.3
          ctx.lineWidth = 0.9 + weight * 1.5
          for (let i = 0; i < steps; i++) {
            const t0 = i / steps
            const t1 = (i + 1) / steps
            // Distance behind the crest, in the direction the flow travels.
            const d = inbound ? (head - t0 + 1) % 1 : (t0 - head + 1) % 1
            if (d > span) continue
            const fade = 1 - d / span
            const pt0 = quadPoint(hx, hy, cx, cy, ex, ey, t0)
            const pt1 = quadPoint(hx, hy, cx, cy, ex, ey, t1)
            ctx.strokeStyle = crest
            ctx.globalAlpha = Math.min(0.95, fade * fade * (0.35 + weight * 0.5))
            ctx.beginPath()
            ctx.moveTo(pt0[0], pt0[1])
            ctx.lineTo(pt1[0], pt1[1])
            ctx.stroke()
          }
        }
      }
      ctx.globalAlpha = 1

      // Destination markers, deduplicated by rounded coordinate.
      const seen = new Map<string, { x: number; y: number; weight: number; verdict: string }>()
      for (const a of arcs) {
        const key = `${a.end_lat.toFixed(1)},${a.end_lng.toFixed(1)}`
        const [x, y] = project(a.end_lat, a.end_lng)
        const existing = seen.get(key)
        if (existing) {
          existing.weight += a.bytes
          if (a.verdict === 'block') existing.verdict = 'block'
        } else {
          seen.set(key, { x, y, weight: Math.max(a.bytes, 1), verdict: a.verdict })
        }
      }
      for (const p of seen.values()) {
        const r = 1.6 + Math.min(4, Math.log10(p.weight) * 0.6)
        ctx.fillStyle = verdictColor(p.verdict)
        ctx.globalAlpha = 0.55
        ctx.beginPath()
        ctx.arc(p.x, p.y, r, 0, Math.PI * 2)
        ctx.fill()
      }
      ctx.globalAlpha = 1

      // Home marker: a pulsing ring, so the eye finds it immediately.
      const pulse = autoAnimate ? 1 + Math.sin(t * 2) * 0.18 : 1
      ctx.strokeStyle = COLORS.home
      ctx.lineWidth = 1.6
      ctx.globalAlpha = 0.9
      ctx.beginPath()
      ctx.arc(hx, hy, 5 * pulse, 0, Math.PI * 2)
      ctx.stroke()
      ctx.fillStyle = COLORS.home
      ctx.beginPath()
      ctx.arc(hx, hy, 2.2, 0, Math.PI * 2)
      ctx.fill()
      ctx.globalAlpha = 1
    }
    raf = requestAnimationFrame(draw)

    return () => {
      cancelAnimationFrame(raf)
      ro.disconnect()
    }
  }, [project, autoAnimate])

  // Hit testing samples each curve; with a few hundred arcs this is far
  // cheaper than maintaining a spatial index that has to be rebuilt on every
  // poll.
  const hitTest = useCallback((px: number, py: number): GlobeArc | null => {
    const home = homeRef.current
    if (!home) return null
    const [hx, hy] = project(home.lat, home.lng)
    let best: GlobeArc | null = null
    let bestDist = 9

    for (const a of arcsRef.current) {
      const [ex, ey] = project(a.end_lat, a.end_lng)
      const mx = (hx + ex) / 2
      const my = (hy + ey) / 2
      const dx = ex - hx
      const dy = ey - hy
      const dist = Math.hypot(dx, dy)
      const lift = Math.min(dist * 0.22, 120)
      const cx = mx - (dy / (dist || 1)) * lift
      const cy = my + (dx / (dist || 1)) * lift

      for (let i = 0; i <= 12; i++) {
        const p = i / 12
        const inv = 1 - p
        const qx = inv * inv * hx + 2 * inv * p * cx + p * p * ex
        const qy = inv * inv * hy + 2 * inv * p * cy + p * p * ey
        const d = Math.hypot(qx - px, qy - py)
        if (d < bestDist) {
          bestDist = d
          best = a
        }
      }
    }
    return best
  }, [project])

  const onPointerMove = (e: React.PointerEvent) => {
    const rect = e.currentTarget.getBoundingClientRect()
    const x = e.clientX - rect.left
    const y = e.clientY - rect.top
    pointerRef.current = { x, y }

    if (dragRef.current) {
      view.current.offsetX += x - dragRef.current.x
      view.current.offsetY += y - dragRef.current.y
      dragRef.current = { x, y }
      return
    }
    const found = hitTest(x, y)
    hoverRef.current = found
    setHover(found ? { arc: found, x, y } : null)
  }

  return (
    <div
      ref={wrapRef}
      className="globe-canvas"
      style={{ cursor: dragRef.current ? 'grabbing' : hover ? 'pointer' : 'grab' }}
      onPointerDown={(e) => {
        const rect = e.currentTarget.getBoundingClientRect()
        dragRef.current = { x: e.clientX - rect.left, y: e.clientY - rect.top }
      }}
      onPointerUp={() => { dragRef.current = null }}
      onPointerLeave={() => { dragRef.current = null; hoverRef.current = null; setHover(null) }}
      onPointerMove={onPointerMove}
      onClick={() => onSelect?.(hover?.arc ?? null)}
      onWheel={(e) => {
        const rect = e.currentTarget.getBoundingClientRect()
        const mx = e.clientX - rect.left
        const my = e.clientY - rect.top
        const v = view.current
        const next = Math.max(1, Math.min(8, v.zoom * (1 - e.deltaY * 0.0015)))
        // Zoom about the cursor so the point under it stays put.
        const k = next / v.zoom
        v.offsetX = mx - (mx - v.offsetX) * k
        v.offsetY = my - (my - v.offsetY) * k
        v.zoom = next
        if (next === 1) { v.offsetX = 0; v.offsetY = 0 }
      }}
      role="img"
      aria-label={`Flat map showing ${arcsRef.current.length} connections`}
    >
      <canvas ref={canvasRef} style={{ display: 'block' }} />
      {hover && (
        <div
          className="globe-tooltip"
          style={{
            left: hover.x > (wrapRef.current?.clientWidth ?? 0) - 320 ? undefined : hover.x + 14,
            right: hover.x > (wrapRef.current?.clientWidth ?? 0) - 320
              ? (wrapRef.current?.clientWidth ?? 0) - hover.x + 14 : undefined,
            top: Math.max(8, hover.y - 10),
          }}
        >
          <div className="host">{hover.arc.label}</div>
          <div className="meta">
            {hover.arc.direction === 'in' ? '← inbound' : '→ outbound'}
            {hover.arc.app && <> · {hover.arc.app}</>} · {hover.arc.proto}/{hover.arc.port}
          </div>
          <div className="meta">
            ↓ {bytes(hover.arc.bytes_in ?? 0)} received · ↑ {bytes(hover.arc.bytes_out ?? 0)} sent
          </div>
          <div className="meta">
            {hover.arc.country && <>{countryFlag(hover.arc.country)} {hover.arc.city || hover.arc.country} · </>}
            {hover.arc.org || hover.arc.dst}
          </div>
        </div>
      )}
    </div>
  )
}

/** quadPoint evaluates the quadratic Bezier used for every arc. */
function quadPoint(
  x0: number, y0: number, cx: number, cy: number, x1: number, y1: number, t: number,
): [number, number] {
  const inv = 1 - t
  return [
    inv * inv * x0 + 2 * inv * t * cx + t * t * x1,
    inv * inv * y0 + 2 * inv * t * cy + t * t * y1,
  ]
}

function hashPhase(s: string): number {
  let h = 2166136261
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i)
    h = Math.imul(h, 16777619)
  }
  return ((h >>> 0) % 1000) / 1000
}
