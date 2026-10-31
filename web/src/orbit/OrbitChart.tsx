import { forwardRef, useEffect, useImperativeHandle, useRef } from 'react'
import { bits } from '../format'

export interface OrbitDevice {
  id: string
  name: string
  rate: number
  flows: number
  paused: boolean
  /** Ring 0 holds things that stay put, ring 1 things people carry. */
  ring: 0 | 1
}

export interface OrbitFlow {
  client: string
  lon: number | null
  blocked: boolean
  bytes: number
}

export interface OrbitHandle {
  /** A lookup from this device was stopped at the shield. */
  strike(clientId: string, name: string): void
  /** A connection just opened: run a light along its route. */
  arrive(clientId: string, lon: number | null): void
  /** Light a device from outside the chart, such as a row under the pointer. */
  focus(clientId: string | null): void
}

/** The chart draws itself in once a visit, not every time the page returns. */
let introduced = false

interface Props {
  devices: OrbitDevice[]
  flows: OrbitFlow[]
  /** The Overview's verdict, so the chart cannot look safe during a fault. */
  tone?: 'ok' | 'attention' | 'problem'
  /** The device under the pointer changed. */
  onHover?: (clientId: string | null) => void
  onSelect?: (id: string) => void
  /** Called with the name behind a mark on the shield. */
  onStrike?: (name: string) => void
  title?: string
  label: string
  /** A small chart keeps the drawing and leaves out the lettering. */
  compact?: boolean
}

interface Body { a: number; target: number; x: number; y: number; size: number; drift: number }
interface Strike { client: string; name: string; born: number; angle: number }

const TAU = Math.PI * 2
const FRAME_MS = 33
const SPARK_MS = 480
/** How long a mark stays on the shield, long enough to go and open it. */
const STRIKE_MS = 15000
const ARRIVE_MS = 1100
const MAX_STRIKES = 24
/** Traffic is grouped into one trunk line per 30 degrees of longitude. */
const BIN = 30
/** Where the gateway sits on the shield, and the rim the trunks leave from. */
const GATEWAY_ANGLE = -Math.PI / 3
const REGIONS: Array<[string, number, number]> = [
  ['Americas', -170, -35], ['Europe and Africa', -25, 55], ['Asia', 65, 145], ['Oceania', 152, 178],
]

function hash(s: string): number {
  let h = 2166136261
  for (let i = 0; i < s.length; i++) h = Math.imul(h ^ s.charCodeAt(i), 16777619)
  return h >>> 0
}

function cssVar(name: string): string {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim()
}

const lonAngle = (lon: number) => ((lon + 180) / 360) * TAU - Math.PI / 2
const binOf = (lon: number) => Math.floor((Math.max(-180, Math.min(179.9, lon)) + 180) / BIN)
const binLon = (bin: number) => bin * BIN - 180 + BIN / 2

/** The network drawn as a star chart. Orbis sits at the centre and every device
 *  on the ring for what it is, sized by what it is doing now. Each one reaches
 *  the world through the gateway on the shield, and traffic runs round the rim
 *  in one line per region, as thick as the bytes on it. Lookups stopped at the
 *  shield leave a mark that can be opened. It draws straight to a canvas from
 *  refs, so a busy network costs a frame, never a React render. */
export const OrbitChart = forwardRef<OrbitHandle, Props>(function OrbitChart(
  { devices, flows, onSelect, onStrike, onHover, title, label, compact, tone }, ref) {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const tipRef = useRef<HTMLDivElement>(null)
  const data = useRef({ devices, flows, tone })
  data.current = { devices, flows, tone }
  const handlers = useRef({ onSelect, onStrike, onHover })
  handlers.current = { onSelect, onStrike, onHover }
  const pinned = useRef<string | null>(null)
  const strikes = useRef<Strike[]>([])
  const arrivals = useRef<Array<{ client: string; lon: number; born: number }>>([])
  const repaint = useRef<() => void>(() => {})

  useImperativeHandle(ref, () => ({
    strike(client, name) {
      strikes.current.push({ client, name, born: performance.now(), angle: NaN })
      if (strikes.current.length > MAX_STRIKES) strikes.current.shift()
      repaint.current()
    },
    arrive(client, lon) {
      if (lon != null && arrivals.current.length < 24) arrivals.current.push({ client, lon, born: performance.now() })
    },
    focus(client) {
      pinned.current = client
      repaint.current()
    },
  }), [])

  useEffect(() => { repaint.current() }, [devices, flows])

  useEffect(() => {
    const canvas = canvasRef.current
    const ctx = canvas?.getContext('2d')
    if (!canvas || !ctx) return
    const still = matchMedia('(prefers-reduced-motion: reduce)').matches
    const color = {
      ivory: cssVar('--text'), dim: cssVar('--text-dim'), faint: cssVar('--text-faint'), brass: cssVar('--brass'),
      jade: cssVar('--accent'), jadeDim: cssVar('--accent-dim'), red: cssVar('--red'), amber: cssVar('--amber'),
      amberDim: cssVar('--amber-dim'),
    }
    const sans = cssVar('--sans')
    const plateColor = cssVar('--bg-1')
    const line = (a: number) => `rgba(214,190,138,${a})`
    const bodies = new Map<string, Body>()
    // The engraving never changes, so it is drawn once and stamped each frame.
    const plate = document.createElement('canvas')
    let w = 0, h = 0, cx = 0, cy = 0, R = 0, dpr = 1
    let raf = 0, last = 0, onScreen = true
    let pointer: { x: number; y: number } | null = null
    let hovered: string | null = null
    let hoveredStrike: Strike | null = null
    let reported: string | null = null
    const born = introduced || still ? -1e9 : performance.now()
    introduced = true

    /** Lettering needs room; a small chart keeps the drawing without it. */
    const lettered = () => !compact && Math.min(w, h) >= 420
    const shieldR = () => R * 0.82
    const orbitR = (ring: number) => R * (ring ? 0.6 : 0.38)
    const gateway = () => ({ x: cx + Math.cos(GATEWAY_ANGLE) * shieldR(), y: cy + Math.sin(GATEWAY_ANGLE) * shieldR() })
    const trunkR = (bin: number) => shieldR() + (R - shieldR()) * (0.2 + (0.6 * bin) / (360 / BIN))

    const curved = (c: CanvasRenderingContext2D, text: string, r: number, mid: number) => {
      c.save()
      c.textAlign = 'center'
      c.textBaseline = 'middle'
      const bottom = Math.sin(mid) > 0.2
      let total = 0
      const widths = [...text].map((ch) => { const m = c.measureText(ch).width + 1.2; total += m; return m })
      let a = mid + ((bottom ? 1 : -1) * total) / r / 2
      ;[...text].forEach((ch, i) => {
        const step = widths[i] / r
        a += ((bottom ? -1 : 1) * step) / 2
        c.save()
        c.translate(cx + Math.cos(a) * r, cy + Math.sin(a) * r)
        c.rotate(a + (bottom ? -Math.PI / 2 : Math.PI / 2))
        c.fillText(ch, 0, 0)
        c.restore()
        a += ((bottom ? -1 : 1) * step) / 2
      })
      c.restore()
    }

    const engrave = () => {
      plate.width = w * dpr
      plate.height = h * dpr
      const c = plate.getContext('2d')!
      c.setTransform(dpr, 0, 0, dpr, 0, 0)
      const ring = (r: number, a: number, dash?: number[]) => {
        c.beginPath()
        c.setLineDash(dash ?? [])
        c.strokeStyle = line(a)
        c.arc(cx, cy, r, 0, TAU)
        c.stroke()
        c.setLineDash([])
      }
      const ticks = (r: number, n: number, rot: number, len: number, a: number) => {
        c.beginPath()
        c.strokeStyle = line(a)
        for (let i = 0; i < n; i++) {
          const t = rot + (i * TAU) / n, cs = Math.cos(t), sn = Math.sin(t), l = i % 6 ? len : len * 2.2
          c.moveTo(cx + cs * r, cy + sn * r)
          c.lineTo(cx + cs * (r - l), cy + sn * (r - l))
        }
        c.stroke()
      }
      // A faint field of stars, the same every time for the same id.
      let seed = 7
      const next = () => (seed = (seed * 16807) % 2147483647) / 2147483647
      for (let i = 0; i < Math.round((w * h) / 5200); i++) {
        c.fillStyle = `rgba(239,233,218,${0.1 + next() * 0.28})`
        const s = 0.4 + next() * 0.9
        c.fillRect(next() * w, next() * h, s, s)
      }
      c.lineWidth = 1
      ring(R, 0.55)
      ticks(R, 72, -Math.PI / 2, 4, 0.36)
      ring(shieldR(), 0.5)
      ticks(shieldR() + 6, 120, 0, 3, 0.16)
      ring(orbitR(1), 0.2, [2, 6])
      ring(orbitR(0), 0.2, [2, 6])
      ring(R * 0.11, 0.55)

      if (lettered()) {
        c.font = `500 11px ${sans}`
        c.fillStyle = color.faint
        curved(c, "People's devices", orbitR(1) + 11, Math.PI / 2 + 0.5)
        curved(c, 'Fixed devices', orbitR(0) + 11, Math.PI / 2 + 0.5)
        c.fillStyle = color.dim
        curved(c, 'Shield', shieldR() - 11, -Math.PI / 2 - 0.2)
        for (const [name, from, to] of REGIONS) {
          const a0 = lonAngle(from), a1 = lonAngle(to), mid = (a0 + a1) / 2
          c.beginPath()
          c.strokeStyle = line(0.5)
          c.arc(cx, cy, R + 8, a0, a1)
          c.stroke()
          c.fillStyle = color.faint
          curved(c, name, R + 18, mid)
        }
      }
    }

    const size = () => {
      const box = canvas.parentElement!.getBoundingClientRect()
      dpr = Math.min(devicePixelRatio || 1, 2)
      // A kept page sits hidden with no size; it is drawn again when it returns.
      if (Math.min(box.width, box.height) < (compact ? 60 : 160)) return
      w = box.width; h = box.height
      canvas.width = w * dpr; canvas.height = h * dpr
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
      cx = w / 2; cy = h / 2; R = Math.min(w, h) / 2 - (compact ? 10 : 34)
      engrave()
    }

    // Devices spread evenly round their orbit and glide when one joins, so the
    // chart never jumps. The order comes from the id, so a device keeps its
    // place from one visit to the next.
    const layout = () => {
      const rings: OrbitDevice[][] = [[], []]
      for (const d of data.current.devices) rings[d.ring].push(d)
      rings.forEach((list, ring) => {
        list.sort((p, q) => hash(p.id) - hash(q.id))
        list.forEach((d, i) => {
          const target = (i / list.length) * TAU + ring * 0.7
          const b = bodies.get(d.id)
          if (b) b.target = target
          else bodies.set(d.id, { a: target, target, x: 0, y: 0, size: 3, drift: (0.012 + (hash(d.id) % 8) / 900) * (ring ? 1 : -1) })
        })
      })
      const live = new Set(data.current.devices.map((d) => d.id))
      for (const id of bodies.keys()) if (!live.has(id)) bodies.delete(id)
    }

    const spokeControl = (b: Body) => {
      const g = gateway(), mid = Math.atan2((b.y + g.y) / 2 - cy, (b.x + g.x) / 2 - cx)
      const r = Math.hypot((b.x + g.x) / 2 - cx, (b.y + g.y) / 2 - cy) * 0.82 + R * 0.08
      return { x: cx + Math.cos(mid) * r, y: cy + Math.sin(mid) * r, g }
    }
    /** The way round the rim from the gateway to a region, the short way. */
    const trunk = (bin: number) => {
      const end = lonAngle(binLon(bin))
      const delta = Math.atan2(Math.sin(end - GATEWAY_ANGLE), Math.cos(end - GATEWAY_ANGLE))
      return { r: trunkR(bin), from: GATEWAY_ANGLE, to: end, ccw: delta < 0, delta }
    }

    const frame = (t: number) => {
      const { devices, flows, tone } = data.current
      const shield = shieldR()
      // At rest the lines themselves say whether things are well.
      const rest = !tone || tone === 'ok' ? color.jadeDim : color.amberDim
      layout()
      // The focal moment: the plate opens from the centre, the devices rise to
      // their orbits and the lines run out to the rim.
      const intro = 1 - (1 - Math.min(1, (t - born) / 1200)) ** 3
      ctx.clearRect(0, 0, w, h)
      if (intro < 1) {
        ctx.save()
        ctx.beginPath()
        ctx.arc(cx, cy, Math.hypot(w, h) * 0.6 * intro, 0, TAU)
        ctx.clip()
        ctx.drawImage(plate, 0, 0, w, h)
        ctx.restore()
      } else ctx.drawImage(plate, 0, 0, w, h)

      const peak = devices.reduce((m, d) => Math.max(m, d.rate), 1)
      const ringOf = new Map(devices.map((d) => [d.id, d.ring]))
      for (const d of devices) {
        const b = bodies.get(d.id)
        if (!b) continue
        b.a += Math.atan2(Math.sin(b.target - b.a), Math.cos(b.target - b.a)) * 0.05
        if (!still) b.target += (b.drift / 1000) * FRAME_MS
        const r = orbitR(ringOf.get(d.id) ?? 0) * intro
        b.x = cx + Math.cos(b.a) * r
        b.y = cy + Math.sin(b.a) * r
        b.size = 2.4 + Math.sqrt(d.rate / peak) * 4.6
      }

      // Hit test once a frame, not once a pointer event.
      hoveredStrike = null
      if (pointer) {
        let best: string | null = null, bestD = 18
        for (const [id, b] of bodies) {
          const dist = Math.hypot(b.x - pointer.x, b.y - pointer.y)
          if (dist < bestD) { bestD = dist; best = id }
        }
        hovered = best
        if (!best) {
          let near = 14
          for (const s of strikes.current) {
            if (Number.isNaN(s.angle)) continue
            const dist = Math.hypot(cx + Math.cos(s.angle) * shield - pointer.x, cy + Math.sin(s.angle) * shield - pointer.y)
            if (dist < near) { near = dist; hoveredStrike = s }
          }
        }
        canvas.style.cursor = best || hoveredStrike ? 'pointer' : 'default'
        if (best !== reported) { reported = best; handlers.current.onHover?.(best) }
      } else hovered = pinned.current

      // Group what is flowing by region once, then draw one line per group.
      const bins = new Map<number, { bytes: number; lit: boolean }>()
      const talking = new Set<string>()
      for (const f of flows) {
        if (f.lon == null || f.blocked) continue
        talking.add(f.client)
        const k = binOf(f.lon), e = bins.get(k) ?? { bytes: 0, lit: false }
        e.bytes += f.bytes
        e.lit ||= f.client === hovered
        bins.set(k, e)
      }
      const heaviest = Math.max(1, ...[...bins.values()].map((b) => b.bytes))

      // Spokes: each device to the gateway, as heavy as its traffic.
      for (const lit of [false, true]) {
        for (const d of devices) {
          if ((d.id === hovered) !== lit || !talking.has(d.id)) continue
          const b = bodies.get(d.id)
          if (!b) continue
          const c = spokeControl(b)
          ctx.beginPath()
          ctx.moveTo(b.x, b.y)
          ctx.quadraticCurveTo(c.x, c.y, c.g.x, c.g.y)
          ctx.lineWidth = lit ? 1.6 : 0.7 + Math.sqrt(d.rate / peak) * 1.3
          ctx.strokeStyle = lit ? color.jade : rest
          ctx.globalAlpha = (lit ? 0.9 : hovered ? 0.16 : 1) * intro
          ctx.stroke()
        }
      }
      ctx.globalAlpha = 1

      // Traffic is seen moving: dots along each busy line, faster the busier.
      if (!still) {
        ctx.fillStyle = color.jade
        for (const d of [...devices].filter((x) => talking.has(x.id)).sort((p, q) => q.rate - p.rate).slice(0, 12)) {
          const b = bodies.get(d.id)
          if (!b || (hovered && hovered !== d.id)) continue
          const c = spokeControl(b), load = Math.sqrt(d.rate / peak), dots = 1 + Math.round(load * 2)
          for (let k = 0; k < dots; k++) {
            const e = ((t / 2400) * (0.4 + load) + k / dots + (hash(d.id) % 97) / 97) % 1, u = 1 - e
            ctx.fillRect(u * u * b.x + 2 * u * e * c.x + e * e * c.g.x - 1, u * u * b.y + 2 * u * e * c.y + e * e * c.g.y - 1, 2, 2)
          }
        }
      }

      // Trunks: round the rim to each region, then out to the scale.
      for (const [bin, e] of bins) {
        const tr = trunk(bin)
        ctx.beginPath()
        ctx.arc(cx, cy, tr.r, tr.from, tr.from + tr.delta * intro, tr.ccw)
        if (intro === 1) ctx.lineTo(cx + Math.cos(tr.to) * R, cy + Math.sin(tr.to) * R)
        // Never wider than the gap to the next trunk, or they merge into a band.
        ctx.lineWidth = Math.min(0.8 + Math.sqrt(e.bytes / heaviest) * 2.6, ((R - shield) * 0.6 * BIN) / 360 - 0.5)
        ctx.strokeStyle = e.lit ? color.jade : rest
        ctx.globalAlpha = e.lit ? 0.95 : hovered ? 0.2 : 1
        ctx.stroke()
        ctx.globalAlpha = 1
        if (!still && intro === 1) {
          const a = tr.from + tr.delta * ((t / 3400 + bin * 0.137) % 1)
          ctx.fillStyle = color.jade
          ctx.fillRect(cx + Math.cos(a) * tr.r - 1, cy + Math.sin(a) * tr.r - 1, 2, 2)
        }
        ctx.beginPath()
        ctx.arc(cx + Math.cos(tr.to) * R, cy + Math.sin(tr.to) * R, 2.2, 0, TAU)
        ctx.fillStyle = e.lit ? color.jade : color.dim
        ctx.fill()
      }
      ctx.globalAlpha = 1
      ctx.lineWidth = 1

      // The watch: one slow sweep round the shield, always moving.
      if (!still && ctx.createConicGradient) {
        const a = (t / 14000) * TAU, ink = !tone || tone === 'ok' ? '98,216,178' : '242,181,68'
        const fall = ctx.createConicGradient(a, cx, cy)
        fall.addColorStop(0, `rgba(${ink},0)`)
        fall.addColorStop(0.86, `rgba(${ink},0)`)
        fall.addColorStop(1, `rgba(${ink},.11)`)
        ctx.globalAlpha = intro
        ctx.fillStyle = fall
        ctx.beginPath()
        ctx.arc(cx, cy, R, 0, TAU)
        ctx.arc(cx, cy, shield, 0, TAU, true)
        ctx.fill()
        ctx.beginPath()
        ctx.moveTo(cx + Math.cos(a) * shield, cy + Math.sin(a) * shield)
        ctx.lineTo(cx + Math.cos(a) * R, cy + Math.sin(a) * R)
        ctx.strokeStyle = `rgba(${ink},.4)`
        ctx.stroke()
        ctx.globalAlpha = 1
      }

      // The orbit of whatever is under the pointer.
      if (hovered) {
        ctx.beginPath()
        ctx.arc(cx, cy, orbitR(ringOf.get(hovered) ?? 0), 0, TAU)
        ctx.strokeStyle = color.jade
        ctx.globalAlpha = 0.5
        ctx.stroke()
        ctx.globalAlpha = 1
      }

      // A light runs out along a new connection: to the gateway, then the rim.
      arrivals.current = arrivals.current.filter((a) => t - a.born < ARRIVE_MS)
      ctx.fillStyle = color.jade
      for (const a of arrivals.current) {
        const b = bodies.get(a.client)
        if (!b) continue
        const p = (t - a.born) / ARRIVE_MS
        let x: number, y: number
        if (p < 0.5) {
          const c = spokeControl(b), e = p * 2, u = 1 - e
          x = u * u * b.x + 2 * u * e * c.x + e * e * c.g.x
          y = u * u * b.y + 2 * u * e * c.y + e * e * c.g.y
        } else {
          const tr = trunk(binOf(a.lon)), e = (p - 0.5) * 2
          const sweep = Math.atan2(Math.sin(tr.to - tr.from), Math.cos(tr.to - tr.from))
          const ang = tr.from + sweep * e
          x = cx + Math.cos(ang) * tr.r
          y = cy + Math.sin(ang) * tr.r
        }
        ctx.beginPath()
        ctx.arc(x, y, 1.9, 0, TAU)
        ctx.fill()
      }

      // The gateway: everything leaves through here.
      const g = gateway()
      ctx.fillStyle = color.brass
      ctx.fillRect(g.x - 3.5, g.y - 3.5, 7, 7)

      // Stopped lookups: out from the device, dead at the shield, and a mark
      // left there that can be opened.
      strikes.current = strikes.current.filter((s) => t - s.born < STRIKE_MS)
      ctx.lineWidth = 1.4
      for (const s of strikes.current) {
        const b = bodies.get(s.client)
        const age = t - s.born
        if (age < SPARK_MS && b && !still) {
          const e = 1 - (1 - age / SPARK_MS) ** 3
          const r0 = Math.hypot(b.x - cx, b.y - cy), r1 = r0 + (shield - r0) * e, r2 = Math.max(r0, r1 - 26)
          ctx.beginPath()
          ctx.moveTo(cx + Math.cos(b.a) * r2, cy + Math.sin(b.a) * r2)
          ctx.lineTo(cx + Math.cos(b.a) * r1, cy + Math.sin(b.a) * r1)
          ctx.strokeStyle = color.red
          ctx.stroke()
          continue
        }
        if (Number.isNaN(s.angle)) s.angle = b ? b.a : hash(s.name) / 683565275
        const f = Math.min(1, (age - SPARK_MS) / 900), fade = 1 - (age / STRIKE_MS) ** 2
        if (f < 1) {
          ctx.globalAlpha = 1 - f
          ctx.beginPath()
          ctx.arc(cx, cy, shield, s.angle - 0.04 - f * 0.14, s.angle + 0.04 + f * 0.14)
          ctx.strokeStyle = color.red
          ctx.stroke()
        }
        ctx.globalAlpha = fade
        ctx.beginPath()
        ctx.arc(cx + Math.cos(s.angle) * shield, cy + Math.sin(s.angle) * shield, s === hoveredStrike ? 4.5 : 2.6, 0, TAU)
        ctx.fillStyle = color.red
        ctx.fill()
        ctx.globalAlpha = 1
      }
      ctx.lineWidth = 1

      // Orbis, then the bodies on top of everything that passes them.
      ctx.beginPath()
      ctx.arc(cx, cy, 4, 0, TAU)
      ctx.fillStyle = color.brass
      ctx.fill()
      for (const d of devices) {
        const b = bodies.get(d.id)
        if (!b) continue
        const lit = d.id === hovered
        ctx.beginPath()
        ctx.arc(b.x, b.y, b.size, 0, TAU)
        ctx.fillStyle = d.paused ? color.amber : lit ? color.jade : color.ivory
        ctx.fill()
        if (lit) {
          ctx.beginPath()
          ctx.arc(b.x, b.y, b.size + 4, 0, TAU)
          ctx.strokeStyle = color.jade
          ctx.stroke()
        }
      }

      // Names go where they cover nothing: the side away from the centre if
      // that is free, the other side if not, and not at all if neither is. A
      // halo of the plate's colour keeps them readable across a line, the way
      // a chart's lettering is knocked out of its engraving.
      if (lettered()) {
        ctx.font = `500 11.5px ${sans}`
        ctx.textBaseline = 'middle'
        ctx.lineJoin = 'round'
        const placed: Array<{ x0: number; x1: number; y0: number; y1: number }> = []
        const hit = (r: { x0: number; x1: number; y0: number; y1: number }) => {
          for (const p of placed) if (r.x0 < p.x1 && r.x1 > p.x0 && r.y0 < p.y1 && r.y1 > p.y0) return true
          for (const q of bodies.values()) if (q.x > r.x0 - q.size && q.x < r.x1 + q.size && q.y > r.y0 - q.size && q.y < r.y1 + q.size) return true
          return false
        }
        const write = (text: string, x: number, y: number, side: number) => {
          const tw = ctx.measureText(text).width
          const box = { x0: side > 0 ? x : x - tw, x1: side > 0 ? x + tw : x, y0: y - 8, y1: y + 8 }
          if (box.x0 < 2 || box.x1 > w - 2 || hit(box)) return false
          ctx.textAlign = side > 0 ? 'left' : 'right'
          ctx.lineWidth = 3.5
          ctx.strokeStyle = plateColor
          ctx.strokeText(text, x, y)
          ctx.fillStyle = color.ivory
          ctx.fillText(text, x, y)
          placed.push(box)
          return true
        }
        const gx = gateway()
        write('Gateway', gx.x - 9, gx.y - 13, -1) || write('Gateway', gx.x + 9, gx.y - 13, 1)
        write('Orbis', cx + 9, cy, 1)
        for (const d of [...devices].sort((p, q) => q.rate - p.rate).slice(0, 4)) {
          const b = bodies.get(d.id)
          if (!b || d.id === hovered || d.rate <= 0) continue
          const name = d.name.length > 18 ? d.name.slice(0, 17) + '…' : d.name
          const out = b.x < cx ? -1 : 1, gap = b.size + 7
          write(name, b.x + out * gap, b.y, out) || write(name, b.x - out * gap, b.y, -out)
        }
        ctx.lineWidth = 1
      }

      const tip = tipRef.current
      if (tip) {
        const d = hovered ? devices.find((x) => x.id === hovered) : null
        const b = hovered ? bodies.get(hovered) : null
        const nameEl = tip.firstElementChild as HTMLElement, meta = tip.lastElementChild as HTMLElement
        if (d && b) {
          nameEl.textContent = d.name
          meta.textContent = `${bits(d.rate)}, ${d.flows} connection${d.flows === 1 ? '' : 's'}${d.paused ? ', paused' : ''}`
          tip.style.opacity = '1'
          tip.style.transform = `translate3d(${Math.min(b.x + 14, w - 190)}px, ${Math.max(b.y - 44, 4)}px, 0)`
        } else if (hoveredStrike) {
          const s = hoveredStrike
          nameEl.textContent = s.name
          meta.textContent = 'Stopped at the shield. Open to see why.'
          tip.style.opacity = '1'
          tip.style.transform = `translate3d(${Math.min(cx + Math.cos(s.angle) * shield + 12, w - 200)}px, ${Math.max(cy + Math.sin(s.angle) * shield - 44, 4)}px, 0)`
        } else tip.style.opacity = '0'
      }
    }

    const loop = (t: number) => {
      raf = 0
      if (t - last >= FRAME_MS) { last = t; frame(t) }
      if (!document.hidden && onScreen && !still) raf = requestAnimationFrame(loop)
    }
    const wake = () => { if (!raf && !document.hidden && onScreen && !still) raf = requestAnimationFrame(loop) }
    repaint.current = () => { if (still) frame(performance.now()) }

    const at = (e: { clientX: number; clientY: number }) => {
      const box = canvas.getBoundingClientRect()
      return { x: e.clientX - box.left, y: e.clientY - box.top }
    }
    const move = (e: PointerEvent) => { pointer = at(e); if (still) frame(performance.now()) }
    const leave = (e: PointerEvent) => {
      if (e.pointerType === 'touch') return
      pointer = null; hovered = null
      if (reported) { reported = null; handlers.current.onHover?.(null) }
      if (still) frame(performance.now())
    }
    // On a touch screen the first tap lights a body and the second opens it.
    let touched: string | null = null
    const click = (e: MouseEvent) => {
      const p = at(e)
      pointer = p
      frame(performance.now())
      if (hoveredStrike) { handlers.current.onStrike?.(hoveredStrike.name); return }
      if (!hovered) { touched = null; return }
      if ((e as PointerEvent).pointerType === 'touch' && touched !== hovered) { touched = hovered; return }
      handlers.current.onSelect?.(hovered)
    }

    const resize = new ResizeObserver(() => { size(); if (still) frame(performance.now()) })
    resize.observe(canvas.parentElement!)
    const seen = new IntersectionObserver(([e]) => { onScreen = e.isIntersecting; wake() })
    seen.observe(canvas)
    canvas.addEventListener('pointermove', move)
    canvas.addEventListener('pointerleave', leave)
    canvas.addEventListener('click', click)
    document.addEventListener('visibilitychange', wake)
    // Lettering drawn before the web font lands would stay in the fallback.
    document.fonts?.ready.then(() => { if (w) engrave() })
    size()
    if (still) frame(performance.now()); else wake()

    return () => {
      cancelAnimationFrame(raf)
      resize.disconnect()
      seen.disconnect()
      canvas.removeEventListener('pointermove', move)
      canvas.removeEventListener('pointerleave', leave)
      canvas.removeEventListener('click', click)
      document.removeEventListener('visibilitychange', wake)
    }
  }, [])

  return (
    <div className="orbit">
      <canvas ref={canvasRef} role="img" aria-label={label} />
      {title && <div className="orbit-title">{title}</div>}
      {!compact && <div className="orbit-key">Size shows traffic now. Lines thicken with bytes.</div>}
      <div className="orbit-tip" ref={tipRef} aria-hidden="true"><b /><span /></div>
    </div>
  )
})
