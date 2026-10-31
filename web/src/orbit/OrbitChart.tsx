import { forwardRef, useEffect, useImperativeHandle, useRef } from 'react'
import { bits } from '../format'

export interface OrbitDevice {
  id: string
  name: string
  rate: number
  flows: number
  paused: boolean
}

export interface OrbitFlow {
  id: string
  client: string
  lon: number | null
  blocked: boolean
  bytes: number
}

export interface OrbitHandle {
  /** A device just had a lookup stopped: draw it hitting the shield. */
  spark(clientId: string): void
  /** A connection just opened: run a light along its arc. */
  arrive(flowId: string): void
}

interface Props {
  devices: OrbitDevice[]
  flows: OrbitFlow[]
  onSelect?: (id: string) => void
  label: string
}

interface Body { a: number; target: number; ring: number; drift: number; x: number; y: number; size: number }

const TAU = Math.PI * 2
const FRAME_MS = 33
const SPARK_MS = 480
const FLARE_MS = 900
const ARRIVE_MS = 850
const MAX_ARCS = 80
const REGIONS: Array<[string, number]> = [['Americas', -100], ['Europe', 12], ['Asia', 105], ['Oceania', 150]]

function hash(s: string): number {
  let h = 2166136261
  for (let i = 0; i < s.length; i++) h = Math.imul(h ^ s.charCodeAt(i), 16777619)
  return h >>> 0
}

function cssVar(name: string): string {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim()
}

const lonAngle = (lon: number) => ((lon + 180) / 360) * TAU - Math.PI / 2

/** The network drawn as a star chart: Orbis at the centre, every device a body
 *  on its orbit, connections arcing out to a world scale read by longitude, and
 *  blocked lookups stopping dead at the shield ring. It draws straight to a
 *  canvas from refs, so a busy network costs a frame, never a React render. */
export const OrbitChart = forwardRef<OrbitHandle, Props>(function OrbitChart({ devices, flows, onSelect, label }, ref) {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const tipRef = useRef<HTMLDivElement>(null)
  const data = useRef({ devices, flows })
  data.current = { devices, flows }
  const select = useRef(onSelect)
  select.current = onSelect
  const sparks = useRef<Array<{ client: string; born: number }>>([])
  const arrivals = useRef(new Map<string, number>())
  const repaint = useRef<() => void>(() => {})

  useImperativeHandle(ref, () => ({
    spark(client) {
      if (sparks.current.length < 24) sparks.current.push({ client, born: performance.now() })
    },
    arrive(id) {
      if (arrivals.current.size < 40) arrivals.current.set(id, performance.now())
    },
  }), [])

  // Reduced motion draws on change, so new data still has to reach the canvas.
  useEffect(() => { repaint.current() }, [devices, flows])

  useEffect(() => {
    const canvas = canvasRef.current
    const ctx = canvas?.getContext('2d')
    if (!canvas || !ctx) return
    const still = matchMedia('(prefers-reduced-motion: reduce)').matches
    const color = {
      ivory: cssVar('--text'), dim: cssVar('--text-dim'), faint: cssVar('--text-faint'), brass: cssVar('--brass'),
      jade: cssVar('--accent'), red: cssVar('--red'), amber: cssVar('--amber'), ground: cssVar('--bg-1'),
    }
    const line = (a: number) => `rgba(214,190,138,${a})`
    const bodies = new Map<string, Body>()
    let w = 0, h = 0, cx = 0, cy = 0, R = 0
    let raf = 0, last = 0, onScreen = true
    let pointer: { x: number; y: number } | null = null
    let hovered: string | null = null

    const size = () => {
      const box = canvas.parentElement!.getBoundingClientRect()
      const dpr = Math.min(devicePixelRatio || 1, 2)
      w = box.width; h = box.height
      canvas.width = w * dpr; canvas.height = h * dpr
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
      cx = w / 2; cy = h / 2; R = Math.min(w, h) / 2 - 22
    }

    // Devices spread evenly round their orbit and glide when one joins, so the
    // chart never jumps. The ring and the order come from the id, so a device
    // keeps its place from one visit to the next.
    const layout = () => {
      const rings: OrbitDevice[][] = [[], []]
      for (const d of data.current.devices) rings[hash(d.id) % 2].push(d)
      rings.forEach((list, ring) => {
        list.sort((p, q) => hash(p.id) - hash(q.id))
        list.forEach((d, i) => {
          const target = (i / list.length) * TAU + ring * 0.7
          const b = bodies.get(d.id)
          if (b) { b.target = target; b.ring = ring } else {
            bodies.set(d.id, { a: target, target, ring, drift: 0.012 + (hash(d.id) % 8) / 900, x: 0, y: 0, size: 3 })
          }
        })
      })
      const live = new Set(data.current.devices.map((d) => d.id))
      for (const id of bodies.keys()) if (!live.has(id)) bodies.delete(id)
    }

    const ring = (r: number, a: number, dash?: number[]) => {
      ctx.beginPath()
      ctx.setLineDash(dash ?? [])
      ctx.strokeStyle = line(a)
      ctx.arc(cx, cy, r, 0, TAU)
      ctx.stroke()
      ctx.setLineDash([])
    }
    const ticks = (r: number, n: number, rot: number, len: number, a: number) => {
      ctx.beginPath()
      ctx.strokeStyle = line(a)
      for (let i = 0; i < n; i++) {
        const t = rot + (i * TAU) / n, c = Math.cos(t), s = Math.sin(t), l = i % 6 ? len : len * 2.2
        ctx.moveTo(cx + c * r, cy + s * r)
        ctx.lineTo(cx + c * (r - l), cy + s * (r - l))
      }
      ctx.stroke()
    }
    const curve = (b: Body, angle: number) => {
      const mid = b.a + Math.atan2(Math.sin(angle - b.a), Math.cos(angle - b.a)) / 2
      const r = (Math.hypot(b.x - cx, b.y - cy) + R) * 0.56
      return {
        cpx: cx + Math.cos(mid) * r, cpy: cy + Math.sin(mid) * r,
        ex: cx + Math.cos(angle) * R, ey: cy + Math.sin(angle) * R,
      }
    }

    const frame = (t: number) => {
      const { devices, flows } = data.current
      const shield = R * 0.8
      layout()
      ctx.clearRect(0, 0, w, h)
      ctx.lineWidth = 1

      // The engraving.
      ring(R, 0.5)
      ticks(R, 72, -Math.PI / 2, 4, 0.34)
      ring(shield, 0.42)
      ticks(shield + 5, 120, still ? 0 : t / 180000, 3, 0.16)
      const orbit = (i: number) => R * (i ? 0.58 : 0.4)
      ring(orbit(0), 0.16, [2, 6])
      ring(orbit(1), 0.16, [2, 6])
      ring(R * 0.13, 0.5)

      ctx.font = `500 10.5px ${cssVar('--sans')}`
      ctx.textAlign = 'center'
      ctx.textBaseline = 'middle'
      ctx.fillStyle = color.faint
      if (R > 150) {
        for (const [name, lon] of REGIONS) {
          const a = lonAngle(lon)
          ctx.fillText(name, cx + Math.cos(a) * R * 0.9, cy + Math.sin(a) * R * 0.9)
        }
        ctx.fillText('Shield', cx, cy - shield + 12)
      }

      // Bodies.
      const peak = devices.reduce((m, d) => Math.max(m, d.rate), 1)
      for (const d of devices) {
        const b = bodies.get(d.id)
        if (!b) continue
        b.a += Math.atan2(Math.sin(b.target - b.a), Math.cos(b.target - b.a)) * 0.05
        if (!still) { b.target += (b.drift / 1000) * FRAME_MS; }
        const r = orbit(b.ring)
        b.x = cx + Math.cos(b.a) * r
        b.y = cy + Math.sin(b.a) * r
        b.size = 2.4 + Math.sqrt(d.rate / peak) * 4.6
      }

      // Hit test once a frame, not once a pointer event.
      if (pointer) {
        let best: string | null = null, bestD = 18
        for (const [id, b] of bodies) {
          const dist = Math.hypot(b.x - pointer.x, b.y - pointer.y)
          if (dist < bestD) { bestD = dist; best = id }
        }
        if (best !== hovered) {
          hovered = best
          canvas.style.cursor = best ? 'pointer' : 'default'
        }
      }

      // Connections.
      const drawn = flows.slice(0, MAX_ARCS)
      const stroke = (blocked: boolean, lit: boolean, a: number) => {
        ctx.beginPath()
        for (const f of drawn) {
          if (f.lon == null || f.blocked !== blocked || (f.client === hovered) !== lit) continue
          const b = bodies.get(f.client)
          if (!b) continue
          const c = curve(b, lonAngle(f.lon))
          ctx.moveTo(b.x, b.y)
          ctx.quadraticCurveTo(c.cpx, c.cpy, c.ex, c.ey)
        }
        ctx.strokeStyle = blocked ? color.red : lit ? color.jade : color.ivory
        ctx.globalAlpha = a
        ctx.stroke()
        ctx.globalAlpha = 1
      }
      ctx.lineWidth = 0.8
      stroke(false, false, hovered ? 0.05 : 0.14)
      stroke(true, false, hovered ? 0.1 : 0.4)
      ctx.lineWidth = 1.2
      stroke(false, true, 0.75)
      stroke(true, true, 0.85)

      // A light runs out along a new connection.
      ctx.fillStyle = color.jade
      for (const [id, born] of arrivals.current) {
        const p = (t - born) / ARRIVE_MS
        const f = drawn.find((x) => x.id === id)
        const b = f && bodies.get(f.client)
        if (p >= 1 || !f || !b || f.lon == null) { if (p >= 1 || !f) arrivals.current.delete(id); continue }
        const e = 1 - (1 - p) ** 3, c = curve(b, lonAngle(f.lon)), u = 1 - e
        ctx.beginPath()
        ctx.arc(u * u * b.x + 2 * u * e * c.cpx + e * e * c.ex, u * u * b.y + 2 * u * e * c.cpy + e * e * c.ey, 1.8, 0, TAU)
        ctx.fill()
      }

      // The endpoints on the world scale.
      ctx.fillStyle = color.dim
      const ends = new Set<number>()
      for (const f of drawn) if (f.lon != null) ends.add(Math.round(f.lon / 3) * 3)
      for (const lon of ends) {
        const a = lonAngle(lon)
        ctx.beginPath()
        ctx.arc(cx + Math.cos(a) * R, cy + Math.sin(a) * R, 1.6, 0, TAU)
        ctx.fill()
      }

      // Stopped lookups: out from the device, dead at the shield.
      ctx.lineWidth = 1.4
      sparks.current = sparks.current.filter((s) => t - s.born < SPARK_MS + FLARE_MS)
      for (const s of sparks.current) {
        const b = bodies.get(s.client)
        if (!b) continue
        const age = t - s.born
        if (age < SPARK_MS) {
          const e = 1 - (1 - age / SPARK_MS) ** 3
          const r0 = Math.hypot(b.x - cx, b.y - cy), r1 = r0 + (shield - r0) * e, r2 = Math.max(r0, r1 - 26)
          ctx.beginPath()
          ctx.moveTo(cx + Math.cos(b.a) * r2, cy + Math.sin(b.a) * r2)
          ctx.lineTo(cx + Math.cos(b.a) * r1, cy + Math.sin(b.a) * r1)
          ctx.strokeStyle = color.red
          ctx.stroke()
        } else {
          const f = (age - SPARK_MS) / FLARE_MS
          ctx.globalAlpha = 1 - f
          ctx.beginPath()
          ctx.arc(cx, cy, shield, b.a - 0.04 - f * 0.14, b.a + 0.04 + f * 0.14)
          ctx.strokeStyle = color.red
          ctx.stroke()
          ctx.beginPath()
          ctx.arc(cx + Math.cos(b.a) * shield, cy + Math.sin(b.a) * shield, 2 + f * 5, 0, TAU)
          ctx.fillStyle = color.red
          ctx.fill()
          ctx.globalAlpha = 1
        }
      }
      ctx.lineWidth = 1

      // Orbis itself, then the bodies on top of everything that passes them.
      ctx.beginPath()
      ctx.arc(cx, cy, 4, 0, TAU)
      ctx.fillStyle = color.brass
      ctx.fill()

      const busiest = [...devices].sort((p, q) => q.rate - p.rate).slice(0, R > 150 ? 4 : 0)
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
      ctx.textAlign = 'left'
      ctx.font = `500 11.5px ${cssVar('--sans')}`
      for (const d of busiest) {
        const b = bodies.get(d.id)
        if (!b || d.id === hovered || d.rate <= 0) continue
        const name = d.name.length > 18 ? d.name.slice(0, 17) + '…' : d.name
        const right = b.x < cx
        ctx.textAlign = right ? 'right' : 'left'
        ctx.fillStyle = color.dim
        ctx.fillText(name, b.x + (right ? -(b.size + 7) : b.size + 7), b.y)
      }

      const tip = tipRef.current
      if (tip) {
        const d = hovered ? devices.find((x) => x.id === hovered) : null
        const b = hovered ? bodies.get(hovered) : null
        if (d && b) {
          const nameEl = tip.firstElementChild as HTMLElement, meta = tip.lastElementChild as HTMLElement
          nameEl.textContent = d.name
          meta.textContent = `${bits(d.rate)} · ${d.flows} connection${d.flows === 1 ? '' : 's'}${d.paused ? ' · paused' : ''}`
          tip.style.opacity = '1'
          tip.style.transform = `translate3d(${Math.min(b.x + 14, w - 190)}px, ${Math.max(b.y - 44, 4)}px, 0)`
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

    const move = (e: PointerEvent) => {
      const box = canvas.getBoundingClientRect()
      pointer = { x: e.clientX - box.left, y: e.clientY - box.top }
      if (still) frame(performance.now())
    }
    const leave = () => { pointer = null; hovered = null; if (still) frame(performance.now()) }
    const click = (e: MouseEvent) => {
      const box = canvas.getBoundingClientRect(), x = e.clientX - box.left, y = e.clientY - box.top
      let best: string | null = null, bestD = 26
      for (const [id, b] of bodies) {
        const dist = Math.hypot(b.x - x, b.y - y)
        if (dist < bestD) { bestD = dist; best = id }
      }
      if (best) select.current?.(best)
    }

    const resize = new ResizeObserver(() => { size(); if (still) frame(performance.now()) })
    resize.observe(canvas.parentElement!)
    const seen = new IntersectionObserver(([e]) => { onScreen = e.isIntersecting; wake() })
    seen.observe(canvas)
    canvas.addEventListener('pointermove', move)
    canvas.addEventListener('pointerleave', leave)
    canvas.addEventListener('click', click)
    document.addEventListener('visibilitychange', wake)
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
      <div className="orbit-tip" ref={tipRef} aria-hidden="true"><b /><span /></div>
    </div>
  )
})
