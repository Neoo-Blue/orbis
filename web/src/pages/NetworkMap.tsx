import { useMemo, useRef, useState, useEffect } from 'react'
import type { TopoGraph, TopoNode } from '../types'
import { bytes } from '../format'

/**
 * The network map.
 *
 * Not a force-directed cloud: physics layouts jitter, and on a home or lab
 * network they tell you nothing a structured view does not. This is a
 * deterministic constellation. The gateway is the hub. Infrastructure
 * (hypervisors, NAS, servers, access points) sits on an inner ring; endpoints
 * on an outer one. A hypervisor's guests orbit it directly, so "one Proxmox
 * host with eleven containers" reads as exactly that. Edges carry animated flow
 * in the direction traffic was opened, so inbound and outbound are legible at a
 * glance.
 */

const ROLE_COLOR: Record<string, string> = {
  gateway: 'var(--accent)',
  access_point: 'var(--blue)',
  hypervisor: 'var(--violet)',
  nas: 'var(--blue)',
  server: 'var(--accent)',
  vm: 'var(--violet)',
  container: 'var(--violet)',
  workstation: 'var(--green)',
  mobile: 'var(--green)',
  printer: 'var(--text-dim)',
  iot: 'var(--amber)',
  unknown: 'var(--text-faint)',
}

const INFRA = new Set(['gateway', 'hypervisor', 'nas', 'server', 'access_point'])

interface Placed extends TopoNode {
  x: number
  y: number
  r: number
}

const W = 1000
const H = 720

export function NetworkMap({ graph, onSelect, selectedId }: {
  graph: TopoGraph
  onSelect: (n: TopoNode) => void
  selectedId?: string
}) {
  const wrapRef = useRef<HTMLDivElement>(null)
  const [view, setView] = useState({ x: 0, y: 0, k: 1 })
  const [hover, setHover] = useState<string | null>(null)
  const drag = useRef<{ x: number; y: number; vx: number; vy: number } | null>(null)

  const { placed, edges, hosted } = useMemo(() => layout(graph), [graph])
  const byId = useMemo(() => new Map(placed.map((p) => [p.id, p])), [placed])

  // Pan and zoom. Kept in a transform on the root group so it costs nothing
  // per node.
  const onWheel = (e: React.WheelEvent) => {
    e.preventDefault()
    const k = Math.min(3, Math.max(0.4, view.k * (e.deltaY < 0 ? 1.12 : 0.89)))
    setView((v) => ({ ...v, k }))
  }
  const onDown = (e: React.MouseEvent) => {
    drag.current = { x: e.clientX, y: e.clientY, vx: view.x, vy: view.y }
  }
  useEffect(() => {
    const move = (e: MouseEvent) => {
      if (!drag.current) return
      setView((v) => ({
        ...v,
        x: drag.current!.vx + (e.clientX - drag.current!.x),
        y: drag.current!.vy + (e.clientY - drag.current!.y),
      }))
    }
    const up = () => { drag.current = null }
    window.addEventListener('mousemove', move)
    window.addEventListener('mouseup', up)
    return () => { window.removeEventListener('mousemove', move); window.removeEventListener('mouseup', up) }
  }, [])

  const active = hover ?? selectedId

  return (
    <div ref={wrapRef} style={{
      position: 'relative', height: 560, borderRadius: 'var(--radius)',
      border: '1px solid var(--line)', overflow: 'hidden',
      background: 'radial-gradient(1200px 600px at 50% 20%, color-mix(in srgb, var(--accent) 5%, transparent), transparent 60%), var(--bg)',
      cursor: drag.current ? 'grabbing' : 'grab',
    }}>
      <svg width="100%" height="100%" viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="xMidYMid meet"
        onWheel={onWheel} onMouseDown={onDown}>
        <defs>
          <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
            <path d="M40 0H0V40" fill="none" stroke="var(--line-soft)" strokeWidth="0.5" opacity="0.4" />
          </pattern>
          <filter id="glow" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="3" result="b" />
            <feMerge><feMergeNode in="b" /><feMergeNode in="SourceGraphic" /></feMerge>
          </filter>
        </defs>
        <rect x="0" y="0" width={W} height={H} fill="url(#grid)" />

        <g transform={`translate(${view.x} ${view.y}) scale(${view.k})`}>
          {/* Hosting edges: hypervisor -> guest, drawn first so they sit under traffic. */}
          {hosted.map((e, i) => {
            const a = byId.get(e.from), b = byId.get(e.to)
            if (!a || !b) return null
            return (
              <line key={`h${i}`} x1={a.x} y1={a.y} x2={b.x} y2={b.y}
                stroke="var(--violet)" strokeOpacity={0.28} strokeWidth={1.1} strokeDasharray="1 3" />
            )
          })}

          {/* Traffic edges with animated flow in the direction of the conversation. */}
          {edges.map((e, i) => {
            const a = byId.get(e.from), b = byId.get(e.to)
            if (!a || !b) return null
            const lit = active === e.from || active === e.to
            const width = Math.max(0.6, Math.min(3, Math.log10(Math.max(e.bytes ?? 1, 1)) * 0.5))
            return (
              <g key={`t${i}`}>
                <line x1={a.x} y1={a.y} x2={b.x} y2={b.y}
                  stroke="var(--accent)" strokeOpacity={lit ? 0.5 : 0.12} strokeWidth={width} />
                <line x1={a.x} y1={a.y} x2={b.x} y2={b.y}
                  stroke="var(--accent)" strokeOpacity={lit ? 0.9 : 0.4} strokeWidth={width}
                  strokeDasharray="2 10" strokeLinecap="round">
                  <animate attributeName="stroke-dashoffset" from="12" to="0" dur="0.7s" repeatCount="indefinite" />
                </line>
              </g>
            )
          })}

          {/* Nodes. */}
          {placed.map((n) => {
            const color = ROLE_COLOR[n.role] ?? 'var(--text-faint)'
            const isSel = selectedId === n.id
            const isHov = hover === n.id
            const dim = active && !isSel && !isHov &&
              !edges.some((e) => (e.from === active && e.to === n.id) || (e.to === active && e.from === n.id))
            const inHeavy = n.bytes_in > n.bytes_out
            return (
              <g key={n.id} transform={`translate(${n.x} ${n.y})`}
                onMouseEnter={() => setHover(n.id)} onMouseLeave={() => setHover(null)}
                onClick={() => onSelect(n)} style={{ cursor: 'pointer', opacity: dim ? 0.35 : 1 }}>
                {/* activity pulse for online nodes with traffic */}
                {n.online && (n.bytes_in + n.bytes_out > 0) && (
                  <circle r={n.r} fill="none" stroke={inHeavy ? 'var(--amber)' : color} strokeWidth={1}>
                    <animate attributeName="r" from={n.r} to={n.r + 10} dur="2.4s" repeatCount="indefinite" />
                    <animate attributeName="stroke-opacity" from="0.5" to="0" dur="2.4s" repeatCount="indefinite" />
                  </circle>
                )}
                <circle r={n.r + (isSel || isHov ? 3 : 0)} fill={color} fillOpacity={0.18}
                  stroke={color} strokeWidth={isSel ? 2 : 1.3}
                  filter={isSel || isHov ? 'url(#glow)' : undefined} />
                <circle r={2.2} fill={color} />
                {(n.r > 9 || isHov || isSel) && (
                  <text y={n.r + 12} textAnchor="middle" fontSize={10}
                    fill="var(--text-dim)" style={{ pointerEvents: 'none', userSelect: 'none' }}>
                    {truncate(n.label, 18)}
                  </text>
                )}
                {n.virtual && <circle r={n.r + 2.5} fill="none" stroke="var(--violet)"
                  strokeWidth={0.7} strokeDasharray="2 2" opacity={0.6} />}
              </g>
            )
          })}
        </g>
      </svg>

      {/* Legend + controls, absolutely positioned so they never move with pan. */}
      <div style={{
        position: 'absolute', left: 12, bottom: 12, display: 'flex', gap: 12, flexWrap: 'wrap',
        fontSize: 10.5, color: 'var(--text-faint)', background: 'color-mix(in srgb, var(--bg) 80%, transparent)',
        padding: '6px 10px', borderRadius: 8, border: '1px solid var(--line-soft)', backdropFilter: 'blur(6px)',
      }}>
        {[['gateway', 'gateway'], ['hypervisor', 'hypervisor'], ['nas', 'storage'],
          ['server', 'server'], ['workstation', 'endpoint'], ['iot', 'iot']].map(([role, label]) => (
          <span key={role} style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}>
            <span style={{ width: 8, height: 8, borderRadius: 999, background: ROLE_COLOR[role] }} />
            {label}
          </span>
        ))}
      </div>
      <div style={{ position: 'absolute', right: 12, top: 12, display: 'flex', gap: 6 }}>
        <button className="btn sm" onClick={() => setView({ x: 0, y: 0, k: 1 })}>Reset</button>
      </div>
      <div style={{ position: 'absolute', right: 12, bottom: 12, fontSize: 10, color: 'var(--text-faint)' }}>
        scroll to zoom · drag to pan
      </div>
    </div>
  )
}

/** layout computes deterministic node positions. */
function layout(graph: TopoGraph) {
  const nodes = graph.nodes ?? []
  const byId = new Map(nodes.map((n) => [n.id, n]))
  const childrenOf = new Map<string, TopoNode[]>()
  const roots: TopoNode[] = []
  for (const n of nodes) {
    if (n.parent_id && byId.has(n.parent_id)) {
      const a = childrenOf.get(n.parent_id) ?? []
      a.push(n); childrenOf.set(n.parent_id, a)
    } else roots.push(n)
  }

  const cx = W / 2, cy = H / 2 - 20
  const placed: Placed[] = []
  const sizeOf = (n: TopoNode) => {
    const t = Math.log10(Math.max(n.bytes_in + n.bytes_out, 1))
    return Math.max(6, Math.min(16, 6 + t * 1.2))
  }

  const gateway = roots.find((n) => n.role === 'gateway')
  if (gateway) placed.push({ ...gateway, x: cx, y: cy, r: sizeOf(gateway) + 3 })

  const infra = roots.filter((n) => n !== gateway && INFRA.has(n.role))
  const endpoints = roots.filter((n) => n !== gateway && !INFRA.has(n.role))

  // Inner ring: infrastructure.
  const rInner = 190
  infra.forEach((n, i) => {
    const ang = (i / Math.max(infra.length, 1)) * Math.PI * 2 - Math.PI / 2
    const x = cx + Math.cos(ang) * rInner
    const y = cy + Math.sin(ang) * rInner
    placed.push({ ...n, x, y, r: sizeOf(n) + (n.role === 'hypervisor' ? 3 : 1) })
    // Guests orbit their host in a fan pointing outward from centre.
    const kids = childrenOf.get(n.id) ?? []
    const spread = Math.min(Math.PI * 1.1, 0.35 + kids.length * 0.14)
    const rk = 62 + Math.min(30, kids.length * 2)
    kids.forEach((c, j) => {
      const a = ang - spread / 2 + (kids.length > 1 ? (j / (kids.length - 1)) * spread : spread / 2)
      placed.push({ ...c, x: x + Math.cos(a) * rk, y: y + Math.sin(a) * rk, r: sizeOf(c) })
    })
  })

  // Outer ring: endpoints.
  const rOuter = 300
  endpoints.forEach((n, i) => {
    const ang = (i / Math.max(endpoints.length, 1)) * Math.PI * 2 - Math.PI / 2 + 0.15
    placed.push({
      ...n, x: cx + Math.cos(ang) * rOuter, y: cy + Math.sin(ang) * rOuter, r: sizeOf(n),
    })
  })

  const hosted = (graph.edges ?? []).filter((e) => e.kind === 'hosts')
  // Cap traffic edges so a busy network stays readable; the heaviest survive.
  const traffic = (graph.edges ?? [])
    .filter((e) => e.kind === 'traffic')
    .sort((a, b) => (b.bytes ?? 0) - (a.bytes ?? 0))
    .slice(0, 60)

  return { placed, edges: traffic, hosted }
}

function truncate(s: string, n: number) {
  return s.length > n ? s.slice(0, n - 1) + '…' : s
}

/** MiniStat renders a compact figure for the top strip. */
export function trafficSummary(graph: TopoGraph) {
  const nodes = graph.nodes ?? []
  const din = nodes.reduce((a, n) => a + n.bytes_in, 0)
  const dout = nodes.reduce((a, n) => a + n.bytes_out, 0)
  const top = [...nodes].sort((a, b) => (b.bytes_in + b.bytes_out) - (a.bytes_in + a.bytes_out)).slice(0, 5)
  return { din, dout, top, label: `${bytes(din)} in · ${bytes(dout)} out` }
}
