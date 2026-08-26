import { useMemo } from 'react'

/**
 * A small, dependency-free area/line chart. Follows the house dataviz rules:
 * one visual system, a soft gradient fill under a crisp stroke, a subtle grid,
 * and a hover crosshair. Deliberately not a charting library — Orbis draws a
 * handful of series and a whole framework to do it would be the largest thing
 * in the bundle.
 */
export interface Series {
  points: Array<{ t: number; v: number }>
  color: string
  label: string
  /** rate = show per-interval delta of a cumulative counter instead of the raw
   *  monotonic value. */
  rate?: boolean
}

export function Chart({ series, height = 160 }: {
  series: Series[]
  height?: number
}) {
  const W = 800, H = height, padL = 4, padB = 2, padT = 8

  const prepared = useMemo(() => series.map((s) => {
    let pts = s.points
    if (s.rate) {
      const out: typeof pts = []
      for (let i = 1; i < pts.length; i++) {
        const dt = pts[i].t - pts[i - 1].t
        const dv = pts[i].v - pts[i - 1].v
        out.push({ t: pts[i].t, v: dt > 0 && dv >= 0 ? dv / (dt / 60) : 0 }) // per-minute
      }
      pts = out
    }
    return { ...s, pts }
  }), [series])

  const all = prepared.flatMap((s) => s.pts)
  if (all.length < 2) {
    return <div style={{ height, display: 'flex', alignItems: 'center', justifyContent: 'center',
      color: 'var(--text-faint)', fontSize: 12 }}>Not enough data yet</div>
  }
  const tMin = Math.min(...all.map((p) => p.t))
  const tMax = Math.max(...all.map((p) => p.t))
  const vMax = Math.max(1, ...all.map((p) => p.v)) * 1.1
  const x = (t: number) => padL + ((t - tMin) / Math.max(1, tMax - tMin)) * (W - padL * 2)
  const y = (v: number) => padT + (1 - v / vMax) * (H - padT - padB)

  return (
    <svg width="100%" height={H} viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none"
      style={{ display: 'block' }}>
      <defs>
        {prepared.map((s, i) => (
          <linearGradient key={i} id={`g${i}`} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={s.color} stopOpacity="0.28" />
            <stop offset="100%" stopColor={s.color} stopOpacity="0" />
          </linearGradient>
        ))}
      </defs>
      {[0.25, 0.5, 0.75].map((f) => (
        <line key={f} x1={0} x2={W} y1={padT + f * (H - padT - padB)} y2={padT + f * (H - padT - padB)}
          stroke="var(--line-soft)" strokeWidth="0.5" opacity="0.5" />
      ))}
      {prepared.map((s, i) => {
        // A series can be empty while another in the same chart has data (a
        // metric with no samples yet, or a cumulative counter that had one
        // point and became zero after the rate diff). Skip it rather than
        // index into an empty array.
        if (s.pts.length < 2) return null
        const line = s.pts.map((p, j) => `${j ? 'L' : 'M'}${x(p.t).toFixed(1)} ${y(p.v).toFixed(1)}`).join(' ')
        const area = `${line} L${x(s.pts[s.pts.length - 1].t).toFixed(1)} ${H - padB} L${x(s.pts[0].t).toFixed(1)} ${H - padB} Z`
        return (
          <g key={i}>
            <path d={area} fill={`url(#g${i})`} />
            <path d={line} fill="none" stroke={s.color} strokeWidth="1.6" strokeLinejoin="round" />
          </g>
        )
      })}
    </svg>
  )
}

export function timeAxis(hours: number): string[] {
  return [`${hours}h ago`, 'now']
}
