import { useState } from 'react'
import { api } from '../api'
import { usePoll } from '../hooks'
import { Card, Loading, Segmented, Stat } from '../ui'
import { Chart, type Series } from '../Chart'
import { bits, compact } from '../format'

const RANGES = [
  { value: '1', label: '1h' },
  { value: '6', label: '6h' },
  { value: '24', label: '24h' },
  { value: '168', label: '7d' },
  { value: '336', label: '14d' },
] as const

export function AnalyticsPage() {
  const [hours, setHours] = useState('24')
  const h = Number(hours)
  const pts = 240

  const tin = usePoll(() => api.series('throughput_in', h, pts), 15000, [hours])
  const tout = usePoll(() => api.series('throughput_out', h, pts), 15000, [hours])
  const q = usePoll(() => api.series('dns_queries_total', h, pts), 15000, [hours])
  const bl = usePoll(() => api.series('dns_blocked_total', h, pts), 15000, [hours])
  const flows = usePoll(() => api.series('flows_active', h, pts), 15000, [hours])

  if (!tin.data) return <Loading what="analytics" />

  const thru: Series[] = [
    { points: tout.data?.points ?? [], color: 'var(--accent)', label: 'Up' },
    { points: tin.data?.points ?? [], color: 'var(--blue)', label: 'Down' },
  ]
  const dns: Series[] = [
    { points: q.data?.points ?? [], color: 'var(--blue)', label: 'Queries/min', rate: true },
    { points: bl.data?.points ?? [], color: 'var(--red)', label: 'Blocked/min', rate: true },
  ]
  const flowSeries: Series[] = [
    { points: flows.data?.points ?? [], color: 'var(--violet)', label: 'Active flows' },
  ]

  const lastQ = rateLast(q.data?.points)
  const lastB = rateLast(bl.data?.points)
  const blockRate = lastQ > 0 ? (lastB / lastQ) * 100 : 0
  const peakUp = Math.max(0, ...(tout.data?.points ?? []).map((p) => p.v))
  const peakDown = Math.max(0, ...(tin.data?.points ?? []).map((p) => p.v))

  return (
    <div style={{ display: 'grid', gap: 12 }}>
      <div className="toolbar" style={{ marginBottom: 0 }}>
        <Segmented value={hours} onChange={setHours}
          options={RANGES.map((r) => ({ value: r.value, label: r.label }))} />
        <div className="spacer" style={{ flex: 1 }} />
        <span style={{ fontSize: 11.5, color: 'var(--text-faint)' }}>up to 14 days retained</span>
      </div>

      <div className="grid c4">
        <Stat label="Peak down" value={bits(peakDown)} tone="blue" />
        <Stat label="Peak up" value={bits(peakUp)} tone="accent" />
        <Stat label="DNS / min" value={compact(lastQ)} sub="recent rate" />
        <Stat label="Block rate" value={`${blockRate.toFixed(1)}%`} tone={blockRate > 0 ? 'amber' : undefined} />
      </div>

      <Card title="Throughput" actions={<Legend items={[['Down', 'var(--blue)'], ['Up', 'var(--accent)']]} />}>
        <Chart series={thru} height={190} />
      </Card>

      <Card title="DNS: queries vs blocked"
        actions={<Legend items={[['Queries', 'var(--blue)'], ['Blocked', 'var(--red)']]} />}>
        <Chart series={dns} height={170} />
      </Card>

      <Card title="Active connections">
        <Chart series={flowSeries} height={150} />
      </Card>
    </div>
  )
}

function Legend({ items }: { items: Array<[string, string]> }) {
  return (
    <div style={{ display: 'flex', gap: 12 }}>
      {items.map(([label, color]) => (
        <span key={label} style={{ display: 'inline-flex', alignItems: 'center', gap: 5,
          fontSize: 11, color: 'var(--text-dim)' }}>
          <span style={{ width: 9, height: 2.5, borderRadius: 2, background: color }} />{label}
        </span>
      ))}
    </div>
  )
}

// rateLast returns the last per-minute delta of a cumulative counter series.
function rateLast(points?: Array<{ t: number; v: number }>): number {
  if (!points || points.length < 2) return 0
  const a = points[points.length - 2], b = points[points.length - 1]
  const dt = (b.t - a.t) / 60
  return dt > 0 ? Math.max(0, (b.v - a.v) / dt) : 0
}
