import { useState } from 'react'
import { api } from '../api'
import { usePoll } from '../hooks'
import { Card, Icons, Loading, Segmented, Stat, useToast } from '../ui'
import { bytes, compact } from '../format'

const RANGES = [
  { value: '24', label: 'Last 24h' },
  { value: '168', label: 'Last 7 days' },
  { value: '336', label: 'Last 14 days' },
]

export function ReportsPage() {
  const [hours, setHours] = useState('168')
  const h = Number(hours)
  const { data } = usePoll(() => api.report.preview(h), 0, [hours])
  const toast = useToast()

  if (!data) return <Loading what="report" />

  const dl = (format: 'csv' | 'html') => {
    // Same-origin download; the browser handles the auth cookie.
    window.open(api.report.downloadURL(h, format), '_blank')
    toast(`${format.toUpperCase()} opened`, 'ok')
  }

  return (
    <div style={{ display: 'grid', gap: 12 }}>
      <div className="toolbar" style={{ marginBottom: 0 }}>
        <Segmented value={hours} onChange={setHours}
          options={RANGES.map((r) => ({ value: r.value, label: r.label }))} />
        <div className="spacer" style={{ flex: 1 }} />
        <button className="btn sm" onClick={() => dl('html')}><Icons.download size={13} /> HTML / print</button>
        <button className="btn sm" onClick={() => dl('csv')}><Icons.download size={13} /> CSV</button>
      </div>

      <div className="grid c4">
        <Stat label="DNS queries" value={compact(data.dns_queries)} />
        <Stat label="Blocked" value={`${data.block_rate.toFixed(1)}%`} tone="amber" sub={compact(data.dns_blocked)} />
        <Stat label="Downloaded" value={bytes(data.bytes_in)} tone="blue" />
        <Stat label="Uploaded" value={bytes(data.bytes_out)} tone="accent" />
      </div>

      <div className="grid c2">
        <RankCard title="Top talkers" rows={data.top_talkers} render={bytes} />
        <RankCard title="Most blocked" rows={data.top_blocked} render={(v) => compact(v)} />
      </div>
      <div className="grid c2">
        <RankCard title="Top countries" rows={data.top_countries} render={(v) => `${compact(v)} conns`} />
        <Card title="New devices">
          {data.new_devices.length === 0 ? (
            <div style={{ fontSize: 12.5, color: 'var(--text-faint)', padding: '8px 0' }}>
              None joined in this window.
            </div>
          ) : (
            <div style={{ display: 'grid', gap: 5 }}>
              {data.new_devices.map((d) => (
                <div key={d} style={{ fontSize: 12.5, display: 'flex', gap: 8, alignItems: 'center' }}>
                  <Icons.plus size={12} /> {d}
                </div>
              ))}
            </div>
          )}
        </Card>
      </div>

      <Card title="Scheduled delivery">
        <div className="hint">
          A recurring summary can be emailed automatically. Enable it under Alerts → Delivery and set
          the cadence in config (<span className="mono">notify.report</span>). It uses the same email
          sink as alerts.
        </div>
      </Card>
    </div>
  )
}

function RankCard({ title, rows, render }: {
  title: string; rows: Array<{ label: string; value: number }>; render: (v: number) => string
}) {
  const max = rows[0]?.value || 1
  return (
    <Card title={title}>
      {rows.length === 0 ? (
        <div style={{ fontSize: 12.5, color: 'var(--text-faint)', padding: '8px 0' }}>No data yet.</div>
      ) : (
        <div style={{ display: 'grid', gap: 7 }}>
          {rows.map((r) => (
            <div key={r.label} style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <span style={{ fontSize: 12.5, width: 150, overflow: 'hidden', textOverflow: 'ellipsis',
                whiteSpace: 'nowrap' }}>{r.label}</span>
              <div style={{ flex: 1, height: 6, borderRadius: 3, background: 'var(--line-soft)', overflow: 'hidden' }}>
                <div style={{ width: `${(r.value / max) * 100}%`, height: '100%',
                  background: 'linear-gradient(90deg, var(--accent), var(--blue))' }} />
              </div>
              <span className="mono" style={{ fontSize: 11, color: 'var(--text-faint)', width: 84, textAlign: 'right' }}>
                {render(r.value)}
              </span>
            </div>
          ))}
        </div>
      )}
    </Card>
  )
}
