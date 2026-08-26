import { useMemo, useState } from 'react'
import { api } from '../api'
import { usePoll } from '../hooks'
import { Card, Empty, Icons, Loading, Search, Segmented, useToast } from '../ui'
import { ago, dateTime } from '../format'
import type { EventItem } from '../types'

export function EventsPage() {
  const [severity, setSeverity] = useState('')
  const [unackOnly, setUnackOnly] = useState(false)
  const [query, setQuery] = useState('')
  const [expanded, setExpanded] = useState<string | null>(null)
  const [showAudit, setShowAudit] = useState(false)

  const { data, refresh } = usePoll(
    () => api.events.list({ hours: 168, severity: severity || undefined, unack_only: unackOnly, limit: 400 }),
    20000, [severity, unackOnly],
  )
  const { data: audit } = usePoll(() => api.audit(200), showAudit ? 20000 : 0, [showAudit])
  const toast = useToast()

  const rows = useMemo(() => {
    const q = query.toLowerCase()
    return (data?.events ?? []).filter(
      (e) => !q || [e.title, e.detail, e.category].filter(Boolean).join(' ').toLowerCase().includes(q),
    )
  }, [data, query])

  return (
    <div style={{ display: 'grid', gap: 14 }}>
      <div className="toolbar" style={{ marginBottom: 0 }}>
        <Search value={query} onChange={setQuery} placeholder="Search events…" />
        <select className="select" style={{ width: 140 }} value={severity} onChange={(e) => setSeverity(e.target.value)}>
          <option value="">All severities</option>
          <option value="critical">Critical</option>
          <option value="warning">Warning</option>
          <option value="notice">Notice</option>
          <option value="info">Info</option>
        </select>
        <Segmented value={unackOnly ? 'open' : 'all'} onChange={(v) => setUnackOnly(v === 'open')}
          options={[{ value: 'all', label: 'All' }, { value: 'open', label: 'Unacknowledged' }]} />
        <div style={{ flex: 1 }} />
        <Segmented value={showAudit ? 'audit' : 'events'} onChange={(v) => setShowAudit(v === 'audit')}
          options={[{ value: 'events', label: 'Events' }, { value: 'audit', label: 'Audit log' }]} />
        <button className="btn sm" onClick={refresh}><Icons.refresh size={13} /></button>
      </div>

      {showAudit ? (
        <Card flush>
          {!audit ? <Loading what="audit log" /> : audit.entries.length === 0 ? (
            <Empty title="Nothing recorded yet">
              Every change made through the UI, the API or the assistant lands here.
            </Empty>
          ) : (
            <div className="table-wrap" style={{ maxHeight: 'calc(100vh - 190px)' }}>
              <table className="t">
                <thead><tr><th style={{ width: 130 }}>When</th><th>Actor</th><th>Action</th>
                  <th>Target</th><th>Result</th></tr></thead>
                <tbody>
                  {audit.entries.map((a) => (
                    <tr key={a.id}>
                      <td style={{ fontSize: 11.5, color: 'var(--text-faint)' }}>{dateTime(a.ts)}</td>
                      <td className="truncate" style={{ maxWidth: 180, fontSize: 12 }}>{a.actor}</td>
                      <td className="mono" style={{ fontSize: 11.5 }}>{a.action}</td>
                      <td className="truncate mono" style={{ maxWidth: 240, fontSize: 11, color: 'var(--text-dim)' }}>
                        {a.target || '—'}
                      </td>
                      <td>
                        <span className={`tag ${a.result === 'ok' ? 'allow' : a.result === 'error' ? 'block' : ''}`}>
                          {a.result || '—'}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      ) : (
        <Card flush>
          {!data ? <Loading what="events" /> : rows.length === 0 ? (
            <Empty title="Nothing to report">
              Events cover new devices, detected anomalies, subsystem failures and automatic blocks.
            </Empty>
          ) : (
            <div style={{ display: 'grid' }}>
              {rows.map((e) => (
                <EventRow key={e.id} event={e} expanded={expanded === e.id}
                  onToggle={() => setExpanded(expanded === e.id ? null : e.id)}
                  onAck={async () => {
                    await api.events.ack(e.id)
                    toast('Acknowledged', 'ok')
                    refresh()
                  }} />
              ))}
            </div>
          )}
        </Card>
      )}
    </div>
  )
}

function EventRow({ event, expanded, onToggle, onAck }: {
  event: EventItem; expanded: boolean; onToggle: () => void; onAck: () => void
}) {
  const tone = event.severity === 'critical' ? 'block'
    : event.severity === 'warning' ? 'warn'
    : event.severity === 'notice' ? 'info' : ''

  return (
    <div style={{
      borderBottom: '1px solid var(--line-soft)',
      background: event.acknowledged ? undefined : 'rgba(255,255,255,.012)',
    }}>
      <div style={{ display: 'flex', gap: 11, alignItems: 'flex-start', padding: '11px 14px', cursor: 'pointer' }}
        onClick={onToggle}>
        <span className={`tag ${tone}`} style={{ marginTop: 1, minWidth: 62, justifyContent: 'center' }}>
          {event.severity}
        </span>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontSize: 13 }}>{event.title}</div>
          <div style={{ fontSize: 11, color: 'var(--text-faint)', marginTop: 2 }}>
            {event.category} · {ago(event.ts)}
          </div>
          {expanded && event.detail && (
            <div style={{
              marginTop: 9, fontSize: 12.5, color: 'var(--text-dim)',
              whiteSpace: 'pre-wrap', lineHeight: 1.65,
            }}>{event.detail}</div>
          )}
          {expanded && event.data && Object.keys(event.data).length > 0 && (
            <pre style={{
              marginTop: 9, background: 'var(--bg-2)', border: '1px solid var(--line-soft)',
              borderRadius: 7, padding: '9px 11px', fontSize: 11, overflow: 'auto',
            }}>{JSON.stringify(event.data, null, 2)}</pre>
          )}
        </div>
        {!event.acknowledged && (
          <button className="btn sm" onClick={(ev) => { ev.stopPropagation(); onAck() }}>
            <Icons.check size={12} /> Ack
          </button>
        )}
      </div>
    </div>
  )
}
