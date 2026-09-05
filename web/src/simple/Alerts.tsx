import { useState } from 'react'
import { api } from '../api'
import { usePoll } from '../hooks'
import { Dot, Empty, Loading, Segmented, useToast } from '../ui'
import { ago } from '../format'
import { Section, plainCategory } from './common'

/** What happened, in sentences. Warnings first, then the assistant's checks. */
export function SimpleAlerts({ onNavigate }: { onNavigate: (r: string) => void }) {
  const [range, setRange] = useState<'24' | '168'>('24')
  const { data, refresh } = usePoll(() => api.events.list({ hours: Number(range), limit: 200 }), 20000, [range])
  const toast = useToast()
  if (!data) return <Loading what="events" />
  const important = data.events.filter((e) => e.severity === 'warning' || e.severity === 'critical')
  const checks = data.events.filter((e) => e.category === 'ai:brief' || e.category === 'ai:review')
  const rest = data.events.filter((e) => !important.includes(e) && !checks.includes(e))

  const row = (e: typeof data.events[number]) => (
    <div key={e.id} className="alert-row">
      <Dot state={e.severity === 'critical' ? 'err' : e.severity === 'warning' ? 'warn' : e.severity === 'notice' ? 'warn' : 'on'} />
      <div>
        <div className="title">{e.title}</div>
        {e.detail && <div className="detail">{e.detail.length > 400 ? `${e.detail.slice(0, 400)}…` : e.detail}</div>}
        <div className="when" style={{ marginTop: 4 }}>{plainCategory(e.category)} · {ago(e.ts)}</div>
      </div>
      <div>
        {!e.acknowledged && (e.severity === 'warning' || e.severity === 'critical') && (
          <button className="btn sm" onClick={async () => { try { await api.events.ack(e.id); refresh() } catch (err) { toast(err instanceof Error ? err.message : 'Could not mark it', 'err') } }}>Seen it</button>
        )}
      </div>
    </div>
  )

  return (
    <div style={{ display: 'grid', gap: 6, maxWidth: 900 }}>
      <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap', marginBottom: 8 }}>
        <Segmented value={range} onChange={setRange} options={[{ value: '24', label: 'Today' }, { value: '168', label: 'This week' }]} />
        <div style={{ flex: 1 }} />
        <button className="btn sm" onClick={() => onNavigate('problems')}>Something is broken? Report it</button>
        <button className="btn sm" onClick={() => onNavigate('events')}>Full log</button>
      </div>
      <Section title="Needs a look" hint={important.length ? undefined : 'Nothing serious.'}>
        {important.length ? <div>{important.map(row)}</div> : <Empty title="All quiet" />}
      </Section>
      <Section title="Network checks" hint="The assistant reads the network every few hours and writes a short note.">
        {checks.length ? <div>{checks.map(row)}</div> : <Empty title="No checks yet">Turn on scheduled checks in Settings, or press Check now on the home page.</Empty>}
      </Section>
      {rest.length > 0 && (
        <Section title="Everything else">
          <div>{rest.slice(0, 40).map(row)}</div>
        </Section>
      )}
    </div>
  )
}
