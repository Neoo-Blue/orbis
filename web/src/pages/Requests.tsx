import { useMemo, useState } from 'react'
import { api } from '../api'
import { clientName, ago } from '../format'
import { usePoll } from '../hooks'
import { useLiveBatch } from '../live'
import { Card, CopyButton, Empty, Loading, Switch, useToast } from '../ui'
import type { UnblockRequest } from '../types'

const HOUR = 60, DAY = 1440
const PHONE = 'Phone'

function until(r: UnblockRequest) {
  if (!r.until || r.until.startsWith('0001')) return 'until you end it'
  return `until ${new Date(r.until).toLocaleString([], { hour: 'numeric', minute: '2-digit', weekday: 'short' })}`
}

export function useUnblock() {
  const state = usePoll(() => api.unblock.list(), 15000)
  useLiveBatch(['unblock.pending', 'unblock.decided'], () => state.refresh())
  return state
}

/** One ask. It is answered here, in place, in one tap. */
export function RequestRow({ r, onDone }: { r: UnblockRequest; onDone: () => void }) {
  const toast = useToast()
  const answer = async (allow: boolean, minutes: number, everyone: boolean, done: string) => {
    try {
      await api.unblock.decide(r.id, { allow, minutes, everyone })
      toast(done, allow ? 'ok' : 'info')
      onDone()
    } catch (e) {
      toast(e instanceof Error ? e.message : 'Could not answer that', 'err')
    }
  }
  return (
    <div className="request">
      <div className="request-title"><b>{r.device}</b> asks for <span className="mono">{r.host}</span></div>
      {r.note && <div className="request-note">{r.note}</div>}
      <div className={`request-why${r.risky ? ' risky' : ''}`}>{r.risky ? `On a threat list. ${r.why ?? ''}` : r.why}</div>
      <div className="request-acts">
        <button className="btn sm primary" onClick={() => void answer(true, HOUR, false, `${r.device} can open ${r.host} for an hour`)}>1 hour</button>
        <button className="btn sm" onClick={() => void answer(true, DAY, false, `${r.device} can open ${r.host} today`)}>Today</button>
        {!r.risky && <button className="btn sm" onClick={() => void answer(true, 0, false, `${r.device} can always open ${r.host}`)}>Always</button>}
        <button className="btn sm" onClick={() => void answer(false, 0, false, `Said no to ${r.device}`)}>Deny</button>
      </div>
    </div>
  )
}

/** Requests reach a phone through ntfy: a free app, no account, and nothing
 *  opened on this network. The topic is random, because it is the only secret. */
function PhoneCard() {
  const { data, refresh } = usePoll(() => api.notify.get(), 0)
  const toast = useToast()
  const [topic] = useState(() => `orbis-${[...crypto.getRandomValues(new Uint8Array(10))].map((b) => b.toString(16).padStart(2, '0')).join('')}`)
  const on = (data?.webhooks ?? []).some((h) => h.name === PHONE && h.enabled)
  const run = async (fn: () => Promise<unknown>, done: string) => {
    try { await fn(); toast(done, 'ok'); refresh() } catch (e) { toast(e instanceof Error ? e.message : 'That did not work', 'err') }
  }
  const enable = () => run(async () => {
    await api.notify.saveWebhook({ name: PHONE, enabled: true, url: `https://ntfy.sh/${topic}`, format: 'ntfy', headers: {}, only: 'unblock' })
    await api.config.patch({ 'notify.enabled': true })
  }, 'Requests will reach your phone')
  return (
    <Card title="Answer from your phone" actions={on ? <span className="tag allow">On</span> : undefined}>
      {on ? (
        <div style={{ display: 'grid', gap: 10 }}>
          <p className="hint">Each request reaches your phone with Allow 1 hour and Deny on the notification. Your phone has to be on home Wi-Fi or Tailscale for the buttons to work.</p>
          <div style={{ display: 'flex', gap: 8 }}>
            <button className="btn sm" onClick={() => void run(() => api.notify.test(), 'Test sent')}>Send a test</button>
            <button className="btn sm" onClick={() => void run(() => api.notify.deleteWebhook(PHONE), 'Phone alerts are off')}>Turn off</button>
          </div>
        </div>
      ) : (
        <ol className="phone-steps">
          <li>Install the free <b>ntfy</b> app on your phone.</li>
          <li>In the app, subscribe to this topic: <span className="mono">{topic}</span> <CopyButton text={topic} /></li>
          <li><button className="btn sm primary" onClick={() => void enable()}>Turn on phone alerts</button></li>
        </ol>
      )}
    </Card>
  )
}

export function RequestsPage() {
  const { data, refresh } = useUnblock()
  const { data: clients, } = usePoll(() => api.clients.list(), 30000)
  const toast = useToast()
  const devices = useMemo(() => [...(clients?.clients ?? [])].sort((a, b) => clientName(a).localeCompare(clientName(b))), [clients])
  if (!data) return <Loading what="requests" />
  const trusted = new Set(data.trusted)
  const trust = async (id: string, on: boolean) => {
    try { await api.unblock.trust(id, on); refresh() } catch (e) { toast(e instanceof Error ? e.message : 'Could not change that', 'err') }
  }
  const revoke = async (r: UnblockRequest) => {
    try { await api.unblock.revoke(r.id); toast(`${r.host} is blocked again`, 'ok'); refresh() } catch (e) { toast(e instanceof Error ? e.message : 'Could not end that', 'err') }
  }
  return (
    <div style={{ display: 'grid', gap: 14 }}>
      <Card title="Waiting for you">
        {data.pending.length === 0
          ? <Empty title="No one is waiting">When someone asks to open a blocked site from the block page, it appears here.</Empty>
          : <div className="stack-in" style={{ display: 'grid', gap: 12 }}>{data.pending.map((r) => <RequestRow key={r.id} r={r} onDone={refresh} />)}</div>}
      </Card>
      <PhoneCard />
      <div className="grid c2">
        <Card title="Open right now">
          {data.grants.length === 0
            ? <Empty title="Nothing is open">Sites you approve appear here until they end.</Empty>
            : <div className="stack-in" style={{ display: 'grid', gap: 6 }}>{data.grants.map((r) => (
              <div key={r.id} className="grant">
                <div style={{ minWidth: 0, flex: 1 }}>
                  <div className="mono truncate" title={r.host}>{r.host}</div>
                  <div className="hint">{r.everyone ? 'Everyone' : r.device}, {until(r)}</div>
                </div>
                <button className="btn sm" onClick={() => void revoke(r)}>End now</button>
              </div>
            ))}</div>}
        </Card>
        <Card title="Your devices">
          <p className="hint" style={{ marginBottom: 10 }}>
            A trusted device gets Unblock for an hour on the block page, with no request. Trust goes by device on this network, so keep it to devices that are yours.
          </p>
          <div className="stack-in" style={{ display: 'grid', gap: 4, maxHeight: 320, overflowY: 'auto' }}>
            {devices.map((c) => (
              <Switch key={c.id} checked={trusted.has(c.id)} onChange={(v) => void trust(c.id, v)} label={clientName(c)} />
            ))}
          </div>
        </Card>
      </div>
      {data.past.length > 0 && (
        <Card title="Earlier">
          <div style={{ display: 'grid', gap: 6 }}>
            {data.past.map((r) => (
              <div key={r.id} className="grant">
                <span className="mono truncate" style={{ flex: 1 }} title={r.host}>{r.host}</span>
                <span className="hint">{r.device}, {r.state === 'denied' ? 'denied' : 'ended'} {ago(r.decided ?? r.asked)}</span>
              </div>
            ))}
          </div>
        </Card>
      )}
    </div>
  )
}
