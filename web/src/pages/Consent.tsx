import { useMemo } from 'react'
import { api } from '../api'
import { usePoll } from '../hooks'
import { Banner, Card, Empty, Icons, Loading, Stat, useConfirm, useToast } from '../ui'
import { ago, clientName } from '../format'
import type { ConsentRequest } from '../types'

// Ask-on-first-connection. This is the one screen where doing nothing is a
// valid state: an empty queue means every destination an enrolled device has
// reached already has a decision.
export function ConsentPage() {
  const { data, refresh } = usePoll(() => api.consent.status(), 4000)
  const { data: clients } = usePoll(() => api.clients.list(), 30000)
  const toast = useToast()
  const confirm = useConfirm()

  const byID = useMemo(() => {
    const m = new Map<string, string>()
    for (const c of clients?.clients ?? []) m.set(c.id, clientName(c))
    return m
  }, [clients])

  if (!data) return <Loading what="pending connections" />

  const decide = async (req: ConsentRequest, decision: 'allow' | 'deny', scope: 'device' | 'network') => {
    try {
      await api.consent.decide(req.id, decision, scope)
      refresh()
    } catch (e) {
      toast(e instanceof Error ? e.message : 'Could not record decision', 'err')
    }
  }

  const toggleEnrol = async (id: string) => {
    const next = data.enrolled.includes(id)
      ? data.enrolled.filter((x) => x !== id)
      : [...data.enrolled, id]
    try {
      await api.consent.enrol(next)
      refresh()
    } catch (e) {
      toast(e instanceof Error ? e.message : 'Could not change enrolment', 'err')
    }
  }

  const forget = async (clientID: string, host: string, scope: string) => {
    if (!(await confirm(`Forget the decision for ${host}? The next connection will ask again.`))) return
    try {
      await api.consent.forget(clientID, host, scope)
      refresh()
    } catch (e) {
      toast(e instanceof Error ? e.message : 'Could not forget', 'err')
    }
  }

  return (
    <div style={{ display: 'grid', gap: 14 }}>
      <Banner tone={data.enrolled.length ? 'info' : 'warn'}>
        <strong style={{ display: 'block', marginBottom: 3 }}>
          Ask before a device reaches somewhere new
        </strong>
        The rest of Orbis is observe-then-block: a new destination is allowed until someone notices
        it. This inverts that for the devices you enrol. The first time one reaches a hostname it
        has never reached before, it lands here and waits for you. It is per-device on purpose:
        enrolling the whole house produces hundreds of questions on the first day and gets switched
        off within the hour. Point it at one suspicious device, or at a gadget that should only ever
        talk to two hosts.
      </Banner>

      <div className="grid c3">
        <Stat label="Waiting" value={String(data.pending.length)}
          tone={data.pending.length ? 'amber' : undefined} />
        <Stat label="Enrolled devices" value={String(data.enrolled.length)} />
        <Stat label="Decisions made" value={String(data.rules.length)} />
      </div>

      <Card
        title="Waiting for a decision"
        actions={data.pending.length > 0 ? (
          <button className="btn sm" onClick={async () => {
            if (!(await confirm('Discard every pending question without deciding?'))) return
            await api.consent.clear()
            refresh()
          }}>Clear queue</button>
        ) : undefined}
      >
        {data.pending.length === 0 ? (
          <Empty title="Nothing waiting">
            {data.enrolled.length === 0
              ? 'Enrol a device below to start asking.'
              : 'Every destination these devices have reached already has a decision.'}
          </Empty>
        ) : (
          <div style={{ display: 'grid', gap: 10 }}>
            {data.pending.map((p) => (
              <div key={p.id} style={{
                border: '1px solid var(--line-soft)', borderRadius: 8, padding: 11,
              }}>
                <div style={{ display: 'flex', alignItems: 'baseline', gap: 8, flexWrap: 'wrap' }}>
                  <strong style={{ fontSize: 13.5 }}>{p.host}</strong>
                  <span className="tag" style={{ fontSize: 10.5 }}>{p.proto}/{p.port}</span>
                  {p.app && <span className="tag info" style={{ fontSize: 10.5 }}>{p.app}</span>}
                  {p.count > 1 && (
                    <span style={{ fontSize: 11, color: 'var(--amber)' }}>
                      tried {p.count} times
                    </span>
                  )}
                </div>
                <div style={{ fontSize: 11.5, color: 'var(--text-dim)', margin: '4px 0 9px' }}>
                  {byID.get(p.client_id) ?? p.client_ip} reached {p.dst_ip}
                  {p.as_org ? ` · ${p.as_org}` : ''}
                  {p.country ? ` · ${p.country}` : ''}
                  {' · first seen '}{ago(p.first_seen)}
                </div>
                <div style={{ display: 'flex', gap: 7, flexWrap: 'wrap' }}>
                  <button className="btn sm primary" onClick={() => decide(p, 'allow', 'device')}>
                    <Icons.check size={13} /> Allow for this device
                  </button>
                  <button className="btn sm danger" onClick={() => decide(p, 'deny', 'device')}>
                    <Icons.close size={13} /> Deny for this device
                  </button>
                  <button className="btn sm" onClick={() => decide(p, 'deny', 'network')}
                    title="Deny this host for every device, now and in future">
                    Deny everywhere
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>

      <Card title="Enrolled devices">
        <div className="hint" style={{ marginBottom: 10 }}>
          Only these devices generate questions. Everything else keeps the normal behaviour.
        </div>
        {(clients?.clients ?? []).length === 0 ? (
          <Empty title="No devices known yet" />
        ) : (
          <div style={{ display: 'grid', gap: 6, maxHeight: 320, overflow: 'auto' }}>
            {(clients?.clients ?? []).map((c) => {
              const on = data.enrolled.includes(c.id)
              return (
                <label key={c.id} style={{
                  display: 'flex', alignItems: 'center', gap: 9, cursor: 'pointer',
                  fontSize: 12.5, padding: '3px 0',
                }}>
                  <input type="checkbox" checked={on} onChange={() => toggleEnrol(c.id)} />
                  <span className={`dot ${c.online ? 'on' : 'off'}`} />
                  <span style={{ flex: 1, minWidth: 0 }}>{clientName(c)}</span>
                  <span className="mono" style={{ fontSize: 11, color: 'var(--text-faint)' }}>{c.ip}</span>
                </label>
              )
            })}
          </div>
        )}
      </Card>

      <Card title="Decisions">
        {data.rules.length === 0 ? (
          <Empty title="No decisions yet" />
        ) : (
          <div style={{ display: 'grid', gap: 7 }}>
            {data.rules.map((r) => (
              <div key={`${r.scope}-${r.client_id}-${r.host}`}
                style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <span className={`dot ${r.decision === 'allow' ? 'on' : 'err'}`} />
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: 12.5 }}>{r.host}</div>
                  <div style={{ fontSize: 11, color: 'var(--text-faint)' }}>
                    {r.decision} · {r.scope === 'network' ? 'every device' : (byID.get(r.client_id) ?? r.client_id)}
                    {' · '}{ago(r.decided_at)}
                  </div>
                </div>
                <button className="btn sm" title="Ask again next time"
                  onClick={() => forget(r.client_id, r.host, r.scope)}>
                  <Icons.trash size={13} />
                </button>
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  )
}
