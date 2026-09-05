import { useMemo, useState } from 'react'
import { api } from '../api'
import { usePoll } from '../hooks'
import { Drawer, Empty, Field, Loading, Search, Spinner, useToast } from '../ui'
import { ago, bits, clientName, deviceGlyph } from '../format'
import type { Client, Policy } from '../types'
import { Section } from './common'

/**
 * Devices, for people. Each card is one thing in the house with the three
 * actions that matter: pause its internet, choose who it is for, give it a
 * name. Anything deeper is a tap away on the advanced Devices page.
 */
export function SimpleDevices({ onNavigate }: { onNavigate: (r: string) => void }) {
  const { data, refresh } = usePoll(() => api.clients.list(), 10000)
  const { data: policies, refresh: refreshPolicies } = usePoll(() => api.policies.list(), 30000)
  const { data: pauses, refresh: refreshPauses } = usePoll(() => api.simple.pauses(), 15000)
  const [query, setQuery] = useState('')
  const [editing, setEditing] = useState<Client | null>(null)
  const [busy, setBusy] = useState<string | null>(null)
  const toast = useToast()

  const clients = useMemo(() => {
    const q = query.trim().toLowerCase()
    return [...(data?.clients ?? [])]
      .filter((c) => !q || clientName(c).toLowerCase().includes(q) || c.ip.includes(q) || (c.vendor ?? '').toLowerCase().includes(q))
      .sort((a, b) => Number(b.online) - Number(a.online) || (b.rate_in + b.rate_out) - (a.rate_in + a.rate_out) || clientName(a).localeCompare(clientName(b)))
  }, [data, query])

  const policyName = (id?: string) => policies?.policies.find((p) => p.id === id)?.name ?? 'Normal'

  const act = async (c: Client, fn: () => Promise<unknown>, ok: string, undo?: () => Promise<unknown>) => {
    setBusy(c.id)
    try {
      await fn()
      toast(ok, 'ok', undo ? { label: 'Undo', onClick: async () => { try { await undo(); refresh(); refreshPauses() } catch { /* state refreshes anyway */ } } } : undefined)
      refresh(); refreshPauses()
    } catch (e) {
      toast(e instanceof Error ? e.message : 'That did not work', 'err')
    } finally {
      setBusy(null)
    }
  }

  if (!data) return <Loading what="devices" />
  const online = clients.filter((c) => c.online)
  const offline = clients.filter((c) => !c.online)

  const card = (c: Client) => {
    const until = pauses?.pauses[c.id]
    return (
      <div key={c.id} className={`device-card${c.blocked ? ' paused' : ''}`}>
        <div className="glyph" aria-hidden="true">{deviceGlyph(c.device_type)}</div>
        <div style={{ minWidth: 0 }}>
          <div className="name">
            <span className="truncate">{clientName(c)}</span>
            <span className={`pill ${c.blocked ? 'paused' : c.online ? 'on' : 'off'}`}>
              {c.blocked ? (until ? `paused until ${new Date(until).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' })}` : 'paused') : c.online ? 'online' : `last seen ${ago(c.last_seen)}`}
            </span>
            {c.policy_id && <span className="pill">{policyName(c.policy_id)}</span>}
          </div>
          <div className="meta">
            {c.vendor ? `${c.vendor} · ` : ''}{c.ip}{c.online && c.rate_in + c.rate_out > 1000 ? ` · using ${bits(c.rate_in + c.rate_out)}` : ''}
          </div>
        </div>
        <div className="actions">
          {c.blocked ? (
            <button className="btn sm primary" disabled={busy === c.id} onClick={() => act(c, () => api.simple.resume(c.id), `${clientName(c)} is back online`)}>
              {busy === c.id ? <Spinner /> : 'Resume internet'}
            </button>
          ) : (
            <PauseMenu disabled={busy === c.id} onPick={(min) => act(c, () => api.simple.pause(c.id, min), min ? `${clientName(c)} paused for ${min >= 60 ? `${min / 60} hour${min > 60 ? 's' : ''}` : `${min} minutes`}` : `${clientName(c)} paused until you resume it`, () => api.simple.resume(c.id))} />
          )}
          <button className="btn sm" onClick={() => setEditing(c)}>Edit</button>
        </div>
      </div>
    )
  }

  return (
    <div style={{ display: 'grid', gap: 18, maxWidth: 900 }}>
      <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
        <div style={{ flex: 1, minWidth: 200, maxWidth: 360 }}><Search value={query} onChange={setQuery} placeholder="Find a device…" /></div>
        <button className="btn sm" onClick={() => onNavigate('profiles')}>Profiles</button>
        <button className="btn sm" onClick={() => onNavigate('clients')}>Advanced view</button>
      </div>
      {clients.length === 0 && <Empty title="No devices yet">Devices appear here as soon as they use the internet through Orbis.</Empty>}
      {online.length > 0 && (
        <Section title={`Online now (${online.length})`}>
          <div style={{ display: 'grid', gap: 10 }}>{online.map(card)}</div>
        </Section>
      )}
      {offline.length > 0 && (
        <Section title={`Not connected (${offline.length})`} hint="Seen before, not online right now.">
          <div style={{ display: 'grid', gap: 10 }}>{offline.map(card)}</div>
        </Section>
      )}
      {editing && (
        <EditDevice client={editing} policies={policies?.policies ?? []} onClose={() => setEditing(null)}
          onSaved={() => { setEditing(null); refresh(); refreshPolicies() }} />
      )}
    </div>
  )
}

function PauseMenu({ onPick, disabled }: { onPick: (minutes: number) => void; disabled?: boolean }) {
  const [open, setOpen] = useState(false)
  if (!open) return <button className="btn sm" disabled={disabled} onClick={() => setOpen(true)}>Pause internet</button>
  return (
    <span style={{ display: 'inline-flex', gap: 4, flexWrap: 'wrap' }}>
      {[{ m: 30, l: '30 min' }, { m: 60, l: '1 hour' }, { m: 180, l: '3 hours' }, { m: 0, l: 'Until I resume' }].map((o) => (
        <button key={o.m} className="btn sm" onClick={() => { setOpen(false); onPick(o.m) }}>{o.l}</button>
      ))}
      <button className="btn sm" onClick={() => setOpen(false)}>Cancel</button>
    </span>
  )
}

function EditDevice({ client, policies, onClose, onSaved }: { client: Client; policies: Policy[]; onClose: () => void; onSaved: () => void }) {
  const [label, setLabel] = useState(client.label ?? '')
  const [policyId, setPolicyId] = useState(client.policy_id ?? '')
  const [busy, setBusy] = useState(false)
  const toast = useToast()
  const chosen = policies.find((p) => p.id === policyId)
  return (
    <Drawer title={clientName(client)} onClose={onClose}
      actions={<button className="btn primary" disabled={busy} onClick={async () => {
        setBusy(true)
        try {
          await api.clients.update(client.id, { label, policy_id: policyId })
          toast('Saved', 'ok'); onSaved()
        } catch (e) {
          toast(e instanceof Error ? e.message : 'Could not save', 'err')
        } finally { setBusy(false) }
      }}>{busy ? <Spinner /> : 'Save'}</button>}>
      <div style={{ display: 'grid', gap: 16 }}>
        <Field label="Name" hint="What you call it at home.">
          <input className="input" value={label} placeholder={client.hostname || client.vendor || client.ip} onChange={(e) => setLabel(e.target.value)} />
        </Field>
        <Field label="Who is it for" hint="A profile decides what is filtered on this device.">
          <select className="select" value={policyId} onChange={(e) => setPolicyId(e.target.value)}>
            <option value="">Normal (ads and trackers blocked)</option>
            {policies.map((p) => <option key={p.id} value={p.id}>{p.name}{p.unfiltered ? ' (nothing blocked)' : ''}</option>)}
          </select>
          {chosen?.description && <div className="hint" style={{ marginTop: 6 }}>{chosen.description}</div>}
        </Field>
        <div className="hint">
          {client.vendor ? `Made by ${client.vendor}. ` : ''}Address {client.ip}{client.mac ? `, hardware id ${client.mac}` : ''}.
          First seen {ago(client.first_seen)}.
        </div>
      </div>
    </Drawer>
  )
}
