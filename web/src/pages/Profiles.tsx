import { useState } from 'react'
import { api } from '../api'
import { usePoll } from '../hooks'
import { Banner, Card, Drawer, Empty, Field, Loading, Spinner, Switch, useToast } from '../ui'
import type { Policy } from '../types'
import { PRESETS } from '../simple/common'

/**
 * Profiles are per-device filtering policies with a name a family can use:
 * Kids, Homework, Guests, Unfiltered. This page is the editor both modes
 * share; assignment happens on a device.
 */
export function ProfilesPage() {
  const { data, refresh } = usePoll(() => api.policies.list(), 30000)
  const { data: bundles } = usePoll(() => api.simple.bundles(), 0)
  const { data: clients } = usePoll(() => api.clients.list(), 30000)
  const [editing, setEditing] = useState<Partial<Policy> | null>(null)
  const [busy, setBusy] = useState<string | null>(null)
  const toast = useToast()

  const usedBy = (id: string) => (clients?.clients ?? []).filter((c) => c.policy_id === id).length

  const createPreset = async (presetID: string) => {
    const p = PRESETS.find((x) => x.id === presetID)
    if (!p) return
    setBusy(presetID)
    try {
      await api.policies.save({ name: p.name, description: p.description, ...p.policy, allowlist: [], denylist: [], categories: [] })
      toast(`${p.name} profile created`, 'ok'); refresh()
    } catch (e) {
      toast(e instanceof Error ? e.message : 'Could not create the profile', 'err')
    } finally { setBusy(null) }
  }

  if (!data) return <Loading what="profiles" />
  const existing = new Set(data.policies.map((p) => p.name.toLowerCase()))
  return (
    <div style={{ display: 'grid', gap: 14, maxWidth: 960 }}>
      <Banner tone="info">
        A profile decides what is filtered for the devices assigned to it: which apps are switched off, safe search,
        whether blocklists apply at all. Assign one to a device from Devices → Edit.
      </Banner>

      <Card title="Start from a preset" flush>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 10, padding: 14 }}>
          {PRESETS.map((p) => (
            <div key={p.id} className="tile" style={{ cursor: 'default' }}>
              <div style={{ fontWeight: 600, fontSize: 14 }}>{p.name}</div>
              <div className="hint" style={{ minHeight: 42 }}>{p.description}</div>
              <div>
                <button className="btn sm primary" disabled={busy === p.id || existing.has(p.name.toLowerCase())} onClick={() => createPreset(p.id)}>
                  {existing.has(p.name.toLowerCase()) ? 'Created' : busy === p.id ? <Spinner /> : 'Create'}
                </button>
              </div>
            </div>
          ))}
        </div>
      </Card>

      <Card title={`${data.policies.length} profile${data.policies.length === 1 ? '' : 's'}`}
        actions={<button className="btn sm" onClick={() => setEditing({ name: '', blocked_services: [], allowlist: [], denylist: [], categories: [], safe_search: false, block_doh: true })}>New profile</button>}>
        {data.policies.length === 0 ? <Empty title="No profiles yet">Create one from a preset above, or start blank.</Empty> : (
          <div style={{ display: 'grid', gap: 8 }}>
            {data.policies.map((p) => (
              <div key={p.id} className="device-card" style={{ gridTemplateColumns: '1fr auto' }}>
                <div style={{ minWidth: 0 }}>
                  <div className="name">
                    {p.name}
                    {p.unfiltered && <span className="pill paused">nothing blocked</span>}
                    {p.safe_search && <span className="pill on">safe search</span>}
                    {(p.blocked_services ?? []).length > 0 && <span className="pill">{p.blocked_services!.length} apps off</span>}
                    {p.schedule && <span className="pill">{p.schedule}</span>}
                  </div>
                  <div className="meta">{p.description || 'No description'} · used by {usedBy(p.id)} device{usedBy(p.id) === 1 ? '' : 's'}</div>
                </div>
                <div className="actions">
                  <button className="btn sm" onClick={() => setEditing(p)}>Edit</button>
                  <button className="btn sm danger" disabled={usedBy(p.id) > 0} title={usedBy(p.id) > 0 ? 'Unassign it from its devices first' : 'Delete'}
                    onClick={async () => { if (!confirm(`Delete the ${p.name} profile?`)) return; try { await api.policies.remove(p.id); toast('Deleted', 'ok'); refresh() } catch (e) { toast(e instanceof Error ? e.message : 'Could not delete', 'err') } }}>Delete</button>
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>

      {editing && (
        <ProfileEditor policy={editing} bundles={bundles?.services ?? []} onClose={() => setEditing(null)}
          onSaved={() => { setEditing(null); refresh() }} />
      )}
    </div>
  )
}

function ProfileEditor({ policy, bundles, onClose, onSaved }: {
  policy: Partial<Policy>; bundles: Array<{ id: string; name: string }>; onClose: () => void; onSaved: () => void
}) {
  const [p, setP] = useState<Partial<Policy>>({ ...policy, blocked_services: policy.blocked_services ?? [], allowlist: policy.allowlist ?? [], denylist: policy.denylist ?? [] })
  const [busy, setBusy] = useState(false)
  const toast = useToast()
  const set = (patch: Partial<Policy>) => setP((prev) => ({ ...prev, ...patch }))
  const toggleService = (id: string) => {
    const cur = new Set(p.blocked_services ?? [])
    if (cur.has(id)) cur.delete(id); else cur.add(id)
    set({ blocked_services: [...cur] })
  }
  const listField = (label: string, key: 'allowlist' | 'denylist', hint: string) => (
    <Field label={label} hint={hint}>
      <textarea className="textarea" rows={3} value={(p[key] ?? []).join('\n')}
        onChange={(e) => set({ [key]: e.target.value.split('\n').map((x) => x.trim()).filter(Boolean) } as Partial<Policy>)} />
    </Field>
  )
  return (
    <Drawer title={p.id ? `Edit ${policy.name}` : 'New profile'} onClose={onClose}
      actions={<button className="btn primary" disabled={!p.name?.trim() || busy} onClick={async () => {
        setBusy(true)
        try {
          await api.policies.save({ ...p, name: p.name!.trim(), categories: p.categories ?? [] })
          toast('Profile saved', 'ok'); onSaved()
        } catch (e) {
          toast(e instanceof Error ? e.message : 'Could not save', 'err')
        } finally { setBusy(false) }
      }}>{busy ? <Spinner /> : 'Save'}</button>}>
      <div style={{ display: 'grid', gap: 16 }}>
        <Field label="Name"><input className="input" value={p.name ?? ''} onChange={(e) => set({ name: e.target.value })} placeholder="Kids" /></Field>
        <Field label="Description"><input className="input" value={p.description ?? ''} onChange={(e) => set({ description: e.target.value })} placeholder="What this profile is for" /></Field>

        <div style={{ display: 'grid', gap: 10 }}>
          <Switch checked={Boolean(p.unfiltered)} onChange={(v) => set({ unfiltered: v })} label="Nothing blocked on these devices (unfiltered)" />
          <div className="hint" style={{ marginTop: -6 }}>Blocklists and CNAME uncloaking are skipped. The switches below still apply.</div>
          <Switch checked={Boolean(p.safe_search)} onChange={(v) => set({ safe_search: v })} label="Safe search on Google, Bing, DuckDuckGo and YouTube" />
          <Switch checked={Boolean(p.block_doh)} onChange={(v) => set({ block_doh: v })} label="Stop these devices bypassing the filter with private DNS" />
        </div>

        <Field label="Apps switched off" hint="Whole services by name. Conservative lists, so nothing else breaks.">
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(150px, 1fr))', gap: 6 }}>
            {bundles.map((b) => (
              <label key={b.id} style={{ display: 'flex', gap: 8, alignItems: 'center', fontSize: 13, padding: '6px 8px', border: '1px solid var(--line-soft)', borderRadius: 8, cursor: 'pointer' }}>
                <input type="checkbox" checked={(p.blocked_services ?? []).includes(b.id)} onChange={() => toggleService(b.id)} />
                {b.name}
              </label>
            ))}
          </div>
        </Field>

        <Field label="Active hours" hint='Leave empty for always. Example: "mon-fri 08:00-15:00" or "daily 21:00-07:00".'>
          <input className="input mono" value={p.schedule ?? ''} onChange={(e) => set({ schedule: e.target.value })} placeholder="always" />
        </Field>

        {listField('Always allow', 'allowlist', 'One site per line. Wins over every blocklist for these devices.')}
        {listField('Always block', 'denylist', 'One site per line. Use *.example.com to include subdomains.')}
      </div>
    </Drawer>
  )
}
