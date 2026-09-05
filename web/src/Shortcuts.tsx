import { useState } from 'react'
import { api } from './api'
import { usePoll } from './hooks'
import { Card, Empty, Icons, Spinner, useToast } from './ui'
import type { DNSShortcut } from './types'

/**
 * Shortcuts: a name that includes the port. "deep.seek" -> 192.168.50.223:8080.
 * DNS answers the name with this node; Orbis then sends the browser on.
 */
export function ShortcutsCard({ compact }: { compact?: boolean } = {}) {
  const { data, refresh } = usePoll(() => api.shortcuts.list(), 0)
  const [draft, setDraft] = useState<Partial<DNSShortcut>>({ name: '', target: '', mode: 'redirect' })
  const [busy, setBusy] = useState(false)
  const toast = useToast()
  const suffix = data?.node_port && data.node_port !== '80' ? `:${data.node_port}` : ''

  const save = async () => {
    setBusy(true)
    try {
      const res = await api.shortcuts.save(draft)
      toast(`Done. Type ${res.open} in any browser on this network.`, 'ok')
      setDraft({ name: '', target: '', mode: draft.mode })
      refresh()
    } catch (e) {
      toast(e instanceof Error ? e.message : 'Could not save the shortcut', 'err')
    } finally { setBusy(false) }
  }

  return (
    <Card title={compact ? undefined : 'Shortcuts: a name for something on a port'}>
      <div className="hint" style={{ marginBottom: 11, lineHeight: 1.6 }}>
        DNS can only hold an address, never a port. A shortcut fixes that: Orbis answers the name with
        its own address and sends the browser on to the real host and port. <span className="mono">deep.seek</span> →
        <span className="mono"> 192.168.50.223:8080</span>. Works for http on every device that uses Orbis for DNS.
      </div>
      {(data?.shortcuts ?? []).length > 0 && (
        <div style={{ display: 'grid', gap: 6, marginBottom: 12 }}>
          {data!.shortcuts.map((sc) => (
            <div key={sc.name} style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
              <a className="mono" style={{ fontSize: 12.5, minWidth: 0 }} href={`http://${sc.name}${suffix}`} target="_blank" rel="noreferrer">http://{sc.name}{suffix}</a>
              <span className="hint">→</span>
              <span className="mono" style={{ fontSize: 11.5, color: 'var(--text-dim)', flex: 1, minWidth: 0 }}>{sc.target}</span>
              <span className="pill">{sc.mode === 'proxy' ? 'keeps the name' : 'redirects'}</span>
              <button className="btn sm" title="Remove" onClick={async () => { try { await api.shortcuts.remove(sc.name); refresh() } catch (e) { toast(e instanceof Error ? e.message : 'Could not remove', 'err') } }}><Icons.trash size={13} /></button>
            </div>
          ))}
        </div>
      )}
      {data && data.shortcuts.length === 0 && <Empty title="No shortcuts yet">Add one below.</Empty>}
      <div style={{ borderTop: '1px solid var(--line-soft)', marginTop: 8, paddingTop: 12, display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'flex-end' }}>
        <label className="field" style={{ flex: '1 1 160px' }}>
          <span>Name to type</span>
          <input className="input mono" placeholder="deep.seek" value={draft.name ?? ''} onChange={(e) => setDraft({ ...draft, name: e.target.value })} />
        </label>
        <label className="field" style={{ flex: '2 1 220px' }}>
          <span>Where it goes (host:port or URL)</span>
          <input className="input mono" placeholder="192.168.50.223:8080" value={draft.target ?? ''} onChange={(e) => setDraft({ ...draft, target: e.target.value })} />
        </label>
        <label className="field" style={{ flex: '0 0 190px' }}>
          <span>How</span>
          <select className="input" value={draft.mode ?? 'redirect'} onChange={(e) => setDraft({ ...draft, mode: e.target.value as DNSShortcut['mode'] })}>
            <option value="redirect">Send me there (address bar shows the real host)</option>
            <option value="proxy">Keep the name (Orbis relays the traffic)</option>
          </select>
        </label>
        <button className="btn primary" disabled={busy || !draft.name?.trim() || !draft.target?.trim()} onClick={save}>
          {busy ? <Spinner /> : <><Icons.plus size={13} /> Add</>}
        </button>
      </div>
      {draft.mode === 'proxy' && (
        <div className="hint" style={{ marginTop: 8 }}>
          Relaying keeps the name in the address bar but some apps break when served under another name (absolute links,
          strict cookies, WebSockets on odd ports). If a target misbehaves, switch it to "Send me there".
        </div>
      )}
    </Card>
  )
}
