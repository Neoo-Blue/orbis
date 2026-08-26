import { useState } from 'react'
import { api } from '../api'
import { usePoll } from '../hooks'
import { Card, Empty, Icons, useConfirm, useToast } from '../ui'
import type { DNSRecord } from '../types'

const TYPES = ['A', 'AAAA', 'CNAME', 'TXT', 'MX', 'SRV', 'NS', 'PTR']

// Local DNS records: the part that makes Orbis authoritative for your own
// names, so nas.home resolves to your NAS while everything else is still
// filtered and forwarded normally.
export function DNSRecordsCard() {
  const { data, refresh } = usePoll(() => api.dnsRecords.list(), 0)
  const toast = useToast()
  const confirm = useConfirm()
  const [draft, setDraft] = useState<DNSRecord>({ name: '', type: 'A', value: '' })

  const records = data?.records ?? []
  const needsNumeric = draft.type === 'MX' || draft.type === 'SRV'

  const save = async () => {
    try {
      await api.dnsRecords.save(draft)
      setDraft({ name: '', type: draft.type, value: '' })
      refresh()
      toast('Record saved', 'ok')
    } catch (e) {
      toast(e instanceof Error ? e.message : 'Could not save', 'err')
    }
  }

  const remove = async (r: DNSRecord) => {
    if (!(await confirm(`Delete ${r.type} record for ${r.name}?`))) return
    try {
      await api.dnsRecords.remove(r)
      refresh()
    } catch (e) {
      toast(e instanceof Error ? e.message : 'Could not delete', 'err')
    }
  }

  return (
    <Card title="Local DNS records">
      <div className="hint" style={{ marginBottom: 11 }}>
        Answers Orbis gives authoritatively for your own names. A local record wins over both a
        DHCP lease of the same name and anything the internet would say, so <span className="mono">
        nas.home</span> can point at your NAS while every other lookup is still filtered and
        forwarded. Wildcards like <span className="mono">*.lab</span> are supported.
      </div>

      {records.length > 0 && (
        <div style={{ display: 'grid', gap: 6, marginBottom: 12 }}>
          {records.map((r, i) => (
            <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <span className="tag" style={{ fontSize: 10, minWidth: 44, textAlign: 'center' }}>{r.type}</span>
              <span className="mono" style={{ fontSize: 12.5, flex: 1, minWidth: 0 }}>{r.name}</span>
              <span className="mono" style={{ fontSize: 11.5, color: 'var(--text-dim)', flex: 1, minWidth: 0 }}>
                {(r.type === 'MX' || r.type === 'SRV') && r.priority ? `${r.priority} ` : ''}
                {r.type === 'SRV' && r.port ? `${r.weight ?? 0} ${r.port} ` : ''}
                {r.value}
              </span>
              <button className="btn sm" onClick={() => remove(r)}><Icons.trash size={13} /></button>
            </div>
          ))}
        </div>
      )}
      {records.length === 0 && <Empty title="No local records yet">Add one below.</Empty>}

      <div style={{
        borderTop: '1px solid var(--line-soft)', marginTop: records.length ? 4 : 12, paddingTop: 12,
        display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'flex-end',
      }}>
        <label className="field" style={{ flex: '0 0 92px' }}>
          <span>Type</span>
          <select className="input" value={draft.type}
            onChange={(e) => setDraft({ ...draft, type: e.target.value })}>
            {TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
        </label>
        <label className="field" style={{ flex: '1 1 150px' }}>
          <span>Name</span>
          <input className="input mono" placeholder="nas.home" value={draft.name}
            onChange={(e) => setDraft({ ...draft, name: e.target.value })} />
        </label>
        <label className="field" style={{ flex: '1 1 150px' }}>
          <span>{draft.type === 'CNAME' || draft.type === 'MX' || draft.type === 'NS' ? 'Target' : 'Value'}</span>
          <input className="input mono"
            placeholder={draft.type === 'A' ? '192.168.50.100' : draft.type === 'AAAA' ? 'fd00::100' : draft.type === 'TXT' ? 'v=spf1 …' : 'host.name'}
            value={draft.value}
            onChange={(e) => setDraft({ ...draft, value: e.target.value })} />
        </label>
        {needsNumeric && (
          <label className="field" style={{ flex: '0 0 80px' }}>
            <span>Priority</span>
            <input className="input" type="number" value={draft.priority ?? ''}
              onChange={(e) => setDraft({ ...draft, priority: Number(e.target.value) })} />
          </label>
        )}
        {draft.type === 'SRV' && (
          <label className="field" style={{ flex: '0 0 74px' }}>
            <span>Port</span>
            <input className="input" type="number" value={draft.port ?? ''}
              onChange={(e) => setDraft({ ...draft, port: Number(e.target.value) })} />
          </label>
        )}
        <button className="btn primary" disabled={!draft.name || !draft.value} onClick={save}>
          <Icons.plus size={13} /> Add
        </button>
      </div>
    </Card>
  )
}
