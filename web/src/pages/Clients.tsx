import { useEffect, useMemo, useState } from 'react'
import { api } from '../api'
import { usePoll, useDebounced } from '../hooks'
import {
  Bar, Card, CopyButton, Drawer, Empty, Icons, Loading, Search, Segmented, Switch, useToast,
} from '../ui'
import { ago, bits, bytes, clientName, compact, countryFlag, deviceGlyph, flowTarget } from '../format'
import type { Client, DNSQuery, Flow, Policy } from '../types'

export function ClientsPage() {
  const [query, setQuery] = useState('')
  const [filter, setFilter] = useState<'all' | 'online' | 'blocked'>('all')
  const [selected, setSelected] = useState<string | null>(null)
  const debounced = useDebounced(query, 200)

  const { data, refresh } = usePoll(() => api.clients.list(), 8000)
  const clients = data?.clients ?? []

  const visible = useMemo(() => {
    const q = debounced.toLowerCase()
    return clients
      .filter((c) => {
        if (filter === 'online' && !c.online) return false
        if (filter === 'blocked' && !c.blocked) return false
        if (!q) return true
        return [c.label, c.hostname, c.ip, c.mac, c.vendor, c.device_type, c.os_guess]
          .filter(Boolean).join(' ').toLowerCase().includes(q)
      })
      .sort((a, b) => {
        if (a.online !== b.online) return a.online ? -1 : 1
        return b.rate_in + b.rate_out - (a.rate_in + a.rate_out)
      })
  }, [clients, debounced, filter])

  const peak = Math.max(...visible.map((c) => c.rate_in + c.rate_out), 1)

  return (
    <>
      <div className="toolbar">
        <Search value={query} onChange={setQuery} placeholder="Search by name, IP, MAC or vendor…" />
        <Segmented
          value={filter}
          onChange={setFilter}
          options={[
            { value: 'all', label: `All ${clients.length}` },
            { value: 'online', label: `Online ${clients.filter((c) => c.online).length}` },
            { value: 'blocked', label: `Blocked ${clients.filter((c) => c.blocked).length}` },
          ]}
        />
        <div style={{ flex: 1 }} />
        <button className="btn sm" onClick={refresh}><Icons.refresh size={13} /> Refresh</button>
      </div>

      <Card flush>
        {!data ? <Loading what="devices" /> : visible.length === 0 ? (
          <Empty title="No devices match">
            Devices are discovered from ARP, DHCP and traffic. If this list is empty entirely,
            check that packet capture found an interface.
          </Empty>
        ) : (
          <div className="table-wrap">
            <table className="t">
              <thead>
                <tr>
                  <th style={{ width: 30 }} />
                  <th>Device</th>
                  <th>Address</th>
                  <th>Vendor / OS</th>
                  <th className="num">Conns</th>
                  <th style={{ width: 130 }}>Throughput</th>
                  <th className="num">Total</th>
                  <th>Seen</th>
                </tr>
              </thead>
              <tbody>
                {visible.map((c) => (
                  <tr key={c.id} className="clickable" onClick={() => setSelected(c.id)}>
                    <td style={{ textAlign: 'center', color: c.online ? 'var(--accent)' : 'var(--text-faint)' }}
                      title={c.device_type}>
                      {deviceGlyph(c.device_type)}
                    </td>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
                        <span className={`dot ${c.online ? 'on' : 'off'}`} />
                        <span className="truncate" style={{ maxWidth: 220 }}>{clientName(c)}</span>
                        {c.blocked && <span className="tag block">blocked</span>}
                        {c.meta?.randomized_mac && (
                          <span className="tag" title="This device rotates its MAC address, so it may reappear as a new device">
                            random MAC
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="mono" style={{ fontSize: 11.5, color: 'var(--text-dim)' }}>{c.ip}</td>
                    <td className="truncate" style={{ maxWidth: 180, color: 'var(--text-dim)', fontSize: 12 }}>
                      {[c.vendor, c.os_guess].filter(Boolean).join(' · ') || '—'}
                    </td>
                    <td className="num">{c.active_flows || '—'}</td>
                    <td>
                      <Bar value={c.rate_in + c.rate_out} max={peak} />
                      <div className="num" style={{ fontSize: 10.5, color: 'var(--text-faint)', marginTop: 2 }}>
                        {bits(c.rate_in + c.rate_out)}
                      </div>
                    </td>
                    <td className="num">{bytes(c.rx_bytes + c.tx_bytes)}</td>
                    <td style={{ color: 'var(--text-faint)', fontSize: 11.5 }}>{ago(c.last_seen)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {selected && (
        <ClientDrawer
          id={selected}
          onClose={() => setSelected(null)}
          onChanged={refresh}
        />
      )}
    </>
  )
}

function ClientDrawer({ id, onClose, onChanged }: { id: string; onClose: () => void; onChanged: () => void }) {
  const [tab, setTab] = useState<'activity' | 'dns' | 'settings'>('activity')
  const { data: client } = usePoll(() => api.clients.get(id), 8000, [id])
  const { data: flows } = usePoll(
    () => api.clients.flows(id, tab === 'activity' ? { hours: 24, limit: 120 } : { limit: 1 }),
    tab === 'activity' ? 8000 : 0, [id, tab],
  )
  const { data: dns } = usePoll(
    () => api.clients.dns(id, { hours: 6, limit: 150 }),
    tab === 'dns' ? 8000 : 0, [id, tab],
  )
  const { data: dests } = usePoll(() => api.clients.destinations(id, 24, 12), 20000, [id])

  if (!client) {
    return <Drawer title="Device" onClose={onClose}><Loading what="device" /></Drawer>
  }

  return (
    <Drawer
      title={
        <span style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span className={`dot ${client.online ? 'on' : 'off'}`} />
          {clientName(client)}
          {client.blocked && <span className="tag block">blocked</span>}
        </span>
      }
      onClose={onClose}
    >
      <div style={{ display: 'grid', gap: 14 }}>
        <dl className="kv">
          <dt>IP address</dt><dd>{client.ip}</dd>
          {client.mac && <><dt>MAC</dt><dd>{client.mac}</dd></>}
          {client.vendor && <><dt>Vendor</dt><dd>{client.vendor}</dd></>}
          {client.os_guess && <><dt>Operating system</dt><dd>{client.os_guess}</dd></>}
          {client.device_type && <><dt>Type</dt><dd>{client.device_type}</dd></>}
          <dt>First seen</dt><dd>{ago(client.first_seen)}</dd>
          <dt>Last seen</dt><dd>{ago(client.last_seen)}</dd>
          <dt>Transferred</dt><dd>{bytes(client.rx_bytes)} down · {bytes(client.tx_bytes)} up</dd>
          <dt>Right now</dt><dd>{bits(client.rate_in + client.rate_out)} · {client.active_flows} connections</dd>
        </dl>

        <Segmented
          value={tab} onChange={setTab}
          options={[
            { value: 'activity', label: 'Activity' },
            { value: 'dns', label: 'DNS' },
            { value: 'settings', label: 'Settings' },
          ]}
        />

        {tab === 'activity' && (
          <>
            <Card title="Talks to most (24h)" flush>
              {!dests?.destinations.length ? <Empty title="No destinations yet" /> : (
                <div className="table-wrap">
                  <table className="t">
                    <thead><tr><th>Host</th><th className="num">Conns</th><th className="num">Bytes</th></tr></thead>
                    <tbody>
                      {dests.destinations.map((d, i) => (
                        <tr key={i}>
                          <td className="truncate" title={String(d.host)}>
                            {d.country ? <span style={{ marginRight: 6 }}>{countryFlag(String(d.country))}</span> : null}
                            {String(d.host)}
                          </td>
                          <td className="num">{compact(Number(d.connections))}</td>
                          <td className="num">{bytes(Number(d.bytes))}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </Card>
            <Card title="Recent connections" flush>
              <FlowList flows={flows?.flows ?? []} />
            </Card>
          </>
        )}

        {tab === 'dns' && <Card title="Recent lookups" flush><DNSList queries={dns?.queries ?? []} /></Card>}

        {tab === 'settings' && (
          <ClientSettings client={client} onChanged={() => { onChanged() }} />
        )}
      </div>
    </Drawer>
  )
}

function FlowList({ flows }: { flows: Flow[] }) {
  if (!flows.length) return <Empty title="No connections recorded" />
  return (
    <div className="table-wrap" style={{ maxHeight: 340 }}>
      <table className="t">
        <thead><tr><th>Destination</th><th className="num">Port</th><th className="num">Bytes</th><th>When</th></tr></thead>
        <tbody>
          {flows.map((f) => (
            <tr key={f.id}>
              <td className="truncate" title={flowTarget(f)}>
                {f.verdict === 'block' && <span className="tag block" style={{ marginRight: 6 }}>blocked</span>}
                {f.country && <span style={{ marginRight: 5 }}>{countryFlag(f.country)}</span>}
                {flowTarget(f)}
              </td>
              <td className="num">{f.dst_port}</td>
              <td className="num">{bytes(f.bytes_in + f.bytes_out)}</td>
              <td style={{ color: 'var(--text-faint)', fontSize: 11 }}>{ago(f.started_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function DNSList({ queries }: { queries: DNSQuery[] }) {
  if (!queries.length) return <Empty title="No lookups recorded" />
  return (
    <div className="table-wrap" style={{ maxHeight: 380 }}>
      <table className="t">
        <thead><tr><th>Domain</th><th>Type</th><th>Result</th><th>When</th></tr></thead>
        <tbody>
          {queries.map((q) => (
            <tr key={q.id}>
              <td className="truncate mono" style={{ fontSize: 11.5 }} title={q.name}>{q.name}</td>
              <td style={{ color: 'var(--text-faint)', fontSize: 11 }}>{q.qtype}</td>
              <td>
                {q.blocked
                  ? <span className="tag block" title={q.block_source}>blocked</span>
                  : <span className="tag" style={{ opacity: .7 }}>{q.cached ? 'cached' : q.rcode}</span>}
              </td>
              <td style={{ color: 'var(--text-faint)', fontSize: 11 }}>{ago(q.ts)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function ClientSettings({ client, onChanged }: { client: Client; onChanged: () => void }) {
  const [label, setLabel] = useState(client.label ?? '')
  const [zone, setZone] = useState(client.zone ?? '')
  const [notes, setNotes] = useState(client.notes ?? '')
  const [policyId, setPolicyId] = useState(client.policy_id ?? '')
  const [saving, setSaving] = useState(false)
  const toast = useToast()
  const { data: policies } = usePoll(() => api.policies.list(), 0)

  useEffect(() => {
    setLabel(client.label ?? '')
    setZone(client.zone ?? '')
    setNotes(client.notes ?? '')
    setPolicyId(client.policy_id ?? '')
  }, [client.id, client.label, client.zone, client.notes, client.policy_id])

  const save = async () => {
    setSaving(true)
    try {
      await api.clients.update(client.id, { label, zone, notes, policy_id: policyId })
      toast('Device updated', 'ok')
      onChanged()
    } catch (e) {
      toast(e instanceof Error ? e.message : 'Could not save', 'err')
    } finally {
      setSaving(false)
    }
  }

  const toggleBlock = async () => {
    const wasBlocked = client.blocked
    try {
      await api.clients.update(client.id, { blocked: !wasBlocked })
      toast(wasBlocked ? 'Device restored' : 'Device blocked', 'ok', {
        label: 'Undo',
        onClick: async () => {
          try { await api.clients.update(client.id, { blocked: wasBlocked }); onChanged() } catch { /* the drawer shows the real state */ }
        },
      })
      onChanged()
    } catch (e) {
      toast(e instanceof Error ? e.message : 'Could not change access', 'err')
    }
  }

  return (
    <div style={{ display: 'grid', gap: 13 }}>
      <div className="field">
        <label>Name</label>
        <input className="input" value={label} placeholder={client.hostname || client.ip}
          onChange={(e) => setLabel(e.target.value)} />
        <div className="hint">Shown everywhere instead of the hostname or MAC.</div>
      </div>
      <div className="field">
        <label>Zone</label>
        <input className="input" value={zone} placeholder="lan / guest / iot"
          onChange={(e) => setZone(e.target.value)} />
        <div className="hint">Firewall rules can target a whole zone rather than one address.</div>
      </div>
      <div className="field">
        <label>Filtering policy</label>
        <select className="select" value={policyId} onChange={(e) => setPolicyId(e.target.value)}>
          <option value="">Default (global blocklists)</option>
          {(policies?.policies ?? []).map((p: Policy) => (
            <option key={p.id} value={p.id}>{p.name}{p.unfiltered ? ' (unfiltered)' : ''}</option>
          ))}
        </select>
        {(policies?.policies ?? []).find((p: Policy) => p.id === policyId)?.unfiltered && (
          <div className="hint">
            Unfiltered: blocklists and CNAME uncloaking are skipped for this device. Only the policy's own
            rules, blocked services and DoH setting apply.
          </div>
        )}
      </div>
      <div className="field">
        <label>Notes</label>
        <textarea className="textarea" value={notes} onChange={(e) => setNotes(e.target.value)}
          placeholder="Anything worth remembering about this device" />
      </div>

      <div style={{ display: 'flex', gap: 8 }}>
        <button className="btn primary" onClick={save} disabled={saving}>
          {saving ? 'Saving…' : 'Save'}
        </button>
        <div style={{ flex: 1 }} />
        <CopyButton text={client.mac || client.ip} label="Copy MAC" />
        <button className={`btn ${client.blocked ? '' : 'danger'}`} onClick={toggleBlock}>
          {client.blocked ? 'Restore access' : 'Block device'}
        </button>
      </div>

      <div style={{ borderTop: '1px solid var(--line-soft)', paddingTop: 12 }}>
        <Switch checked={client.blocked} onChange={toggleBlock}
          label={client.blocked ? 'Blocked from the network' : 'Has network access'} />
      </div>
    </div>
  )
}
