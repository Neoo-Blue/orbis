import { useEffect, useState } from 'react'
import { api } from '../api'
import { usePoll } from '../hooks'
import {
  Banner, Card, Drawer, Empty, Field, Icons, Loading, Segmented, Stat, Switch, useToast,
} from '../ui'
import { ago, bytes, compact, dateTime } from '../format'
import type { SystemStatus } from '../types'

/** DHCP leases, zones and interfaces — the LAN plumbing view. */
type Tab = 'leases' | 'vlans'

export function NetworkPage({ status }: { status: SystemStatus | null }) {
  const [tab, setTab] = useState<Tab>('leases')
  return (
    <div style={{ display: 'grid', gap: 14 }}>
      <div className="toolbar" style={{ marginBottom: 0 }}>
        <Segmented value={tab} onChange={setTab}
          options={[
            { value: 'leases', label: 'DHCP & interfaces' },
            { value: 'vlans', label: 'VLANs' },
          ]} />
      </div>
      {tab === 'leases' ? <LeasesTab status={status} /> : <VLANTab />}
    </div>
  )
}

function LeasesTab({ status }: { status: SystemStatus | null }) {
  const { data: leases, refresh } = usePoll(() => api.dhcp.leases(), 15000)
  const { data: ifaces } = usePoll(() => api.config.interfaces(), 60000)
  const { data: config } = usePoll(() => api.config.get(), 0)
  const [query, setQuery] = useState('')
  const toast = useToast()

  const dhcp = status?.dhcp as Record<string, unknown> | undefined
  const running = Boolean(dhcp?.running)
  const rows = (leases?.leases ?? []).filter(
    (l) => !query || [l.ip, l.mac, l.hostname, l.vendor_class].join(' ').toLowerCase().includes(query.toLowerCase()),
  )

  return (
    <div style={{ display: 'grid', gap: 14 }}>
      {!running && (
        <Banner tone="info">
          The DHCP server is not running. It only starts in inline mode with at least one scope
          configured — running a second DHCP server on a network that already has one causes
          address conflicts, so this stays off until you ask for it.
        </Banner>
      )}

      <div className="grid c4">
        <Stat label="Active leases" value={String(leases?.count ?? 0)} tone="blue"
          sub={running ? 'server running' : 'from the stored table'} />
        <Stat label="Offers" value={compact(Number(dhcp?.offers ?? 0))}
          sub={`${compact(Number(dhcp?.discovers ?? 0))} discovers`} />
        <Stat label="Acknowledged" value={compact(Number(dhcp?.acks ?? 0))} tone="accent"
          sub={`${compact(Number(dhcp?.naks ?? 0))} declined`} />
        <Stat label="Pool exhausted"
          value={String(Number(dhcp?.pool_exhausted ?? 0))}
          tone={Number(dhcp?.pool_exhausted ?? 0) > 0 ? 'red' : undefined}
          sub="requests with no free address" />
      </div>

      <div className="grid c2">
        <Card title="Scopes">
          {!config?.dhcp.scopes.length ? (
            <Empty title="No scopes configured">
              Add one in Settings → DHCP to start handing out addresses.
            </Empty>
          ) : (
            <div style={{ display: 'grid', gap: 12 }}>
              {config.dhcp.scopes.map((s) => (
                <div key={s.name} style={{ borderLeft: '2px solid var(--accent)', paddingLeft: 11 }}>
                  <div style={{ fontWeight: 540, marginBottom: 3 }}>{s.name}</div>
                  <dl className="kv" style={{ fontSize: 11.5 }}>
                    <dt>Interface</dt><dd>{s.interface}</dd>
                    <dt>Subnet</dt><dd>{s.subnet}</dd>
                    <dt>Range</dt><dd>{s.range_start} – {s.range_end}</dd>
                    <dt>Gateway</dt><dd>{s.gateway || '—'}</dd>
                    <dt>DNS</dt><dd>{s.dns.join(', ') || '—'}</dd>
                    <dt>Lease</dt><dd>{s.lease_hours}h</dd>
                  </dl>
                </div>
              ))}
            </div>
          )}
        </Card>

        <Card title="Interfaces">
          {!ifaces ? <Loading what="interfaces" /> : (
            <div className="table-wrap" style={{ maxHeight: 300 }}>
              <table className="t">
                <thead><tr><th>Name</th><th>Addresses</th><th className="num">MTU</th></tr></thead>
                <tbody>
                  {ifaces.interfaces.filter((i) => !i.loopback).map((i) => (
                    <tr key={i.name}>
                      <td>
                        <span className={`dot ${i.up ? 'on' : 'off'}`} style={{ marginRight: 7 }} />
                        <span className="mono">{i.name}</span>
                        {i.virtual && <span className="tag" style={{ marginLeft: 6 }}>virtual</span>}
                      </td>
                      <td className="mono truncate" style={{ fontSize: 11, color: 'var(--text-dim)', maxWidth: 220 }}>
                        {i.addresses.join(', ') || '—'}
                      </td>
                      <td className="num">{i.mtu}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </div>

      <div className="toolbar" style={{ marginBottom: 0 }}>
        <div className="search">
          <Icons.search />
          <input className="input" value={query} placeholder="Search leases…"
            onChange={(e) => setQuery(e.target.value)} />
        </div>
        <div style={{ flex: 1 }} />
        <button className="btn sm" onClick={refresh}><Icons.refresh size={13} /> Refresh</button>
      </div>

      <Card flush>
        {!leases ? <Loading what="leases" /> : rows.length === 0 ? (
          <Empty title="No leases">Devices appear here once they request an address from this node.</Empty>
        ) : (
          <div className="table-wrap">
            <table className="t">
              <thead>
                <tr><th>IP</th><th>MAC</th><th>Hostname</th><th>Scope</th>
                  <th>Vendor class</th><th>Expires</th><th style={{ width: 44 }} /></tr>
              </thead>
              <tbody>
                {rows.map((l) => (
                  <tr key={l.mac}>
                    <td className="mono">{l.ip}</td>
                    <td className="mono" style={{ fontSize: 11, color: 'var(--text-dim)' }}>{l.mac}</td>
                    <td className="truncate" style={{ maxWidth: 180 }}>{l.hostname || '—'}</td>
                    <td>
                      {l.static
                        ? <span className="tag allow">reserved</span>
                        : <span className="tag">{l.scope || 'dynamic'}</span>}
                    </td>
                    <td className="truncate" style={{ maxWidth: 200, fontSize: 11.5, color: 'var(--text-faint)' }}
                      title={l.fingerprint}>{l.vendor_class || '—'}</td>
                    <td style={{ fontSize: 11.5, color: 'var(--text-faint)' }}
                      title={dateTime(l.expires)}>{ago(l.expires)}</td>
                    <td>
                      {!l.static && (
                        <button className="btn icon" title="Release" onClick={async () => {
                          await api.dhcp.deleteLease(l.mac)
                          toast('Lease released', 'ok')
                          refresh()
                        }}><Icons.trash size={13} /></button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  )
}

/**
 * VLANs.
 *
 * The reason this sits next to DHCP rather than in Settings is that a VLAN is
 * only half a network on its own. It needs an address to be a gateway, a zone
 * to get firewall policy, and a DHCP scope to hand out addresses — so the page
 * shows all three together and says which are missing.
 */
function VLANTab() {
  const { data, refresh } = usePoll(() => api.network.vlans(), 10000)
  const { data: config } = usePoll(() => api.config.get(), 0)
  const [editing, setEditing] = useState<Record<string, unknown> | null>(null)
  const toast = useToast()

  if (!data) return <Loading what="VLANs" />

  const scopeFor = (iface: string) =>
    (config?.dhcp.scopes ?? []).find((s) => s.interface === iface)

  return (
    <>
      {!data.available && (
        <Banner tone="warn">
          <strong style={{ display: 'block', marginBottom: 3 }}>VLANs cannot be created here</strong>
          {data.reason}
        </Banner>
      )}
      {data.last_error && <Banner tone="err">{data.last_error}</Banner>}

      <div className="toolbar" style={{ marginBottom: 0 }}>
        <button className="btn primary" disabled={!data.available}
          onClick={() => setEditing({
            parent: data.parents[0] ?? '', id: 20, enabled: true,
            address: '', zone: '', mtu: 0, description: '',
          })}>
          <Icons.plus size={13} /> Add a VLAN
        </button>
        <div style={{ flex: 1 }} />
        <span className="tag">{data.vlans.length} configured</span>
      </div>

      {data.vlans.length === 0 ? (
        <Card><Empty title="No VLANs">
          One physical link from the switch, several logical networks on it. Each VLAN becomes a
          normal interface that zones, DHCP scopes and firewall rules can target.
        </Empty></Card>
      ) : (
        <div style={{ display: 'grid', gap: 11 }}>
          {data.vlans.map((v) => {
            const scope = scopeFor(v.name)
            return (
              <div key={v.name} className="card" style={{ padding: 13 }}>
                <div style={{ display: 'flex', gap: 12, alignItems: 'flex-start' }}>
                  <span className={`dot ${v.up ? 'on' : v.enabled ? 'err' : 'off'}`} style={{ marginTop: 6 }} />
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
                      <strong className="mono">{v.name}</strong>
                      <span className="tag">VLAN {v.id}</span>
                      <span className="tag" title="Physical interface carrying the tagged traffic">
                        on {v.parent}
                      </span>
                      {v.zone && <span className="tag info">zone: {v.zone}</span>}
                      {!v.enabled && <span className="tag">disabled</span>}
                    </div>
                    {v.description && (
                      <div style={{ fontSize: 12, color: 'var(--text-dim)', marginTop: 4 }}>{v.description}</div>
                    )}
                    <div style={{ display: 'flex', gap: 14, flexWrap: 'wrap', marginTop: 6, fontSize: 11.5, color: 'var(--text-faint)' }}>
                      <span>{v.addresses.length ? v.addresses.join(', ') : v.address || 'no address'}</span>
                      {v.present && <span>↓ {bytes(v.rx_bytes)} · ↑ {bytes(v.tx_bytes)}</span>}
                      {v.mtu > 0 && <span>MTU {v.mtu}</span>}
                    </div>

                    {/* The three things that make a VLAN actually usable. */}
                    <div style={{ display: 'flex', gap: 14, marginTop: 9, flexWrap: 'wrap' }}>
                      <Readiness ok={v.present} label="Interface"
                        detail={v.present ? 'created' : 'not created'} />
                      <Readiness ok={!!v.address} label="Gateway address"
                        detail={v.address ? v.address : 'devices will have no gateway'} />
                      <Readiness ok={!!v.zone} label="Firewall zone"
                        detail={v.zone ? v.zone : 'no policy applies to this VLAN'} />
                      <Readiness ok={!!scope} label="DHCP"
                        detail={scope ? `${scope.range_start}–${scope.range_end}` : 'no scope — devices need static addresses'} />
                    </div>

                    {v.error && (
                      <div style={{ fontSize: 11.5, color: 'var(--red)', marginTop: 7 }}>{v.error}</div>
                    )}
                  </div>

                  <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                    <Switch checked={v.enabled} onChange={async (on) => {
                      const r = await api.network.saveVLAN({ ...v, enabled: on }, v.name)
                      if (r.warning) toast(r.warning, 'err')
                      refresh()
                    }} />
                    <button className="btn sm" onClick={() => setEditing({ ...v })}>Edit</button>
                    <button className="btn icon" title="Remove" onClick={async () => {
                      if (!confirm(`Remove ${v.name}? Devices on this VLAN lose their gateway.`)) return
                      await api.network.deleteVLAN(v.name)
                      toast('VLAN removed', 'ok')
                      refresh()
                    }}><Icons.trash size={13} /></button>
                  </div>
                </div>
              </div>
            )
          })}
        </div>
      )}

      {editing && (
        <VLANEditor vlan={editing} parents={data.parents}
          zones={(config?.firewall.zones ?? []).map((z) => z.name)}
          onClose={() => setEditing(null)}
          onSaved={() => { setEditing(null); refresh() }} />
      )}
    </>
  )
}

function Readiness({ ok, label, detail }: { ok: boolean; label: string; detail: string }) {
  return (
    <div style={{ display: 'flex', gap: 7, alignItems: 'flex-start' }}>
      <span className={`dot ${ok ? 'on' : 'warn'}`} style={{ marginTop: 5 }} />
      <div>
        <div style={{ fontSize: 11.5 }}>{label}</div>
        <div style={{ fontSize: 10.5, color: ok ? 'var(--text-faint)' : 'var(--amber)' }}>{detail}</div>
      </div>
    </div>
  )
}

function VLANEditor({ vlan, parents, zones, onClose, onSaved }: {
  vlan: Record<string, unknown>
  parents: string[]
  zones: string[]
  onClose: () => void
  onSaved: () => void
}) {
  const [draft, setDraft] = useState(vlan)
  const [busy, setBusy] = useState(false)
  const toast = useToast()
  const original = String(vlan.name ?? '')

  const set = (patch: Record<string, unknown>) => setDraft((d) => ({ ...d, ...patch }))
  const derivedName = `${draft.parent}.${draft.id}`

  useEffect(() => {
    // The interface name follows <parent>.<id> unless it was set explicitly,
    // which is the convention every other tool on the box uses.
    if (!vlan.name) set({ name: '' })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  return (
    <Drawer title={original ? `Edit ${original}` : 'New VLAN'} onClose={onClose}
      actions={
        <button className="btn primary sm" disabled={busy} onClick={async () => {
          setBusy(true)
          try {
            const r = await api.network.saveVLAN(draft, original || undefined)
            if (r.warning) toast(r.warning, 'err')
            else toast('VLAN saved', 'ok')
            onSaved()
          } catch (e) {
            toast(e instanceof Error ? e.message : 'Could not save', 'err')
          } finally {
            setBusy(false)
          }
        }}>Save</button>
      }>
      <div style={{ display: 'grid', gap: 13 }}>
        <div className="grid c2">
          <Field label="Parent interface" hint="The physical link carrying the tagged traffic.">
            <select className="select" value={String(draft.parent ?? '')}
              onChange={(e) => set({ parent: e.target.value })}>
              {parents.map((p) => <option key={p} value={p}>{p}</option>)}
            </select>
          </Field>
          <Field label="VLAN ID" hint="The 802.1Q tag, 1–4094. Must match the switch.">
            <input className="input mono" type="number" min={1} max={4094}
              value={Number(draft.id ?? 0)}
              onChange={(e) => set({ id: Number(e.target.value) })} />
          </Field>
        </div>

        <Field label="Interface name"
          hint={`Leave empty to use ${derivedName}, which is the usual convention.`}>
          <input className="input mono" value={String(draft.name ?? '')} placeholder={derivedName}
            onChange={(e) => set({ name: e.target.value })} />
        </Field>

        <Field label="Gateway address"
          hint="This node's address on the VLAN, in CIDR form. It becomes the gateway for devices on it. Leave empty for a VLAN this node only observes.">
          <input className="input mono" value={String(draft.address ?? '')} placeholder="192.168.20.1/24"
            onChange={(e) => set({ address: e.target.value })} />
        </Field>

        <Field label="Firewall zone"
          hint="Assigns the VLAN a trust level. Without one it gets no policy at all. A name that does not exist yet is created as a trusted LAN zone.">
          <input className="input" list="vlan-zones" value={String(draft.zone ?? '')} placeholder="iot"
            onChange={(e) => set({ zone: e.target.value })} />
          <datalist id="vlan-zones">
            {zones.map((z) => <option key={z} value={z} />)}
          </datalist>
        </Field>

        <div className="grid c2">
          <Field label="MTU" hint="Leave 0 to inherit the parent's. Lower it only if the upstream link cannot carry the extra 4 bytes of tag.">
            <input className="input mono" type="number" value={Number(draft.mtu ?? 0)}
              onChange={(e) => set({ mtu: Number(e.target.value) })} />
          </Field>
          <Field label="Description">
            <input className="input" value={String(draft.description ?? '')} placeholder="IoT devices"
              onChange={(e) => set({ description: e.target.value })} />
          </Field>
        </div>

        <Switch checked={Boolean(draft.enabled ?? true)} onChange={(v) => set({ enabled: v })}
          label="Enabled" />

        <Banner tone="info">
          Saving creates the tagged interface, adds it to its zone, starts capturing on it, and
          treats its subnet as local so devices there are attributed correctly. Add a DHCP scope on
          this interface if you want it to hand out addresses.
        </Banner>
      </div>
    </Drawer>
  )
}
