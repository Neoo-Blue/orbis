import { useMemo, useState } from 'react'
import { api } from '../api'
import { usePoll } from '../hooks'
import { Banner, Card, Drawer, Empty, Icons, Loading, Segmented, Stat, useToast } from '../ui'
import { NetworkMap } from './NetworkMap'
import { bytes, compact } from '../format'
import type { TopoGraph, TopoNode } from '../types'

const ROLE_LABEL: Record<string, string> = {
  gateway: 'Gateway', access_point: 'Access points', hypervisor: 'Hypervisors',
  nas: 'Storage', server: 'Servers', vm: 'Virtual machines & containers',
  container: 'Containers', workstation: 'Computers', mobile: 'Phones & tablets',
  printer: 'Printers', iot: 'Smart home', unknown: 'Unidentified',
}
const ROLE_ICON: Record<string, keyof typeof Icons> = {
  gateway: 'route', access_point: 'globe', hypervisor: 'grid', nas: 'dns',
  server: 'dns', vm: 'grid', container: 'grid', workstation: 'devices',
  mobile: 'devices', printer: 'devices', iot: 'spark', unknown: 'search',
}

export function TopologyPage() {
  const { data, refresh } = usePoll<TopoGraph>(() => api.topology.get(), 20000)
  const [scanning, setScanning] = useState(false)
  const [selected, setSelected] = useState<TopoNode | null>(null)
  const [tab, setTab] = useState<'map' | 'list'>('map')
  const toast = useToast()

  const grouped = useMemo(() => {
    const out = new Map<string, TopoNode[]>()
    for (const n of data?.nodes ?? []) {
      if (n.parent_id) continue
      const arr = out.get(n.role) ?? []
      arr.push(n); out.set(n.role, arr)
    }
    return out
  }, [data])

  const childrenOf = useMemo(() => {
    const out = new Map<string, TopoNode[]>()
    for (const n of data?.nodes ?? []) {
      if (!n.parent_id) continue
      const arr = out.get(n.parent_id) ?? []
      arr.push(n); out.set(n.parent_id, arr)
    }
    return out
  }, [data])

  if (!data) return <Loading what="topology" />

  const scan = async () => {
    setScanning(true)
    try {
      await api.topology.scan(); refresh(); toast('Scan complete', 'ok')
    } catch (e) {
      toast(e instanceof Error ? e.message : 'Scan failed', 'err')
    } finally { setScanning(false) }
  }

  const nodes = data.nodes ?? []
  const totalIn = nodes.reduce((n, d) => n + d.bytes_in, 0)
  const totalOut = nodes.reduce((n, d) => n + d.bytes_out, 0)
  const identified = nodes.filter((n) => n.role !== 'unknown').length
  const online = nodes.filter((n) => n.online).length
  const top = [...nodes].sort((a, b) => (b.bytes_in + b.bytes_out) - (a.bytes_in + a.bytes_out)).slice(0, 5)

  return (
    <div style={{ display: 'grid', gap: 12 }}>
      <div className="toolbar" style={{ marginBottom: 0, gap: 10 }}>
        <Segmented value={tab} onChange={setTab}
          options={[{ value: 'map', label: 'Map' }, { value: 'list', label: 'List' }]} />
        <div style={{ fontSize: 12, color: 'var(--text-faint)' }}>
          {data.subnet || 'this network'}
          {data.scanned_at && <> · scanned {new Date(data.scanned_at).toLocaleTimeString()}</>}
        </div>
        <div className="spacer" style={{ flex: 1 }} />
        <button className="btn sm" disabled={scanning} onClick={scan}>
          <Icons.search size={13} /> {scanning ? 'Scanning…' : 'Scan network'}
        </button>
      </div>

      <div className="grid c4">
        <Stat label="Devices" value={String(nodes.length)} sub={`${online} online · ${identified} identified`} />
        <Stat label="Inbound" value={bytes(totalIn)} sub="towards these" tone="amber" />
        <Stat label="Outbound" value={bytes(totalOut)} sub="from these" tone="accent" />
        <Stat label="Roles" value={String(grouped.size)} sub="device classes" />
      </div>

      {(data.notes ?? []).map((n) => <Banner key={n} tone="info">{n}</Banner>)}

      {nodes.length === 0 ? (
        <Empty title="No devices on this network yet">
          Orbis only knows devices whose traffic it has seen. If this is empty, nothing routes
          through this node.
        </Empty>
      ) : tab === 'map' ? (
        <>
          <NetworkMap graph={data} onSelect={setSelected} selectedId={selected?.id} />
          {top.length > 0 && (
            <Card title="Top talkers">
              <div style={{ display: 'grid', gap: 7 }}>
                {top.map((n) => {
                  const total = n.bytes_in + n.bytes_out
                  const max = top[0].bytes_in + top[0].bytes_out || 1
                  return (
                    <button key={n.id} onClick={() => setSelected(n)} style={{
                      display: 'flex', alignItems: 'center', gap: 10, background: 'transparent',
                      border: 'none', color: 'inherit', cursor: 'pointer', padding: 0, width: '100%',
                    }}>
                      <span style={{ fontSize: 12.5, width: 150, textAlign: 'left', overflow: 'hidden',
                        textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{n.label}</span>
                      <div style={{ flex: 1, height: 6, borderRadius: 3, background: 'var(--line-soft)', overflow: 'hidden' }}>
                        <div style={{ width: `${(total / max) * 100}%`, height: '100%',
                          background: 'linear-gradient(90deg, var(--accent), var(--blue))' }} />
                      </div>
                      <span className="mono" style={{ fontSize: 11, color: 'var(--text-faint)', width: 80, textAlign: 'right' }}>
                        {bytes(total)}
                      </span>
                    </button>
                  )
                })}
              </div>
            </Card>
          )}
        </>
      ) : (
        [...grouped.entries()].map(([role, list]) => {
          const Icon = Icons[ROLE_ICON[role] ?? 'search']
          return (
            <Card key={role} title={`${ROLE_LABEL[role] ?? role} (${list.length})`}>
              <div style={{ display: 'grid', gap: 7 }}>
                {list.map((n) => (
                  <div key={n.id}>
                    <DeviceRow n={n} onSelect={() => setSelected(n)} icon={Icon} />
                    {(childrenOf.get(n.id) ?? []).length > 0 && (
                      <div style={{ marginLeft: 22, marginTop: 6, paddingLeft: 13,
                        borderLeft: '1px solid var(--line-soft)', display: 'grid', gap: 6 }}>
                        <div style={{ fontSize: 11, color: 'var(--text-faint)' }}>
                          hosts {(childrenOf.get(n.id) ?? []).length} guest(s)
                        </div>
                        {(childrenOf.get(n.id) ?? []).map((c) => (
                          <DeviceRow key={c.id} n={c} onSelect={() => setSelected(c)}
                            icon={Icons[ROLE_ICON[c.role] ?? 'grid']} dense />
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </Card>
          )
        })
      )}

      {selected && (
        <Drawer title={selected.label} onClose={() => setSelected(null)}>
          <DetailBody n={selected} />
        </Drawer>
      )}
    </div>
  )
}

function DeviceRow({ n, onSelect, icon: Icon, dense }: {
  n: TopoNode; onSelect: () => void; icon: (p: { size?: number }) => JSX.Element; dense?: boolean
}) {
  const inHeavy = n.bytes_in > n.bytes_out
  return (
    <button onClick={onSelect} style={{
      display: 'flex', alignItems: 'center', gap: 10, width: '100%', background: 'transparent',
      border: 'none', color: 'inherit', cursor: 'pointer', padding: dense ? '2px 0' : '3px 0', textAlign: 'left',
    }}>
      <span className={`dot ${n.online ? 'on' : 'off'}`} />
      <Icon size={dense ? 13 : 15} />
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: dense ? 12.5 : 13, display: 'flex', gap: 7, alignItems: 'baseline', flexWrap: 'wrap' }}>
          <span>{n.label}</span>
          {n.platform && <span className="tag" style={{ fontSize: 10 }}>{n.platform}</span>}
          {n.virtual && <span className="tag info" style={{ fontSize: 10 }}>virtual</span>}
          {n.confidence === 'guessed' && <span className="tag warn" style={{ fontSize: 10 }}>uncertain</span>}
        </div>
        <div className="mono" style={{ fontSize: 10.5, color: 'var(--text-faint)' }}>
          {n.ip}{n.services?.length ? ` · ${n.services.slice(0, 3).join(', ')}` : ''}
        </div>
      </div>
      <div style={{ textAlign: 'right', fontSize: 10.5, color: 'var(--text-faint)', minWidth: 96 }}>
        <div style={{ color: inHeavy ? 'var(--amber)' : undefined }}>↓ {bytes(n.bytes_in)}</div>
        <div style={{ color: !inHeavy ? 'var(--accent)' : undefined }}>↑ {bytes(n.bytes_out)}</div>
      </div>
    </button>
  )
}

function DetailBody({ n }: { n: TopoNode }) {
  return (
    <div>
      <dl className="kv">
        <dt>Address</dt><dd className="mono">{n.ip}</dd>
        {n.mac && <><dt>MAC</dt><dd className="mono">{n.mac}</dd></>}
        {n.vendor && <><dt>Vendor</dt><dd>{n.vendor}</dd></>}
        <dt>Role</dt><dd>{ROLE_LABEL[n.role] ?? n.role} <span style={{ color: 'var(--text-faint)' }}>({n.confidence})</span></dd>
        {n.platform && <><dt>Platform</dt><dd>{n.platform}</dd></>}
        {n.parent_basis && <><dt>Hosted by</dt><dd>{n.parent_basis}</dd></>}
        <dt>Inbound</dt><dd>{bytes(n.bytes_in)} over {compact(n.conns_in)} connection(s)</dd>
        <dt>Outbound</dt><dd>{bytes(n.bytes_out)} over {compact(n.conns_out)} connection(s)</dd>
        <dt>To the internet</dt><dd>{compact(n.external_conns)} connection(s)</dd>
        {n.services?.length ? <><dt>Listening</dt><dd>{n.services.join(', ')}</dd></> : null}
      </dl>
      {n.evidence?.length ? (
        <div style={{ borderTop: '1px solid var(--line-soft)', marginTop: 12, paddingTop: 11 }}>
          <div style={{ fontSize: 12, color: 'var(--text-dim)', marginBottom: 6 }}>How it was identified</div>
          <ul style={{ margin: 0, paddingLeft: 18, fontSize: 11.5, color: 'var(--text-faint)', lineHeight: 1.7 }}>
            {n.evidence.map((e) => <li key={e}>{e}</li>)}
          </ul>
        </div>
      ) : null}
    </div>
  )
}
