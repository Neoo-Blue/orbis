import { useMemo, useState } from 'react'
import { api } from '../api'
import { usePoll } from '../hooks'
import { Banner, Card, Empty, Icons, Loading, Stat, useToast } from '../ui'
import { bytes, compact } from '../format'
import type { TopoGraph, TopoNode } from '../types'

/**
 * The internal map.
 *
 * Grouped by role rather than drawn as a force-directed cloud: on a home
 * network a physics layout tells you nothing you could not see from a list, and
 * it moves every time you look at it. What actually helps is knowing which box
 * is the hypervisor, what it hosts, and which direction the traffic runs.
 */

const ROLE_LABEL: Record<string, string> = {
  gateway: 'Gateway',
  access_point: 'Access points',
  hypervisor: 'Hypervisors',
  nas: 'Storage',
  server: 'Servers',
  vm: 'Virtual machines & containers',
  container: 'Containers',
  workstation: 'Computers',
  mobile: 'Phones & tablets',
  printer: 'Printers',
  iot: 'Smart home',
  unknown: 'Unidentified',
}

const ROLE_ICON: Record<string, keyof typeof Icons> = {
  gateway: 'route',
  access_point: 'globe',
  hypervisor: 'grid',
  nas: 'dns',
  server: 'dns',
  vm: 'grid',
  container: 'grid',
  workstation: 'devices',
  mobile: 'devices',
  printer: 'devices',
  iot: 'spark',
  unknown: 'search',
}

export function TopologyPage() {
  const { data, refresh } = usePoll<TopoGraph>(() => api.topology.get(), 20000)
  const [scanning, setScanning] = useState(false)
  const [selected, setSelected] = useState<TopoNode | null>(null)
  const toast = useToast()

  const grouped = useMemo(() => {
    const out = new Map<string, TopoNode[]>()
    for (const n of data?.nodes ?? []) {
      // A guest with a known host is drawn under it, not in its own group.
      if (n.parent_id) continue
      const arr = out.get(n.role) ?? []
      arr.push(n)
      out.set(n.role, arr)
    }
    return out
  }, [data])

  const childrenOf = useMemo(() => {
    const out = new Map<string, TopoNode[]>()
    for (const n of data?.nodes ?? []) {
      if (!n.parent_id) continue
      const arr = out.get(n.parent_id) ?? []
      arr.push(n)
      out.set(n.parent_id, arr)
    }
    return out
  }, [data])

  if (!data) return <Loading what="topology" />

  const scan = async () => {
    setScanning(true)
    try {
      await api.topology.scan()
      refresh()
      toast('Scan complete', 'ok')
    } catch (e) {
      toast(e instanceof Error ? e.message : 'Scan failed', 'err')
    } finally {
      setScanning(false)
    }
  }

  const totalIn = (data.nodes ?? []).reduce((n, d) => n + d.bytes_in, 0)
  const totalOut = (data.nodes ?? []).reduce((n, d) => n + d.bytes_out, 0)
  const identified = (data.nodes ?? []).filter((n) => n.role !== 'unknown').length

  return (
    <div style={{ display: 'grid', gap: 14 }}>
      <div className="toolbar" style={{ marginBottom: 0 }}>
        <div style={{ fontSize: 12.5, color: 'var(--text-dim)' }}>
          {data.subnet || 'this network'}
          {data.scanned_at && <> · scanned {new Date(data.scanned_at).toLocaleTimeString()}</>}
        </div>
        <div className="spacer" style={{ flex: 1 }} />
        <button className="btn sm" disabled={scanning} onClick={scan}>
          <Icons.search size={13} /> {scanning ? 'Scanning…' : 'Scan network'}
        </button>
      </div>

      <div className="grid c3">
        <Stat label="Devices" value={String(data.nodes?.length ?? 0)}
          sub={`${identified} identified`} />
        <Stat label="Inbound" value={bytes(totalIn)} sub="towards these devices" tone="amber" />
        <Stat label="Outbound" value={bytes(totalOut)} sub="from these devices" tone="accent" />
      </div>

      {(data.notes ?? []).map((n) => (
        <Banner key={n} tone="info">{n}</Banner>
      ))}

      {(data.nodes ?? []).length === 0 ? (
        <Empty title="No devices on this network yet">
          Orbis only knows about devices whose traffic it has seen. If this is empty, nothing is
          routing through this node.
        </Empty>
      ) : (
        [...grouped.entries()].map(([role, nodes]) => {
          const Icon = Icons[ROLE_ICON[role] ?? 'search']
          return (
            <Card key={role} title={`${ROLE_LABEL[role] ?? role} (${nodes.length})`}>
              <div style={{ display: 'grid', gap: 9 }}>
                {nodes.map((n) => (
                  <div key={n.id}>
                    <DeviceRow n={n} onSelect={() => setSelected(n)} icon={Icon} />
                    {(childrenOf.get(n.id) ?? []).length > 0 && (
                      <div style={{
                        marginLeft: 22, marginTop: 7, paddingLeft: 13,
                        borderLeft: '1px solid var(--line-soft)', display: 'grid', gap: 7,
                      }}>
                        <div style={{ fontSize: 11, color: 'var(--text-faint)' }}>
                          hosts {(childrenOf.get(n.id) ?? []).length} guest(s)
                          {n.parent_basis ? '' : ''}
                        </div>
                        {(childrenOf.get(n.id) ?? []).map((c) => (
                          <DeviceRow key={c.id} n={c} onSelect={() => setSelected(c)}
                            icon={Icons[ROLE_ICON[c.role] ?? 'grid']} compact />
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

      {selected && <Detail n={selected} onClose={() => setSelected(null)} />}
    </div>
  )
}

function DeviceRow({ n, onSelect, icon: Icon, compact: dense }: {
  n: TopoNode; onSelect: () => void; icon: (p: { size?: number }) => JSX.Element; compact?: boolean
}) {
  // Direction at a glance: an arrow whose weight follows the dominant flow.
  const inHeavy = n.bytes_in > n.bytes_out
  return (
    <button onClick={onSelect} style={{
      display: 'flex', alignItems: 'center', gap: 10, width: '100%',
      background: 'transparent', border: 'none', color: 'inherit',
      cursor: 'pointer', padding: dense ? '2px 0' : '3px 0', textAlign: 'left',
    }}>
      <span className={`dot ${n.online ? 'on' : 'off'}`} />
      <Icon size={dense ? 13 : 15} />
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: dense ? 12.5 : 13, display: 'flex', gap: 7, alignItems: 'baseline', flexWrap: 'wrap' }}>
          <span>{n.label}</span>
          {n.platform && <span className="tag" style={{ fontSize: 10 }}>{n.platform}</span>}
          {n.virtual && <span className="tag info" style={{ fontSize: 10 }}>virtual</span>}
          {n.confidence === 'guessed' && (
            <span className="tag warn" style={{ fontSize: 10 }}>uncertain</span>
          )}
        </div>
        <div className="mono" style={{ fontSize: 10.5, color: 'var(--text-faint)' }}>
          {n.ip}{n.services?.length ? ` · ${n.services.slice(0, 3).join(', ')}` : ''}
        </div>
      </div>
      <div style={{ textAlign: 'right', fontSize: 10.5, color: 'var(--text-faint)', minWidth: 96 }}>
        <div style={{ color: inHeavy ? 'var(--amber)' : undefined }}>
          ↓ {bytes(n.bytes_in)}
        </div>
        <div style={{ color: !inHeavy ? 'var(--accent)' : undefined }}>
          ↑ {bytes(n.bytes_out)}
        </div>
      </div>
    </button>
  )
}

function Detail({ n, onClose }: { n: TopoNode; onClose: () => void }) {
  return (
    <Card title={n.label} actions={<button className="btn sm" onClick={onClose}>Close</button>}>
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
          <div style={{ fontSize: 12, color: 'var(--text-dim)', marginBottom: 6 }}>
            How it was identified
          </div>
          <ul style={{ margin: 0, paddingLeft: 18, fontSize: 11.5, color: 'var(--text-faint)', lineHeight: 1.7 }}>
            {n.evidence.map((e) => <li key={e}>{e}</li>)}
          </ul>
        </div>
      ) : null}
    </Card>
  )
}
