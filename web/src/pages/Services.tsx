import { useMemo, useState } from 'react'
import { api } from '../api'
import { usePoll } from '../hooks'
import { Banner, Bar, Card, Drawer, Empty, Loading, Search, Segmented, Sparkline, Spinner, useToast } from '../ui'
import { bytes, num } from '../format'
import type { ServiceDetail, ServiceDevice, ServicePoint, ServiceTotal } from '../types'

/**
 * Services: who uses what. Two views over the same hourly rollups: by
 * service across the network, and by device. Devices whose bytes this node
 * cannot see (not intercepted, node not inline) are marked DNS-only rather
 * than shown as zero, because zero would be a lie.
 */

const RANGES = [
  { value: '1', label: '1h' }, { value: '24', label: '24h' }, { value: '168', label: '7d' }, { value: '720', label: '30d' },
]

const PALETTE = ['#4ee8c0', '#63b3ff', '#c39bff', '#ff8fa3', '#ffc266', '#5ce39a', '#8fd3ff', '#e8b04e']

export function ServicesPage({ onNavigate }: { onNavigate: (r: 'clients' | 'intercept') => void }) {
  const [hours, setHours] = useState(24)
  const [view, setView] = useState<'service' | 'device'>('service')
  const [query, setQuery] = useState('')
  const [openService, setOpenService] = useState<string | null>(null)
  const [openDevice, setOpenDevice] = useState<string | null>(null)
  const toast = useToast()

  const { data, loading } = usePoll(() => api.services.list(hours), 30000, [hours])
  const { data: byDevice } = usePoll(() => (view === 'device' ? api.services.devices(hours) : Promise.resolve(null)), 30000, [hours, view])

  const services = useMemo(() => {
    const q = query.trim().toLowerCase()
    return (data?.services ?? []).filter((s) => !q || s.service.toLowerCase().includes(q) || s.category.includes(q))
  }, [data, query])

  const visible = (data?.devices ?? []).filter((d) => d.bytes_visible).length
  const total = data?.devices.length ?? 0
  const totalBytes = (data?.services ?? []).reduce((a, s) => a + s.bytes_in + s.bytes_out, 0)
  const totalLookups = (data?.services ?? []).reduce((a, s) => a + s.lookups, 0)

  return (
    <>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14, flexWrap: 'wrap' }}>
        <Segmented value={String(hours)} onChange={(v) => setHours(Number(v))} options={RANGES} />
        <Segmented value={view} onChange={setView}
          options={[{ value: 'service', label: 'By service' }, { value: 'device', label: 'By device' }]} />
        <div style={{ flex: 1, minWidth: 160, maxWidth: 320 }}>
          <Search value={query} onChange={setQuery} placeholder="Service or category…" />
        </div>
        {data && (
          <span className="hint" style={{ whiteSpace: 'nowrap' }}>
            {bytes(totalBytes)} · {num(totalLookups)} lookups · bytes visible for {visible} of {total} devices
          </span>
        )}
      </div>

      {data && data.mode !== 'inline' && visible < total && (
        <Banner tone="info">
          This node is not the gateway, so it sees bytes only for devices it intercepts ({visible} of {total}).
          The rest show DNS lookups, which still tell you which services a device talks to and how often.
          Use "Intercept" on a device below to see its bytes, or switch the node to inline mode.
        </Banner>
      )}

      {view === 'service' ? (
        <Card title={`${services.length} services`} flush>
          {loading && !data ? <Loading what="services" /> : services.length === 0 ? (
            <Empty title="Nothing yet">Rollups fill in within a minute of traffic; history is folded in on first start.</Empty>
          ) : (
            <div className="table-wrap">
              <table className="t">
                <thead>
                  <tr>
                    <th>Service</th><th>Devices</th><th>Connections</th><th>Down</th><th>Up</th><th>Lookups</th><th>Blocked</th><th style={{ width: 130 }}>Trend</th>
                  </tr>
                </thead>
                <tbody>
                  {services.map((s) => (
                    <tr key={s.service} style={{ cursor: 'pointer' }} onClick={() => setOpenService(s.service)}>
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                          <span style={{ fontWeight: 560 }}>{s.service}</span>
                          <span className={`cat ${s.category}`}>{s.category}</span>
                        </div>
                      </td>
                      <td className="mono">{s.devices}</td>
                      <td className="mono">{num(s.conns)}</td>
                      <td className="mono">{s.bytes_in ? bytes(s.bytes_in) : <span className="hint">—</span>}</td>
                      <td className="mono">{s.bytes_out ? bytes(s.bytes_out) : <span className="hint">—</span>}</td>
                      <td className="mono">{num(s.lookups)}</td>
                      <td className="mono" style={{ color: s.blocked ? 'var(--red)' : undefined }}>{s.blocked ? num(s.blocked) : '—'}</td>
                      <td><Sparkline points={s.spark ?? []} height={26} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      ) : (
        <div style={{ display: 'grid', gap: 12 }}>
          {!byDevice ? <Loading what="devices" /> : byDevice.devices.length === 0 ? (
            <Card><Empty title="No device activity in this window" /></Card>
          ) : (
            [...byDevice.devices]
              .filter((d) => !query.trim() || d.name.toLowerCase().includes(query.trim().toLowerCase()) || (d.ip ?? '').includes(query.trim()))
              .sort((a, b) => (b.bytes_in + b.bytes_out) - (a.bytes_in + a.bytes_out) || b.lookups - a.lookups)
              .map((d) => <DeviceRow key={d.client_id} d={d} onOpen={() => setOpenDevice(d.client_id)} onIntercept={async () => {
                if (!d.ip || !d.mac) { toast('This device has no MAC recorded yet; wait for it to be seen on the LAN.', 'err'); return }
                if (!confirm(`Pull ${d.name}'s traffic through this node by ARP interception? Its connections will flow via Orbis from now on.`)) return
                try {
                  await api.intercept.enroll(d.ip, d.mac)
                  toast(`${d.name} is now intercepted; bytes appear within a minute`, 'ok')
                } catch (e) {
                  toast(e instanceof Error ? e.message : 'Could not enrol the device', 'err')
                }
              }} />)
          )}
        </div>
      )}

      {openService && <ServiceDrawer service={openService} hours={hours} onClose={() => setOpenService(null)} />}
      {openDevice && <DeviceDrawer clientID={openDevice} hours={hours} onClose={() => setOpenDevice(null)} onNavigate={onNavigate} />}
    </>
  )
}

function DeviceRow({ d, onOpen, onIntercept }: { d: ServiceDevice; onOpen: () => void; onIntercept: () => void }) {
  const svcs = Array.isArray(d.services) ? d.services : []
  const totalBytes = d.bytes_in + d.bytes_out
  const measure = totalBytes > 0 ? (s: ServiceTotal) => s.bytes_in + s.bytes_out : (s: ServiceTotal) => s.lookups
  const sum = svcs.reduce((a, s) => a + measure(s), 0) || 1
  return (
    <Card>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
        <div style={{ flex: 1, minWidth: 200 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ fontWeight: 560 }}>{d.name}</span>
            {d.ip && <span className="mono hint" style={{ fontSize: 11.5 }}>{d.ip}</span>}
            <span className={`vis${d.bytes_visible ? ' bytes' : ''}`}>{d.bytes_visible ? 'bytes visible' : 'DNS only'}</span>
          </div>
          <div className="hint" style={{ fontSize: 11.5, marginTop: 2 }}>
            {totalBytes > 0 ? `${bytes(d.bytes_in)} down · ${bytes(d.bytes_out)} up · ` : ''}{num(d.conns)} connections · {num(d.lookups)} lookups{d.blocked ? ` · ${num(d.blocked)} blocked` : ''}
          </div>
        </div>
        <div style={{ display: 'flex', gap: 6 }}>
          {!d.bytes_visible && !d.intercepted && <button className="btn sm" onClick={onIntercept}>Intercept</button>}
          <button className="btn sm" onClick={onOpen}>Details</button>
        </div>
      </div>
      {svcs.length > 0 && (
        <div style={{ marginTop: 10 }}>
          <div className="stack">
            {svcs.map((s, i) => (
              <i key={s.service} style={{ width: `${(measure(s) / sum) * 100}%`, background: PALETTE[i % PALETTE.length] }}
                title={`${s.service}: ${totalBytes > 0 ? bytes(s.bytes_in + s.bytes_out) : `${num(s.lookups)} lookups`}`} />
            ))}
          </div>
          <div className="legend">
            {svcs.map((s, i) => (
              <span key={s.service}><i style={{ background: PALETTE[i % PALETTE.length] }} />{s.service} <span className="mono">{totalBytes > 0 ? bytes(s.bytes_in + s.bytes_out) : num(s.lookups)}</span></span>
            ))}
          </div>
        </div>
      )}
    </Card>
  )
}

function HourBars({ series }: { series: ServicePoint[] }) {
  const hasBytes = series.some((p) => p.bytes_in + p.bytes_out > 0)
  const vals = series.map((p) => (hasBytes ? p.bytes_in + p.bytes_out : p.lookups))
  const max = Math.max(1, ...vals)
  return (
    <div>
      <div className="bars">
        {series.map((p, i) => (
          <i key={p.t} className={hasBytes ? '' : 'lookups'} style={{ height: `${Math.max(2, (vals[i] / max) * 100)}%` }}
            title={`${new Date(p.t * 1000).toLocaleString()}: ${hasBytes ? bytes(vals[i]) : `${num(vals[i])} lookups`}`} />
        ))}
      </div>
      <div className="hint" style={{ fontSize: 11, marginTop: 4 }}>
        {hasBytes ? 'Bytes per hour' : 'Lookups per hour (this node does not see the bytes)'}
        {series.length > 0 ? ` · ${new Date(series[0].t * 1000).toLocaleString()} → now` : ''}
      </div>
    </div>
  )
}

function ServiceDrawer({ service, hours, onClose }: { service: string; hours: number; onClose: () => void }) {
  const { data } = usePoll<ServiceDetail>(() => api.services.detail(service, hours), 60000, [service, hours])
  const max = Math.max(1, ...(data?.devices ?? []).map((d) => d.bytes_in + d.bytes_out || d.lookups))
  return (
    <Drawer title={service} onClose={onClose}>
      {!data ? <Loading what="detail" /> : (
        <div style={{ display: 'grid', gap: 16 }}>
          <HourBars series={data.series} />
          <div>
            <div className="hint" style={{ marginBottom: 6, textTransform: 'uppercase', letterSpacing: '.08em', fontSize: 10.5 }}>By device</div>
            <div style={{ display: 'grid', gap: 8 }}>
              {data.devices.map((d) => (
                <div key={d.client_id}>
                  <div style={{ display: 'flex', gap: 8, alignItems: 'baseline', fontSize: 12.5 }}>
                    <span className="truncate" style={{ flex: 1 }}>{d.name}</span>
                    <span className="mono hint" style={{ fontSize: 11.5 }}>
                      {d.bytes_visible ? `${bytes(d.bytes_in)} ↓ ${bytes(d.bytes_out)} ↑ · ` : ''}{num(d.conns)} conn · {num(d.lookups)} lookups{d.blocked ? ` · ${num(d.blocked)} blocked` : ''}
                    </span>
                  </div>
                  <Bar value={d.bytes_in + d.bytes_out || d.lookups} max={max} tone={d.bytes_visible ? undefined : 'info'} />
                </div>
              ))}
            </div>
          </div>
          {data.hosts.length > 0 && (
            <div>
              <div className="hint" style={{ marginBottom: 6, textTransform: 'uppercase', letterSpacing: '.08em', fontSize: 10.5 }}>Hosts behind it</div>
              <table className="t">
                <tbody>
                  {data.hosts.map((h) => (
                    <tr key={h.host}>
                      <td className="mono truncate" style={{ fontSize: 11.5 }} title={h.host}>{h.host}</td>
                      <td className="mono" style={{ whiteSpace: 'nowrap' }}>{num(h.conns)}</td>
                      <td className="mono" style={{ whiteSpace: 'nowrap' }}>{bytes(h.bytes_in + h.bytes_out)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </Drawer>
  )
}

function DeviceDrawer({ clientID, hours, onClose, onNavigate }: {
  clientID: string; hours: number; onClose: () => void; onNavigate: (r: 'clients' | 'intercept') => void
}) {
  const { data } = usePoll(() => api.services.device(clientID, hours), 60000, [clientID, hours])
  const name = (data?.device?.name as string | undefined) ?? clientID
  const totalBytes = (data?.services ?? []).reduce((a, s) => a + s.bytes_in + s.bytes_out, 0)
  return (
    <Drawer title={name} onClose={onClose}
      actions={<button className="btn sm" onClick={() => onNavigate('clients')}>Open in Devices</button>}>
      {!data ? <Loading what="device" /> : (
        <div style={{ display: 'grid', gap: 16 }}>
          <HourBars series={data.series} />
          <div className="table-wrap">
            <table className="t">
              <thead><tr><th>Service</th><th>Conn</th><th>{totalBytes > 0 ? 'Bytes' : 'Lookups'}</th><th>Blocked</th><th style={{ width: 110 }}>Trend</th></tr></thead>
              <tbody>
                {data.services.map((s) => (
                  <tr key={s.service}>
                    <td><span style={{ fontWeight: 560 }}>{s.service}</span> <span className={`cat ${s.category}`}>{s.category}</span></td>
                    <td className="mono">{num(s.conns)}</td>
                    <td className="mono">{totalBytes > 0 ? bytes(s.bytes_in + s.bytes_out) : num(s.lookups)}</td>
                    <td className="mono" style={{ color: s.blocked ? 'var(--red)' : undefined }}>{s.blocked ? num(s.blocked) : '—'}</td>
                    <td><Sparkline points={s.spark ?? []} height={22} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {data.services.length === 0 && <Empty title="Nothing in this window" />}
          <span style={{ display: 'none' }}><Spinner /></span>
        </div>
      )}
    </Drawer>
  )
}
