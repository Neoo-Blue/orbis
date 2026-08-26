import { useState } from 'react'
import { api } from '../api'
import { usePoll } from '../hooks'
import { Banner, Card, Empty, Icons, Loading, Stat, useToast } from '../ui'
import { ago, dateTime, compact } from '../format'
import type { SystemStatus } from '../types'

/** DHCP leases, zones and interfaces — the LAN plumbing view. */
export function NetworkPage({ status }: { status: SystemStatus | null }) {
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
