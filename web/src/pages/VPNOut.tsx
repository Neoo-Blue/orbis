import { useMemo, useState } from 'react'
import { api } from '../api'
import { usePoll } from '../hooks'
import { Banner, Card, Drawer, Empty, Field, Icons, Loading, Search, Switch, useToast } from '../ui'
import { bytes, clientName } from '../format'
import type { Client } from '../types'

/**
 * Outbound VPN: connecting this network to a provider and choosing which
 * devices go through it.
 *
 * The mental model the page is built around is a single question per device —
 * "how does this leave the network" — with the same answer set whether the
 * destination is a WireGuard provider or a Tailscale exit node.
 */
export function VPNOutPage() {
  const { data, refresh } = usePoll(() => api.egress.status(), 8000)
  const { data: clients } = usePoll(() => api.clients.list(), 12000)
  const [importing, setImporting] = useState(false)
  const [query, setQuery] = useState('')
  const toast = useToast()

  const routeFor = useMemo(() => {
    const m = new Map<string, string>()
    for (const r of data?.routes ?? []) {
      if (r.client_id) m.set(r.client_id, r.target)
    }
    return m
  }, [data])

  const allRoute = (data?.routes ?? []).find((r) => r.source.toLowerCase() === 'all')

  const visible = useMemo(() => {
    const q = query.toLowerCase()
    return (clients?.clients ?? [])
      .filter((c) => !q || [c.label, c.hostname, c.ip, c.vendor].filter(Boolean).join(' ').toLowerCase().includes(q))
      .sort((a, b) => {
        // Devices already routed through a tunnel first: they are the ones
        // an operator came here to check on.
        const ar = routeFor.has(a.id) ? 0 : 1
        const br = routeFor.has(b.id) ? 0 : 1
        if (ar !== br) return ar - br
        if (a.online !== b.online) return a.online ? -1 : 1
        return clientName(a).localeCompare(clientName(b))
      })
  }, [clients, query, routeFor])

  if (!data) return <Loading what="outbound VPN" />

  const assign = async (clientId: string, target: string) => {
    try {
      await api.egress.assign(clientId, target)
      toast(target === 'wan' ? 'Device now goes out directly' : 'Device routed through the tunnel', 'ok')
      refresh()
    } catch (e) {
      toast(e instanceof Error ? e.message : 'Could not change routing', 'err')
    }
  }

  return (
    <>
      {data.warnings.map((w, i) => (
        <Banner key={i} tone={w.includes('unprotected') ? 'err' : 'warn'}>{w}</Banner>
      ))}

      <Card title="Tunnels" actions={
        <button className="btn primary sm" onClick={() => setImporting(true)}>
          <Icons.plus size={13} /> Add a provider
        </button>
      }>
        {data.tunnels.length === 0 ? (
          <Empty title="No outbound tunnels">
            Paste a WireGuard config from any provider — Mullvad, Proton, AirVPN, your own
            server — and then choose which devices go through it.
          </Empty>
        ) : (
          <div style={{ display: 'grid', gap: 11 }}>
            {data.tunnels.map((t) => {
              const target = data.targets.find((x) => x.id === t.name)
              const routed = data.routes.filter((r) => r.target === t.name).length
              return (
                <div key={t.name} style={{ border: '1px solid var(--line-soft)', borderRadius: 8, padding: 12 }}>
                  <div style={{ display: 'flex', gap: 11, alignItems: 'flex-start' }}>
                    <span className={`dot ${target?.up ? 'on' : t.enabled ? 'err' : 'off'}`} style={{ marginTop: 6 }} />
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
                        <strong>{t.name}</strong>
                        <span className="tag mono">{t.interface}</span>
                        {t.kill_switch && <span className="tag warn">kill switch</span>}
                        {routed > 0 && (
                          <span className="tag live">{routed} device{routed === 1 ? '' : 's'}</span>
                        )}
                      </div>
                      <div style={{ fontSize: 11.5, color: 'var(--text-faint)', marginTop: 3 }}>
                        {target?.detail} · {t.endpoint} · table {t.route_table}
                      </div>
                    </div>
                    <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                      <Switch checked={t.kill_switch} label="Kill switch"
                        onChange={async (v) => {
                          await api.egress.updateTunnel(t.name, { kill_switch: v })
                          toast(v
                            ? 'Traffic will stop rather than leak if this tunnel drops'
                            : 'Traffic will fall back to the WAN if this tunnel drops', 'ok')
                          refresh()
                        }} />
                      <button className="btn sm" onClick={async () => {
                        try {
                          await api.egress.tunnelAction(t.name, t.enabled ? 'stop' : 'start')
                          refresh()
                        } catch (e) {
                          toast(e instanceof Error ? e.message : 'Failed', 'err')
                        }
                      }}>{t.enabled ? 'Stop' : 'Start'}</button>
                      <button className="btn icon" title="Remove" onClick={async () => {
                        if (!confirm(`Remove ${t.name}? Devices routed through it go back to the WAN.`)) return
                        await api.egress.deleteTunnel(t.name)
                        refresh()
                      }}><Icons.trash size={13} /></button>
                    </div>
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </Card>

      <Card title="Every device">
        <div style={{ display: 'flex', gap: 11, alignItems: 'center', flexWrap: 'wrap' }}>
          <select className="select" style={{ maxWidth: 300 }} value={allRoute?.target ?? 'wan'}
            onChange={async (e) => {
              try {
                await api.egress.assignAll(e.target.value)
                toast(e.target.value === 'wan'
                  ? 'The whole network goes out directly again'
                  : 'The whole network now routes through the tunnel', 'ok')
                refresh()
              } catch (err) {
                toast(err instanceof Error ? err.message : 'Could not change routing', 'err')
              }
            }}>
            {data.targets.map((t) => (
              <option key={t.id} value={t.id}>{t.name}{t.up || t.kind === 'wan' ? '' : ' (down)'}</option>
            ))}
          </select>
          <span className="hint" style={{ flex: 1, minWidth: 220 }}>
            Applies to {data.lan.length ? data.lan.join(', ') : 'the local network'}. A device with
            its own setting below overrides this, so you can send everything through the VPN and
            still let one machine out directly.
          </span>
        </div>
      </Card>

      <div className="toolbar" style={{ marginBottom: 0 }}>
        <Search value={query} onChange={setQuery} placeholder="Find a device…" />
        <div style={{ flex: 1 }} />
        <span className="tag">{routeFor.size} device{routeFor.size === 1 ? '' : 's'} individually routed</span>
      </div>

      <Card flush>
        {visible.length === 0 ? <Empty title="No devices match" /> : (
          <div className="table-wrap" style={{ maxHeight: 'calc(100vh - 480px)', minHeight: 220 }}>
            <table className="t">
              <thead>
                <tr><th>Device</th><th>Address</th><th className="num">Traffic</th><th style={{ width: 240 }}>Leaves through</th></tr>
              </thead>
              <tbody>
                {visible.map((c: Client) => {
                  const current = routeFor.get(c.id) ?? 'wan'
                  return (
                    <tr key={c.id}>
                      <td>
                        <span className={`dot ${c.online ? 'on' : 'off'}`} style={{ marginRight: 8 }} />
                        <span className="truncate" style={{ maxWidth: 200 }}>{clientName(c)}</span>
                      </td>
                      <td className="mono" style={{ fontSize: 11.5, color: 'var(--text-dim)' }}>{c.ip}</td>
                      <td className="num">{bytes(c.rx_bytes + c.tx_bytes)}</td>
                      <td>
                        <select className="select" value={current}
                          onChange={(e) => assign(c.id, e.target.value)}>
                          {data.targets.map((t) => (
                            <option key={t.id} value={t.id}>
                              {t.name}{t.up || t.kind === 'wan' ? '' : ' (down)'}
                            </option>
                          ))}
                        </select>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {data.status.active_rules.length > 0 && (
        <Card title="Policy rules in the kernel">
          <div className="hint" style={{ marginBottom: 9 }}>
            What is actually installed right now, as opposed to what is configured.
          </div>
          <pre style={{
            background: 'var(--bg-2)', border: '1px solid var(--line-soft)', borderRadius: 7,
            padding: '9px 11px', fontSize: 11, overflow: 'auto', maxHeight: 160,
          }}>{data.status.active_rules.join('\n')}</pre>
        </Card>
      )}

      {importing && <ImportTunnel onClose={() => setImporting(false)} onDone={() => { setImporting(false); refresh() }} />}
    </>
  )
}

function ImportTunnel({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const [name, setName] = useState('')
  const [conf, setConf] = useState('')
  const [killSwitch, setKillSwitch] = useState(true)
  const [busy, setBusy] = useState(false)
  const toast = useToast()

  const submit = async () => {
    setBusy(true)
    try {
      const r = await api.egress.importTunnel({
        name: name.trim() || 'vpn', config: conf, kill_switch: killSwitch, enable: true,
      })
      if (r.warning) toast(r.warning, 'err')
      else if (r.ignored?.length) toast(`Imported. Ignored provider directives: ${r.ignored.join(', ')}`, 'ok')
      else toast('Tunnel imported and connecting', 'ok')
      onDone()
    } catch (e) {
      toast(e instanceof Error ? e.message : 'Could not import that config', 'err')
    } finally {
      setBusy(false)
    }
  }

  return (
    <Drawer title="Add a VPN provider" onClose={onClose}
      actions={
        <button className="btn primary sm" disabled={busy || !conf.trim()} onClick={submit}>
          {busy ? 'Connecting…' : 'Import'}
        </button>
      }>
      <div style={{ display: 'grid', gap: 13 }}>
        <Field label="Name" hint="What this connection is, so you can tell two providers apart.">
          <input className="input" value={name} autoFocus placeholder="Mullvad — Amsterdam"
            onChange={(e) => setName(e.target.value)} />
        </Field>

        <Field label="WireGuard configuration"
          hint="Paste the whole .conf file your provider gave you. Orbis reads the keys, address, endpoint and MTU from it.">
          <textarea className="textarea" rows={13} value={conf} spellCheck={false}
            placeholder={'[Interface]\nPrivateKey = ...\nAddress = 10.64.0.2/32\nDNS = 10.64.0.1\n\n[Peer]\nPublicKey = ...\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 1.2.3.4:51820'}
            onChange={(e) => setConf(e.target.value)} />
        </Field>

        <div style={{ display: 'grid', gap: 5 }}>
          <Switch checked={killSwitch} onChange={setKillSwitch} label="Kill switch" />
          <div className="hint" style={{ marginLeft: 43 }}>
            If the tunnel drops, devices routed through it lose internet instead of silently
            falling back to the plain connection. That fallback is the failure a VPN exists to
            prevent, and the one nobody notices.
          </div>
        </div>

        <Banner tone="info">
          <code>PostUp</code> and <code>PostDown</code> hooks in a provider's file are ignored
          rather than executed — they are arbitrary shell from a third party, and everything they
          normally do (NAT, kill switch, DNS) Orbis does itself.
        </Banner>
      </div>
    </Drawer>
  )
}
