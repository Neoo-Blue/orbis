import { useState } from 'react'
import { api } from '../api'
import { usePoll } from '../hooks'
import {
  Banner, Card, CopyButton, Drawer, Empty, Field, Icons, Loading, Segmented, Stat, Switch, useToast,
} from '../ui'
import { ago, bytes, clientName } from '../format'
import type { Client, WGPeer } from '../types'

type Tab = 'wireguard' | 'tailscale'

export function VPNPage() {
  const [tab, setTab] = useState<Tab>('wireguard')
  return (
    <div style={{ display: 'grid', gap: 14 }}>
      <div className="toolbar" style={{ marginBottom: 0 }}>
        <Segmented value={tab} onChange={setTab}
          options={[
            { value: 'wireguard', label: 'WireGuard' },
            { value: 'tailscale', label: 'Tailscale' },
          ]} />
      </div>
      {tab === 'wireguard' ? <WireGuard /> : <Tailscale />}
    </div>
  )
}

/* ---------------- WireGuard ---------------- */

function WireGuard() {
  const { data: status, refresh: refreshStatus } = usePoll(() => api.vpn.status(), 10000)
  const { data: peers, refresh: refreshPeers } = usePoll(() => api.vpn.peers(), 15000)
  const { refresh: refreshConfig } = usePoll(() => api.config.get(), 0)
  const [adding, setAdding] = useState(false)
  const [created, setCreated] = useState<{ peer: WGPeer; config: string } | null>(null)
  const [showQR, setShowQR] = useState<WGPeer | null>(null)
  const toast = useToast()

  const s = (status?.status ?? {}) as Record<string, unknown>
  const running = Boolean(s.server_up)
  const available = Boolean(s.available)
  const endpointSet = Boolean(s.server_endpoint)

  const toggle = async () => {
    try {
      await api.vpn.serverAction(running ? 'stop' : 'start')
      toast(running ? 'WireGuard stopped' : 'WireGuard started', 'ok')
      refreshStatus()
      refreshConfig()
    } catch (e) {
      toast(e instanceof Error ? e.message : 'Could not change state', 'err')
    }
  }

  return (
    <>
      {!available && (
        <Banner tone="err">
          <code>wg</code> is not installed on this node. Install <code>wireguard-tools</code>
          {' '}and restart Orbis.
        </Banner>
      )}
      {available && !endpointSet && (
        <Banner tone="warn">
          No public endpoint is set, so generated peer configs will not know where to connect.
          Set it in Settings → VPN as <code>host:port</code>.
        </Banner>
      )}

      <div className="grid c4">
        <Stat label="Server" value={running ? 'Running' : 'Stopped'} tone={running ? 'accent' : undefined}
          sub={`port ${s.server_port ?? '—'}`} />
        <Stat label="Peers" value={String(peers?.peers.length ?? 0)}
          sub={`${(peers?.peers ?? []).filter((p) => p.last_handshake &&
            Date.now() - new Date(p.last_handshake).getTime() < 180000).length} connected`} />
        <Stat label="Received" value={bytes((peers?.peers ?? []).reduce((a, p) => a + p.rx_bytes, 0))} />
        <Stat label="Sent" value={bytes((peers?.peers ?? []).reduce((a, p) => a + p.tx_bytes, 0))} />
      </div>

      <div className="toolbar" style={{ marginBottom: 0 }}>
        <button className={`btn ${running ? 'danger' : 'primary'}`} onClick={toggle} disabled={!available}>
          {running ? 'Stop server' : 'Start server'}
        </button>
        <button className="btn" onClick={() => setAdding(true)} disabled={!available}>
          <Icons.plus size={13} /> Add a device
        </button>
        <div style={{ flex: 1 }} />
        {typeof s.server_pubkey === 'string' && s.server_pubkey && (
          <>
            <span className="tag mono" style={{ maxWidth: 260 }} title={String(s.server_pubkey)}>
              <span className="truncate">{String(s.server_pubkey)}</span>
            </span>
            <CopyButton text={String(s.server_pubkey)} label="Copy public key" />
          </>
        )}
      </div>

      <Card flush>
        {!peers ? <Loading what="peers" /> : peers.peers.length === 0 ? (
          <Empty title="No devices yet">
            Add one to generate a key pair and a config you can scan or download.
          </Empty>
        ) : (
          <div className="table-wrap">
            <table className="t">
              <thead>
                <tr><th>Device</th><th>Tunnel address</th><th>Endpoint</th>
                  <th>Last handshake</th><th className="num">Down</th><th className="num">Up</th>
                  <th style={{ width: 150 }} /></tr>
              </thead>
              <tbody>
                {peers.peers.map((p) => {
                  const online = p.last_handshake && Date.now() - new Date(p.last_handshake).getTime() < 180000
                  return (
                    <tr key={p.id}>
                      <td>
                        <span className={`dot ${online ? 'on' : 'off'}`} style={{ marginRight: 8 }} />
                        {p.name}
                      </td>
                      <td className="mono" style={{ fontSize: 11.5 }}>{p.address}</td>
                      <td className="mono truncate" style={{ fontSize: 11, color: 'var(--text-faint)', maxWidth: 160 }}>
                        {p.endpoint || '—'}
                      </td>
                      <td style={{ fontSize: 11.5, color: 'var(--text-faint)' }}>{ago(p.last_handshake)}</td>
                      <td className="num">{bytes(p.rx_bytes)}</td>
                      <td className="num">{bytes(p.tx_bytes)}</td>
                      <td>
                        <div style={{ display: 'flex', gap: 5 }}>
                          <button className="btn sm" onClick={() => setShowQR(p)}>QR</button>
                          <a className="btn sm" href={api.vpn.peerConfigURL(p.id)} download>Config</a>
                          <button className="btn icon" title="Remove" onClick={async () => {
                            await api.vpn.deletePeer(p.id)
                            refreshPeers()
                          }}><Icons.trash size={13} /></button>
                        </div>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {adding && (
        <AddPeer
          onClose={() => setAdding(false)}
          onCreated={(result) => {
            setAdding(false)
            setCreated(result)
            refreshPeers()
          }}
        />
      )}

      {created && (
        <Drawer title={`${created.peer.name} is ready`} onClose={() => setCreated(null)}>
          <Banner tone="warn">
            This is the only convenient moment to move the key onto the device. The config stays
            downloadable, but treat it like a password from here on.
          </Banner>
          <img src={api.vpn.peerQRURL(created.peer.id)} alt="WireGuard configuration QR code"
            style={{ width: 260, margin: '0 auto 16px', borderRadius: 8, background: '#fff', padding: 8 }} />
          <pre style={{
            background: 'var(--bg-2)', border: '1px solid var(--line-soft)', borderRadius: 8,
            padding: 12, fontSize: 11, overflow: 'auto', lineHeight: 1.65,
          }}>{created.config}</pre>
          <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
            <CopyButton text={created.config} label="Copy config" />
            <a className="btn sm" href={api.vpn.peerConfigURL(created.peer.id)} download>
              <Icons.download size={13} /> Download
            </a>
          </div>
        </Drawer>
      )}

      {showQR && (
        <Drawer title={showQR.name} onClose={() => setShowQR(null)}>
          <img src={api.vpn.peerQRURL(showQR.id)} alt="WireGuard configuration QR code"
            style={{ width: 280, margin: '0 auto', borderRadius: 8, background: '#fff', padding: 8 }} />
          <div className="hint" style={{ textAlign: 'center', marginTop: 12 }}>
            Scan with the WireGuard app on the device.
          </div>
        </Drawer>
      )}
    </>
  )
}

function AddPeer({ onClose, onCreated }: {
  onClose: () => void
  onCreated: (r: { peer: WGPeer; config: string }) => void
}) {
  const [name, setName] = useState('')
  const [note, setNote] = useState('')
  const [busy, setBusy] = useState(false)
  const toast = useToast()

  return (
    <Drawer title="Add a device" onClose={onClose}
      actions={
        <button className="btn primary sm" disabled={!name.trim() || busy} onClick={async () => {
          setBusy(true)
          try {
            onCreated(await api.vpn.addPeer({ name: name.trim(), note }))
          } catch (e) {
            toast(e instanceof Error ? e.message : 'Could not create the peer', 'err')
          } finally {
            setBusy(false)
          }
        }}>{busy ? 'Creating…' : 'Create'}</button>
      }>
      <div style={{ display: 'grid', gap: 13 }}>
        <Field label="Name" hint="What this device is, so you can revoke the right one later.">
          <input className="input" value={name} autoFocus placeholder="Alex's phone"
            onChange={(e) => setName(e.target.value)} />
        </Field>
        <Field label="Note">
          <input className="input" value={note} onChange={(e) => setNote(e.target.value)} />
        </Field>
        <Banner tone="info">
          Orbis generates the key pair, a pre-shared key, and the next free tunnel address. The
          config routes all traffic through this network and points DNS here, so the device gets
          the same filtering it would on the LAN.
        </Banner>
      </div>
    </Drawer>
  )
}

/* ---------------- Tailscale ---------------- */

function Tailscale() {
  const { data, refresh } = usePoll(() => api.tailscale.status(), 8000)
  const { data: clients } = usePoll(() => api.clients.list(), 20000)
  const [busy, setBusy] = useState(false)
  const [authURL, setAuthURL] = useState<string | null>(null)
  const [routeDraft, setRouteDraft] = useState<string | null>(null)
  const toast = useToast()

  if (!data) return <Loading what="Tailscale" />

  const st = data.status
  const cfg = data.config as Record<string, unknown>
  const steered = new Set(data.steering_active ?? [])
  const gw = data.gateway ?? {
    applied: false, interfaces: [], wan: '', ip_forwarding: false,
    masquerade: false, dns_redirect: false,
  }

  const run = async (fn: () => Promise<unknown>, okMsg: string) => {
    setBusy(true)
    try {
      await fn()
      toast(okMsg, 'ok')
      refresh()
    } catch (e) {
      toast(e instanceof Error ? e.message : 'That did not work', 'err')
    } finally {
      setBusy(false)
    }
  }

  if (!st.available) {
    return (
      <Banner tone="warn">
        <strong style={{ display: 'block', marginBottom: 4 }}>Tailscale is not installed</strong>
        Install it on this node, then reload this page:
        <pre style={{
          background: 'var(--bg-2)', borderRadius: 6, padding: '7px 10px',
          marginTop: 7, fontSize: 11.5,
        }}>{data.install_hint ?? 'curl -fsSL https://tailscale.com/install.sh | sh'}</pre>
      </Banner>
    )
  }

  return (
    <>
      {data.warnings?.map((w, i) => (
        <Banner key={i} tone={w.includes('off the LAN') ? 'err' : 'warn'}>{w}</Banner>
      ))}
      {st.auth_url && (
        <Banner tone="info" action={
          <a className="btn sm primary" href={st.auth_url} target="_blank" rel="noreferrer">Open</a>
        }>
          This node is waiting to be authenticated to a tailnet.
        </Banner>
      )}
      {authURL && (
        <Banner tone="info" action={
          <a className="btn sm primary" href={authURL} target="_blank" rel="noreferrer">Open login</a>
        }>
          Finish the login in your browser, then come back and refresh.
        </Banner>
      )}

      <div className="grid c4">
        <Stat label="State" value={st.running ? 'Connected' : st.backend_state || 'Stopped'}
          tone={st.running ? 'accent' : undefined}
          sub={st.tailnet_name || (st.version ? `v${st.version.split('-')[0]}` : '—')} />
        <Stat label="Peers" value={String(st.peers?.length ?? 0)}
          sub={`${(st.peers ?? []).filter((p) => p.online).length} online`} />
        <Stat label="Exit node offered"
          value={st.advertising_exit_node ? (st.exit_node_approved ? 'Approved' : 'Pending') : 'No'}
          tone={st.advertising_exit_node ? (st.exit_node_approved ? 'accent' : 'amber') : undefined}
          sub={st.advertising_exit_node && !st.exit_node_approved ? 'approve in the admin console' : 'this network as an exit'} />
        <Stat label="Egress via" value={st.exit_node_in_use || 'Direct'}
          tone={st.exit_node_in_use ? 'blue' : undefined}
          sub={st.exit_node_in_use ? `${steered.size} device(s) steered` : 'traffic leaves over the WAN'} />
      </div>

      <div className="toolbar" style={{ marginBottom: 0 }}>
        {st.running ? (
          <button className="btn danger" disabled={busy}
            onClick={() => run(() => api.tailscale.down(), 'Tailscale disconnected')}>Disconnect</button>
        ) : (
          <button className="btn primary" disabled={busy}
            onClick={() => run(() => api.tailscale.up(), 'Tailscale connecting')}>Connect</button>
        )}
        <button className="btn" disabled={busy} onClick={async () => {
          setBusy(true)
          try {
            const r = await api.tailscale.login()
            setAuthURL(r.auth_url)
          } catch (e) {
            toast(e instanceof Error ? e.message : 'Login failed', 'err')
          } finally {
            setBusy(false)
          }
        }}>Log in…</button>
        <div style={{ flex: 1 }} />
        {st.self && (
          <span className="tag mono" title={st.self.addresses.join(', ')}>
            {st.self.dns_name || st.self.name}
          </span>
        )}
      </div>

      <Card title="Gateway path">
        <div className="hint" style={{ marginBottom: 12, lineHeight: 1.7 }}>
          Being an approved exit node is not enough on its own — this node also has to forward and
          NAT the traffic. These are the pieces that make it actually work, and they are installed
          whether or not Orbis is inline for the LAN, because for tunnel traffic it <em>is</em> the
          gateway.
        </div>
        <div className="grid c4">
          <GatewayCheck ok={gw.applied} label="Tunnel rules" detail={gw.applied ? `on ${(gw.interfaces || []).join(', ')}` : 'not installed'} />
          <GatewayCheck ok={gw.ip_forwarding} label="IP forwarding" detail={gw.ip_forwarding ? 'enabled' : 'off — nothing can be routed'} />
          <GatewayCheck ok={gw.masquerade} label="NAT" detail={gw.masquerade ? `out via ${gw.wan}` : 'no WAN interface set'} />
          <GatewayCheck ok={gw.dns_redirect} label="DNS filtering" detail={gw.dns_redirect ? 'tunnel clients forced onto this resolver' : 'clients keep their own DNS'} />
        </div>
        {gw.last_error && (
          <div className="hint" style={{ color: 'var(--red)', marginTop: 10 }}>{gw.last_error}</div>
        )}
      </Card>

      <div className="grid c2">
        <Card title="Serve this network as an exit node">
          <div style={{ display: 'grid', gap: 12 }}>
            <Switch
              checked={st.advertising_exit_node}
              onChange={(v) => run(async () => {
                const r = await api.tailscale.advertiseExitNode(v)
                if (r.next_step) toast(r.next_step, 'info')
              }, v ? 'Now advertising as an exit node' : 'No longer advertising')}
              label="Advertise as an exit node"
            />
            <div className="hint">
              Devices anywhere on your tailnet can route their internet traffic through this
              network. Their connections are captured and filtered here like any LAN device — but
              their <em>DNS</em> goes through Tailscale's MagicDNS on the client and never reaches
              this resolver. To filter that too, set{' '}
              <code>{st.self?.addresses?.[0] ?? "this node's tailnet address"}</code> as the global
              nameserver under DNS → Nameservers in the Tailscale admin console, with "Override
              local DNS" on.
              {st.advertising_exit_node && !st.exit_node_approved && (
                <strong style={{ color: 'var(--amber)', display: 'block', marginTop: 5 }}>
                  Advertised, but not yet approved. Open the Tailscale admin console → Machines →
                  this node → Edit route settings → Use as exit node.
                </strong>
              )}
            </div>

            <div style={{ borderTop: '1px solid var(--line-soft)', paddingTop: 12 }}>
              <Field label="Advertise LAN subnets"
                hint="Comma-separated CIDRs. Makes this node a subnet router so tailnet devices reach the LAN without a client on every host. Also needs approval in the admin console.">
                <div style={{ display: 'flex', gap: 8 }}>
                  <input className="input mono"
                    value={routeDraft ?? (cfg.advertise_routes as string[] ?? []).join(', ')}
                    placeholder="192.168.1.0/24"
                    onChange={(e) => setRouteDraft(e.target.value)} />
                  <button className="btn" disabled={busy || routeDraft === null} onClick={() => run(
                    () => api.tailscale.setRoutes(
                      (routeDraft ?? '').split(',').map((r) => r.trim()).filter(Boolean),
                    ),
                    'Routes updated',
                  ).then(() => setRouteDraft(null))}>Save</button>
                </div>
              </Field>
              {st.pending_routes.length > 0 && (
                <div className="hint" style={{ color: 'var(--amber)', marginTop: 6 }}>
                  Awaiting approval: {st.pending_routes.join(', ')}
                </div>
              )}
              {st.approved_routes.length > 0 && (
                <div className="hint" style={{ color: 'var(--accent)', marginTop: 6 }}>
                  Active: {st.approved_routes.join(', ')}
                </div>
              )}
            </div>
          </div>
        </Card>

        <Card title="Route this network through an exit node">
          <div style={{ display: 'grid', gap: 12 }}>
            <Field label="Exit node"
              hint="Sends this node's own traffic out through the chosen peer.">
              <select className="select" value={String(cfg.exit_node ?? '')} disabled={busy}
                onChange={(e) => run(() => api.tailscale.setExitNode(e.target.value),
                  e.target.value ? `Egress now via ${e.target.value}` : 'Egress restored to the WAN')}>
                <option value="">None — go out the WAN directly</option>
                {st.available_exit_nodes.map((n) => (
                  <option key={n.id} value={n.dns_name || n.name}>
                    {n.name} {n.online ? '' : '(offline)'}
                  </option>
                ))}
              </select>
            </Field>
            {st.available_exit_nodes.length === 0 && (
              <div className="hint">
                No peer on this tailnet is offering itself as an exit node yet.
              </div>
            )}

            <Switch checked={Boolean(cfg.exit_node_allow_lan)} disabled={busy}
              onChange={(v) => run(
                () => api.tailscale.setExitNode(String(cfg.exit_node ?? ''), v),
                v ? 'LAN stays reachable' : 'LAN access through the exit node disabled',
              )}
              label="Keep the local network reachable" />
            <div className="hint" style={{ marginTop: -4 }}>
              Without this, selecting an exit node also cuts off this box's own UI from LAN devices.
            </div>

            <div style={{ borderTop: '1px solid var(--line-soft)', paddingTop: 12 }}>
              <div style={{ fontSize: 11.5, color: 'var(--text-dim)', marginBottom: 8 }}>
                Steer specific devices through the exit node. Everything else keeps using the WAN.
                <strong style={{ display: 'block', color: 'var(--text-faint)', marginTop: 4 }}>
                  Selecting an exit node alone only moves this node's traffic — LAN clients need to
                  be listed here.
                </strong>
              </div>
              <SteerPicker
                clients={clients?.clients ?? []}
                selected={steered}
                disabled={busy || !cfg.exit_node}
                onChange={(list) => run(() => api.tailscale.steer(list), 'Steering updated')}
              />
            </div>
          </div>
        </Card>
      </div>

      <Card title="Tailnet peers" flush>
        {st.peers.length === 0 ? <Empty title="No peers" /> : (
          <div className="table-wrap">
            <table className="t">
              <thead>
                <tr><th>Machine</th><th>Address</th><th>OS</th><th>Role</th>
                  <th className="num">Down</th><th className="num">Up</th><th>Seen</th></tr>
              </thead>
              <tbody>
                {st.peers.map((p) => (
                  <tr key={p.id}>
                    <td>
                      <span className={`dot ${p.online ? 'on' : 'off'}`} style={{ marginRight: 8 }} />
                      {p.name}
                    </td>
                    <td className="mono" style={{ fontSize: 11.5 }}>{p.addresses[0] ?? '—'}</td>
                    <td style={{ color: 'var(--text-faint)', fontSize: 11.5 }}>{p.os || '—'}</td>
                    <td>
                      {p.is_exit_node && <span className="tag live">in use as exit</span>}
                      {!p.is_exit_node && p.exit_node_option && <span className="tag info">exit available</span>}
                      {p.routes && p.routes.length > 0 && (
                        <span className="tag" title={p.routes.join(', ')} style={{ marginLeft: 4 }}>subnet router</span>
                      )}
                    </td>
                    <td className="num">{bytes(p.rx_bytes)}</td>
                    <td className="num">{bytes(p.tx_bytes)}</td>
                    <td style={{ fontSize: 11.5, color: 'var(--text-faint)' }}>
                      {p.online ? 'now' : ago(p.last_seen)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </>
  )
}

function GatewayCheck({ ok, label, detail }: { ok: boolean; label: string; detail: string }) {
  return (
    <div style={{ display: 'flex', gap: 9, alignItems: 'flex-start' }}>
      <span className={`dot ${ok ? 'on' : 'err'}`} style={{ marginTop: 5 }} />
      <div style={{ minWidth: 0 }}>
        <div style={{ fontSize: 12.5 }}>{label}</div>
        <div style={{ fontSize: 11, color: ok ? 'var(--text-faint)' : 'var(--amber)' }}>{detail}</div>
      </div>
    </div>
  )
}

function SteerPicker({ clients, selected, disabled, onChange }: {
  clients: Client[]; selected: Set<string>; disabled: boolean; onChange: (list: string[]) => void
}) {
  const [manual, setManual] = useState('')
  const list = [...selected]

  const toggle = (ip: string) => {
    const next = new Set(selected)
    if (next.has(ip)) next.delete(ip)
    else next.add(ip)
    onChange([...next])
  }

  return (
    <div style={{ display: 'grid', gap: 9 }}>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, maxHeight: 132, overflowY: 'auto' }}>
        {clients.filter((c) => c.online).slice(0, 40).map((c) => (
          <button key={c.id} className="btn sm" disabled={disabled}
            style={selected.has(c.ip)
              ? { borderColor: 'rgba(78,232,192,.5)', color: 'var(--accent)', background: 'var(--accent-glow)' }
              : undefined}
            onClick={() => toggle(c.ip)}>
            {clientName(c)}
          </button>
        ))}
        {clients.filter((c) => c.online).length === 0 && (
          <span className="hint">No devices are online to steer.</span>
        )}
      </div>
      <div style={{ display: 'flex', gap: 8 }}>
        <input className="input mono" value={manual} placeholder="Or a CIDR: 192.168.1.0/24"
          disabled={disabled} onChange={(e) => setManual(e.target.value)} />
        <button className="btn" disabled={disabled || !manual.trim()} onClick={() => {
          onChange([...new Set([...list, manual.trim()])])
          setManual('')
        }}>Add</button>
      </div>
      {list.length > 0 && (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5 }}>
          {list.map((ip) => (
            <span key={ip} className="tag live">
              {ip}
              <button style={{ background: 'none', border: 0, cursor: 'pointer', color: 'inherit', padding: 0, marginLeft: 3 }}
                onClick={() => onChange(list.filter((x) => x !== ip))} aria-label={`Stop steering ${ip}`}>×</button>
            </span>
          ))}
        </div>
      )}
    </div>
  )
}
