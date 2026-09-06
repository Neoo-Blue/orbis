import { useState } from 'react'
import { api } from '../api'
import { usePoll } from '../hooks'
import { Banner, Card, Empty, Field, Icons, Loading, Segmented, Stat, useToast } from '../ui'
import { ago, bytes, num } from '../format'
import type { HostedHost, LANService, PortForward, RouterInfo, StorageDevice } from '../types'

/**
 * Hosted apps: what this network runs, found by knocking on well-known ports
 * and reading the page behind each one (and by asking Docker hosts that let
 * us), the storage on it, and the port forwards this node created, in its own
 * firewall when it is the gateway or on the router over UPnP when it is not.
 */
type Tab = 'apps' | 'storage' | 'forwards'

const KIND_LABEL: Record<string, string> = { app: 'app', admin: 'admin panel', storage: 'storage', infra: 'infrastructure', web: 'web', other: 'port' }

export function HostedPage() {
  const [tab, setTab] = useState<Tab>('apps')
  const { data, refresh } = usePoll(() => api.hosted.overview(), 15000)
  const { data: storage, refresh: refreshStorage } = usePoll(() => api.hosted.storage(), 20000)
  const { data: fwd, refresh: refreshFwd } = usePoll(() => api.hosted.forwards(), 20000)
  const toast = useToast()
  const [busy, setBusy] = useState<string | null>(null)
  const [forwardFor, setForwardFor] = useState<{ host: string; port: number; name: string; sensitive: boolean } | null>(null)

  const refreshAll = () => { refresh(); refreshStorage(); refreshFwd() }
  const act = async (key: string, fn: () => Promise<unknown>, ok: string) => {
    setBusy(key)
    try {
      await fn()
      toast(ok, 'ok')
      refreshAll()
    } catch (e) {
      toast(e instanceof Error ? e.message : 'That did not work', 'err')
    } finally {
      setBusy(null)
    }
  }

  if (!data) return <Loading what="hosted apps" />
  const hosts = data.hosts ?? []
  const services = hosts.reduce((n, h) => n + h.services.filter((s) => s.online).length, 0)
  const containers = hosts.reduce((n, h) => n + h.services.filter((s) => s.source === 'docker' && s.online).length, 0)
  const forwards = fwd?.forwards ?? []
  const router = fwd?.router
  const canForward = data.forwarding.inline || data.forwarding.upnp

  return (
    <div style={{ display: 'grid', gap: 14 }}>
      {!data.enabled && (
        <Banner tone="warn" action={<button className="btn sm primary" onClick={() => act('on', () => api.config.patch({ 'discover.enabled': true }), 'Discovery is on')}>Turn on</button>}>
          Discovery is switched off. Nothing is scanned until it is on.
        </Banner>
      )}
      {data.last_error && <Banner tone="warn">{data.last_error}</Banner>}
      {!canForward && (
        <Banner tone="info">
          Port forwards need this node to be the gateway (inline mode) or UPnP to be on in Settings, so the router can be asked. Right now neither is the case, so the Forward buttons will explain rather than act.
        </Banner>
      )}

      <div className="grid c4">
        <Stat label="Devices hosting something" value={num(hosts.filter((h) => h.services.some((s) => s.online)).length)}
          sub={data.last_scan ? `scanned ${ago(data.last_scan)}` : 'not scanned yet'} />
        <Stat label="Services" value={num(services)} sub={containers > 0 ? `${containers} from Docker` : 'from port scans'} />
        <Stat label="Storage devices" value={num(storage?.storage.length ?? 0)} sub={(storage?.storage ?? []).map((s) => s.Name).slice(0, 3).join(', ') || 'none found'} />
        <Stat label="Port forwards" value={num(forwards.length)}
          sub={router?.found ? `router: ${router.model || router.name || 'found'}${router.external_ip ? `, ${router.external_ip}` : ''}` : data.forwarding.inline ? 'this node is the gateway' : router?.upnp_enabled ? 'router not found over UPnP' : 'UPnP off'} />
      </div>

      <div className="toolbar">
        <Segmented value={tab} onChange={setTab} options={[
          { value: 'apps', label: `Apps (${services})` },
          { value: 'storage', label: `Storage (${storage?.storage.length ?? 0})` },
          { value: 'forwards', label: `Port forwards (${forwards.length})` },
        ]} />
        <div className="spacer" />
        <button className="btn" disabled={data.scanning || busy === 'scan'}
          onClick={() => act('scan', () => api.hosted.scan(), 'Scanning the network; results land within a minute or two')}>
          <Icons.refresh size={14} /> {data.scanning ? 'Scanning…' : 'Scan now'}
        </button>
        <a className="btn" href="#/settings/hosted">Settings</a>
      </div>

      {tab === 'apps' && (
        hosts.length === 0
          ? <Card><Empty title="Nothing found yet">The first scan runs about a minute after start, then every {data.interval_hours} hours. Press Scan now to run one.</Empty></Card>
          : hosts.map((h) => <HostCard key={h.IP} host={h} onForward={(s) => setForwardFor({ host: s.host, port: s.port, name: s.name, sensitive: s.sensitive })} />)
      )}
      {tab === 'storage' && <StorageTab storage={storage?.storage ?? []} onForward={(host, port, name) => setForwardFor({ host, port, name, sensitive: true })} />}
      {tab === 'forwards' && (
        <ForwardsTab forwards={forwards} router={router} inline={data.forwarding.inline} busy={busy} act={act}
          onNew={() => setForwardFor({ host: '', port: 0, name: '', sensitive: false })} />
      )}

      {forwardFor && (
        <ForwardDialog initial={forwardFor} onClose={() => setForwardFor(null)} onDone={() => { setForwardFor(null); refreshAll() }} />
      )}
    </div>
  )
}

function HostCard({ host, onForward }: { host: HostedHost; onForward: (s: LANService) => void }) {
  const online = host.services.filter((s) => s.online)
  const offline = host.services.filter((s) => !s.online)
  return (
    <Card title={
      <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
        <h2>{host.Name}</h2>
        <span className="hint mono">{host.IP}</span>
        {host.Vendor && <span className="tag">{host.Vendor}</span>}
        {host.docker && <span className="tag info">Docker</span>}
        {host.storage && <span className="tag">storage</span>}
      </div>
    } actions={<span className="hint">{online.length} service{online.length === 1 ? '' : 's'}</span>} flush>
      <div className="table-wrap">
        <table className="t">
          <thead><tr><th>Service</th><th>Port</th><th>What</th><th>Seen</th><th></th></tr></thead>
          <tbody>
            {online.map((s) => <ServiceRow key={s.port + s.proto} s={s} onForward={onForward} />)}
            {offline.length > 0 && (
              <tr><td colSpan={5} className="hint" style={{ fontSize: 11.5 }}>
                Not answering now: {offline.map((s) => `${s.name} (:${s.port})`).join(', ')}
              </td></tr>
            )}
          </tbody>
        </table>
      </div>
    </Card>
  )
}

function ServiceRow({ s, onForward }: { s: LANService; onForward: (s: LANService) => void }) {
  const url = s.scheme ? `${s.scheme}://${s.host}:${s.port}/` : ''
  return (
    <tr>
      <td>
        <div style={{ display: 'flex', gap: 6, alignItems: 'center', flexWrap: 'wrap' }}>
          <strong>{s.name}</strong>
          {s.sensitive && <span className="tag warn" title="Should not be exposed to the internet directly">sensitive</span>}
        </div>
        {s.container && <div className="hint" style={{ fontSize: 11.5 }}>container {s.container} · {s.image}</div>}
        {!s.container && s.title && s.title !== s.name && <div className="hint" style={{ fontSize: 11.5 }}>{s.title}</div>}
      </td>
      <td className="mono">{s.port}/{s.proto}</td>
      <td className="hint">{KIND_LABEL[s.kind] ?? s.kind}{s.category ? ` · ${s.category}` : ''}{s.server ? ` · ${s.server}` : ''}</td>
      <td className="hint" style={{ whiteSpace: 'nowrap' }}>{ago(s.last_seen)}</td>
      <td style={{ whiteSpace: 'nowrap' }}>
        {url && <a className="btn sm" href={url} target="_blank" rel="noreferrer">Open</a>}{' '}
        <button className="btn sm" onClick={() => onForward(s)} title="Open an internet port to this service">Forward</button>
      </td>
    </tr>
  )
}

function StorageTab({ storage, onForward }: { storage: StorageDevice[]; onForward: (host: string, port: number, name: string) => void }) {
  if (storage.length === 0) {
    return <Card><Empty title="No NAS or SAN found">A device counts as storage when it is a known NAS vendor, the identifier called it a NAS, or it serves NFS, iSCSI, AFP or two file protocols. A Windows PC with file sharing alone does not.</Empty></Card>
  }
  return (
    <>
      {storage.map((s) => (
        <Card key={s.IP} title={
          <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
            <h2>{s.Name}</h2>
            <span className="hint mono">{s.IP}</span>
            {s.Vendor && <span className="tag">{s.Vendor}</span>}
            <span className={`tag ${s.Online ? 'ok' : ''}`}>{s.Online ? 'online' : 'not seen recently'}</span>
          </div>
        } actions={s.web_ui ? <a className="btn sm" href={s.web_ui} target="_blank" rel="noreferrer">Open admin</a> : undefined}>
          <div style={{ display: 'grid', gap: 12 }}>
            {s.exposed.length > 0 && (
              <Banner tone="warn">This storage is forwarded from the internet: {s.exposed.join(', ')}. File protocols on the open internet are the classic way a NAS gets ransomed. Prefer a VPN.</Banner>
            )}
            <div>
              <div className="hint" style={{ marginBottom: 6 }}>Protocols</div>
              <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                {s.protocols.length === 0 && <span className="hint">no file protocol answered; the vendor or identifier says storage</span>}
                {s.protocols.map((p) => (
                  <span key={p.port} className="tag" title={`port ${p.port}`}>{p.name} <span className="mono hint">:{p.port}</span>
                    <button className="btn sm" style={{ marginLeft: 6 }} onClick={() => onForward(s.IP, p.port, `${s.Name} ${p.name}`)} title="Forward this protocol (not recommended)">Forward</button>
                  </span>
                ))}
              </div>
            </div>
            <div>
              <div className="hint" style={{ marginBottom: 6 }}>Using it right now</div>
              {s.users.length === 0
                ? <span className="hint">no live connections seen from here{s.bytes_in + s.bytes_out === 0 ? ' (this node only sees traffic that passes through it)' : ''}</span>
                : (
                  <div className="table-wrap"><table className="t">
                    <thead><tr><th>Device</th><th>Connections</th><th>To storage</th><th>From storage</th></tr></thead>
                    <tbody>{s.users.map((u) => (
                      <tr key={u.ip}><td className="mono">{u.ip}</td><td>{u.connections}</td><td className="mono">{bytes(u.bytes_out)}</td><td className="mono">{bytes(u.bytes_in)}</td></tr>
                    ))}</tbody>
                  </table></div>
                )}
            </div>
          </div>
        </Card>
      ))}
    </>
  )
}

function ForwardsTab({ forwards, router, inline, busy, act, onNew }: {
  forwards: PortForward[]; router?: RouterInfo; inline: boolean; busy: string | null
  act: (k: string, fn: () => Promise<unknown>, ok: string) => Promise<void>; onNew: () => void
}) {
  const others = (router?.mappings ?? []).filter((m) => !m.ours)
  return (
    <>
      <Card title="Forwards made by Orbis" actions={<button className="btn sm primary" onClick={onNew}><Icons.plus size={13} /> New forward</button>} flush>
        <div className="table-wrap">
          <table className="t">
            <thead><tr><th>Name</th><th>Internet port</th><th>Goes to</th><th>Where</th><th>Created</th><th></th></tr></thead>
            <tbody>
              {forwards.map((f) => (
                <tr key={f.id}>
                  <td>{f.name}</td>
                  <td className="mono">{f.ext_port}/{f.proto}</td>
                  <td className="mono">{f.host}:{f.port}</td>
                  <td>{f.method === 'nft' ? <span className="tag">this node's firewall</span> : <span className="tag info">router (UPnP){f.lease_until ? `, renews ${ago(f.lease_until).replace(' ago', '')}` : ''}</span>}</td>
                  <td className="hint" style={{ whiteSpace: 'nowrap' }}>{ago(f.created)}</td>
                  <td><button className="btn sm" disabled={busy === 'rm:' + f.id} onClick={() => act('rm:' + f.id, () => api.hosted.removeForward(f.id), 'Forward removed')}>Remove</button></td>
                </tr>
              ))}
              {forwards.length === 0 && <tr><td colSpan={6}><Empty title="No forwards yet">Press Forward next to a service, or New forward for anything else.</Empty></td></tr>}
            </tbody>
          </table>
        </div>
      </Card>

      <Card title="On the router" actions={router?.external_ip ? <span className="hint">internet address <span className="mono">{router.external_ip}</span></span> : undefined}>
        {!router?.upnp_enabled && <div className="hint">UPnP is switched off in Settings, so the router's table is not read.</div>}
        {router?.upnp_enabled && !router.found && (
          <div className="hint">No UPnP gateway answered{router.error ? `: ${router.error}` : ''}. {inline ? 'This node is the gateway, so forwards are its own rules.' : 'Turn UPnP on in the router, or run Orbis inline.'}</div>
        )}
        {router?.found && (
          <div style={{ display: 'grid', gap: 10 }}>
            <div className="hint">{router.model || router.name} answers over UPnP. These are the mappings it holds that Orbis did not create: consoles, apps and old experiments. Anything here is open to the internet right now.</div>
            {router.mappings_error && <Banner tone="warn">Could not read the mapping table: {router.mappings_error}</Banner>}
            {others.length === 0 && !router.mappings_error && <span className="hint">nothing else is mapped</span>}
            {others.length > 0 && (
              <div className="table-wrap"><table className="t">
                <thead><tr><th>Internet port</th><th>Goes to</th><th>Description</th><th>Lease</th><th></th></tr></thead>
                <tbody>{others.map((m) => (
                  <tr key={`${m.proto}-${m.ext_port}`}>
                    <td className="mono">{m.ext_port}/{m.proto}</td>
                    <td className="mono">{m.host}:{m.port}</td>
                    <td>{m.description || <span className="hint">none</span>}{!m.enabled && <span className="tag" style={{ marginLeft: 6 }}>disabled</span>}</td>
                    <td className="hint">{m.lease_seconds > 0 ? `${Math.round(m.lease_seconds / 3600)}h` : 'permanent'}</td>
                    <td><button className="btn sm" disabled={busy === `rt:${m.proto}${m.ext_port}`}
                      onClick={() => act(`rt:${m.proto}${m.ext_port}`, () => api.hosted.removeRouterMapping(m.proto, m.ext_port), 'Mapping removed from the router')}>Remove</button></td>
                  </tr>
                ))}</tbody>
              </table></div>
            )}
          </div>
        )}
      </Card>
    </>
  )
}

function ForwardDialog({ initial, onClose, onDone }: {
  initial: { host: string; port: number; name: string; sensitive: boolean }; onClose: () => void; onDone: () => void
}) {
  const [host, setHost] = useState(initial.host)
  const [port, setPort] = useState(initial.port ? String(initial.port) : '')
  const [ext, setExt] = useState(initial.port ? String(initial.port) : '')
  const [proto, setProto] = useState<'tcp' | 'udp'>('tcp')
  const [name, setName] = useState(initial.name)
  const [needsConfirm, setNeedsConfirm] = useState(initial.sensitive)
  const [confirmed, setConfirmed] = useState(false)
  const [busy, setBusy] = useState(false)
  const toast = useToast()

  const submit = async () => {
    setBusy(true)
    try {
      await api.hosted.forward({ host: host.trim(), port: Number(port), ext_port: Number(ext) || Number(port), proto, name: name.trim(), confirm: confirmed })
      toast(`Internet port ${ext || port}/${proto} now reaches ${host}:${port}`, 'ok')
      onDone()
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'Could not create the forward'
      if (msg.includes('should not be exposed')) setNeedsConfirm(true)
      toast(msg, 'err')
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <div className="scrim" onClick={onClose} />
      <div className="drawer" role="dialog" aria-label="Forward a port">
        <div className="drawer-head"><h2 style={{ fontSize: 15 }}>Forward a port</h2><div className="spacer" /><button className="btn sm" onClick={onClose}><Icons.close size={14} /></button></div>
        <div className="drawer-body" style={{ display: 'grid', gap: 14 }}>
          <div className="hint" style={{ lineHeight: 1.6 }}>
            Opens a port on your internet address and sends it to one device here. Anyone on the internet can then reach that service, so it had better have a login and be kept up to date.
          </div>
          <div style={{ display: 'grid', gap: 10, gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))' }}>
            <Field label="Device address"><input className="input mono" value={host} onChange={(e) => setHost(e.target.value)} placeholder="192.168.1.50" /></Field>
            <Field label="Service port"><input className="input mono" value={port} onChange={(e) => { setPort(e.target.value); if (!ext || ext === port) setExt(e.target.value) }} placeholder="32400" /></Field>
            <Field label="Internet port"><input className="input mono" value={ext} onChange={(e) => setExt(e.target.value)} placeholder="same" /></Field>
            <Field label="Protocol">
              <select className="input" value={proto} onChange={(e) => setProto(e.target.value as 'tcp' | 'udp')}><option value="tcp">TCP</option><option value="udp">UDP</option></select>
            </Field>
          </div>
          <Field label="Name"><input className="input" value={name} onChange={(e) => setName(e.target.value)} placeholder="Plex" /></Field>
          {needsConfirm && (
            <Banner tone="warn">
              <strong style={{ display: 'block', marginBottom: 4 }}>This is not a service to put on the internet</strong>
              Storage, admin panels, databases and remote desktops on the open internet are how home networks get compromised. Reach it over WireGuard or Tailscale instead. If you still want the forward, confirm below.
              <label style={{ display: 'flex', gap: 8, alignItems: 'center', marginTop: 8 }}>
                <input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} /> I understand, forward it anyway
              </label>
            </Banner>
          )}
          <div style={{ display: 'flex', gap: 8 }}>
            <button className="btn primary" disabled={busy || !host || !port || (needsConfirm && !confirmed)} onClick={submit}>Create forward</button>
            <button className="btn" onClick={onClose}>Cancel</button>
          </div>
        </div>
      </div>
    </>
  )
}
