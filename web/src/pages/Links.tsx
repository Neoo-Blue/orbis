import { useState } from 'react'
import { api } from '../api'
import { usePoll } from '../hooks'
import { Banner, Card, Empty, Field, Icons, Loading, Switch, useToast } from '../ui'
import { ago, bytes } from '../format'
import type { NetLink, WiFiStatus } from '../types'

/**
 * Cables & Wi-Fi: which physical port is the internet, which is the network,
 * with the evidence, and the access point. The classification is shown with
 * its reasons and applied with one click, or automatically when allowed.
 */
const ROLE_LABEL: Record<string, string> = { wan: 'Internet (WAN)', lan: 'Network (LAN)', wifi: 'Wi-Fi network', unplugged: 'Nothing plugged in', single: 'The only cable', '': 'Unknown' }
const ROLE_TAG: Record<string, string> = { wan: 'info', lan: 'ok', wifi: 'ok', unplugged: '', single: 'info' }

export function LinksPage() {
  const { data, refresh } = usePoll(() => api.links.get(), 5000)
  const { data: wifi, refresh: refreshWiFi } = usePoll(() => api.wifi.status(), 8000)
  const toast = useToast()
  const [busy, setBusy] = useState<string | null>(null)
  const act = async (key: string, fn: () => Promise<unknown>, ok: string) => {
    setBusy(key)
    try {
      await fn()
      toast(ok, 'ok')
      refresh(); refreshWiFi()
    } catch (e) {
      toast(e instanceof Error ? e.message : 'That did not work', 'err')
    } finally {
      setBusy(null)
    }
  }
  if (!data) return <Loading what="network links" />
  const sug = data.suggestion
  const changes = sug?.changes ?? []
  const links = data.links ?? []
  const pending = changes.length > 0

  return (
    <div style={{ display: 'grid', gap: 14 }}>
      <Card title="Cables" actions={
        <label style={{ display: 'flex', gap: 8, alignItems: 'center', fontSize: 12.5 }}>
          <Switch checked={data.auto_assign} onChange={(v) => act('auto', () => api.config.patch({ 'network.links.auto_assign': v }), v ? 'Orbis will assign cables on its own when the evidence is clear' : 'Cable changes will be proposed, not applied')} />
          assign automatically
        </label>
      }>
        <div style={{ display: 'grid', gap: 12 }}>
          <div className="hint" style={{ lineHeight: 1.6 }}>{sug?.reason}</div>
          {pending && (
            <Banner tone={sug.confidence === 'high' ? 'info' : 'warn'} action={
              <button className="btn sm primary" disabled={busy === 'apply'} onClick={() => act('apply', () => api.links.apply(), 'Assignment applied')}>Apply</button>
            }>
              <strong style={{ display: 'block', marginBottom: 3 }}>{sug.confidence === 'high' ? 'Proposed assignment' : 'Proposed assignment, thin evidence'}</strong>
              {changes.join('; ')}.
              {sug.confidence === 'low' && ' Check the cables before applying: WAN and LAN the wrong way round on a gateway means no internet for anyone.'}
            </Banner>
          )}
          <div style={{ display: 'grid', gap: 10, gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))' }}>
            {links.map((l) => <LinkCard key={l.name} link={l} mode={data.mode} />)}
            {links.length === 0 && <Empty title="No physical interfaces found">This node has no Ethernet or wireless adapters the kernel reports, which usually means it runs in a container.</Empty>}
          </div>
        </div>
      </Card>

      <WiFiCard wifi={wifi} busy={busy} act={act} refresh={refreshWiFi} />
    </div>
  )
}

function LinkCard({ link, mode }: { link: NetLink; mode: string }) {
  return (
    <div className="device-card" style={{ alignItems: 'start', gridTemplateColumns: '44px 1fr' }}>
      <div className="glyph" aria-hidden="true">{link.wireless ? '📶' : link.carrier ? '🔌' : '⭘'}</div>
      <div style={{ minWidth: 0 }}>
        <div className="name">
          <span className="mono">{link.name}</span>
          <span className={`tag ${ROLE_TAG[link.role] ?? ''}`}>{ROLE_LABEL[link.role] ?? link.role}</span>
          {link.configured !== 'none' && link.configured !== link.role && link.role !== 'single' && link.role !== 'unplugged' && (
            <span className="tag warn" title="What the configuration says today">configured as {link.configured}</span>
          )}
        </div>
        <div className="meta">
          {link.wireless ? 'wireless' : link.carrier ? `link up${link.speed_mbps ? `, ${link.speed_mbps >= 1000 ? `${link.speed_mbps / 1000} Gbps` : `${link.speed_mbps} Mbps`}` : ''}` : 'no link'}
          {(link.addresses ?? []).length > 0 && <> · <span className="mono">{(link.addresses ?? []).join(', ')}</span></>}
          {link.default_route && ' · default route'}
        </div>
        {(link.evidence ?? []).length > 0 && (
          <ul className="hint" style={{ margin: '6px 0 0', paddingLeft: 16, lineHeight: 1.6 }}>
            {(link.evidence ?? []).map((e, i) => <li key={i}>{e}</li>)}
            {link.neighbours > 0 && !(link.evidence ?? []).some((e) => e.includes('neighbour')) && <li>{link.neighbours} neighbour{link.neighbours === 1 ? '' : 's'} answer on it</li>}
          </ul>
        )}
        {link.role === 'single' && mode !== 'inline' && <div className="hint" style={{ marginTop: 6 }}>Observe mode on one cable: filtering by DNS and by interception. A second cable makes gateway mode possible.</div>}
      </div>
    </div>
  )
}

function WiFiCard({ wifi, busy, act, refresh }: { wifi: WiFiStatus | null; busy: string | null; act: (k: string, fn: () => Promise<unknown>, ok: string) => Promise<void>; refresh: () => void }) {
  const [ssid, setSsid] = useState('')
  const [pass, setPass] = useState('')
  const [show, setShow] = useState(false)
  const toast = useToast()
  if (!wifi) return <Card title="Wi-Fi"><Loading what="wireless state" /></Card>
  const adapters = wifi.adapters ?? []
  const noAdapter = adapters.length === 0 && !wifi.interface
  const cfg = wifi.config
  const save = async (patch: Record<string, unknown>, ok: string) => act('cfg', () => api.config.patch(patch), ok)

  return (
    <Card title="Wi-Fi network" actions={
      wifi.running
        ? <span className="tag ok">broadcasting {wifi.ssid}</span>
        : wifi.enabled ? <span className="tag warn">enabled, not running</span> : <span className="tag">off</span>
    }>
      <div style={{ display: 'grid', gap: 12 }}>
        {noAdapter && <Banner tone="info">No wireless adapter on this node. Plug in a USB Wi-Fi adapter that supports access point mode and it will appear here.</Banner>}
        {!noAdapter && !wifi.hostapd_available && (
          <Banner tone="warn">hostapd is not installed, so the adapter cannot broadcast. On the node: <code>sudo apt install hostapd iw</code>, then enable below.</Banner>
        )}
        {wifi.error && wifi.enabled && <Banner tone="err">{wifi.error}</Banner>}
        <div className="hint" style={{ lineHeight: 1.6 }}>
          Broadcast a network from the adapter <span className="mono">{wifi.interface || adapters[0] || ''}</span>. In routed mode it gets its own subnet
          (<span className="mono">{wifi.subnet}</span>) with Orbis as gateway, DHCP and DNS, so every device that joins is fully filtered even while Orbis is not the main router.
          Devices on the wired network can be reached from it; they cannot reach Wi-Fi devices unless you forward a port.
        </div>

        {!wifi.enabled ? (
          <div style={{ display: 'grid', gap: 10, gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', alignItems: 'end' }}>
            <Field label="Network name"><input className="input" value={ssid} placeholder={wifi.ssid || 'Orbis'} onChange={(e) => setSsid(e.target.value)} /></Field>
            <Field label="Passphrase" hint="Leave empty to have one generated"><input className="input mono" value={pass} placeholder="8 to 63 characters" onChange={(e) => setPass(e.target.value)} /></Field>
            <div>
              <button className="btn primary" disabled={noAdapter || !wifi.hostapd_available || busy === 'on'}
                onClick={() => act('on', () => api.wifi.enable({ ssid: ssid.trim() || undefined, passphrase: pass.trim() || undefined }), 'Wi-Fi is coming up')}>Turn on Wi-Fi</button>
            </div>
          </div>
        ) : (
          <>
            <dl className="kv">
              <dt>Network name</dt><dd>{wifi.ssid}</dd>
              <dt>Passphrase</dt>
              <dd style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
                <span className="mono">{show ? wifi.passphrase : '••••••••••••'}</span>
                <button className="btn sm" onClick={() => setShow(!show)}>{show ? 'Hide' : 'Show'}</button>
                <button className="btn sm" onClick={() => { if (wifi.passphrase) { navigator.clipboard?.writeText(wifi.passphrase); toast('Copied', 'ok') } }}>Copy</button>
                <button className="btn sm" disabled={busy === 'regen'} onClick={() => act('regen', () => api.wifi.passphrase(), 'New passphrase set; devices must rejoin')}>New passphrase</button>
              </dd>
              <dt>Adapter</dt><dd>{wifi.interface} {wifi.type ? `(${wifi.type})` : ''} {wifi.channel_info ? `· ${wifi.channel_info}` : ''}</dd>
              <dt>State</dt><dd>{wifi.running ? `up since ${ago(wifi.since ?? '')}${wifi.restarts ? `, restarted ${wifi.restarts}×` : ''}` : wifi.error || 'starting'}</dd>
              <dt>Mode</dt><dd>{wifi.mode === 'bridge' ? `bridged into ${cfg?.bridge}` : `routed, ${wifi.subnet}`}</dd>
            </dl>
            <div style={{ display: 'grid', gap: 8, gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))' }}>
              <label className="field"><span>Band</span>
                <select className="input" value={cfg?.band ?? 'auto'} onChange={(e) => save({ 'wifi.band': e.target.value }, 'Band changed; Wi-Fi restarts')}>
                  <option value="auto">Auto (5 GHz when possible)</option><option value="2.4">2.4 GHz (range)</option><option value="5">5 GHz (speed)</option>
                </select>
              </label>
              <label className="field"><span>Country code</span>
                <input className="input mono" defaultValue={cfg?.country ?? ''} placeholder="US" maxLength={2}
                  onBlur={(e) => { const v = e.target.value.trim().toUpperCase(); if (v !== (cfg?.country ?? '')) save({ 'wifi.country': v }, 'Country set; 5 GHz becomes available') }} />
              </label>
              <label className="field"><span>Network name</span>
                <input className="input" defaultValue={wifi.ssid} onBlur={(e) => { const v = e.target.value.trim(); if (v && v !== wifi.ssid) save({ 'wifi.ssid': v }, 'Name changed; devices must rejoin') }} />
              </label>
            </div>
            <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
              <label style={{ display: 'flex', gap: 8, alignItems: 'center', fontSize: 13 }}><Switch checked={cfg?.lan_access ?? true} onChange={(v) => save({ 'wifi.lan_access': v }, v ? 'Wi-Fi devices can reach the wired network' : 'Wi-Fi devices are kept off the wired network')} /> reach the wired network</label>
              <label style={{ display: 'flex', gap: 8, alignItems: 'center', fontSize: 13 }}><Switch checked={cfg?.isolate_clients ?? false} onChange={(v) => save({ 'wifi.isolate_clients': v }, v ? 'Wi-Fi devices cannot see each other' : 'Wi-Fi devices can see each other')} /> isolate devices from each other</label>
              <label style={{ display: 'flex', gap: 8, alignItems: 'center', fontSize: 13 }}><Switch checked={cfg?.hidden ?? false} onChange={(v) => save({ 'wifi.hidden': v }, v ? 'Network name hidden' : 'Network name visible')} /> hide the name</label>
              <label style={{ display: 'flex', gap: 8, alignItems: 'center', fontSize: 13 }}><Switch checked={cfg?.wpa3 ?? false} onChange={(v) => save({ 'wifi.wpa3': v }, v ? 'WPA3 offered alongside WPA2' : 'WPA2 only')} /> WPA3</label>
            </div>
            <div>
              <div className="hint" style={{ marginBottom: 6 }}>Connected devices</div>
              {(wifi.clients ?? []).length === 0
                ? <span className="hint">nobody has joined yet</span>
                : (
                  <div className="table-wrap"><table className="t">
                    <thead><tr><th>Device</th><th>Address</th><th>Signal</th><th>Received</th><th>Sent</th><th>Joined</th></tr></thead>
                    <tbody>{(wifi.clients ?? []).map((c) => (
                      <tr key={c.mac}>
                        <td>{c.name || <span className="mono">{c.mac}</span>}</td>
                        <td className="mono">{c.ip || ''}</td>
                        <td className="mono">{c.signal_dbm ? `${c.signal_dbm} dBm` : ''}</td>
                        <td className="mono">{bytes(c.rx_bytes)}</td><td className="mono">{bytes(c.tx_bytes)}</td>
                        <td className="hint">{c.connected_seconds ? `${Math.round(c.connected_seconds / 60)} min ago` : ''}</td>
                      </tr>
                    ))}</tbody>
                  </table></div>
                )}
            </div>
            <div>
              <button className="btn" disabled={busy === 'off'} onClick={() => act('off', () => api.wifi.disable(), 'Wi-Fi is off')}>Turn off Wi-Fi</button>
              <button className="btn" style={{ marginLeft: 8 }} onClick={refresh}><Icons.refresh size={13} /> Refresh</button>
            </div>
          </>
        )}
      </div>
    </Card>
  )
}
