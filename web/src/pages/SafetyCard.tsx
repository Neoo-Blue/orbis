import { useState } from 'react'
import { api } from '../api'
import { usePoll } from '../hooks'
import { Banner, Card, Icons, Loading, Switch, useToast } from '../ui'
import { ago } from '../format'
import type { AppConfig, SafetyStatus } from '../types'

// The safety net, layer by layer: what is in place, what is not, and the
// runbook for the one failure software cannot cover.

const placementLabel: Record<string, string> = {
  gateway: 'This node is the gateway and the DHCP server',
  'gateway-no-dhcp': 'This node is the gateway; another device serves DHCP',
  intercept: 'This node intercepts selected devices; the router stays the gateway',
  resolver: 'This node only resolves names; the router does everything else',
}

export function SafetyCard({ config, save, compact = false }: {
  config: AppConfig; save: (patch: Record<string, unknown>) => Promise<boolean>; compact?: boolean
}) {
  const { data, refresh } = usePoll(() => api.safety.get(), 20000)
  const [busy, setBusy] = useState(false)
  const [custom, setCustom] = useState('')
  const toast = useToast()
  if (!data) return <Loading what="the safety net" />

  const relevant = data.layers.filter((l) => l.applies)
  const inPlace = relevant.filter((l) => l.ok).length
  const install = async () => {
    setBusy(true)
    try {
      await api.safety.install()
      toast('Safety net installed', 'ok')
      refresh()
    } catch (e) {
      toast(e instanceof Error ? e.message : 'Could not install', 'err')
    } finally { setBusy(false) }
  }
  const mode = config.safety.fallback_dns === 'none' ? 'none' : config.safety.fallback_dns === 'auto' || config.safety.fallback_dns === '' ? 'auto' : 'custom'

  const summary = (
    <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
      <span className={`tag ${inPlace === relevant.length ? 'ok' : inPlace === 0 ? 'block' : 'warn'}`}>{inPlace} of {relevant.length} layers in place</span>
      <span className="hint">{placementLabel[data.placement]}</span>
      {data.method !== 'systemd' && <span className="tag warn">not under systemd</span>}
    </div>
  )

  return (
    <div style={{ display: 'grid', gap: 14 }}>
      {data.last_episode && (
        <Banner tone="warn">
          The lifeboat ran {ago(data.last_episode.started)}: {data.last_episode.reason}. It retried Orbis {data.last_episode.retries} time(s).
          Read <code>journalctl -u orbis</code> for why it failed.
        </Banner>
      )}
      <Card title="What keeps the network up when Orbis is down" actions={
        <button className="btn sm primary" disabled={busy || data.method !== 'systemd'} onClick={install}>
          <Icons.check size={13} /> {busy ? 'Installing…' : data.install_hint ? 'Install the safety net' : 'Reinstall'}
        </button>
      }>
        <div style={{ display: 'grid', gap: 12 }}>
          {summary}
          {data.install_hint && <Banner tone="warn">{data.install_hint}</Banner>}
          <div style={{ display: 'grid', gap: 8 }}>
            {data.layers.map((l) => (
              <div key={l.id} style={{ display: 'flex', gap: 10, alignItems: 'flex-start', opacity: l.applies ? 1 : 0.55 }}>
                <span className={`tag ${l.ok ? 'ok' : l.applies ? 'block' : ''}`} style={{ minWidth: 76, justifyContent: 'center', marginTop: 1 }}>
                  {l.ok ? 'in place' : l.applies ? 'missing' : 'n/a'}
                </span>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: 13, fontWeight: 600 }}>{l.title}</div>
                  {!compact && <div className="hint" style={{ lineHeight: 1.55 }}>{l.detail}</div>}
                </div>
              </div>
            ))}
          </div>
        </div>
      </Card>

      {!compact && (
        <Card title="Settings">
          <div style={{ display: 'grid', gap: 14 }}>
            <div style={{ display: 'grid', gap: 6 }}>
              <div style={{ fontSize: 13 }}>Second DNS server in every lease</div>
              <div className="hint">Devices try it when this node stops answering. Names resolve, unfiltered, instead of everything looking dead.</div>
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
                <select className="select" value={mode} onChange={(e) => {
                  const v = e.target.value
                  if (v === 'custom') { setCustom(data.fallback_dns || '1.1.1.1'); save({ 'safety.fallback_dns': data.fallback_dns || '1.1.1.1' }) }
                  else save({ 'safety.fallback_dns': v })
                }}>
                  <option value="auto">Automatic ({data.fallback_dns || 'the first public upstream'})</option>
                  <option value="custom">A specific address</option>
                  <option value="none">None, this node only</option>
                </select>
                {mode === 'custom' && (
                  <input className="input mono" style={{ width: 180 }} value={custom || config.safety.fallback_dns}
                    onChange={(e) => setCustom(e.target.value)}
                    onBlur={() => custom && save({ 'safety.fallback_dns': custom.trim() })} placeholder="1.1.1.1" />
                )}
              </div>
            </div>
            <Switch checked={config.safety.liveness_probe} label="Only send the watchdog heartbeat while the resolver answers"
              onChange={(v) => save({ 'safety.liveness_probe': v })} />
            <Switch checked={config.safety.lifeboat} label="Install the lifeboat standby"
              onChange={(v) => save({ 'safety.lifeboat': v })} />
            <Switch checked={data.has_hardware_watchdog && config.safety.hardware_watchdog} disabled={!data.has_hardware_watchdog}
              label={data.has_hardware_watchdog ? 'Arm the hardware watchdog at the next reboot (reset a frozen board)' : 'Hardware watchdog (no /dev/watchdog on this host)'}
              onChange={(v) => save({ 'safety.hardware_watchdog': v })} />
            <div className="hint">Changes to the lifeboat and the hardware watchdog take effect after Reinstall.</div>
          </div>
        </Card>
      )}

      <Card title="If the box itself dies">
        <ol style={{ margin: 0, paddingLeft: 20, display: 'grid', gap: 6, fontSize: 12.5, lineHeight: 1.6 }}>
          {data.runbook.map((step, i) => <li key={i}>{step}</li>)}
        </ol>
      </Card>
    </div>
  )
}

export function safetySummary(s: SafetyStatus): string {
  const relevant = s.layers.filter((l) => l.applies)
  return `${relevant.filter((l) => l.ok).length} of ${relevant.length} layers in place`
}
