import { api } from '../api'
import { usePoll } from '../hooks'
import { Field, Loading } from '../ui'
import type { AppConfig, SystemStatus } from '../types'
import { BigSwitch, Section } from './common'

/** The handful of settings a household changes, in plain words. */
export function SimpleSettings({ config, status, save, uiMode, setUIMode, onNavigate }: {
  config: AppConfig; status: SystemStatus | null; save: (patch: Record<string, unknown>) => Promise<boolean>
  uiMode: 'simple' | 'advanced'; setUIMode: (m: 'simple' | 'advanced') => void; onNavigate: (r: string) => void
}) {
  const { data: models } = usePoll(() => api.ai.models(), 60000)
  if (!config) return <Loading what="settings" />
  return (
    <div style={{ display: 'grid', gap: 4, maxWidth: 900 }}>
      <Section title="This Orbis">
        <div className="bigswitch" style={{ display: 'grid', gap: 12 }}>
          <Field label="Name" hint="Shows in the corner and in reports.">
            <input className="input" defaultValue={config.node.name} onBlur={(e) => { if (e.target.value.trim() && e.target.value !== config.node.name) save({ 'node.name': e.target.value.trim() }) }} />
          </Field>
          <div className="hint">Version {status?.version ?? '…'} · {status?.mode === 'inline' ? 'acting as the gateway' : 'watching and filtering, not routing'} · {Math.floor((status?.uptime_sec ?? 0) / 3600)} hours up</div>
        </div>
      </Section>

      <Section title="Assistant">
        <div style={{ display: 'grid', gap: 10 }}>
          <BigSwitch icon="💬" title="Assistant on" checked={config.ai.enabled}
            desc={config.ai.enabled ? `Answering with ${models?.chat_chain?.[0] ?? 'the configured model'}${models?.openrouter ? `, ${models.free_today} of ${models.free_budget} free requests used today` : ''}.` : 'Needs a provider and key under Advanced → Settings → Assistant.'}
            onChange={(v) => save({ 'ai.enabled': v })} />
          <BigSwitch icon="🛠️" title="Let the assistant make changes for me" checked={config.ai.allow_write}
            desc={config.ai.allow_write
              ? 'On. When you ask it to block a site, pause a device or fix something, it does it and tells you what it did. Everything it changes is listed under Alerts and in the audit log.'
              : 'Off. The assistant explains what it would change and where to click, but does not touch anything. Turn on to let "pause the tablet" or "unblock that site" just happen.'}
            onChange={(v) => {
              if (v && !confirm('The assistant will be able to pause devices, block or allow sites and change rules when you ask it to. Every change is logged. Turn on?')) return
              save({ 'ai.allow_write': v })
            }} />
          <BigSwitch icon="📝" title="Write a network check every few hours" checked={config.ai.brief.enabled}
            desc="A short note on what happened and whether anything needs you. Shows on the home page and under Alerts."
            onChange={(v) => save({ 'ai.brief.enabled': v })} />
          <BigSwitch icon="🔍" title="Review the blocklists daily" checked={config.ai.review.enabled}
            desc="Suggests sites to unblock when blocking breaks something, and new ad hosts to block. You approve each one."
            onChange={(v) => save({ 'ai.review.enabled': v })} />
          <BigSwitch icon="🔔" title="Tell me when a new device joins" checked={config.ai.anomaly.new_device_alert}
            desc="An alert the first time something new connects to the network."
            onChange={(v) => save({ 'ai.anomaly.new_device_alert': v })} />
        </div>
      </Section>

      <Section title="Help make Orbis better">
        <div style={{ display: 'grid', gap: 10 }}>
          <BigSwitch icon="🐞" title="Send problem reports" checked={config.issues.github.enabled}
            desc="When something in Orbis breaks, a report goes to the project so it gets fixed. Names, addresses and keys are removed first; you can preview every report under Problems."
            onChange={(v) => save({ 'issues.github.enabled': v })} />
        </div>
      </Section>

      <Section title="Interface">
        <div className="bigswitch" style={{ display: 'grid', gap: 10 }}>
          <div className="title">Simple or advanced</div>
          <div className="desc">Simple shows the essentials in plain words. Advanced shows every page and setting: DNS, firewall, VPN, interception, lists, and more. You can switch any time from the top bar.</div>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            <button className={`btn${uiMode === 'simple' ? ' primary' : ''}`} onClick={() => setUIMode('simple')}>Simple</button>
            <button className={`btn${uiMode === 'advanced' ? ' primary' : ''}`} onClick={() => setUIMode('advanced')}>Advanced</button>
            <button className="btn" onClick={() => save({ 'node.ui_mode': uiMode })}>Make this the default for everyone</button>
            <button className="btn" onClick={() => onNavigate('settings')}>All settings</button>
          </div>
        </div>
      </Section>
    </div>
  )
}
