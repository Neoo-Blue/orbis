import { useState } from 'react'
import { api } from '../api'
import { usePoll } from '../hooks'
import { Card, Empty, Icons, Loading, Segmented, Switch, useConfirm, useToast } from '../ui'
import type { AlertRule, NotifyConfig } from '../types'

const RULE_TYPES: Array<{ value: string; label: string; hint: string; unit?: string; matchLabel?: string }> = [
  { value: 'new_device', label: 'New device joins', hint: 'Fires when a device Orbis has never seen appears.' },
  { value: 'device_offline', label: 'Device goes offline', hint: 'Fires when a named device is unseen for N minutes.', unit: 'minutes', matchLabel: 'Device (IP or name)' },
  { value: 'bandwidth', label: 'Bandwidth spike', hint: 'Fires when total throughput crosses a line.', unit: 'Mbps' },
  { value: 'domain', label: 'Domain queried', hint: 'Fires when any device looks up a matching name.', matchLabel: 'Domain contains' },
  { value: 'blocked_rate', label: 'Block-rate spike', hint: 'Fires when blocking exceeds N domains/min.', unit: 'per min' },
]

export function AlertsPage() {
  const [tab, setTab] = useState<'rules' | 'delivery'>('rules')
  return (
    <div style={{ display: 'grid', gap: 12 }}>
      <div className="toolbar" style={{ marginBottom: 0 }}>
        <Segmented value={tab} onChange={setTab}
          options={[{ value: 'rules', label: 'Rules' }, { value: 'delivery', label: 'Delivery' }]} />
      </div>
      {tab === 'rules' ? <Rules /> : <Delivery />}
    </div>
  )
}

function Rules() {
  const { data, refresh } = usePoll(() => api.alerts.rules(), 0)
  const toast = useToast()
  const confirm = useConfirm()
  const [draft, setDraft] = useState<Partial<AlertRule>>({ type: 'new_device', severity: 'warning', enabled: true, threshold: 0, cooldown_minutes: 30 })

  const rules = data?.rules ?? []
  const meta = RULE_TYPES.find((t) => t.value === draft.type)

  const save = async () => {
    if (!draft.name) { toast('Give the rule a name', 'err'); return }
    try {
      await api.alerts.save(draft); refresh()
      setDraft({ type: draft.type, severity: 'warning', enabled: true, threshold: 0, cooldown_minutes: 30 })
      toast('Rule saved', 'ok')
    } catch (e) { toast(e instanceof Error ? e.message : 'Failed', 'err') }
  }
  const toggle = async (r: AlertRule) => { await api.alerts.save({ ...r, enabled: !r.enabled }); refresh() }
  const remove = async (r: AlertRule) => {
    if (!(await confirm(`Delete "${r.name}"?`))) return
    await api.alerts.remove(r.id); refresh()
  }

  return (
    <>
      <Card title="Alert rules">
        <div className="hint" style={{ marginBottom: 11 }}>
          These fire on conditions you name and route to the same sinks as the built-in anomaly
          detectors. Configure where they go under Delivery.
        </div>
        {rules.length === 0 ? <Empty title="No rules yet">Add one below.</Empty> : (
          <div style={{ display: 'grid', gap: 7 }}>
            {rules.map((r) => (
              <div key={r.id} style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <Switch checked={r.enabled} onChange={() => toggle(r)} label="" />
                <span className={`tag ${sevTone(r.severity)}`} style={{ fontSize: 10, minWidth: 58, textAlign: 'center' }}>{r.severity}</span>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: 13 }}>{r.name}</div>
                  <div style={{ fontSize: 11, color: 'var(--text-faint)' }}>
                    {RULE_TYPES.find((t) => t.value === r.type)?.label ?? r.type}
                    {r.match ? ` · ${r.match}` : ''}{r.threshold ? ` · ≥ ${r.threshold}` : ''}
                  </div>
                </div>
                <button className="btn sm" onClick={() => remove(r)}><Icons.trash size={13} /></button>
              </div>
            ))}
          </div>
        )}
      </Card>

      <Card title="New rule">
        <div style={{ display: 'grid', gap: 10 }}>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            <label className="field" style={{ flex: '1 1 160px' }}>
              <span>Name</span>
              <input className="input" placeholder="TV offline" value={draft.name ?? ''}
                onChange={(e) => setDraft({ ...draft, name: e.target.value })} />
            </label>
            <label className="field" style={{ flex: '1 1 180px' }}>
              <span>When</span>
              <select className="input" value={draft.type} onChange={(e) => setDraft({ ...draft, type: e.target.value })}>
                {RULE_TYPES.map((t) => <option key={t.value} value={t.value}>{t.label}</option>)}
              </select>
            </label>
            <label className="field" style={{ flex: '0 0 120px' }}>
              <span>Severity</span>
              <select className="input" value={draft.severity} onChange={(e) => setDraft({ ...draft, severity: e.target.value })}>
                <option value="info">info</option><option value="warning">warning</option><option value="critical">critical</option>
              </select>
            </label>
          </div>
          <div className="hint" style={{ marginTop: -4 }}>{meta?.hint}</div>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            {meta?.matchLabel && (
              <label className="field" style={{ flex: '1 1 200px' }}>
                <span>{meta.matchLabel}</span>
                <input className="input mono" value={draft.match ?? ''}
                  onChange={(e) => setDraft({ ...draft, match: e.target.value })} />
              </label>
            )}
            {meta?.unit && (
              <label className="field" style={{ flex: '0 0 140px' }}>
                <span>Threshold ({meta.unit})</span>
                <input className="input" type="number" value={draft.threshold ?? 0}
                  onChange={(e) => setDraft({ ...draft, threshold: Number(e.target.value) })} />
              </label>
            )}
            <label className="field" style={{ flex: '0 0 130px' }}>
              <span>Cooldown (min)</span>
              <input className="input" type="number" value={draft.cooldown_minutes ?? 30}
                onChange={(e) => setDraft({ ...draft, cooldown_minutes: Number(e.target.value) })} />
            </label>
            <button className="btn primary" onClick={save} style={{ alignSelf: 'flex-end' }}>
              <Icons.plus size={13} /> Add rule
            </button>
          </div>
        </div>
      </Card>
    </>
  )
}

function Delivery() {
  const { data, refresh } = usePoll(() => api.notify.get(), 0)
  const toast = useToast()
  if (!data) return <Loading what="delivery settings" />
  const cfg = data as NotifyConfig

  const patch = async (body: Record<string, unknown>) => {
    try { await api.config.patch(body); refresh() }
    catch (e) { toast(e instanceof Error ? e.message : 'Failed', 'err') }
  }

  return (
    <>
      <Card title="Where alerts go"
        actions={<button className="btn sm" onClick={async () => {
          try { await api.notify.test(); toast('Test sent', 'ok') }
          catch (e) { toast(e instanceof Error ? e.message : 'Test failed', 'err') }
        }}>Send test</button>}>
        <div style={{ display: 'grid', gap: 10 }}>
          <Switch checked={cfg.enabled} onChange={(v) => patch({ 'notify.enabled': v })}
            label="Deliver alerts and reports" />
          <label className="field" style={{ maxWidth: 220 }}>
            <span>Minimum severity</span>
            <select className="input" value={cfg.min_severity}
              onChange={(e) => patch({ 'notify.min_severity': e.target.value })}>
              <option value="info">info and up</option>
              <option value="warning">warning and up</option>
              <option value="critical">critical only</option>
            </select>
          </label>
        </div>
      </Card>

      <Card title="Email">
        <div className="hint" style={{ marginBottom: 10 }}>
          Configure the SMTP details in Settings → config. Alerts, and the scheduled report, use
          this sink.
        </div>
        <dl className="kv">
          <dt>Status</dt><dd>{cfg.email?.enabled ? `on · ${cfg.email.host}:${cfg.email.port}` : 'off'}</dd>
          <dt>Recipients</dt><dd>{cfg.email?.to?.join(', ') || '—'}</dd>
        </dl>
      </Card>

      <Card title="Webhooks">
        {(cfg.webhooks ?? []).length === 0 ? (
          <Empty title="No webhooks">Slack, Discord, or any JSON endpoint. Add via the API or config.</Empty>
        ) : (
          <div style={{ display: 'grid', gap: 6 }}>
            {cfg.webhooks.map((h) => (
              <div key={h.name} style={{ display: 'flex', alignItems: 'center', gap: 10, fontSize: 12.5 }}>
                <span className={`dot ${h.enabled ? 'on' : 'off'}`} />
                <span style={{ flex: 1 }}>{h.name}</span>
                <span className="tag" style={{ fontSize: 10 }}>{h.format || 'json'}</span>
              </div>
            ))}
          </div>
        )}
      </Card>
    </>
  )
}

function sevTone(s: string) { return s === 'critical' ? 'warn' : s === 'warning' ? 'warn' : 'info' }
