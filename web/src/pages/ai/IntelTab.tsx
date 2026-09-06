import { useState } from 'react'
import { api } from '../../api'
import { usePoll } from '../../hooks'
import { Banner, Card, Empty, Icons, Loading, Switch, useToast } from '../../ui'
import { ago } from '../../format'
import type { AIAction, AIIntel, IntelFinding } from '../../types'

// The AI threat-intelligence view: the latest assessment with its findings,
// the actions it proposed or took, and the switch for active blocking.

const riskTone: Record<string, string> = { low: 'ok', guarded: '', elevated: 'warn', high: 'block' }
const riskLabel: Record<string, string> = { low: 'Low risk', guarded: 'Guarded', elevated: 'Elevated', high: 'High risk' }
const sevTone: Record<string, string> = { info: '', notice: 'info', warning: 'warn', critical: 'block' }
const statusLabel: Record<string, string> = {
  suggested: 'waiting for you', applied: 'applied', dismissed: 'dismissed', undone: 'undone', failed: 'failed', refused: 'refused by the guard rail',
}

export function RiskBadge({ risk }: { risk: string }) {
  return <span className={`tag ${riskTone[risk] ?? ''}`}>{riskLabel[risk] ?? risk}</span>
}

function actionLabel(a: { kind: string; value: string; hours?: number }) {
  return a.kind === 'ban_ip' ? `Ban ${a.value}${a.hours ? ` for ${a.hours}h` : ''}` : `Block ${a.value}`
}

export function IntelTab({ onToggleActive, compact = false }: {
  onToggleActive: (v: boolean) => Promise<void>; compact?: boolean
}) {
  const { data, refresh } = usePoll(() => api.ai.intel(8), 15000)
  const [busy, setBusy] = useState<string | null>(null)
  const [showAll, setShowAll] = useState(false)
  const toast = useToast()

  const run = async () => {
    setBusy('run')
    try {
      const r = await api.ai.runIntel()
      toast(`Assessment written: ${r.assessment.headline}`, 'ok')
      refresh()
    } catch (e) {
      toast(e instanceof Error ? e.message : 'The assessment failed', 'err')
    } finally { setBusy(null) }
  }
  const decide = async (a: AIAction, decision: 'apply' | 'dismiss' | 'undo') => {
    setBusy(a.id)
    try {
      await api.ai.decideAction(a.id, decision)
      toast(decision === 'apply' ? `${actionLabel(a)}: done` : decision === 'undo' ? 'Undone' : 'Dismissed', 'ok')
      refresh()
    } catch (e) {
      toast(e instanceof Error ? e.message : 'That did not work', 'err')
    } finally { setBusy(null) }
  }

  if (!data) return <Loading what="threat intelligence" />
  const activeBlocking = data.active_blocking
  const latest = data.assessments[0]
  const actionsByValue = new Map(data.actions.map((a) => [a.kind + ':' + a.value, a]))
  const open = data.actions.filter((a) => a.status === 'suggested')
  const applied = data.actions.filter((a) => a.status === 'applied')

  return (
    <div style={{ display: 'grid', gap: 14 }}>
      {!data.configured && (
        <Banner tone="warn" action={<a className="btn sm" href="#/settings/assistant">Set up</a>}>
          The assistant is not configured. Threat intelligence needs a model: add a provider and key under Settings, Assistant.
        </Banner>
      )}
      {data.configured && !data.enabled && (
        <Banner tone="info" action={<a className="btn sm" href="#/settings/assistant">Settings</a>}>
          Scheduled assessments are off. You can still run one now.
        </Banner>
      )}
      {data.last_error && <Banner tone="warn">The last scheduled assessment failed: {data.last_error}</Banner>}

      <Card title="AI threat check" actions={
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          {!compact && (
            <label style={{ display: 'flex', gap: 8, alignItems: 'center', fontSize: 12 }}>
              Active blocking
              <Switch checked={activeBlocking} disabled={busy === 'active'} onChange={async (v) => {
                if (v && !confirm('Active blocking lets the assistant ban addresses and block domains on its own when it is confident. Every action is bounded, logged and can be undone here. Turn it on?')) return
                setBusy('active')
                try { await onToggleActive(v) } finally { setBusy(null) }
              }} />
            </label>
          )}
          <button className="btn sm primary" disabled={busy === 'run' || data.running || !data.configured} onClick={run}>
            <Icons.refresh size={13} /> {data.running || busy === 'run' ? 'Assessing…' : 'Check now'}
          </button>
        </div>
      }>
        {!latest ? (
          <Empty title="No assessment yet">{data.configured ? `The first one runs on the schedule (every ${data.interval_hours}h) or when you press Check now.` : 'Configure the assistant first.'}</Empty>
        ) : (
          <div style={{ display: 'grid', gap: 12 }}>
            <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
              <RiskBadge risk={latest.risk} />
              <span style={{ fontWeight: 600, fontSize: 14 }}>{latest.headline}</span>
              <span className="hint">{ago(latest.ts)}, last {latest.hours}h, {latest.model}</span>
            </div>
            <div style={{ fontSize: 13, lineHeight: 1.7, color: 'var(--text-dim)', whiteSpace: 'pre-wrap' }}>{latest.summary}</div>
            <div style={{ display: 'grid', gap: 8 }}>
              {(latest.findings ?? []).map((f, i) => (
                <Finding key={i} f={f} action={f.action?.kind !== 'none' ? actionsByValue.get(f.action.kind + ':' + f.action.value) : undefined}
                  busy={busy} decide={decide} />
              ))}
            </div>
            {activeBlocking && (
              <div className="hint">
                Active blocking is on: actions at or above {Math.round(data.min_confidence * 100)}% confidence are applied at once,
                at most {data.max_actions_per_run} per check, bans no longer than {data.max_ban_hours}h. Undo any of them below.
              </div>
            )}
          </div>
        )}
      </Card>

      {(open.length > 0 || applied.length > 0 || showAll) && (
        <Card title={`Actions (${open.length} waiting, ${applied.length} in force)`} actions={
          <button className="btn sm" onClick={() => setShowAll((v) => !v)}>{showAll ? 'Live only' : 'Show history'}</button>
        }>
          <div className="table-wrap">
            <table className="t">
              <thead><tr><th>Action</th><th>Why</th><th className="num">Confidence</th><th>Status</th><th style={{ width: 160 }} /></tr></thead>
              <tbody>
                {(showAll ? data.actions : [...open, ...applied]).map((a) => (
                  <tr key={a.id}>
                    <td className="mono" style={{ whiteSpace: 'nowrap' }}>{actionLabel(a)}</td>
                    <td style={{ fontSize: 12, color: 'var(--text-dim)', maxWidth: 420 }}>{a.reason}{a.status === 'refused' || a.status === 'failed' ? <div className="hint">{a.ref}</div> : null}</td>
                    <td className="num">{Math.round(a.confidence * 100)}%</td>
                    <td><span className={`tag ${a.status === 'applied' ? 'ok' : a.status === 'suggested' ? 'warn' : ''}`}>{statusLabel[a.status] ?? a.status}</span>
                      <div className="hint" style={{ fontSize: 10.5 }}>{a.decided_by ? `${a.decided_by === 'ai' ? 'active blocking' : a.decided_by}, ` : ''}{ago(a.decided_at || a.ts)}</div></td>
                    <td style={{ textAlign: 'right' }}>
                      {a.status === 'suggested' && (
                        <span style={{ display: 'inline-flex', gap: 6 }}>
                          <button className="btn sm primary" disabled={busy === a.id} onClick={() => decide(a, 'apply')}>Apply</button>
                          <button className="btn sm" disabled={busy === a.id} onClick={() => decide(a, 'dismiss')}>Dismiss</button>
                        </span>
                      )}
                      {a.status === 'applied' && <button className="btn sm" disabled={busy === a.id} onClick={() => decide(a, 'undo')}>Undo</button>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {!compact && data.assessments.length > 1 && (
        <Card title="Earlier checks">
          <div style={{ display: 'grid', gap: 6 }}>
            {data.assessments.slice(1).map((a: AIIntel) => (
              <div key={a.id} style={{ display: 'flex', gap: 10, alignItems: 'baseline', fontSize: 12.5 }}>
                <RiskBadge risk={a.risk} />
                <span style={{ flex: 1 }}>{a.headline}</span>
                <span className="hint">{ago(a.ts)}</span>
              </div>
            ))}
          </div>
        </Card>
      )}
    </div>
  )
}

function Finding({ f, action, busy, decide }: {
  f: IntelFinding; action?: AIAction; busy: string | null; decide: (a: AIAction, d: 'apply' | 'dismiss' | 'undo') => Promise<void>
}) {
  const [open, setOpen] = useState(false)
  return (
    <div style={{ border: '1px solid var(--line-soft)', borderRadius: 8, padding: '9px 12px' }}>
      <div style={{ display: 'flex', gap: 9, alignItems: 'center', cursor: 'pointer', flexWrap: 'wrap' }} onClick={() => setOpen((v) => !v)}>
        <span className={`tag ${sevTone[f.severity] ?? ''}`} style={{ minWidth: 60, justifyContent: 'center' }}>{f.severity}</span>
        <span style={{ fontWeight: 600, fontSize: 13, flex: 1 }}>{f.title}</span>
        {f.action?.kind !== 'none' && f.action?.value && (
          <span className={`tag ${action?.status === 'applied' ? 'ok' : action?.status === 'suggested' ? 'warn' : ''}`}>
            {actionLabel(f.action)}{action ? `: ${statusLabel[action.status] ?? action.status}` : ''}
          </span>
        )}
      </div>
      {open && (
        <div style={{ marginTop: 8, display: 'grid', gap: 7, fontSize: 12.5, lineHeight: 1.65 }}>
          <div style={{ color: 'var(--text-dim)', whiteSpace: 'pre-wrap' }}>{f.detail}</div>
          {f.indicators?.length > 0 && <div className="mono" style={{ fontSize: 11.5 }}>{f.indicators.join('  ')}</div>}
          {f.recommendation && <div><b>What to do:</b> {f.recommendation}</div>}
          {action && action.status === 'suggested' && (
            <div style={{ display: 'flex', gap: 6 }}>
              <button className="btn sm primary" disabled={busy === action.id} onClick={() => decide(action, 'apply')}>{actionLabel(action)}</button>
              <button className="btn sm" disabled={busy === action.id} onClick={() => decide(action, 'dismiss')}>Dismiss</button>
              <span className="hint" style={{ alignSelf: 'center' }}>{Math.round(action.confidence * 100)}% confident</span>
            </div>
          )}
          {action && action.status === 'applied' && (
            <div><button className="btn sm" disabled={busy === action.id} onClick={() => decide(action, 'undo')}>Undo</button></div>
          )}
        </div>
      )}
    </div>
  )
}
