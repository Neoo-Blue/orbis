import { useMemo, useState } from 'react'
import { api } from '../api'
import { RequestRow, useUnblock } from '../pages/Requests'
import { usePoll } from '../hooks'
import { Dot, Icons, Loading, Spinner, useToast } from '../ui'
import { ago, num } from '../format'
import { OrbitChart } from '../orbit/OrbitChart'
import { orbitDevices, orbitFlows } from '../pages/Dashboard'
import { Section } from './common'

function Glance({ what, sub, value, onClick }: { what: string; sub?: string; value?: string | number; onClick: () => void }) {
  return (
    <li>
      <button type="button" onClick={onClick}>
        <span className="what">{what}{sub && <small>{sub}</small>}</span>
        {value !== undefined && <span className="value">{value}</span>}
        <Icons.chevron size={14} />
      </button>
    </li>
  )
}

export function SimpleHome({ onNavigate, onAsk }: { onNavigate: (r: string) => void; onAsk: (q: string) => void }) {
  const { data: asks, refresh: refreshAsks } = useUnblock()
  const { data: health, refresh } = usePoll(() => api.simple.health(), 15000)
  const { data: consent } = usePoll(() => api.consent.status(), 15000)
  const { data: clients } = usePoll(() => api.clients.list(), 20000)
  const { data: active } = usePoll(() => api.flows.active(120), 20000)
  const devices = useMemo(() => orbitDevices((clients?.clients ?? []).filter((c) => c.online)), [clients])
  const flows = useMemo(() => orbitFlows(active?.flows ?? []), [active])
  // With ask-first off the status carries no queue at all.
  const pending = consent?.pending?.length ?? 0
  const [question, setQuestion] = useState('')
  const [checking, setChecking] = useState(false)
  const toast = useToast()

  const runCheck = async () => {
    setChecking(true)
    try {
      await api.ai.runBrief()
      refresh()
    } catch (e) {
      toast(e instanceof Error ? e.message : 'Could not run a check', 'err')
    } finally {
      setChecking(false)
    }
  }

  if (!health) return <Loading what="your network" />
  return (
    <div style={{ display: 'grid', gap: 22 }}>
      {(asks?.pending.length ?? 0) > 0 && (
        <div className="stack-in" style={{ display: 'grid', gap: 10 }}>
          {asks!.pending.map((r) => <RequestRow key={r.id} r={r} onDone={refreshAsks} />)}
        </div>
      )}
      <div className="simple-top">
      <div className="simple-left">
      <div className={`hero ${health.level}`}>
        <div className="hero-title"><span className="orb" />{health.headline}</div>
        <div className="hero-sub">
          {clients ? devices.length : health.devices_online} of {clients?.clients.length ?? health.devices_total} devices are online.
          {' '}{health.protection_on ? `${num(health.blocked_today)} ads and trackers were blocked today.` : 'Protection is switched off.'}
        </div>
        {(health.points ?? []).length > 0 && (
          <div className="hero-points">
            {(health.points ?? []).map((p, i) => (
              <div key={i}><Dot state={p.level === 'problem' ? 'err' : p.level === 'attention' ? 'warn' : 'on'} /><span>{p.text}</span></div>
            ))}
          </div>
        )}
        {health.brief && (
          <div style={{ marginTop: 6, fontSize: 13, color: 'var(--text-dim)', lineHeight: 1.6 }}>
            <strong style={{ color: 'var(--text)' }}>Last check, {ago(health.brief.ts)}:</strong> {health.brief.headline}
          </div>
        )}
        <div style={{ display: 'flex', gap: 8, marginTop: 4, flexWrap: 'wrap' }}>
          <button className="btn sm" disabled={checking} onClick={runCheck}>{checking ? <><Spinner /> checking…</> : 'Check now'}</button>
          <button className="btn sm" onClick={() => onNavigate('s-alerts')}>See what happened</button>
          {pending > 0 && (
            <button className="btn sm" onClick={() => onNavigate('consent')}>
              {pending} {pending === 1 ? 'request' : 'requests'} waiting for your OK
            </button>
          )}
        </div>
      </div>
      <Section title="Ask Orbis" hint="Plain questions work. It reads the network and answers with real numbers.">
        <div className="ask">
          <input className="input" value={question} placeholder="Why is the TV slow?"
            onChange={(e) => setQuestion(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter' && question.trim()) { onAsk(question.trim()); setQuestion('') } }} />
          <button className="btn primary" disabled={!question.trim()} onClick={() => { onAsk(question.trim()); setQuestion('') }}>Ask</button>
        </div>
        <div className="chat-suggestions">
          {['Is anything wrong right now?', 'Which device used the most internet today?', 'Why is a website not loading?', 'Pause the internet on the kids’ tablet for an hour'].map((s) => (
            <button key={s} className="btn sm" onClick={() => onAsk(s)}>{s}</button>
          ))}
        </div>
      </Section>
      </div>
      <div className="simple-chart">
        <OrbitChart compact devices={devices} flows={flows} onSelect={() => onNavigate('s-devices')}
          label={`${devices.length} devices online. Open Devices to see them all.`} />
      </div>
      </div>

      <Section title="At a glance">
        <ul className="glance">
          <Glance what="Ads and trackers blocked today" value={num(health.blocked_today)} onClick={() => onNavigate('s-protection')} />
          <Glance what="Devices online" sub={health.devices_paused ? `${health.devices_paused} paused` : 'None paused'} value={clients ? devices.length : health.devices_online} onClick={() => onNavigate('s-devices')} />
          <Glance what="Protection" sub={health.youtube_tv ? 'YouTube TV ads skipped' : 'YouTube TV skipping off'} value={health.protection_on ? 'On' : 'Off'} onClick={() => onNavigate('s-protection')} />
          <Glance what="What is using the internet" sub="By app and by device" onClick={() => onNavigate('s-usage')} />
          {health.resources && (
            <Glance what="Orbis itself"
              sub={`${(health.resources.rss_bytes / 1024 ** 3).toFixed(1)} GB memory${health.resources.temp_c ? `, ${Math.round(health.resources.temp_c)} °C` : ''}${(health.resources.throttled ?? '').startsWith('now') ? ', power problem' : ''}`}
              value={`${Math.round(health.resources.process_cpu_percent)}% of a core`} onClick={() => onNavigate('s-settings')} />
          )}
        </ul>
      </Section>
    </div>
  )
}
