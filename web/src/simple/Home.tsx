import { useState } from 'react'
import { api } from '../api'
import { usePoll } from '../hooks'
import { Dot, Loading, Spinner, useToast } from '../ui'
import { ago, num } from '../format'
import { Section, Tile } from './common'

export function SimpleHome({ onNavigate, onAsk }: { onNavigate: (r: string) => void; onAsk: (q: string) => void }) {
  const { data: health, refresh } = usePoll(() => api.simple.health(), 15000)
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
    <div style={{ display: 'grid', gap: 22, maxWidth: 900 }}>
      <div className={`hero ${health.level}`}>
        <div className="hero-title"><span className="orb" />{health.headline}</div>
        <div className="hero-sub">
          {health.devices_online} of {health.devices_total} devices are online.
          {' '}{health.protection_on ? `${num(health.blocked_today)} ads and trackers were blocked today.` : 'Protection is switched off.'}
        </div>
        {health.points.length > 0 && (
          <div className="hero-points">
            {health.points.map((p, i) => (
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
        </div>
      </div>

      <Section title="Ask Orbis" hint="Plain questions work. It reads the network and answers with real numbers.">
        <div className="ask">
          <input className="input" value={question} placeholder="Why is the TV slow? What did the kids' tablet do today?"
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

      <Section title="At a glance">
        <div className="tiles">
          <Tile big={num(health.blocked_today)} label="ads and trackers blocked today" onClick={() => onNavigate('s-protection')} />
          <Tile big={health.devices_online} label="devices online" sub={health.devices_paused ? `${health.devices_paused} paused` : 'none paused'} onClick={() => onNavigate('s-devices')} />
          <Tile big={health.protection_on ? 'On' : 'Off'} label="protection" sub={health.youtube_tv ? 'YouTube TV ads skipped' : 'YouTube TV skipping off'} onClick={() => onNavigate('s-protection')} />
          <Tile big="Usage" label="what is using the internet" sub="by app and by device" onClick={() => onNavigate('s-usage')} />
        </div>
      </Section>
    </div>
  )
}
