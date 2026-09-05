import { useState } from 'react'
import { api } from '../api'
import { usePoll } from '../hooks'
import { Banner, Field, Loading, Spinner, useToast } from '../ui'
import type { AppConfig } from '../types'
import { BigSwitch, Section } from './common'

/**
 * Protection: every filtering feature as a sentence and a switch. The
 * switches write the same settings the advanced pages do.
 */
export function SimpleProtection({ config, save, onNavigate }: {
  config: AppConfig; save: (patch: Record<string, unknown>) => Promise<boolean>; onNavigate: (r: string) => void
}) {
  const { data: lists, refresh: refreshLists } = usePoll(() => api.adblock.lists(), 60000)
  const { data: yt, refresh: refreshYT } = usePoll(() => api.youtube.status(), 20000)
  const toast = useToast()
  const [domain, setDomain] = useState('')
  const [busy, setBusy] = useState<string | null>(null)

  const malwareLists = (lists?.lists ?? []).filter((l) => l.category === 'malware')
  const malwareOn = malwareLists.length > 0 && malwareLists.every((l) => l.enabled)
  const trackingLists = (lists?.lists ?? []).filter((l) => l.category === 'tracking')
  const trackingOn = trackingLists.length === 0 || trackingLists.every((l) => l.enabled)

  const setCategory = async (category: string, enabled: boolean) => {
    setBusy(category)
    try {
      for (const l of (lists?.lists ?? []).filter((x) => x.category === category)) {
        if (l.enabled !== enabled) await api.adblock.addList({ name: l.name, url: l.url, category: l.category, enabled })
      }
      toast(enabled ? 'Turned on' : 'Turned off', 'ok')
      refreshLists()
    } catch (e) {
      toast(e instanceof Error ? e.message : 'Could not change that', 'err')
    } finally { setBusy(null) }
  }

  const quick = async (kind: 'allow' | 'block') => {
    const d = domain.trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0]
    if (!d) return
    setBusy(kind)
    try {
      if (kind === 'allow') await api.dnstools.allow(d, 'fixed from the simple Protection page')
      else await api.dnstools.block(d, true, 'blocked from the simple Protection page')
      toast(kind === 'allow' ? `${d} will work now` : `${d} is blocked for everyone`, 'ok')
      setDomain('')
    } catch (e) {
      toast(e instanceof Error ? e.message : 'Could not change that', 'err')
    } finally { setBusy(null) }
  }

  if (!lists) return <Loading what="protection settings" />
  const tvs = yt?.devices ?? []

  return (
    <div style={{ display: 'grid', gap: 4, maxWidth: 900 }}>
      <Section title="Blocking">
        <div style={{ display: 'grid', gap: 10 }}>
          <BigSwitch icon="🛡️" title="Block ads and trackers" checked={config.adblock.enabled}
            desc="Stops ads and tracking on every device that uses this network. The main switch."
            onChange={(v) => save({ 'adblock.enabled': v })} />
          <BigSwitch icon="☣️" title="Block dangerous sites" checked={malwareOn} disabled={busy === 'malware' || malwareLists.length === 0}
            desc={`Scams, phishing and malware sites from ${malwareLists.length} security lists.`}
            onChange={(v) => setCategory('malware', v)} />
          <BigSwitch icon="👁️" title="Block trackers that follow you between apps" checked={trackingOn} disabled={busy === 'tracking' || trackingLists.length === 0}
            desc="Analytics and fingerprinting hosts that apps and sites report to."
            onChange={(v) => setCategory('tracking', v)} />
          <BigSwitch icon="📺" title="Block ads in TV apps" checked={config.adblock.streaming_ads}
            desc="Ad and telemetry hosts used by smart TVs and streaming boxes. Safe list: it never blocks the servers that would freeze a stream."
            onChange={(v) => save({ 'adblock.streaming_ads': v })} />
          <BigSwitch icon="🚪" title="Stop apps sneaking around the filter" checked={config.adblock.block_dns_bypass}
            desc="Some apps and browsers use their own private DNS to avoid filters. This closes that door."
            onChange={(v) => save({ 'adblock.block_dns_bypass': v })} />
          <BigSwitch icon="🧠" title="Learn new ad hosts automatically" checked={config.adblock.smart_capture.enabled}
            desc="Watches for hosts that behave like ad servers before any list knows them, and asks the assistant to judge."
            onChange={(v) => save({ 'adblock.smart_capture.enabled': v })} />
        </div>
      </Section>

      <Section title="YouTube on the TV">
        <div style={{ display: 'grid', gap: 10 }}>
          <BigSwitch icon="▶️" title="Skip YouTube ads on paired TVs" checked={Boolean(yt?.enabled)} disabled={!yt}
            desc={tvs.length ? `${tvs.length} TV${tvs.length > 1 ? 's' : ''} paired. Orbis acts as a remote and presses skip and mute for you.` : 'No TV paired yet. Pair one with the code from the YouTube app on the TV (Settings → Link with TV code).'}
            onChange={async (v) => { try { await api.youtube.settings({ enabled: v }); refreshYT() } catch (e) { toast(e instanceof Error ? e.message : 'Could not change that', 'err') } }}>
            <div style={{ marginTop: 8 }}>
              <PairTV onPaired={refreshYT} />
              {' '}<button className="btn sm" onClick={() => onNavigate('youtube')}>All YouTube settings</button>
            </div>
          </BigSwitch>
        </div>
      </Section>

      <Section title="Fix or block a website" hint="Type the site, not the full link.">
        <div className="bigswitch" style={{ display: 'grid', gap: 10 }}>
          <Field label="Website">
            <input className="input" value={domain} placeholder="example.com" onChange={(e) => setDomain(e.target.value)} />
          </Field>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            <button className="btn primary" disabled={!domain.trim() || busy === 'allow'} onClick={() => quick('allow')}>
              {busy === 'allow' ? <Spinner /> : 'Something is not loading, let it through'}
            </button>
            <button className="btn danger" disabled={!domain.trim() || busy === 'block'} onClick={() => quick('block')}>
              {busy === 'block' ? <Spinner /> : 'Block this site for everyone'}
            </button>
            <button className="btn" onClick={() => onNavigate('dnstools')}>Check why a site is blocked</button>
          </div>
        </div>
      </Section>

      <Section title="Family profiles" hint="Kids, Homework, Guests, Unfiltered. Assign them per device.">
        <div style={{ display: 'flex', gap: 8 }}>
          <button className="btn" onClick={() => onNavigate('profiles')}>Manage profiles</button>
          <button className="btn" onClick={() => onNavigate('s-devices')}>Assign to devices</button>
        </div>
      </Section>

      {!config.adblock.enabled && <Banner tone="warn">Blocking is off. Every device on the network sees ads and trackers until it is turned back on.</Banner>}
    </div>
  )
}

function PairTV({ onPaired }: { onPaired: () => void }) {
  const [open, setOpen] = useState(false)
  const [code, setCode] = useState('')
  const [name, setName] = useState('')
  const [busy, setBusy] = useState(false)
  const toast = useToast()
  if (!open) return <button className="btn sm primary" onClick={() => setOpen(true)}>Pair a TV</button>
  return (
    <div style={{ display: 'grid', gap: 8, marginTop: 6 }}>
      <div className="hint">On the TV: YouTube app → Settings → Link with TV code. Type the code here.</div>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        <input className="input mono" style={{ maxWidth: 180 }} value={code} placeholder="123 456 789 012" onChange={(e) => setCode(e.target.value)} />
        <input className="input" style={{ maxWidth: 200 }} value={name} placeholder="Living room TV" onChange={(e) => setName(e.target.value)} />
        <button className="btn primary" disabled={!code.trim() || busy} onClick={async () => {
          setBusy(true)
          try {
            await api.youtube.pair(code.replace(/\s+/g, ''), name.trim() || undefined)
            toast('TV paired. Ads will be skipped from the next one.', 'ok'); setOpen(false); setCode(''); onPaired()
          } catch (e) {
            toast(e instanceof Error ? e.message : 'Pairing failed; check the code', 'err')
          } finally { setBusy(false) }
        }}>{busy ? <Spinner /> : 'Pair'}</button>
        <button className="btn" onClick={() => setOpen(false)}>Cancel</button>
      </div>
    </div>
  )
}
