import { useCallback, useEffect, useState } from 'react'
import { api } from '../api'
import { Banner, Card, Icons, Segmented, Spinner, Switch, useToast } from '../ui'
import type { OnboardingState, PlacementCheck } from '../types'

/**
 * First-run wizard.
 *
 * The ordering here is deliberate. Feature toggles come last, because a node
 * that is not on the traffic path will happily record its own DNS lookups and
 * some broadcast noise, and every screen then looks populated while showing
 * nothing about the network. Placement is the decision that determines whether
 * any of the rest means anything, so it is asked first and checked honestly.
 */
export function Onboarding({ onDone }: { onDone: () => void }) {
  const [state, setState] = useState<OnboardingState | null>(null)
  const [mode, setMode] = useState<'simple' | 'advanced'>('simple')
  const [step, setStep] = useState(0)
  const [busy, setBusy] = useState(false)
  const toast = useToast()

  // Draft choices, applied in one call at the end.
  const [nodeName, setNodeName] = useState('')
  const [placement, setPlacement] = useState<'observe' | 'inline'>('observe')
  const [wanIface, setWanIface] = useState('')
  const [dns, setDns] = useState(true)
  const [adblock, setAdblock] = useState(true)
  const [dhcp, setDhcp] = useState(false)
  const [youtube, setYoutube] = useState(false)

  const load = useCallback(async () => {
    try {
      const s = await api.onboarding.get()
      setState(s)
      setNodeName(s.node_name || 'orbis')
      setPlacement(s.current_mode === 'inline' ? 'inline' : 'observe')
      setDns(s.dns_enabled)
      setAdblock(s.adblock)
      setDhcp(s.dhcp_enabled)
      setYoutube(s.lounge_enabled)
      if (s.mode === 'advanced') setMode('advanced')
    } catch (e) {
      toast(e instanceof Error ? e.message : 'Could not load setup', 'err')
    }
  }, [toast])

  useEffect(() => { load() }, [load])

  if (!state) {
    return <div className="login"><Spinner /></div>
  }

  const steps = mode === 'simple'
    ? ['Placement', 'What to run', 'Check']
    : ['Placement', 'Network', 'What to run', 'Check']
  const last = steps.length - 1

  const apply = async (finish: boolean) => {
    setBusy(true)
    try {
      const r = await api.onboarding.apply({
        mode, node_name: nodeName, placement,
        wan_interface: wanIface || undefined,
        enable_dns: dns, enable_adblock: adblock,
        enable_dhcp: dhcp, enable_youtube: youtube,
        finish,
      })
      setState({ ...state, placement: r.placement, onboarded: r.onboarded })
      if (finish) {
        toast('Setup saved', 'ok')
        onDone()
      }
      return true
    } catch (e) {
      toast(e instanceof Error ? e.message : 'Could not save', 'err')
      return false
    } finally {
      setBusy(false)
    }
  }

  return (
    <div style={{ maxWidth: 720, margin: '0 auto', padding: '28px 18px', display: 'grid', gap: 14 }}>
      <div>
        <h1 style={{ fontSize: 22, margin: 0 }}>Set up Orbis</h1>
        <p style={{ color: 'var(--text-dim)', fontSize: 13, marginTop: 6, lineHeight: 1.6 }}>
          Three questions, and one honest check at the end that tells you whether this node can
          actually see your network. Nothing here is permanent; you can rerun it from Settings.
        </p>
      </div>

      <div className="toolbar" style={{ marginBottom: 0 }}>
        <Segmented
          value={mode} onChange={(v) => { setMode(v); setStep(0) }}
          options={[
            { value: 'simple', label: 'Simple' },
            { value: 'advanced', label: 'Advanced' },
          ]}
        />
        <div className="spacer" style={{ flex: 1 }} />
        <span style={{ fontSize: 12, color: 'var(--text-faint)' }}>
          Step {step + 1} of {steps.length} · {steps[step]}
        </span>
      </div>

      {step === 0 && (
        <Card title="Where does this node sit?">
          <div className="hint" style={{ marginBottom: 12 }}>
            This is the only choice that decides whether Orbis sees anything. On a normal switched
            network, a node that is not the gateway never sees what other devices send, no matter
            what else is switched on.
          </div>
          <div style={{ display: 'grid', gap: 10 }}>
            <PlacementOption
              selected={placement === 'observe'} onSelect={() => setPlacement('observe')}
              title="Watch only"
              body="Installs no rules and routes nothing. It sees its own traffic and whatever broadcast reaches it. Safe to leave here forever, and the right choice while you are trying it out."
            />
            <PlacementOption
              selected={placement === 'inline'} onSelect={() => setPlacement('inline')}
              title="Be the gateway"
              body="Installs the firewall ruleset, forwards and translates traffic, and hands out DHCP if a scope exists. This is the only mode where Orbis sees the whole network. It also means a mistake here takes the network down, so it is worth doing when you have a few minutes."
            />
          </div>
          {placement === 'inline' && (
            <Banner tone="warn">
              Point your router at this node, or bridge it, before switching. Choosing this while
              nothing routes through Orbis leaves you with the same empty screens plus a firewall.
            </Banner>
          )}
        </Card>
      )}

      {mode === 'advanced' && step === 1 && (
        <Card title="Network">
          <div style={{ display: 'grid', gap: 11 }}>
            <label className="field">
              <span>Node name</span>
              <input className="input" value={nodeName} onChange={(e) => setNodeName(e.target.value)} />
            </label>
            <label className="field">
              <span>WAN interface</span>
              <select className="input" value={wanIface} onChange={(e) => setWanIface(e.target.value)}>
                <option value="">Choose…</option>
                {(state.interfaces ?? []).map((i) => (
                  <option key={i.name} value={i.name}>{i.name} {i.addresses?.[0] ? `(${i.addresses[0]})` : ''}</option>
                ))}
              </select>
              <div className="hint">
                Required for gateway mode: it is the interface NAT translates towards.
              </div>
            </label>
          </div>
        </Card>
      )}

      {((mode === 'simple' && step === 1) || (mode === 'advanced' && step === 2)) && (
        <Card title="What should it run?">
          <div style={{ display: 'grid', gap: 10 }}>
            <Switch checked={dns} onChange={setDns} label="Filtering DNS resolver" />
            <div className="hint" style={{ marginTop: -5 }}>
              Devices have to point at this node for it to matter. The check on the next step tells
              you whether any of them do.
            </div>
            <Switch checked={adblock} onChange={setAdblock} label="Ad and tracker blocklists" />
            <Switch checked={youtube} onChange={setYoutube}
              label="YouTube ad skipping on TVs (no certificate needed)" />
            {mode === 'advanced' && (
              <>
                <Switch checked={dhcp} onChange={setDhcp} label="DHCP server" />
                <div className="hint" style={{ marginTop: -5 }}>
                  Only turn this on once this node is the gateway, and turn your router's DHCP off
                  first. Two servers on one network hand out conflicting addresses.
                </div>
              </>
            )}
          </div>
        </Card>
      )}

      {step === last && (
        <Card
          title="Can this node see your network?"
          actions={<button className="btn sm" disabled={busy} onClick={() => apply(false)}>
            <Icons.refresh size={13} /> Re-check
          </button>}
        >
          <div className="hint" style={{ marginBottom: 11 }}>
            Measured, not assumed. A failing check here is the difference between a dashboard that
            reflects your network and one that only reflects Orbis talking to itself.
          </div>
          <div style={{ display: 'grid', gap: 11 }}>
            {(state.placement ?? []).map((c) => <Check key={c.name} c={c} />)}
          </div>
        </Card>
      )}

      <div style={{ display: 'flex', gap: 8, justifyContent: 'space-between' }}>
        <button className="btn" disabled={step === 0 || busy} onClick={() => setStep((s) => s - 1)}>
          Back
        </button>
        <div style={{ display: 'flex', gap: 8 }}>
          <button className="btn" disabled={busy} onClick={() => apply(true)}>Skip setup</button>
          {step < last ? (
            <button className="btn primary" disabled={busy} onClick={async () => {
              // Apply as we go so the final check reflects the real config
              // rather than the draft.
              if (await apply(false)) setStep((s) => s + 1)
            }}>Continue</button>
          ) : (
            <button className="btn primary" disabled={busy} onClick={() => apply(true)}>
              <Icons.check size={13} /> Finish
            </button>
          )}
        </div>
      </div>
    </div>
  )
}

function PlacementOption({ selected, onSelect, title, body }: {
  selected: boolean; onSelect: () => void; title: string; body: string
}) {
  return (
    <button
      onClick={onSelect}
      style={{
        textAlign: 'left', cursor: 'pointer', padding: 13, borderRadius: 9,
        border: `1px solid ${selected ? 'var(--accent)' : 'var(--line)'}`,
        background: selected ? 'color-mix(in srgb, var(--accent) 10%, transparent)' : 'transparent',
        color: 'inherit',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 9, marginBottom: 5 }}>
        <span className={`dot ${selected ? 'on' : 'off'}`} />
        <strong style={{ fontSize: 13.5 }}>{title}</strong>
      </div>
      <div style={{ fontSize: 12, color: 'var(--text-dim)', lineHeight: 1.6 }}>{body}</div>
    </button>
  )
}

function Check({ c }: { c: PlacementCheck }) {
  const tone = c.status === 'ok' ? 'on' : c.status === 'warn' ? 'warn' : 'err'
  return (
    <div style={{ display: 'flex', gap: 10, alignItems: 'flex-start' }}>
      <span className={`dot ${tone}`} style={{ marginTop: 5 }} />
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: 13 }}>{c.name}</div>
        <div style={{ fontSize: 11.5, color: 'var(--text-dim)', lineHeight: 1.55, marginTop: 2 }}>
          {c.detail}
        </div>
        {c.fix && (
          <div style={{ fontSize: 11.5, color: 'var(--amber)', lineHeight: 1.55, marginTop: 4 }}>
            {c.fix}
          </div>
        )}
      </div>
    </div>
  )
}
