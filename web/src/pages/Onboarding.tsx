import { useCallback, useEffect, useState } from 'react'
import { api } from '../api'
import { Banner, Card, CopyButton, Field, Icons, Segmented, Spinner, Switch, useToast } from '../ui'
import type { OnboardingApplyParams, OnboardingState, PlacementCheck, Preset } from '../types'

type WizardStepId =
  | 'password'
  | 'about'
  | 'mode'
  | 'placement'
  | 'services'
  | 'upstreams'
  | 'blocklists'
  | 'assistant'
  | 'notifications'
  | 'connect'
  | 'done'

const STEP_TITLES: Record<WizardStepId, string> = {
  password: 'Admin password',
  about: 'About this node',
  mode: 'Interface mode',
  placement: 'Where it sits',
  services: 'What to run',
  upstreams: 'DNS upstreams',
  blocklists: 'Blocklists',
  assistant: 'Assistant',
  notifications: 'Notifications',
  connect: 'Point devices',
  done: 'All set',
}

const STEPS: WizardStepId[] = [
  'password',
  'about',
  'mode',
  'placement',
  'services',
  'upstreams',
  'blocklists',
  'assistant',
  'notifications',
  'connect',
  'done',
]

const STORAGE_KEY = 'orbis_wizard_draft_v1'

interface WizardDraft {
  stepId?: WizardStepId
  mode?: 'simple' | 'advanced'
  nodeName?: string
  timezone?: string
  nodeLat?: number
  nodeLng?: number
  locatedCity?: string
  placement?: 'observe' | 'inline'
  wanIface?: string
  dns?: boolean
  adblock?: boolean
  dhcp?: boolean
  youtube?: boolean
  upstreamPreset?: 'cloudflare' | 'quad9' | 'google' | 'keep' | 'custom'
  customUpstreams?: string
  selectedPresetIds?: string[]
  aiEnabled?: boolean
  aiProvider?: string
  aiBaseUrl?: string
  aiPreferFree?: boolean
  notifyEnabled?: boolean
  webhookUrl?: string
}

function loadSavedDraft(): WizardDraft | null {
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY)
    if (raw) return JSON.parse(raw) as WizardDraft
  } catch {}
  return null
}

function persistDraft(draft: WizardDraft) {
  try {
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify(draft))
  } catch {}
}

const TIMEZONES: string[] = (() => {
  try {
    if (typeof Intl !== 'undefined' && typeof Intl.supportedValuesOf === 'function') {
      return Intl.supportedValuesOf('timeZone')
    }
  } catch {}
  try {
    const local = Intl.DateTimeFormat().resolvedOptions().timeZone
    if (local) return [local, 'UTC']
  } catch {}
  return ['UTC']
})()

function getDisplayAddresses(state: OnboardingState): string[] {
  if (state.addresses && state.addresses.length > 0) {
    return state.addresses
  }
  const fromIfaces: string[] = []
  for (const iface of state.interfaces ?? []) {
    for (const addr of iface.addresses ?? []) {
      const ip = addr.split('/')[0]
      if (ip && !ip.startsWith('127.') && !ip.includes(':')) {
        fromIfaces.push(ip)
      }
    }
  }
  if (fromIfaces.length > 0) return Array.from(new Set(fromIfaces))
  const host = typeof window !== 'undefined' ? window.location.hostname : ''
  return host && host !== 'localhost' ? [host] : ['192.168.1.1']
}

export function Onboarding({ onDone }: { onDone: () => void }) {
  const [state, setState] = useState<OnboardingState | null>(null)
  const [stepId, setStepId] = useState<WizardStepId>('password')
  const [busy, setBusy] = useState(false)
  const toast = useToast()

  // Step 1: Password (never stored in sessionStorage)
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')

  // Step 2: About this node
  const [nodeName, setNodeName] = useState('')
  const [timezone, setTimezone] = useState(() => {
    try {
      return Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC'
    } catch {
      return 'UTC'
    }
  })
  const [nodeLat, setNodeLat] = useState<number | undefined>(undefined)
  const [nodeLng, setNodeLng] = useState<number | undefined>(undefined)
  const [locatedCity, setLocatedCity] = useState('')
  const [locating, setLocating] = useState(false)

  // Step 3: Interface mode
  const [mode, setMode] = useState<'simple' | 'advanced'>('simple')

  // Step 4: Where it sits
  const [placement, setPlacement] = useState<'observe' | 'inline'>('observe')
  const [wanIface, setWanIface] = useState('')

  // Step 5: What to run
  const [dns, setDns] = useState(true)
  const [adblock, setAdblock] = useState(true)
  const [dhcp, setDhcp] = useState(false)
  const [youtube, setYoutube] = useState(false)

  // Step 6: DNS upstreams
  const [upstreamPreset, setUpstreamPreset] = useState<'cloudflare' | 'quad9' | 'google' | 'keep' | 'custom'>('cloudflare')
  const [customUpstreams, setCustomUpstreams] = useState('tls://1.1.1.1:853\ntls://1.0.0.1:853')

  // Step 7: Blocklists
  const [presets, setPresets] = useState<Preset[]>([])
  const [presetsLoaded, setPresetsLoaded] = useState(false)
  const [selectedPresetIds, setSelectedPresetIds] = useState<string[]>([])

  // Step 8: Assistant (optional, API key never stored in sessionStorage)
  const [aiEnabled, setAiEnabled] = useState(false)
  const [aiProvider, setAiProvider] = useState('openrouter')
  const [aiApiKey, setAiApiKey] = useState('')
  const [aiBaseUrl, setAiBaseUrl] = useState('')
  const [aiPreferFree, setAiPreferFree] = useState(true)

  // Step 9: Notifications (optional)
  const [notifyEnabled, setNotifyEnabled] = useState(false)
  const [webhookUrl, setWebhookUrl] = useState('')

  // Load state and restore sessionStorage
  const load = useCallback(async () => {
    try {
      const s = await api.onboarding.get()
      setState(s)

      const saved = loadSavedDraft()

      if (saved?.nodeName !== undefined) setNodeName(saved.nodeName)
      else setNodeName(s.node_name || 'orbis')

      if (saved?.timezone !== undefined) setTimezone(saved.timezone)
      else if (s.timezone) setTimezone(s.timezone)

      if (saved?.nodeLat !== undefined) setNodeLat(saved.nodeLat)
      if (saved?.nodeLng !== undefined) setNodeLng(saved.nodeLng)
      if (saved?.locatedCity !== undefined) setLocatedCity(saved.locatedCity)

      if (saved?.mode !== undefined) setMode(saved.mode)
      else if (s.mode === 'advanced') setMode('advanced')

      if (saved?.placement !== undefined) setPlacement(saved.placement)
      else setPlacement(s.current_mode === 'inline' ? 'inline' : 'observe')

      if (saved?.wanIface !== undefined) setWanIface(saved.wanIface)
      else if (s.links?.suggestion?.wan) setWanIface(s.links.suggestion.wan)

      if (saved?.dns !== undefined) setDns(saved.dns)
      else setDns(s.dns_enabled)

      if (saved?.adblock !== undefined) setAdblock(saved.adblock)
      else setAdblock(s.adblock)

      if (saved?.dhcp !== undefined) setDhcp(saved.dhcp)
      else setDhcp(s.dhcp_enabled)

      if (saved?.youtube !== undefined) setYoutube(saved.youtube)
      else setYoutube(s.lounge_enabled)

      if (saved?.upstreamPreset !== undefined) setUpstreamPreset(saved.upstreamPreset)
      if (saved?.customUpstreams !== undefined) setCustomUpstreams(saved.customUpstreams)
      if (saved?.selectedPresetIds !== undefined) setSelectedPresetIds(saved.selectedPresetIds)

      if (saved?.aiEnabled !== undefined) setAiEnabled(saved.aiEnabled)
      if (saved?.aiProvider !== undefined) setAiProvider(saved.aiProvider)
      if (saved?.aiBaseUrl !== undefined) setAiBaseUrl(saved.aiBaseUrl)
      if (saved?.aiPreferFree !== undefined) setAiPreferFree(saved.aiPreferFree)

      if (saved?.notifyEnabled !== undefined) setNotifyEnabled(saved.notifyEnabled)
      if (saved?.webhookUrl !== undefined) setWebhookUrl(saved.webhookUrl)

      // Step selection
      if (saved?.stepId && STEPS.includes(saved.stepId)) {
        setStepId(saved.stepId)
      } else {
        setStepId('password')
      }
    } catch (e) {
      toast(e instanceof Error ? e.message : 'Could not load setup', 'err')
    }
  }, [toast])

  useEffect(() => { void load() }, [load])

  // If WAN iface is still empty and backend suggests one, use it
  useEffect(() => {
    if (!wanIface && state?.links?.suggestion?.wan) {
      setWanIface(state.links.suggestion.wan)
    }
  }, [state?.links?.suggestion?.wan, wanIface])

  // Load presets on demand
  useEffect(() => {
    if (presetsLoaded) return
    let active = true
    api.adblock.presets()
      .then((res) => {
        if (!active) return
        const list = res.presets ?? []
        setPresets(list)
        setPresetsLoaded(true)
        setSelectedPresetIds((prev) => {
          if (prev.length > 0) return prev
          const rec = list.filter((p) => p.recommended).map((p) => p.id)
          if (rec.length > 0) return rec
          return list.slice(0, 2).map((p) => p.id)
        })
      })
      .catch(() => {})
    return () => { active = false }
  }, [presetsLoaded])

  const steps = STEPS

  // Persist draft on state changes (never password or API key)
  useEffect(() => {
    if (!state) return
    persistDraft({
      stepId,
      mode,
      nodeName,
      timezone,
      nodeLat,
      nodeLng,
      locatedCity,
      placement,
      wanIface,
      dns,
      adblock,
      dhcp,
      youtube,
      upstreamPreset,
      customUpstreams,
      selectedPresetIds,
      aiEnabled,
      aiProvider,
      aiBaseUrl,
      aiPreferFree,
      notifyEnabled,
      webhookUrl,
    })
  }, [
    state, stepId, mode, nodeName, timezone, nodeLat, nodeLng, locatedCity,
    placement, wanIface, dns, adblock, dhcp, youtube, upstreamPreset,
    customUpstreams, selectedPresetIds, aiEnabled, aiProvider, aiBaseUrl,
    aiPreferFree, notifyEnabled, webhookUrl,
  ])

  // Step 10 live poll
  useEffect(() => {
    if (stepId !== 'connect') return
    const timer = setInterval(async () => {
      try {
        const s = await api.onboarding.get()
        setState((prev) => (prev ? { ...prev, placement: s.placement, addresses: s.addresses ?? prev.addresses } : s))
      } catch {}
    }, 5000)
    return () => clearInterval(timer)
  }, [stepId])

  if (!state) {
    return <div className="login"><Spinner /></div>
  }

  const currentIndex = Math.max(0, steps.indexOf(stepId))
  const isOptionalStep =
    stepId === 'password' ||
    stepId === 'blocklists' ||
    stepId === 'assistant' ||
    stepId === 'notifications'

  const buildApplyParams = (finish: boolean): OnboardingApplyParams => {
    let upstreams: string[] | undefined
    if (upstreamPreset === 'cloudflare') {
      upstreams = ['tls://1.1.1.1:853', 'tls://1.0.0.1:853']
    } else if (upstreamPreset === 'quad9') {
      upstreams = ['tls://9.9.9.9:853', 'tls://149.112.112.112:853']
    } else if (upstreamPreset === 'google') {
      upstreams = ['tls://8.8.8.8:853', 'tls://8.8.4.4:853']
    } else if (upstreamPreset === 'custom') {
      const lines = customUpstreams
        .split('\n')
        .map((l) => l.trim())
        .filter((l) => l.length > 0)
      if (lines.length > 0) upstreams = lines
    }

    return {
      mode,
      node_name: nodeName.trim() || 'orbis',
      placement,
      wan_interface: placement === 'inline' ? wanIface || undefined : undefined,
      enable_dns: dns,
      enable_adblock: adblock,
      enable_youtube: youtube,
      enable_dhcp: placement === 'inline' ? dhcp : false,
      ...(upstreams ? { upstreams } : {}),
      finish,
    }
  }

  const handleNext = async () => {
    setBusy(true)
    try {
      if (stepId === 'password') {
        if (!state.password_set) {
          if (password.length < 10) {
            toast('Password must be at least 10 characters', 'err')
            return
          }
          if (password !== confirmPassword) {
            toast('Passwords do not match', 'err')
            return
          }
          await api.auth.setPassword('', password)
          setState({ ...state, password_set: true })
          toast('Admin password set', 'ok')
        }
      } else if (stepId === 'about') {
        const patch: Record<string, unknown> = { 'node.timezone': timezone }
        if (nodeLat !== undefined && nodeLng !== undefined) {
          patch['node.latitude'] = nodeLat
          patch['node.longitude'] = nodeLng
        }
        await api.config.patch(patch)
        const res = await api.onboarding.apply(buildApplyParams(false))
        setState({ ...state, placement: res.placement })
      } else if (stepId === 'mode') {
        const res = await api.onboarding.apply(buildApplyParams(false))
        setState({ ...state, placement: res.placement })
      } else if (stepId === 'placement') {
        const res = await api.onboarding.apply(buildApplyParams(false))
        setState({ ...state, placement: res.placement })
      } else if (stepId === 'services') {
        const res = await api.onboarding.apply(buildApplyParams(false))
        setState({ ...state, placement: res.placement })
      } else if (stepId === 'upstreams') {
        const res = await api.onboarding.apply(buildApplyParams(false))
        setState({ ...state, placement: res.placement })
      } else if (stepId === 'blocklists') {
        for (const pid of selectedPresetIds) {
          await api.adblock.addPreset(pid)
        }
      } else if (stepId === 'assistant') {
        if (aiEnabled) {
          const patch: Record<string, unknown> = {
            'ai.enabled': true,
            'ai.provider': aiProvider,
          }
          if (aiApiKey.trim()) patch['ai.api_key'] = aiApiKey.trim()
          if (aiProvider === 'ollama' && aiBaseUrl.trim()) patch['ai.base_url'] = aiBaseUrl.trim()
          if (aiProvider === 'openrouter') patch['ai.prefer_free'] = aiPreferFree
          await api.config.patch(patch)
        }
      } else if (stepId === 'notifications') {
        if (notifyEnabled && webhookUrl.trim()) {
          await api.config.patch({
            'notify.enabled': true,
            'notify.webhooks': [{
              name: 'primary',
              enabled: true,
              url: webhookUrl.trim(),
              format: 'json',
            }],
          })
        }
      } else if (stepId === 'connect') {
        // Point devices step is informational, always allows continue
      } else if (stepId === 'done') {
        await api.onboarding.apply(buildApplyParams(true))
        try {
          sessionStorage.removeItem(STORAGE_KEY)
        } catch {}
        toast('Setup complete', 'ok')
        onDone()
        return
      }

      // Advance to next step
      if (currentIndex < steps.length - 1) {
        setStepId(steps[currentIndex + 1])
      }
    } catch (e) {
      toast(e instanceof Error ? e.message : 'Could not apply settings', 'err')
    } finally {
      setBusy(false)
    }
  }

  const handleSkip = () => {
    if (stepId === 'password') {
      setPassword('')
      setConfirmPassword('')
    }
    if (currentIndex < steps.length - 1) {
      setStepId(steps[currentIndex + 1])
    }
  }

  const handleBack = () => {
    if (currentIndex > 0) {
      setStepId(steps[currentIndex - 1])
    }
  }

  const handleLocate = async () => {
    setLocating(true)
    try {
      const res = await api.locateSelf()
      const city = res.self?.city || ''
      const country = res.self?.country || ''
      const lat = typeof res.home?.lat === 'number' ? res.home.lat : res.self?.lat
      const lng = typeof res.home?.lng === 'number' ? res.home.lng : res.self?.lon
      setNodeLat(lat)
      setNodeLng(lng)
      const label = city ? (country ? `${city}, ${country}` : city) : (lat !== undefined && lng !== undefined ? `${lat.toFixed(2)}, ${lng.toFixed(2)}` : 'Found')
      setLocatedCity(label)
      toast(city ? `Located in ${city}` : 'Node location determined', 'ok')
    } catch (e) {
      toast(e instanceof Error ? e.message : 'Could not locate node from public address', 'err')
    } finally {
      setLocating(false)
    }
  }

  const togglePreset = (id: string) => {
    setSelectedPresetIds((prev) =>
      prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id],
    )
  }

  const addresses = getDisplayAddresses(state)
  const port = typeof window !== 'undefined' && window.location.port ? window.location.port : '80'
  const progressPct = ((currentIndex + 1) / steps.length) * 100

  const canGoBack = currentIndex > 0

  return (
    <div className="wizard-wrap">
      <div className="wizard-header">
        <h1>Set up Orbis</h1>
        <p>Guided setup for your home network. Everything here can be adjusted later in Settings.</p>
        <div className="wizard-meta">
          <span>Step {currentIndex + 1} of {steps.length} · {STEP_TITLES[stepId]}</span>
        </div>
        <div className="wizard-progress-bar">
          <i style={{ width: `${progressPct}%` }} />
        </div>
      </div>

      {stepId === 'password' && (
        <Card title="Admin password">
          {state.password_set ? (
            <div style={{ display: 'grid', gap: 12 }}>
              <Banner tone="info">Admin password already set</Banner>
              <div style={{ fontSize: 13, color: 'var(--text-dim)', lineHeight: 1.55 }}>
                An admin password is already configured for this node. You can change it anytime in Settings.
              </div>
            </div>
          ) : (
            <>
              <div className="wizard-card-why">
                Protects your node and network settings from anyone on the local network.
              </div>
              <div style={{ display: 'grid', gap: 14 }}>
                <Field label="New password" hint="Used to sign in to the Orbis web dashboard.">
                  <input
                    className="input"
                    type="password"
                    autoComplete="new-password"
                    placeholder="At least 10 characters"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                  />
                </Field>
                <Field label="Confirm password">
                  <input
                    className="input"
                    type="password"
                    autoComplete="new-password"
                    placeholder="Repeat password"
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                  />
                </Field>

                <div style={{ display: 'grid', gap: 6, marginTop: 2 }}>
                  <div style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 8,
                    fontSize: 12,
                    color: password.length >= 10 ? 'var(--green)' : 'var(--text-faint)',
                  }}>
                    <span className={`dot ${password.length >= 10 ? 'on' : 'off'}`} />
                    <span>At least 10 characters ({password.length}/10)</span>
                  </div>
                  <div style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 8,
                    fontSize: 12,
                    color: password.length > 0 && confirmPassword.length > 0 && password === confirmPassword ? 'var(--green)' : 'var(--text-faint)',
                  }}>
                    <span className={`dot ${password.length > 0 && confirmPassword.length > 0 && password === confirmPassword ? 'on' : 'off'}`} />
                    <span>Passwords match</span>
                  </div>
                </div>

                <div style={{ fontSize: 12, color: 'var(--text-dim)', lineHeight: 1.5, marginTop: 4 }}>
                  You can set it later in Settings; until then anyone on the network can open this page.
                </div>
              </div>
            </>
          )}
        </Card>
      )}

      {stepId === 'about' && (
        <Card title="About this node">
          <div className="wizard-card-why">
            Names this node on your network and sets its timezone and approximate location for the globe and traffic history.
          </div>
          <div style={{ display: 'grid', gap: 14 }}>
            <Field label="Node name" hint="The hostname other devices use to reach this node.">
              <input
                className="input"
                value={nodeName}
                onChange={(e) => setNodeName(e.target.value)}
                placeholder="orbis"
              />
            </Field>

            <Field label="Timezone" hint="Used for log timestamps, night-time rules, and scheduled reports.">
              <select
                className="select"
                value={timezone}
                onChange={(e) => setTimezone(e.target.value)}
              >
                {TIMEZONES.map((tz) => (
                  <option key={tz} value={tz}>{tz}</option>
                ))}
              </select>
            </Field>

            <Field label="Location" hint="Pins this node on the globe. Discovery queries a DNS resolver for your source IP and resolves it against a local database.">
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
                <button
                  type="button"
                  className="btn"
                  disabled={locating || busy}
                  onClick={handleLocate}
                >
                  {locating ? <Spinner /> : <Icons.globe size={14} />}
                  Use this node's public address
                </button>
                {locatedCity ? (
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span className="tag live">Located: {locatedCity}</span>
                    <button
                      type="button"
                      className="btn sm"
                      onClick={() => {
                        setLocatedCity('')
                        setNodeLat(undefined)
                        setNodeLng(undefined)
                      }}
                    >
                      Clear
                    </button>
                  </div>
                ) : (
                  <span style={{ fontSize: 12, color: 'var(--text-faint)' }}>
                    Or leave blank to use the timezone centroid
                  </span>
                )}
              </div>
            </Field>
          </div>
        </Card>
      )}

      {stepId === 'mode' && (
        <Card title="Interface mode">
          <div className="wizard-card-why">
            Choose how much detail you want to see day-to-day. You can switch between them anytime from the navigation.
          </div>
          <div style={{ display: 'grid', gap: 14 }}>
            <Segmented
              value={mode}
              onChange={(v) => setMode(v)}
              options={[
                { value: 'simple', label: 'Simple' },
                { value: 'advanced', label: 'Advanced' },
              ]}
            />

            <div style={{ display: 'grid', gap: 10 }}>
              <div
                className={`wizard-option ${mode === 'simple' ? 'selected' : ''}`}
                onClick={() => setMode('simple')}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                  <span className={`dot ${mode === 'simple' ? 'on' : 'off'}`} />
                  <strong style={{ fontSize: 13.5 }}>Simple</strong>
                </div>
                <div style={{ fontSize: 12, color: 'var(--text-dim)', lineHeight: 1.55 }}>
                  Everyday protection, devices, usage, and quick toggles in plain language. Best for households and hands-off setups.
                </div>
              </div>

              <div
                className={`wizard-option ${mode === 'advanced' ? 'selected' : ''}`}
                onClick={() => setMode('advanced')}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                  <span className={`dot ${mode === 'advanced' ? 'on' : 'off'}`} />
                  <strong style={{ fontSize: 13.5 }}>Advanced</strong>
                </div>
                <div style={{ fontSize: 12, color: 'var(--text-dim)', lineHeight: 1.55 }}>
                  Full control: deep flow inspector, firewall rules, routing tables, WAN links, and raw DNS logs.
                </div>
              </div>
            </div>
          </div>
        </Card>
      )}

      {stepId === 'placement' && (
        <Card title="Where does this node sit?">
          <div className="wizard-card-why">
            This is the only choice that decides whether Orbis sees anything. On a normal switched network, a node that is not the gateway never sees what other devices send, no matter what else is switched on.
          </div>
          <div style={{ display: 'grid', gap: 10 }}>
            <div
              className={`wizard-option ${placement === 'observe' ? 'selected' : ''}`}
              onClick={() => setPlacement('observe')}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                <span className={`dot ${placement === 'observe' ? 'on' : 'off'}`} />
                <strong style={{ fontSize: 13.5 }}>Watch only</strong>
              </div>
              <div style={{ fontSize: 12, color: 'var(--text-dim)', lineHeight: 1.6 }}>
                Installs no rules and routes nothing. It sees its own traffic and whatever broadcast reaches it. Safe to leave here forever, and the right choice while you are trying it out.
              </div>
            </div>

            <div
              className={`wizard-option ${placement === 'inline' ? 'selected' : ''}`}
              onClick={() => setPlacement('inline')}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                <span className={`dot ${placement === 'inline' ? 'on' : 'off'}`} />
                <strong style={{ fontSize: 13.5 }}>Be the gateway</strong>
              </div>
              <div style={{ fontSize: 12, color: 'var(--text-dim)', lineHeight: 1.6 }}>
                Installs the firewall ruleset, forwards and translates traffic, and hands out DHCP if a scope exists. This is the only mode where Orbis sees the whole network. It also means a mistake here takes the network down, so it is worth doing when you have a few minutes.
              </div>
            </div>
          </div>

          {placement === 'inline' && (
            <div style={{ marginTop: 12 }}>
              <Banner tone="warn">
                Point your router at this node, or bridge it, before switching. Choosing this while nothing routes through Orbis leaves you with the same empty screens plus a firewall.
              </Banner>
            </div>
          )}

          {mode === 'advanced' && placement === 'inline' && (
            <div style={{ marginTop: 14 }}>
              <Field
                label="WAN interface"
                hint={state.links?.suggestion?.wan
                  ? `Orbis thinks ${state.links.suggestion.wan} is the internet: ${state.links.suggestion.reason}`
                  : 'Required for gateway mode: it is the interface NAT translates towards.'}
              >
                <select
                  className="select"
                  value={wanIface}
                  onChange={(e) => setWanIface(e.target.value)}
                >
                  <option value="">Choose…</option>
                  {(state.interfaces ?? []).map((i) => (
                    <option key={i.name} value={i.name}>
                      {i.name} {i.addresses?.[0] ? `(${i.addresses[0]})` : ''}
                    </option>
                  ))}
                </select>
              </Field>
            </div>
          )}
        </Card>
      )}

      {stepId === 'services' && (
        <Card title="What should it run?">
          <div className="wizard-card-why">
            Turn on the core network services you want Orbis to provide.
          </div>
          <div style={{ display: 'grid', gap: 14 }}>
            <div>
              <Switch checked={dns} onChange={setDns} label="Filtering DNS resolver" />
              <div className="hint" style={{ marginTop: 3 }}>
                Devices have to point at this node for it to matter. The check later tells you whether any of them do.
              </div>
            </div>

            <div>
              <Switch checked={adblock} onChange={setAdblock} label="Ad and tracker blocklists" />
              <div className="hint" style={{ marginTop: 3 }}>
                Blocks advertisements and tracking scripts across every device on your network.
              </div>
            </div>

            <div>
              <Switch checked={youtube} onChange={setYoutube} label="YouTube ad skipping on TVs (no certificate needed)" />
              <div className="hint" style={{ marginTop: 3 }}>
                Automatically detects video ads on smart TVs using YouTube Lounge and skips them seamlessly.
              </div>
            </div>

            {placement === 'inline' && (
              <div>
                <Switch checked={dhcp} onChange={setDhcp} label="DHCP server" />
                <div className="hint" style={{ marginTop: 3 }}>
                  Only turn this on once this node is the gateway, and turn your router's DHCP off first. Two servers on one network hand out conflicting addresses.
                </div>
              </div>
            )}
          </div>
        </Card>
      )}

      {stepId === 'upstreams' && (
        <Card title="DNS upstreams">
          <div className="wizard-card-why">
            Where Orbis forwards queries that aren't blocked or answered locally.
          </div>
          <div style={{ display: 'grid', gap: 10 }}>
            <div
              className={`wizard-option ${upstreamPreset === 'cloudflare' ? 'selected' : ''}`}
              onClick={() => setUpstreamPreset('cloudflare')}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span className={`dot ${upstreamPreset === 'cloudflare' ? 'on' : 'off'}`} />
                  <strong style={{ fontSize: 13.5 }}>Cloudflare</strong>
                </div>
                <span className="tag live">tls://1.1.1.1:853</span>
              </div>
              <div style={{ fontSize: 12, color: 'var(--text-dim)', lineHeight: 1.55 }}>
                Fast, privacy-focused DNS over TLS with strict no-logging policy.
              </div>
            </div>

            <div
              className={`wizard-option ${upstreamPreset === 'quad9' ? 'selected' : ''}`}
              onClick={() => setUpstreamPreset('quad9')}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span className={`dot ${upstreamPreset === 'quad9' ? 'on' : 'off'}`} />
                  <strong style={{ fontSize: 13.5 }}>Quad9</strong>
                </div>
                <span className="tag info">tls://9.9.9.9:853</span>
              </div>
              <div style={{ fontSize: 12, color: 'var(--text-dim)', lineHeight: 1.55 }}>
                Blocks malware, phishing, and scam domains using global threat feeds. Swiss non-profit.
              </div>
            </div>

            <div
              className={`wizard-option ${upstreamPreset === 'google' ? 'selected' : ''}`}
              onClick={() => setUpstreamPreset('google')}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span className={`dot ${upstreamPreset === 'google' ? 'on' : 'off'}`} />
                  <strong style={{ fontSize: 13.5 }}>Google</strong>
                </div>
                <span className="tag">tls://8.8.8.8:853</span>
              </div>
              <div style={{ fontSize: 12, color: 'var(--text-dim)', lineHeight: 1.55 }}>
                Reliable global DNS over TLS infrastructure with standard unfiltered resolution.
              </div>
            </div>

            <div
              className={`wizard-option ${upstreamPreset === 'keep' ? 'selected' : ''}`}
              onClick={() => setUpstreamPreset('keep')}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                <span className={`dot ${upstreamPreset === 'keep' ? 'on' : 'off'}`} />
                <strong style={{ fontSize: 13.5 }}>Keep what is configured</strong>
              </div>
              <div style={{ fontSize: 12, color: 'var(--text-dim)', lineHeight: 1.55 }}>
                Leave current upstream DNS configuration as already set on this system.
              </div>
            </div>

            {mode === 'advanced' && (
              <div
                className={`wizard-option ${upstreamPreset === 'custom' ? 'selected' : ''}`}
                onClick={() => setUpstreamPreset('custom')}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                  <span className={`dot ${upstreamPreset === 'custom' ? 'on' : 'off'}`} />
                  <strong style={{ fontSize: 13.5 }}>Custom resolvers</strong>
                </div>
                <div style={{ fontSize: 12, color: 'var(--text-dim)', lineHeight: 1.55, marginBottom: 8 }}>
                  Specify custom DNS over TLS or plain DNS upstreams, one per line.
                </div>
                {upstreamPreset === 'custom' && (
                  <textarea
                    className="textarea"
                    value={customUpstreams}
                    onClick={(e) => e.stopPropagation()}
                    onChange={(e) => setCustomUpstreams(e.target.value)}
                    placeholder="tls://1.1.1.1:853&#10;tls://1.0.0.1:853"
                    rows={3}
                  />
                )}
              </div>
            )}
          </div>
        </Card>
      )}

      {stepId === 'blocklists' && (
        <Card title="Blocklists">
          <div className="wizard-card-why">
            Pre-configured domain lists to stop ads, trackers, and malware across all devices.
          </div>
          {!presetsLoaded ? (
            <div style={{ padding: 20, textAlign: 'center' }}><Spinner /></div>
          ) : (
            <div style={{ display: 'grid', gap: 10 }}>
              {presets.map((p) => {
                const isSelected = selectedPresetIds.includes(p.id)
                return (
                  <div
                    key={p.id}
                    className={`wizard-option ${isSelected ? 'selected' : ''}`}
                    onClick={() => togglePreset(p.id)}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <span className={`dot ${isSelected ? 'on' : 'off'}`} />
                        <strong style={{ fontSize: 13.5 }}>{p.name}</strong>
                        {p.recommended && <span className="tag live">Recommended</span>}
                      </div>
                      <span className="tag">{p.category}</span>
                    </div>
                    <div style={{ fontSize: 12, color: 'var(--text-dim)', lineHeight: 1.55 }}>
                      {p.description}
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </Card>
      )}

      {stepId === 'assistant' && (
        <Card title="Assistant (optional)">
          <div className="wizard-card-why">
            Summarises network traffic and triages anomalies. Everything in Orbis works completely without it.
          </div>
          <div style={{ display: 'grid', gap: 14 }}>
            <Switch
              checked={aiEnabled}
              onChange={setAiEnabled}
              label="Enable AI assistant"
            />

            {aiEnabled && (
              <div style={{ display: 'grid', gap: 12, paddingLeft: 6 }}>
                <Field label="Provider" hint="Select the model provider for chat and traffic analysis.">
                  <select
                    className="select"
                    value={aiProvider}
                    onChange={(e) => setAiProvider(e.target.value)}
                  >
                    <option value="openrouter">OpenRouter</option>
                    <option value="anthropic">Anthropic</option>
                    <option value="openai">OpenAI</option>
                    <option value="ollama">Ollama (local)</option>
                  </select>
                </Field>

                {aiProvider !== 'ollama' ? (
                  <Field label="API key" hint="Stored locally in config with restricted permissions.">
                    <input
                      className="input mono"
                      type="password"
                      value={aiApiKey}
                      onChange={(e) => setAiApiKey(e.target.value)}
                      placeholder={aiProvider === 'openrouter' ? 'sk-or-v1-…' : 'sk-…'}
                    />
                  </Field>
                ) : (
                  <Field label="Base URL" hint="Address of your local Ollama server.">
                    <input
                      className="input mono"
                      type="text"
                      value={aiBaseUrl}
                      onChange={(e) => setAiBaseUrl(e.target.value)}
                      placeholder="http://127.0.0.1:11434/v1"
                    />
                  </Field>
                )}

                {aiProvider === 'openrouter' && (
                  <div>
                    <Switch
                      checked={aiPreferFree}
                      onChange={setAiPreferFree}
                      label="Prefer free models"
                    />
                    <div className="hint" style={{ marginTop: 3 }}>
                      OpenRouter serves rotating free models to active accounts. Orbis will probe and prefer them automatically.
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        </Card>
      )}

      {stepId === 'notifications' && (
        <Card title="Notifications (optional)">
          <div className="wizard-card-why">
            Get alerted when important security events occur. Email delivery can be configured later in Settings.
          </div>
          <div style={{ display: 'grid', gap: 14 }}>
            <Switch
              checked={notifyEnabled}
              onChange={setNotifyEnabled}
              label="Enable webhook notifications"
            />

            {notifyEnabled && (
              <div style={{ paddingLeft: 6 }}>
                <Field
                  label="Webhook URL"
                  hint="ntfy, Slack, Discord, or any custom JSON webhook endpoint accepting HTTP POST."
                >
                  <input
                    className="input mono"
                    type="url"
                    value={webhookUrl}
                    onChange={(e) => setWebhookUrl(e.target.value)}
                    placeholder="https://ntfy.sh/my-network-alerts or Discord/Slack URL"
                  />
                </Field>
              </div>
            )}
          </div>
        </Card>
      )}

      {stepId === 'connect' && (
        <Card title="Point devices here">
          <div className="wizard-card-why">
            Point your home router or individual devices at this node so Orbis can filter their traffic.
          </div>

          <div style={{ display: 'grid', gap: 10, marginBottom: 16 }}>
            <div style={{ fontSize: 11.5, fontWeight: 600, color: 'var(--text-faint)', textTransform: 'uppercase', letterSpacing: '.06em' }}>
              Node IP address{addresses.length > 1 ? 'es' : ''} (port {port})
            </div>
            {addresses.map((addr) => (
              <div key={addr} className="wizard-address-item">
                <div>
                  <div className="wizard-address-text">{addr}</div>
                  <div style={{ fontSize: 11.5, color: 'var(--text-dim)', marginTop: 2 }}>
                    DNS port 53 · Web admin port {port}
                  </div>
                </div>
                <CopyButton text={addr} label="Copy address" />
              </div>
            ))}
          </div>

          <div style={{ display: 'grid', gap: 10, marginBottom: 18 }}>
            <div style={{ padding: '12px 14px', background: 'var(--bg-2)', border: '1px solid var(--line)', borderRadius: 'var(--radius-sm)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                <span className="dot on" />
                <strong style={{ fontSize: 13 }}>Router DHCP DNS setting (recommended)</strong>
              </div>
              <div style={{ fontSize: 12, color: 'var(--text-dim)', lineHeight: 1.6 }}>
                Open your home router's admin page, go to LAN or DHCP settings, and set the primary DNS server to <code>{addresses[0]}</code>. Every device connected to your Wi-Fi will be protected automatically.
              </div>
            </div>

            <div style={{ padding: '12px 14px', background: 'var(--bg-2)', border: '1px solid var(--line)', borderRadius: 'var(--radius-sm)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                <span className="dot on" />
                <strong style={{ fontSize: 13 }}>Single device test</strong>
              </div>
              <div style={{ fontSize: 12, color: 'var(--text-dim)', lineHeight: 1.6 }}>
                To test Orbis first, open Wi-Fi settings on your phone or computer, set DNS to manual, and enter <code>{addresses[0]}</code>.
              </div>
            </div>

            <div style={{ padding: '12px 14px', background: 'var(--bg-2)', border: '1px solid var(--line)', borderRadius: 'var(--radius-sm)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                <span className="dot off" />
                <strong style={{ fontSize: 13 }}>I will do this later</strong>
              </div>
              <div style={{ fontSize: 12, color: 'var(--text-dim)', lineHeight: 1.6 }}>
                You can complete the wizard now and configure your router whenever you have a few minutes.
              </div>
            </div>
          </div>

          <Card
            title="Can this node see your network?"
            actions={(
              <button
                className="btn sm"
                disabled={busy}
                onClick={async () => {
                  setBusy(true)
                  try {
                    const s = await api.onboarding.get()
                    setState({ ...state, placement: s.placement })
                  } catch {}
                  setBusy(false)
                }}
              >
                <Icons.refresh size={13} /> Re-check
              </button>
            )}
          >
            <div className="hint" style={{ marginBottom: 11 }}>
              Measured, not assumed. "Devices using this resolver" turns green automatically when queries start reaching this node.
            </div>
            <div style={{ display: 'grid', gap: 11 }}>
              {(state.placement ?? []).map((c) => <Check key={c.name} c={c} />)}
            </div>
          </Card>
        </Card>
      )}

      {stepId === 'done' && (
        <Card title="All set">
          <div className="wizard-card-why">
            Review your configuration and start protecting your network.
          </div>
          <div className="wizard-summary-list">
            <div className="wizard-summary-row">
              <span className="wizard-summary-label">Node name</span>
              <span className="wizard-summary-val mono">{nodeName || 'orbis'}</span>
            </div>
            <div className="wizard-summary-row">
              <span className="wizard-summary-label">Timezone</span>
              <span className="wizard-summary-val">{timezone || 'Default'}</span>
            </div>
            <div className="wizard-summary-row">
              <span className="wizard-summary-label">Interface</span>
              <span className="wizard-summary-val" style={{ textTransform: 'capitalize' }}>{mode}</span>
            </div>
            <div className="wizard-summary-row">
              <span className="wizard-summary-label">Where it sits</span>
              <span className="wizard-summary-val">
                {placement === 'inline' ? `Gateway${wanIface ? ` (WAN: ${wanIface})` : ''}` : 'Watch only (observe)'}
              </span>
            </div>
            <div className="wizard-summary-row">
              <span className="wizard-summary-label">Running services</span>
              <span className="wizard-summary-val">
                {[
                  dns ? 'DNS resolver' : null,
                  adblock ? 'Ad blocklists' : null,
                  youtube ? 'YouTube ad skipping' : null,
                  placement === 'inline' && dhcp ? 'DHCP server' : null,
                ].filter(Boolean).join(', ') || 'None'}
              </span>
            </div>
            <div className="wizard-summary-row">
              <span className="wizard-summary-label">DNS upstreams</span>
              <span className="wizard-summary-val">
                {upstreamPreset === 'cloudflare' ? 'Cloudflare (DoT)'
                  : upstreamPreset === 'quad9' ? 'Quad9 (DoT)'
                  : upstreamPreset === 'google' ? 'Google (DoT)'
                  : upstreamPreset === 'custom' ? 'Custom'
                  : 'System default'}
              </span>
            </div>
            <div className="wizard-summary-row">
              <span className="wizard-summary-label">Blocklists</span>
              <span className="wizard-summary-val">
                {selectedPresetIds.length > 0
                  ? `${selectedPresetIds.length} list${selectedPresetIds.length === 1 ? '' : 's'} added`
                  : 'Default lists only'}
              </span>
            </div>
            <div className="wizard-summary-row">
              <span className="wizard-summary-label">Assistant</span>
              <span className="wizard-summary-val">
                {aiEnabled ? `Enabled (${aiProvider})` : 'Off'}
              </span>
            </div>
            <div className="wizard-summary-row">
              <span className="wizard-summary-label">Notifications</span>
              <span className="wizard-summary-val">
                {notifyEnabled && webhookUrl ? 'Enabled (Webhook)' : 'Off'}
              </span>
            </div>
          </div>
        </Card>
      )}

      <div className="wizard-actions">
        <button
          type="button"
          className="btn"
          disabled={!canGoBack || busy}
          onClick={handleBack}
        >
          Back
        </button>

        <div className="wizard-actions-right">
          {isOptionalStep && (
            <button
              type="button"
              className="btn"
              disabled={busy}
              onClick={handleSkip}
            >
              Skip
            </button>
          )}

          {stepId === 'done' ? (
            <button
              type="button"
              className="btn primary"
              disabled={busy}
              onClick={handleNext}
            >
              {busy ? <Spinner /> : <Icons.check size={14} />} Open Orbis
            </button>
          ) : (
            <button
              type="button"
              className="btn primary"
              disabled={busy || (stepId === 'password' && !state.password_set && (password.length < 10 || password !== confirmPassword))}
              onClick={handleNext}
            >
              {busy ? <Spinner /> : null} Continue
            </button>
          )}
        </div>
      </div>

      {stepId === 'password' && (
        <div className="wizard-skip-note">
          You can set it later in Settings; until then anyone on the network can open this page.
        </div>
      )}
    </div>
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
