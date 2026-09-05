import { useCallback, useEffect, useMemo, useState, useRef } from 'react'
import { api, setUnauthorizedHandler } from './api'
import { usePoll, useLive, useLocalStorage, type LiveEvent } from './hooks'
import { Icons, ToastProvider, Banner, Spinner, Segmented, useToast } from './ui'
import type { AppConfig, SystemStatus, Summary } from './types'
import { Dashboard } from './pages/Dashboard'
import { GlobePage } from './pages/GlobePage'
import { AnalyticsPage } from './pages/Analytics'
import { AlertsPage } from './pages/Alerts'
import { ReportsPage } from './pages/Reports'
import { ClientsPage } from './pages/Clients'
import { FlowsPage } from './pages/Flows'
import { DNSPage } from './pages/DNS'
import { AdBlockPage } from './pages/AdBlock'
import { YouTubePage } from './pages/YouTube'
import { DNSToolsPage } from './pages/DNSTools'
import { TopologyPage } from './pages/Topology'
import { InterceptPage } from './pages/Intercept'
import { GatewayPage } from './pages/Gateway'
import { ConsentPage } from './pages/Consent'
import { FirewallPage } from './pages/Firewall'
import { NetworkPage } from './pages/Network'
import { VPNPage } from './pages/VPN'
import { AssistantPage } from './pages/Assistant'
import { ProblemsPage } from './pages/Problems'
import { ServicesPage } from './pages/Services'
import { ProfilesPage } from './pages/Profiles'
import { SimpleHome } from './simple/Home'
import { SimpleDevices } from './simple/Devices'
import { SimpleProtection } from './simple/Protection'
import { SimpleAlerts } from './simple/Alerts'
import { SimpleSettings } from './simple/SettingsSimple'
import { EventsPage } from './pages/Events'
import { SettingsPage } from './pages/Settings'
import { Login } from './pages/Login'
import { Onboarding } from './pages/Onboarding'
import { ErrorBoundary } from './ErrorBoundary'
import { CommandPalette } from './CommandPalette'

type Route =
  | 'dashboard' | 'globe' | 'clients' | 'flows' | 'dns' | 'adblock'
  | 'firewall' | 'network' | 'vpn' | 'assistant' | 'events' | 'settings' | 'youtube' | 'gateway' | 'consent' | 'dnstools' | 'topology' | 'intercept' | 'analytics' | 'alerts' | 'reports' | 'problems' | 'services'
  | 'profiles' | 's-home' | 's-devices' | 's-protection' | 's-usage' | 's-alerts' | 's-settings'

const ROUTES: Array<{ id: Route; label: string; icon: keyof typeof Icons; group?: string }> = [
  { id: 'dashboard', label: 'Overview', icon: 'grid' },
  { id: 'globe', label: 'Globe', icon: 'globe' },
  { id: 'flows', label: 'Connections', icon: 'activity' },
  { id: 'services', label: 'Services', icon: 'tv' },
  { id: 'analytics', label: 'Analytics', icon: 'spark' },
  { id: 'clients', label: 'Devices', icon: 'devices' },
  { id: 'topology', label: 'Topology', icon: 'grid' },
  { id: 'dns', label: 'DNS', icon: 'dns', group: 'Filtering' },
  { id: 'adblock', label: 'Ad blocking', icon: 'block' },
  { id: 'profiles', label: 'Profiles', icon: 'shield' },
  { id: 'dnstools', label: 'Domain tester', icon: 'search' },
  { id: 'youtube', label: 'YouTube', icon: 'tv' },
  { id: 'consent', label: 'Ask first', icon: 'shield' },
  { id: 'firewall', label: 'Firewall', icon: 'shield', group: 'Network' },
  { id: 'network', label: 'DHCP & LAN', icon: 'route' },
  { id: 'gateway', label: 'Gateway', icon: 'activity' },
  { id: 'intercept', label: 'Interception', icon: 'route' },
  { id: 'vpn', label: 'VPN', icon: 'key' },
  { id: 'assistant', label: 'Assistant', icon: 'chat', group: 'Operate' },
  { id: 'problems', label: 'Problems', icon: 'alert', group: 'Operate' },
  { id: 'events', label: 'Events', icon: 'bell' },
  { id: 'alerts', label: 'Alerts', icon: 'alert' },
  { id: 'reports', label: 'Reports', icon: 'grid' },
  { id: 'settings', label: 'Settings', icon: 'gear' },
]

/** The simple interface: seven plain words, one screen each. */
const SIMPLE_ROUTES: Array<{ id: Route; label: string; icon: keyof typeof Icons; group?: string }> = [
  { id: 's-home', label: 'Home', icon: 'grid' },
  { id: 's-devices', label: 'Devices', icon: 'devices' },
  { id: 's-protection', label: 'Protection', icon: 'shield' },
  { id: 's-usage', label: 'Usage', icon: 'tv' },
  { id: 'assistant', label: 'Ask', icon: 'chat' },
  { id: 's-alerts', label: 'Alerts', icon: 'bell' },
  { id: 's-settings', label: 'Settings', icon: 'gear' },
]
const ALL_ROUTES = [...ROUTES, ...SIMPLE_ROUTES]

function routeFromHash(): Route {
  const raw = location.hash.replace(/^#\/?/, '').split('/')[0]
  return (ALL_ROUTES.find((r) => r.id === raw)?.id ?? 'dashboard') as Route
}

export default function App() {
  const [authed, setAuthed] = useState<boolean | null>(null)
  const [setupRequired, setSetupRequired] = useState(false)

  const checkAuth = useCallback(async () => {
    try {
      const st = await api.auth.status()
      setAuthed(st.authenticated)
      setSetupRequired(st.setup_required)
    } catch {
      setAuthed(false)
    }
  }, [])

  useEffect(() => {
    setUnauthorizedHandler(() => setAuthed(false))
    checkAuth()
  }, [checkAuth])

  if (authed === null) {
    return <div className="login"><Spinner /></div>
  }
  if (!authed) {
    return (
      <ToastProvider>
        <Login onSuccess={checkAuth} />
      </ToastProvider>
    )
  }
  return (
    <ToastProvider>
      <Gate setupRequired={setupRequired} onAuthChange={checkAuth} />
    </ToastProvider>
  )
}

/** Gate shows the first-run wizard until it has been completed or skipped.
 *  It sits inside ToastProvider because the wizard reports failures that way. */
function Gate({ setupRequired, onAuthChange }: { setupRequired: boolean; onAuthChange: () => void }) {
  const [onboarded, setOnboarded] = useState<boolean | null>(null)

  const check = useCallback(async () => {
    try {
      const s = await api.onboarding.get()
      setOnboarded(s.onboarded)
    } catch {
      // A node whose onboarding endpoint is unavailable should still be usable;
      // failing open here beats locking the operator out of their own UI.
      setOnboarded(true)
    }
  }, [])

  useEffect(() => { check() }, [check])

  if (onboarded === null) return <div className="login"><Spinner /></div>
  if (!onboarded) return <Onboarding onDone={() => setOnboarded(true)} />
  return <Shell setupRequired={setupRequired} onAuthChange={onAuthChange} />
}

function Shell({ setupRequired, onAuthChange }: { setupRequired: boolean; onAuthChange: () => void }) {
  const [route, setRoute] = useState<Route>(routeFromHash)

  useEffect(() => {
    const onHash = () => setRoute(routeFromHash())
    window.addEventListener('hashchange', onHash)
    return () => window.removeEventListener('hashchange', onHash)
  }, [])

  const navigate = useCallback((r: Route) => {
    location.hash = `#/${r}`
    setRoute(r)
  }, [])

  const { data: status } = usePoll<SystemStatus>(() => api.status(), 10000)
  const { data: summary } = usePoll<Summary>(() => api.summary(24), 15000)
  const toast = useToast()

  // Simple or advanced. The browser's own choice wins; otherwise the node's
  // default; otherwise what was picked during onboarding.
  const { data: config, refresh: refreshConfig } = usePoll<AppConfig>(() => api.config.get(), 0)
  const [uiPref, setUIPref] = useLocalStorage<'simple' | 'advanced' | ''>('orbis.ui', '')
  const ui: 'simple' | 'advanced' = uiPref || (
    config?.node.ui_mode === 'simple' || (!config?.node.ui_mode && config?.node.onboarded_mode === 'simple') ? 'simple' : 'advanced')
  const saveConfig = useCallback(async (patch: Record<string, unknown>) => {
    try {
      await api.config.patch(patch)
      refreshConfig()
      return true
    } catch (e) {
      toast(e instanceof Error ? e.message : 'Could not save that setting', 'err')
      return false
    }
  }, [refreshConfig, toast])
  const [pendingQuestion, setPendingQuestion] = useState<string | null>(null)

  // One socket for the whole app; pages subscribe to the shared feed rather
  // than each opening their own.
  const [liveEvents, setLiveEvents] = useState<LiveEvent[]>([])
  const onEvent = useCallback((ev: LiveEvent) => {
    setLiveEvents((prev) => {
      const next = [...prev, ev]
      // A bounded ring: the pages that need history keep their own copy.
      return next.length > 600 ? next.slice(-400) : next
    })
  }, [])
  const connected = useLive(onEvent)

  const mode = status?.mode ?? 'observe'
  const alerts = summary?.open_alerts ?? 0

  // The daemon's build changes underneath a long-lived tab after a deploy;
  // the JavaScript and CSS this tab loaded do not. Remember the first version
  // seen and offer a reload when it moves, rather than letting stale styles
  // and API shapes masquerade as bugs.
  const loadedVersion = useRef<string | null>(null)
  const [updated, setUpdated] = useState<string | null>(null)
  useEffect(() => {
    const v = status?.version
    if (!v) return
    if (loadedVersion.current === null) loadedVersion.current = v
    else if (v !== loadedVersion.current) setUpdated(v)
  }, [status?.version])
  const candidates = summary?.ad_candidates ?? 0

  const navRoutes = ui === 'simple' ? SIMPLE_ROUTES : ROUTES
  const grouped = useMemo(() => {
    const out: Array<{ group?: string; items: typeof ROUTES }> = []
    let current: { group?: string; items: typeof ROUTES } | null = null
    for (const r of navRoutes) {
      if (r.group || !current) {
        current = { group: r.group, items: [] }
        out.push(current)
      }
      current.items.push(r)
    }
    return out
  }, [navRoutes])

  // The hash default is the advanced overview; in simple mode that means Home.
  const shown: Route = ui === 'simple' && route === 'dashboard' ? 's-home' : route
  const title = ALL_ROUTES.find((r) => r.id === shown)?.label ?? 'Orbis'
  const go = (r: string) => navigate(r as Route)
  const onAsk = (q: string) => { setPendingQuestion(q); navigate('assistant') }

  return (
    <div className={`shell${ui === 'simple' ? ' simple' : ''}`}>
      <CommandPalette pages={ROUTES} onNavigate={(r) => navigate(r as Route)} />
      <nav className="nav">
        <div className="brand">
          <svg className="brand-mark" viewBox="0 0 32 32" fill="none" aria-hidden="true">
            <circle cx="16" cy="16" r="11" stroke="var(--accent)" strokeWidth="1.8" />
            <ellipse cx="16" cy="16" rx="11" ry="4.4" stroke="var(--accent)" strokeWidth="1.2" opacity=".55" />
            <ellipse cx="16" cy="16" rx="4.4" ry="11" stroke="var(--accent)" strokeWidth="1.2" opacity=".35" />
            <circle cx="16" cy="16" r="2.6" fill="var(--accent)" />
          </svg>
          <div>
            <div className="brand-name">Orbis</div>
            <span className={`brand-mode ${mode}`}>{mode}</span>
          </div>
        </div>

        {grouped.map((g, gi) => (
          <div key={gi}>
            {g.group && <div className="nav-group">{g.group}</div>}
            {g.items.map((r) => {
              const Icon = Icons[r.icon]
              const badge =
                r.id === 'events' && alerts > 0 ? <span className="nav-badge alert">{alerts}</span>
                : r.id === 'adblock' && candidates > 0 ? <span className="nav-badge live">{candidates}</span>
                : null
              return (
                <button key={r.id} className="nav-item" onClick={() => navigate(r.id)}
                  aria-current={shown === r.id ? 'page' : undefined}>
                  <Icon />
                  <span>{r.label}</span>
                  {badge}
                </button>
              )
            })}
          </div>
        ))}

        <div className="nav-foot">
          <div>{connected ? '● live' : '○ reconnecting'}</div>
          <div>{summary ? `${summary.clients_online}/${summary.clients} online` : '—'}</div>
          <div>{summary ? `${summary.active_flows} flows` : '—'}</div>
        </div>
      </nav>

      <main className="main">
        <header className="topbar">
          <h1>{title}</h1>
          <div className="spacer" />
          <Segmented value={ui} onChange={(v) => setUIPref(v)}
            options={[{ value: 'simple', label: 'Simple' }, { value: 'advanced', label: 'Advanced' }]} />
          {mode === 'observe' && (
            <span className="tag info" title="Nothing is routed through this node yet">
              observe mode
            </span>
          )}
          <span className="tag" title="Live event stream">
            <span className={`dot ${connected ? 'on' : 'off'}`} /> {connected ? 'live' : 'offline'}
          </span>
        </header>

        <div className={`page${shown === 'globe' || shown === 'assistant' ? ' flush' : ''}`}>
          {updated && (
            <div style={{ padding: route === 'globe' || route === 'assistant' ? 18 : 0 }}>
              <Banner tone="info" action={
                <button className="btn sm primary" onClick={() => location.reload()}>Reload</button>
              }>
                Orbis was updated to {updated} while this page was open. Reload to pick up the new interface.
              </Banner>
            </div>
          )}
          {setupRequired && route !== 'settings' && (
            <div style={{ padding: route === 'globe' || route === 'assistant' ? 18 : 0 }}>
              <Banner tone="warn" action={
                <button className="btn sm" onClick={() => navigate('settings')}>Set a password</button>
              }>
                No admin password is set, so this interface is reachable by anyone who can
                reach the node. Set one before putting Orbis on a shared network.
              </Banner>
            </div>
          )}

          <ErrorBoundary name={title} key={shown}>
          {shown === 'dashboard' && <Dashboard status={status} summary={summary} events={liveEvents} onNavigate={navigate} />}
          {route === 'globe' && <GlobePage events={liveEvents} />}
          {route === 'flows' && <FlowsPage events={liveEvents} />}
          {route === 'analytics' && <AnalyticsPage />}
          {route === 'clients' && <ClientsPage />}
          {route === 'topology' && <TopologyPage events={liveEvents} />}
          {route === 'dns' && <DNSPage events={liveEvents} />}
          {route === 'adblock' && <AdBlockPage />}
          {route === 'dnstools' && <DNSToolsPage />}
          {route === 'youtube' && <YouTubePage />}
          {route === 'consent' && <ConsentPage />}
          {route === 'gateway' && <GatewayPage />}
          {route === 'intercept' && <InterceptPage />}
          {route === 'firewall' && <FirewallPage status={status} />}
          {route === 'network' && <NetworkPage status={status} />}
          {route === 'vpn' && <VPNPage />}
          {route === 'assistant' && <AssistantPage initialQuestion={pendingQuestion ?? undefined} onConsumed={() => setPendingQuestion(null)} />}
          {route === 'profiles' && <ProfilesPage />}
          {shown === 's-home' && <SimpleHome onNavigate={go} onAsk={onAsk} />}
          {shown === 's-devices' && <SimpleDevices onNavigate={go} />}
          {shown === 's-protection' && (config ? <SimpleProtection config={config} save={saveConfig} onNavigate={go} /> : <Spinner />)}
          {shown === 's-usage' && (
            <div style={{ display: 'grid', gap: 14 }}>
              <div className="hint" style={{ fontSize: 13.5, lineHeight: 1.6, maxWidth: 760 }}>
                What is using the internet, by app and by device. Devices marked "DNS only" are seen but not measured;
                press Intercept on one to measure it.
              </div>
              <ServicesPage onNavigate={(r) => navigate(r)} />
            </div>
          )}
          {shown === 's-alerts' && <SimpleAlerts onNavigate={go} />}
          {shown === 's-settings' && (config ? <SimpleSettings config={config} status={status} save={saveConfig} uiMode={ui} setUIMode={(m) => setUIPref(m)} onNavigate={go} /> : <Spinner />)}
          {route === 'problems' && <ProblemsPage />}
          {route === 'services' && <ServicesPage onNavigate={(r) => setRoute(r)} />}
          {route === 'events' && <EventsPage />}
          {route === 'alerts' && <AlertsPage />}
          {route === 'reports' && <ReportsPage />}
          {route === 'settings' && <SettingsPage status={status} onAuthChange={onAuthChange} />}
          </ErrorBoundary>
        </div>
      </main>
    </div>
  )
}
