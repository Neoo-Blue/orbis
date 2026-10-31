import { useCallback, useEffect, useMemo, useState, useRef, lazy, Suspense } from 'react'
import { api, setUnauthorizedHandler } from './api'
import { usePoll, useLocalStorage, useMediaQuery } from './hooks'
import { useLiveConnected } from './live'
import { Icons, ToastProvider, Banner, Spinner, Segmented, useToast, Drawer } from './ui'
import type { AppConfig, SystemStatus, Summary } from './types'
import { Dashboard } from './pages/Dashboard'
import { UpdateBanner } from './pages/UpdateCard'
import { SimpleHome } from './simple/Home'
import { SimpleDevices } from './simple/Devices'
import { SimpleProtection } from './simple/Protection'
import { SimpleAlerts } from './simple/Alerts'
import { SimpleSettings } from './simple/SettingsSimple'
import { Login } from './pages/Login'
import { Onboarding } from './pages/Onboarding'
import { ErrorBoundary } from './ErrorBoundary'
import { CommandPalette } from './CommandPalette'
import { GlossaryButton } from './Glossary'

const GlobePage = lazy(() => import('./pages/GlobePage').then(m => ({ default: m.GlobePage })))
const AnalyticsPage = lazy(() => import('./pages/Analytics').then(m => ({ default: m.AnalyticsPage })))
const AlertsPage = lazy(() => import('./pages/Alerts').then(m => ({ default: m.AlertsPage })))
const ReportsPage = lazy(() => import('./pages/Reports').then(m => ({ default: m.ReportsPage })))
const ClientsPage = lazy(() => import('./pages/Clients').then(m => ({ default: m.ClientsPage })))
const FlowsPage = lazy(() => import('./pages/Flows').then(m => ({ default: m.FlowsPage })))
const DNSPage = lazy(() => import('./pages/DNS').then(m => ({ default: m.DNSPage })))
const AdBlockPage = lazy(() => import('./pages/AdBlock').then(m => ({ default: m.AdBlockPage })))
const YouTubePage = lazy(() => import('./pages/YouTube').then(m => ({ default: m.YouTubePage })))
const DNSToolsPage = lazy(() => import('./pages/DNSTools').then(m => ({ default: m.DNSToolsPage })))
const TopologyPage = lazy(() => import('./pages/Topology').then(m => ({ default: m.TopologyPage })))
const InterceptPage = lazy(() => import('./pages/Intercept').then(m => ({ default: m.InterceptPage })))
const GatewayPage = lazy(() => import('./pages/Gateway').then(m => ({ default: m.GatewayPage })))
const ConsentPage = lazy(() => import('./pages/Consent').then(m => ({ default: m.ConsentPage })))
const FirewallPage = lazy(() => import('./pages/Firewall').then(m => ({ default: m.FirewallPage })))
const NetworkPage = lazy(() => import('./pages/Network').then(m => ({ default: m.NetworkPage })))
const VPNPage = lazy(() => import('./pages/VPN').then(m => ({ default: m.VPNPage })))
const AssistantPage = lazy(() => import('./pages/Assistant').then(m => ({ default: m.AssistantPage })))
const ProblemsPage = lazy(() => import('./pages/Problems').then(m => ({ default: m.ProblemsPage })))
const ThreatsPage = lazy(() => import('./pages/Threats').then(m => ({ default: m.ThreatsPage })))
const HostedPage = lazy(() => import('./pages/Hosted').then(m => ({ default: m.HostedPage })))
const LinksPage = lazy(() => import('./pages/Links').then(m => ({ default: m.LinksPage })))
const ServicesPage = lazy(() => import('./pages/Services').then(m => ({ default: m.ServicesPage })))
const ProfilesPage = lazy(() => import('./pages/Profiles').then(m => ({ default: m.ProfilesPage })))
const EventsPage = lazy(() => import('./pages/Events').then(m => ({ default: m.EventsPage })))
const InternetHealthPage = lazy(() => import('./pages/InternetHealth').then(m => ({ default: m.InternetHealthPage })))
const ChangeTimelinePage = lazy(() => import('./pages/ChangeTimeline').then(m => ({ default: m.ChangeTimelinePage })))
const SettingsPage = lazy(() => import('./pages/Settings').then(m => ({ default: m.SettingsPage })))

type Route =
  | 'dashboard' | 'globe' | 'clients' | 'flows' | 'dns' | 'adblock'
  | 'firewall' | 'network' | 'vpn' | 'assistant' | 'events' | 'settings' | 'youtube' | 'gateway' | 'consent' | 'dnstools' | 'topology' | 'intercept' | 'analytics' | 'alerts' | 'reports' | 'problems' | 'services' | 'threats' | 'hosted' | 'links'
  | 'profiles' | 'health' | 'changes' | 's-home' | 's-devices' | 's-protection' | 's-usage' | 's-alerts' | 's-settings'

type NavRoute = { id: Route; label: string; icon: keyof typeof Icons; group?: string; short?: string }
const ROUTES: NavRoute[] = [
  { id: 'dashboard', label: 'Overview', icon: 'orbit', group: 'Observe' },
  { id: 'globe', label: 'Globe', icon: 'globe' },
  { id: 'flows', label: 'Connections', icon: 'activity' },
  { id: 'services', label: 'Services', icon: 'stack' },
  { id: 'analytics', label: 'Analytics', icon: 'chart' },
  { id: 'clients', label: 'Devices', icon: 'devices' },
  { id: 'topology', label: 'Topology', icon: 'nodes' },
  { id: 'health', label: 'Internet health', icon: 'pulse' },
  { id: 'dns', label: 'DNS', icon: 'dns', group: 'Filtering' },
  { id: 'adblock', label: 'Ad blocking', icon: 'block' },
  { id: 'profiles', label: 'Profiles', icon: 'user' },
  { id: 'dnstools', label: 'Domain tester', icon: 'search' },
  { id: 'youtube', label: 'YouTube', icon: 'tv' },
  { id: 'consent', label: 'Ask first', icon: 'question' },
  { id: 'firewall', label: 'Firewall', icon: 'shield', group: 'Network' },
  { id: 'threats', label: 'Threats', icon: 'target' },
  { id: 'hosted', label: 'Hosted apps', icon: 'server' },
  { id: 'links', label: 'Cables & Wi-Fi', icon: 'cable' },
  { id: 'network', label: 'DHCP & LAN', icon: 'route' },
  { id: 'gateway', label: 'Gateway', icon: 'door' },
  { id: 'intercept', label: 'Interception', icon: 'split' },
  { id: 'vpn', label: 'VPN', icon: 'key' },
  { id: 'assistant', label: 'Assistant', icon: 'chat', group: 'Operate' },
  { id: 'problems', label: 'Problems', icon: 'alert', group: 'Operate' },
  { id: 'events', label: 'Events', icon: 'bell' },
  { id: 'alerts', label: 'Alerts', icon: 'flag' },
  { id: 'reports', label: 'Reports', icon: 'doc' },
  { id: 'changes', label: 'Change timeline', icon: 'history' },
  { id: 'settings', label: 'Settings', icon: 'gear' },
]

/** The simple interface: seven plain words, one screen each. */
const SIMPLE_ROUTES: NavRoute[] = [
  { id: 's-home', label: 'Home', icon: 'orbit' },
  { id: 's-devices', label: 'Devices', icon: 'devices' },
  { id: 's-protection', label: 'Protection', icon: 'shield', short: 'Protect' },
  { id: 's-usage', label: 'Usage', icon: 'chart' },
  { id: 'assistant', label: 'Ask', icon: 'chat' },
  { id: 's-alerts', label: 'Alerts', icon: 'bell' },
  { id: 's-settings', label: 'Settings', icon: 'gear' },
]
const ALL_ROUTES = [...ROUTES, ...SIMPLE_ROUTES]
/** On a phone the advanced interface shows these four and a "More" sheet. */
const MOBILE_PRIMARY: Route[] = ['dashboard', 'flows', 'clients', 'assistant']

function routeFromHash(): Route {
  const raw = location.hash.replace(/^#\/?/, '').split('/')[0]
  return (ALL_ROUTES.find((r) => r.id === raw)?.id ?? 'dashboard') as Route
}

export default function App() {
  const [authed, setAuthed] = useState<boolean | null>(null)
  const [setupRequired, setSetupRequired] = useState(false)
  const [onboarded, setOnboarded] = useState(true)
  const [nodeUI, setNodeUI] = useState('')

  const checkAuth = useCallback(async () => {
    try {
      const st = await api.auth.status()
      setAuthed(st.authenticated)
      setSetupRequired(st.setup_required)
      setOnboarded(st.onboarded)
      setNodeUI(st.ui_mode)
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
      {onboarded
        ? <Shell setupRequired={setupRequired} onAuthChange={checkAuth} nodeUI={nodeUI} />
        : <Onboarding onDone={() => setOnboarded(true)} />}
    </ToastProvider>
  )
}

function Shell({ setupRequired, onAuthChange, nodeUI }: { setupRequired: boolean; onAuthChange: () => void; nodeUI: string }) {
  const [route, setRoute] = useState<Route>(routeFromHash)

  useEffect(() => {
    const onHash = () => setRoute(routeFromHash())
    window.addEventListener('hashchange', onHash)
    return () => window.removeEventListener('hashchange', onHash)
  }, [])

  // sub is a deep link inside the page (a device id, a settings section);
  // pages read it from the hash. Without one the hash is reset to the page
  // root, so a sidebar click always leaves a deep link.
  const navigate = useCallback((r: Route, sub?: string) => {
    location.hash = sub ? `#/${r}/${encodeURIComponent(sub)}` : `#/${r}`
    setRoute(r)
  }, [])

  // Simple or advanced. The browser's own choice wins, otherwise the node's.
  const [uiPref, setUIPref] = useLocalStorage<'simple' | 'advanced' | ''>('orbis.ui', '')
  const ui: 'simple' | 'advanced' = uiPref || (nodeUI === 'simple' ? 'simple' : 'advanced')

  const { data: status } = usePoll<SystemStatus>(() => api.status(), 10000)
  const { data: summary } = usePoll<Summary>(() => api.summary(24), ui === 'simple' ? null : 15000, [ui])
  const toast = useToast()

  const { data: config, refresh: refreshConfig } = usePoll<AppConfig>(() => api.config.get(), 0)
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

  const connected = useLiveConnected()

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

  const narrow = useMediaQuery('(max-width: 880px)')
  const [moreOpen, setMoreOpen] = useState(false)
  // The sheet is a navigation aid, so any route change (a tap inside it, the
  // palette, a link in a page) closes it, as does growing past phone width.
  useEffect(() => { setMoreOpen(false) }, [route, narrow])
  const navRoutes = ui === 'simple' ? SIMPLE_ROUTES : narrow ? ROUTES.filter((r) => MOBILE_PRIMARY.includes(r.id)) : ROUTES
  const grouped = useMemo(() => {
    const out: Array<{ group: string; items: NavRoute[] }> = []
    for (const r of navRoutes) {
      const g = r.group ?? (out.length ? out[out.length - 1].group : '')
      let b = out.find((x) => x.group === g)
      if (!b) { b = { group: g, items: [] }; out.push(b) }
      b.items.push(r)
    }
    return out
  }, [navRoutes])

  // The hash default is the advanced overview; in simple mode that means Home.
  const shown: Route = ui === 'simple' && route === 'dashboard' ? 's-home' : route
  const title = ALL_ROUTES.find((r) => r.id === shown)?.label ?? 'Orbis'
  const go = (r: string) => navigate(r as Route)
  const onAsk = (q: string) => { setPendingQuestion(q); navigate('assistant') }

  const tabs = ui === 'simple' || narrow
  const inPrimary = ui === 'simple' || MOBILE_PRIMARY.includes(shown)

  return (
    <div className={`shell${ui === 'simple' ? ' simple' : ''}${tabs ? ' tabs' : ''}`}>
      <CommandPalette pages={ROUTES} onNavigate={navigate as (r: string, sub?: string) => void} />
      <nav className="nav">
        <div className="brand">
          <svg className="brand-mark" viewBox="0 0 32 32" fill="none" aria-hidden="true">
            <circle cx="16" cy="16" r="11" stroke="var(--brass)" strokeWidth="1.6" />
            <ellipse cx="16" cy="16" rx="11" ry="4.4" stroke="var(--brass)" strokeWidth="1.1" opacity=".6" />
            <circle cx="16" cy="16" r="2.6" fill="var(--brass)" />
          </svg>
          <div>
            <div className="brand-name">Orbis</div>
            <span className={`brand-mode ${mode}`} title={`${mode} mode`}>{mode}</span>
          </div>
        </div>

        {grouped.map((g, gi) => (
          <div key={gi} className="nav-section">
            {g.group && !(narrow && ui === 'advanced') && <div className="nav-group">{g.group}</div>}
            {g.items.map((r) => {
              const Icon = Icons[r.icon]
              const badge =
                r.id === 'events' && alerts > 0 ? <span className="nav-badge alert">{alerts}</span>
                : r.id === 'adblock' && candidates > 0 ? <span className="nav-badge live">{candidates}</span>
                : null
              return (
                <button key={r.id} className="nav-item" onClick={() => navigate(r.id)} title={r.label}
                  aria-current={shown === r.id ? 'page' : undefined}>
                  <Icon />
                  <span>{narrow && r.short ? r.short : r.label}</span>
                  {badge}
                </button>
              )
            })}
          </div>
        ))}
        {narrow && ui === 'advanced' && (
          <button className="nav-item" onClick={() => setMoreOpen(true)} title="All pages"
            aria-current={!inPrimary ? 'page' : undefined}>
            <Icons.grid />
            <span>More</span>
          </button>
        )}

        <div className="nav-foot">
          <div className="nav-foot-line"><span className={`dot ${connected ? 'on' : 'off'}`} />{connected ? 'Live' : 'Reconnecting'}</div>
          {summary && <div>{summary.clients_online} of {summary.clients} devices online</div>}
          {status && <div className="mono">{status.version}</div>}
        </div>
      </nav>

      <main className="main">
        <header className="topbar">
          <h1>{title}</h1>
          <div className="spacer" />
          {narrow && ui === 'advanced' && (
            <button className="btn sm" title="Search pages, devices and settings" aria-label="Search"
              onClick={() => window.dispatchEvent(new Event('orbis:palette'))}><Icons.search size={14} /></button>
          )}
          <Segmented value={ui} onChange={(v) => setUIPref(v)}
            options={[{ value: 'simple', label: 'Simple' }, { value: 'advanced', label: 'Advanced' }]} />
          <GlossaryButton />
          {mode === 'observe' && (
            <span className="tag info" title="Nothing is routed through this node yet">
              observe mode
            </span>
          )}
          <span className="tag" title="Live event stream">
            <span className={`dot ${connected ? 'on' : 'off'}`} /> {connected ? 'live' : 'offline'}
          </span>
        </header>

        {moreOpen && (
          <Drawer title="All pages" onClose={() => setMoreOpen(false)}>
            <div style={{ display: 'grid', gap: 14 }}>
              {(() => {
                const out: Array<{ group: string; items: NavRoute[] }> = []
                for (const r of ROUTES) {
                  const g = r.group ?? (out.length ? out[out.length - 1].group : 'Observe')
                  let b = out.find((x) => x.group === g)
                  if (!b) { b = { group: g, items: [] }; out.push(b) }
                  b.items.push(r)
                }
                return out
              })().map((g) => (
                <div key={g.group}>
                  <div className="nav-group" style={{ display: 'block', padding: '0 0 6px' }}>{g.group}</div>
                  <div className="more-grid" style={{ display: 'grid', gridTemplateColumns: 'repeat(2, minmax(0, 1fr))', gap: 6 }}>
                    {g.items.map((r) => {
                      const Icon = Icons[r.icon]
                      return (
                        <button key={r.id} className="nav-item"
                          aria-current={shown === r.id ? 'page' : undefined}
                          onClick={() => { setMoreOpen(false); navigate(r.id) }}>
                          <Icon /><span>{r.label}</span>
                        </button>
                      )
                    })}
                  </div>
                </div>
              ))}
            </div>
          </Drawer>
        )}
        <div className={`page${shown === 'globe' || shown === 'assistant' ? ' flush' : ''}`}>
          {updated && (
            <div className={route === 'globe' || route === 'assistant' ? 'flush-banner' : undefined}>
              <Banner tone="info" action={
                <button className="btn sm primary" onClick={() => location.reload()}>Reload</button>
              }>
                Orbis was updated to {updated} while this page was open. Reload to pick up the new interface.
              </Banner>
            </div>
          )}
          {!updated && route !== 'settings' && route !== 's-settings' && (
            <div className={route === 'globe' || route === 'assistant' ? 'flush-banner' : undefined}>
              <UpdateBanner onSettings={() => navigate('settings')} />
            </div>
          )}
          {setupRequired && route !== 'settings' && shown !== 'dashboard' && (
            <div className={route === 'globe' || route === 'assistant' ? 'flush-banner' : undefined}>
              <Banner tone="warn" action={
                <button className="btn sm" onClick={() => navigate('settings')}>Set a password</button>
              }>
                No admin password is set, so this interface is reachable by anyone who can
                reach the node. Set one before putting Orbis on a shared network.
              </Banner>
            </div>
          )}

          <ErrorBoundary name={title} key={shown}>
            <Suspense fallback={<Spinner />}>
              {shown === 'dashboard' && <Dashboard status={status} summary={summary} setupRequired={setupRequired} onNavigate={navigate} />}
              {route === 'globe' && <GlobePage />}
              {route === 'flows' && <FlowsPage />}
              {route === 'analytics' && <AnalyticsPage />}
              {route === 'clients' && <ClientsPage />}
              {route === 'health' && <InternetHealthPage />}
              {route === 'topology' && <TopologyPage />}
              {route === 'dns' && <DNSPage />}
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
              {route === 'threats' && <ThreatsPage />}
              {route === 'hosted' && <HostedPage />}
              {route === 'links' && <LinksPage />}
              {route === 'services' && <ServicesPage onNavigate={(r) => setRoute(r)} />}
              {route === 'events' && <EventsPage />}
              {route === 'alerts' && <AlertsPage />}
              {route === 'reports' && <ReportsPage />}
              {route === 'changes' && <ChangeTimelinePage />}
              {route === 'settings' && <SettingsPage status={status} onAuthChange={onAuthChange} />}
            </Suspense>
          </ErrorBoundary>
        </div>
      </main>
    </div>
  )
}
