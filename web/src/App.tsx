import { useCallback, useEffect, useState, useRef, lazy, Suspense } from 'react'
import { flushSync } from 'react-dom'
import { api, setUnauthorizedHandler } from './api'
import { usePoll, useLocalStorage, useMediaQuery, ViewVisible } from './hooks'
import { useLiveConnected } from './live'
import { Icons, ToastProvider, Banner, Spinner, Segmented, useToast, Loading } from './ui'
import { transition, useThumb } from './motion'
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

type NavRoute = { id: Route; label: string; icon: keyof typeof Icons; short?: string }
/** A section of the product: one place in the rail, its pages as tabs. Every
 *  page keeps its own address, so old links and the palette still land. */
type Hub = { id: string; label: string; short?: string; icon: keyof typeof Icons; routes: NavRoute[] }
const HUBS: Hub[] = [
  { id: 'overview', label: 'Overview', short: 'Home', icon: 'orbit', routes: [{ id: 'dashboard', label: 'Overview', icon: 'orbit' }] },
  { id: 'traffic', label: 'Traffic', icon: 'activity', routes: [
    { id: 'flows', label: 'Connections', icon: 'activity' },
    { id: 'globe', label: 'Globe', icon: 'globe' },
    { id: 'services', label: 'Services', icon: 'stack' },
    { id: 'analytics', label: 'Analytics', icon: 'chart' },
    { id: 'topology', label: 'Topology', icon: 'nodes' },
    { id: 'health', label: 'Internet health', icon: 'pulse' },
  ] },
  { id: 'devices', label: 'Devices', icon: 'devices', routes: [
    { id: 'clients', label: 'All devices', icon: 'devices' },
    { id: 'profiles', label: 'Profiles', icon: 'user' },
    { id: 'consent', label: 'Ask first', icon: 'question' },
  ] },
  { id: 'protection', label: 'Protection', short: 'Protect', icon: 'shield', routes: [
    { id: 'dns', label: 'DNS', icon: 'dns' },
    { id: 'adblock', label: 'Ad blocking', icon: 'block' },
    { id: 'firewall', label: 'Firewall', icon: 'shield' },
    { id: 'threats', label: 'Threats', icon: 'target' },
    { id: 'youtube', label: 'YouTube', icon: 'tv' },
    { id: 'dnstools', label: 'Domain tester', icon: 'search' },
  ] },
  { id: 'network', label: 'Network', icon: 'route', routes: [
    { id: 'links', label: 'Cables & Wi-Fi', icon: 'cable' },
    { id: 'network', label: 'DHCP & LAN', icon: 'route' },
    { id: 'gateway', label: 'Gateway', icon: 'door' },
    { id: 'vpn', label: 'VPN', icon: 'key' },
    { id: 'intercept', label: 'Interception', icon: 'split' },
    { id: 'hosted', label: 'Hosted apps', icon: 'server' },
  ] },
  { id: 'system', label: 'System', icon: 'gear', routes: [
    { id: 'problems', label: 'Problems', icon: 'alert' },
    { id: 'events', label: 'Events', icon: 'bell' },
    { id: 'alerts', label: 'Alerts', icon: 'flag' },
    { id: 'reports', label: 'Reports', icon: 'doc' },
    { id: 'changes', label: 'Change timeline', icon: 'history' },
    { id: 'settings', label: 'Settings', icon: 'gear' },
  ] },
]
const ASSISTANT: NavRoute = { id: 'assistant', label: 'Ask Orbis', icon: 'chat' }
const ROUTES: NavRoute[] = [...HUBS.flatMap((h) => h.routes), ASSISTANT]

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
const SIMPLE_HUBS: Hub[] = SIMPLE_ROUTES.map((r) => ({ ...r, routes: [r] }))
const ALL_ROUTES = [...ROUTES, ...SIMPLE_ROUTES]

/** Where a page sits, which decides the direction a move between pages takes. */
function placeOf(r: Route) {
  for (const hubs of [HUBS, SIMPLE_HUBS]) {
    const hub = hubs.findIndex((h) => h.routes.some((x) => x.id === r))
    if (hub >= 0) return { hub, tab: hubs[hub].routes.findIndex((x) => x.id === r) }
  }
  return { hub: HUBS.length, tab: 0 }
}

/** The code behind each page, so it can be fetched before it is asked for. The
 *  globe is left out: three.js is the one heavy download. */
const PAGE_CODE: Partial<Record<Route, () => Promise<unknown>>> = {
  flows: () => import('./pages/Flows'), services: () => import('./pages/Services'), analytics: () => import('./pages/Analytics'),
  topology: () => import('./pages/Topology'), health: () => import('./pages/InternetHealth'), clients: () => import('./pages/Clients'),
  profiles: () => import('./pages/Profiles'), consent: () => import('./pages/Consent'), dns: () => import('./pages/DNS'),
  adblock: () => import('./pages/AdBlock'), firewall: () => import('./pages/Firewall'), threats: () => import('./pages/Threats'),
  youtube: () => import('./pages/YouTube'), dnstools: () => import('./pages/DNSTools'), links: () => import('./pages/Links'),
  network: () => import('./pages/Network'), gateway: () => import('./pages/Gateway'), vpn: () => import('./pages/VPN'),
  intercept: () => import('./pages/Intercept'), hosted: () => import('./pages/Hosted'), problems: () => import('./pages/Problems'),
  events: () => import('./pages/Events'), alerts: () => import('./pages/Alerts'), reports: () => import('./pages/Reports'),
  changes: () => import('./pages/ChangeTimeline'), settings: () => import('./pages/Settings'), assistant: () => import('./pages/Assistant'),
}
/** How many visited pages stay mounted, hidden and paused, so going back is
 *  instant and keeps filters and scroll position. */
const KEPT_PAGES = 8

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
  const routeRef = useRef(route)
  routeRef.current = route
  const pageRef = useRef<HTMLDivElement>(null)
  const scrolled = useRef<Partial<Record<string, number>>>({})
  const [kept, setKept] = useState<Route[]>([])

  const show = useCallback((next: Route, apply: () => void) => {
    const was = routeRef.current
    if (next === was) { apply(); return }
    const from = placeOf(was), to = placeOf(next)
    const dx = from.hub === to.hub ? Math.sign(to.tab - from.tab) : 0
    const dy = from.hub === to.hub ? 0 : Math.sign(to.hub - from.hub)
    if (pageRef.current) scrolled.current[was] = pageRef.current.scrollTop
    const go = () => transition(dx, dy, () => {
      flushSync(() => { apply(); setRoute(next) })
      pageRef.current?.scrollTo(0, scrolled.current[next] ?? 0)
    })
    // Wait for the page's code, briefly, so the move lands on the page and not
    // on its placeholder.
    Promise.race([PAGE_CODE[next]?.(), new Promise((r) => setTimeout(r, 160))]).then(go, go)
  }, [])

  useEffect(() => {
    const onHash = () => show(routeFromHash(), () => undefined)
    window.addEventListener('hashchange', onHash)
    return () => window.removeEventListener('hashchange', onHash)
  }, [show])

  // sub is a deep link inside the page (a device id, a settings section);
  // pages read it from the hash when they mount, so a kept page starts afresh.
  // Without one the hash is reset to the page root, so a sidebar click always
  // leaves a deep link.
  const navigate = useCallback((r: Route, sub?: string) => {
    if (sub) setKept((list) => list.filter((x) => x !== r))
    show(r, () => { location.hash = sub ? `#/${r}/${encodeURIComponent(sub)}` : `#/${r}` })
  }, [show])

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
  // The hash default is the advanced overview; in simple mode that means Home.
  const shown: Route = ui === 'simple' && route === 'dashboard' ? 's-home' : route
  const hubs = ui === 'simple' ? SIMPLE_HUBS : HUBS
  const hub = hubs.find((h) => h.routes.some((r) => r.id === shown))
  const title = hub?.label ?? ALL_ROUTES.find((r) => r.id === shown)?.label ?? 'Orbis'
  const go = (r: string) => navigate(r as Route)
  const onAsk = (q: string) => { setPendingQuestion(q); navigate('assistant') }
  const tabs = ui === 'simple' || narrow

  useEffect(() => {
    if (shown !== 'globe') setKept((list) => [shown, ...list.filter((r) => r !== shown)].slice(0, KEPT_PAGES))
  }, [shown])

  // A section remembers which of its pages you were on.
  const lastTab = useRef<Record<string, Route>>({})
  if (hub) lastTab.current[hub.id] = shown
  const openHub = useCallback((h: Hub) => { navigate(lastTab.current[h.id] ?? h.routes[0].id) }, [navigate])

  // Fetch every page's code once the node has finished the first screen.
  useEffect(() => {
    const idle = window.requestIdleCallback ?? ((cb: () => void) => window.setTimeout(cb, 1200))
    idle(() => { for (const load of Object.values(PAGE_CODE)) void load() })
  }, [])

  // 1 to 6 change section, [ and ] change tab, / goes to the page's search.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const el = e.target as HTMLElement
      if (e.metaKey || e.ctrlKey || e.altKey || el.closest('input, textarea, select, [contenteditable]')) return
      const pages = hub?.routes ?? []
      const at = pages.findIndex((r) => r.id === shown)
      if (/^[1-7]$/.test(e.key) && hubs[Number(e.key) - 1]) openHub(hubs[Number(e.key) - 1])
      else if (e.key === ']' && pages[at + 1]) navigate(pages[at + 1].id)
      else if (e.key === '[' && pages[at - 1]) navigate(pages[at - 1].id)
      else if (e.key === '/') {
        const search = document.querySelector<HTMLInputElement>('.view:not([hidden]) .search input')
        if (search) { e.preventDefault(); search.focus() }
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [hub, hubs, shown, navigate, openHub])

  const railThumb = useThumb<HTMLDivElement>(`${hub?.id}|${narrow}|${ui}`)
  const tabThumb = useThumb<HTMLDivElement>(shown)

  const page = (r: Route) => {
    switch (r) {
      case 'dashboard': return <Dashboard status={status} summary={summary} onNavigate={navigate} />
      case 'globe': return <GlobePage />
      case 'flows': return <FlowsPage />
      case 'analytics': return <AnalyticsPage />
      case 'clients': return <ClientsPage />
      case 'health': return <InternetHealthPage />
      case 'topology': return <TopologyPage />
      case 'dns': return <DNSPage />
      case 'adblock': return <AdBlockPage />
      case 'dnstools': return <DNSToolsPage />
      case 'youtube': return <YouTubePage />
      case 'consent': return <ConsentPage />
      case 'gateway': return <GatewayPage />
      case 'intercept': return <InterceptPage />
      case 'firewall': return <FirewallPage status={status} />
      case 'network': return <NetworkPage status={status} />
      case 'vpn': return <VPNPage />
      case 'assistant': return <AssistantPage initialQuestion={pendingQuestion ?? undefined} onConsumed={() => setPendingQuestion(null)} />
      case 'profiles': return <ProfilesPage />
      case 's-home': return <SimpleHome onNavigate={go} onAsk={onAsk} />
      case 's-devices': return <SimpleDevices onNavigate={go} />
      case 's-protection': return config ? <SimpleProtection config={config} save={saveConfig} onNavigate={go} /> : <Loading what="protection" />
      case 's-usage': return (
        <div style={{ display: 'grid', gap: 14 }}>
          <div className="hint" style={{ fontSize: 13.5, lineHeight: 1.6, maxWidth: 760 }}>
            What is using the internet, by app and by device. Devices marked "DNS only" are seen but not measured;
            press Intercept on one to measure it.
          </div>
          <ServicesPage onNavigate={(x) => navigate(x)} />
        </div>
      )
      case 's-alerts': return <SimpleAlerts onNavigate={go} />
      case 's-settings': return config ? <SimpleSettings config={config} status={status} save={saveConfig} uiMode={ui} setUIMode={(m) => setUIPref(m)} onNavigate={go} /> : <Loading what="settings" />
      case 'problems': return <ProblemsPage />
      case 'threats': return <ThreatsPage />
      case 'hosted': return <HostedPage />
      case 'links': return <LinksPage />
      case 'services': return <ServicesPage onNavigate={(x) => navigate(x)} />
      case 'events': return <EventsPage />
      case 'alerts': return <AlertsPage />
      case 'reports': return <ReportsPage />
      case 'changes': return <ChangeTimelinePage />
      case 'settings': return <SettingsPage status={status} onAuthChange={onAuthChange} />
      default: return null
    }
  }

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

        <div className="nav-section" ref={railThumb}>
          <span className="thumb" aria-hidden="true" />
          {hubs.map((h, i) => {
            const Icon = Icons[h.icon]
            const badge =
              h.id === 'system' && alerts > 0 ? <span className="nav-badge alert">{alerts}</span>
              : h.id === 'protection' && candidates > 0 ? <span className="nav-badge live">{candidates}</span>
              : null
            return (
              <button key={h.id} className="nav-item" onClick={() => openHub(h)} title={`${h.label} (${i + 1})`}
                onPointerEnter={() => { for (const r of h.routes) void PAGE_CODE[r.id]?.() }}
                aria-current={hub?.id === h.id ? 'page' : undefined}>
                <Icon />
                <span>{narrow && h.short ? h.short : h.label}</span>
                {badge}
              </button>
            )
          })}
        </div>

        {ui === 'advanced' && !narrow && (
          <button className="nav-item nav-ask" onClick={() => navigate('assistant')}
            aria-current={shown === 'assistant' ? 'page' : undefined}>
            <Icons.chat />
            <span>Ask Orbis</span>
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
          {hub && hub.routes.length > 1 && (
            <div className="subnav" role="navigation" aria-label={`${hub.label} pages`} ref={tabThumb}>
              <span className="thumb" aria-hidden="true" />
              {hub.routes.map((r) => (
                <button key={r.id} onClick={() => navigate(r.id)}
                  onPointerEnter={() => void PAGE_CODE[r.id]?.()}
                  aria-current={shown === r.id ? 'page' : undefined}>{r.label}</button>
              ))}
            </div>
          )}
          <div className="spacer" />
          <button className="search-pill" title="Search pages, devices and settings" aria-label="Search"
            onClick={() => window.dispatchEvent(new Event('orbis:palette'))}>
            <Icons.search size={14} /><span>Search</span><kbd>⌘K</kbd>
          </button>
          <Segmented value={ui} onChange={(v) => setUIPref(v)}
            options={[{ value: 'simple', label: 'Simple' }, { value: 'advanced', label: 'Advanced' }]} />
          <GlossaryButton />
        </header>

        <div ref={pageRef} className={`page${shown === 'globe' || shown === 'assistant' ? ' flush' : ''}`}>
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

          {(kept.includes(shown) ? kept : [shown, ...kept]).map((r) => (
            <div key={r} className="view" hidden={r !== shown}>
              <ViewVisible.Provider value={r === shown}>
                <ErrorBoundary name={ALL_ROUTES.find((x) => x.id === r)?.label ?? title}>
                  <Suspense fallback={<Loading what="this page" />}>{page(r)}</Suspense>
                </ErrorBoundary>
              </ViewVisible.Provider>
            </div>
          ))}
        </div>
      </main>
    </div>
  )
}
