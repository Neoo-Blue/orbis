import type {
  AdCandidate, AIBrief, AIModelsStatus, AINote, AppConfig, AuditEntry, BlockList, ChatTurn, Client, DNSQuery, DNSShortcut, Health, ServiceBundle,
  Issue, IssuesResponse, Recommendation, ServiceDetail, ServiceDevice, ServicePoint, ServicesResponse, ServiceTotal,
  EventItem, Flow, GlobeData, InterfaceInfo, Lease, LocalRule, Policy, Rule,
  Summary, SysctlStatus, SystemStatus, TailscaleStatus, WGPeer,
  YouTubeStatus, DiscoveredScreen, LoungeDevice,
  NotifyConfig, Webhook, StaticRoute, WANStatus, MultiWANConfig,
  ShapingConfig, ShapingStatus, PortMapping, PingResult, TracerouteHop,
  SpeedResult, ConsentStatus, ConsentRule, Diagnosis, ImportResult,
  OnboardingState, PlacementCheck, TopoGraph, InterceptStatus, DNSRecord,
  AlertRule, ReportData, BuiltinList,
} from './types'

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message)
    this.name = 'ApiError'
  }
}

let onUnauthorized: (() => void) | null = null
export function setUnauthorizedHandler(fn: () => void) {
  onUnauthorized = fn
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`/api${path}`, {
    credentials: 'same-origin',
    ...init,
    headers: {
      ...(init?.body ? { 'Content-Type': 'application/json' } : {}),
      ...init?.headers,
    },
  })
  if (res.status === 401) {
    onUnauthorized?.()
    throw new ApiError(401, 'not signed in')
  }
  const text = await res.text()
  let body: unknown = null
  if (text) {
    try {
      body = JSON.parse(text)
    } catch {
      body = text
    }
  }
  if (!res.ok) {
    const msg =
      body && typeof body === 'object' && 'error' in body
        ? String((body as { error: unknown }).error)
        : typeof body === 'string' && body
          ? body
          : `request failed (${res.status})`
    throw new ApiError(res.status, msg)
  }
  return body as T
}

const get = <T,>(path: string) => request<T>(path)
const post = <T,>(path: string, body?: unknown) =>
  request<T>(path, { method: 'POST', body: body === undefined ? undefined : JSON.stringify(body) })
const patch = <T,>(path: string, body: unknown) =>
  request<T>(path, { method: 'PATCH', body: JSON.stringify(body) })
const put = <T,>(path: string, body: unknown) =>
  request<T>(path, { method: 'PUT', body: JSON.stringify(body) })
const del = <T,>(path: string) => request<T>(path, { method: 'DELETE' })

/** qs builds a query string, dropping empty and default-ish values so URLs
 *  stay readable in the network tab. */
function qs(params: Record<string, string | number | boolean | undefined | null>): string {
  const parts: string[] = []
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === '' || v === false) continue
    parts.push(`${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`)
  }
  return parts.length ? `?${parts.join('&')}` : ''
}

export const api = {
  auth: {
    status: () => get<{ setup_required: boolean; authenticated: boolean }>('/auth/status'),
    login: (password: string) => post<{ token: string }>('/auth/login', { password }),
    logout: () => post<{ ok: boolean }>('/auth/logout'),
    setPassword: (current: string, password: string) =>
      post<{ token: string }>('/auth/password', { current, password }),
  },

  status: () => get<SystemStatus>('/status'),
  summary: (hours = 24) => get<Summary>(`/summary${qs({ hours })}`),
  series: (metric: string, hours = 6, points?: number) =>
    get<{ metric: string; points: Array<{ t: number; v: number; max?: number }> }>(`/series/${metric}${qs({ hours, points })}`),
  audit: (limit = 200) => get<{ entries: AuditEntry[] }>(`/audit${qs({ limit })}`),
  geoip: (ip: string) => get<{ ip: string; location: Record<string, unknown> }>(`/geoip/${ip}`),
  locateSelf: () =>
    post<{ self: Record<string, unknown>; home: { lat: number; lng: number } }>('/geoip/locate'),
  geoBackfill: () =>
    post<{ addresses_resolved: number; rows_updated: number; local_rows_cleared: number; unresolved: number }>(
      '/geoip/backfill',
    ),

  clients: {
    list: (opts: { online_only?: boolean; q?: string } = {}) =>
      get<{ count: number; clients: Client[] }>(`/clients${qs(opts)}`),
    get: (id: string) => get<Client>(`/clients/${id}`),
    update: (id: string, body: Partial<Pick<Client, 'label' | 'zone' | 'policy_id' | 'vpn_route' | 'notes' | 'blocked'>>) =>
      patch<{ ok: boolean }>(`/clients/${id}`, body),
    remove: (id: string) => del<{ ok: boolean }>(`/clients/${id}`),
    flows: (id: string, opts: { active?: boolean; hours?: number; limit?: number; q?: string; verdict?: string } = {}) =>
      get<{ count: number; flows: Flow[] }>(`/clients/${id}/flows${qs(opts)}`),
    destinations: (id: string, hours = 24, limit = 50) =>
      get<{ destinations: Array<Record<string, unknown>> }>(`/clients/${id}/destinations${qs({ hours, limit })}`),
    dns: (id: string, opts: { hours?: number; blocked_only?: boolean; limit?: number } = {}) =>
      get<{ count: number; queries: DNSQuery[] }>(`/clients/${id}/dns${qs(opts)}`),
  },

  flows: {
    list: (opts: Record<string, string | number | boolean | undefined> = {}) =>
      get<{ count: number; flows: Flow[] }>(`/flows${qs(opts)}`),
    active: (limit = 500) => get<{ count: number; flows: Flow[] }>(`/flows/active${qs({ limit })}`),
    globe: (opts: { mode?: string; hours?: number; limit?: number; client_id?: string } = {}) =>
      get<GlobeData>(`/flows/globe${qs(opts)}`),
    block: (id: string) => post<{ ok: boolean }>(`/flows/${id}/block`),
  },

  dns: {
    log: (opts: { hours?: number; client_id?: string; blocked_only?: boolean; q?: string; limit?: number } = {}) =>
      get<{ count: number; queries: DNSQuery[] }>(`/dns/log${qs(opts)}`),
    stats: () => get<Record<string, unknown>>('/dns/stats'),
    flush: (domain?: string) => post<{ flushed: number }>(`/dns/flush${qs({ domain })}`),
  },

  adblock: {
    status: () => get<Record<string, unknown>>('/adblock/status'),
    lists: () => get<{ lists: BlockList[]; builtin: BuiltinList[] }>('/adblock/lists'),
    addList: (list: { name: string; url: string; category: string; enabled: boolean }) =>
      post<{ ok: boolean }>('/adblock/lists', list),
    deleteList: (name: string) => del<{ ok: boolean }>(`/adblock/lists/${encodeURIComponent(name)}`),
    refresh: () => post<{ started: boolean }>('/adblock/refresh'),
    topBlocked: (hours = 24, limit = 25) =>
      get<{ domains: Array<{ domain: string; source: string; count: number }> }>(
        `/adblock/top-blocked${qs({ hours, limit })}`,
      ),
    rules: () => get<{ rules: LocalRule[] }>('/adblock/rules'),
    addRule: (body: { domain: string; action: 'block' | 'allow'; wildcard?: boolean; note?: string }) =>
      post<{ ok: boolean }>('/adblock/rules', body),
    deleteRule: (domain: string) => del<{ ok: boolean }>(`/adblock/rules/${encodeURIComponent(domain)}`),
    candidates: (opts: { status?: string; min_score?: number; limit?: number } = {}) =>
      get<{ count: number; candidates: AdCandidate[] }>(`/adblock/candidates${qs(opts)}`),
    decide: (domain: string, decision: 'block' | 'allow' | 'dismiss') =>
      post<{ ok: boolean }>(`/adblock/candidates/${encodeURIComponent(domain)}`, { decision }),
    scan: () => post<{ started: boolean }>('/adblock/scan'),
    check: (domain: string) =>
      get<{
        domain: string; blocked: boolean; allowed: boolean; source?: string
        matched_rule?: string; category?: string; explanation: string; candidate?: AdCandidate
      }>(`/adblock/check/${encodeURIComponent(domain)}`),
  },

  firewall: {
    rules: () => get<{ rules: Rule[] }>('/firewall/rules'),
    create: (rule: Partial<Rule>) => post<Rule>('/firewall/rules', rule),
    update: (id: string, rule: Partial<Rule>) => put<Rule>(`/firewall/rules/${id}`, rule),
    remove: (id: string) => del<{ ok: boolean }>(`/firewall/rules/${id}`),
    reorder: (chain: string, ids: string[]) => post<{ ok: boolean }>('/firewall/rules/reorder', { chain, ids }),
    preview: () => get<{ ruleset: string; status: Record<string, unknown> }>('/firewall/preview'),
    apply: () => post<Record<string, unknown>>('/firewall/apply'),
    flush: () => post<{ ok: boolean }>('/firewall/flush'),
    sysctl: () => get<{ sysctl: SysctlStatus[] }>('/firewall/sysctl'),
    applySysctl: () => post<{ sysctl: SysctlStatus[] }>('/firewall/sysctl'),
  },

  policies: {
    list: () => get<{ policies: Policy[] }>('/policies'),
    save: (p: Partial<Policy>) => (p.id ? put<Policy>(`/policies/${p.id}`, p) : post<Policy>('/policies', p)),
    remove: (id: string) => del<{ ok: boolean }>(`/policies/${id}`),
  },

  dhcp: {
    leases: () => get<{ count: number; leases: Lease[] }>('/dhcp/leases'),
    deleteLease: (mac: string) => del<{ ok: boolean }>(`/dhcp/leases/${encodeURIComponent(mac)}`),
    stats: () => get<Record<string, unknown>>('/dhcp/stats'),
  },

  vpn: {
    status: () => get<{ status: Record<string, unknown>; devices: Array<Record<string, unknown>> }>('/vpn/status'),
    peers: () => get<{ peers: WGPeer[] }>('/vpn/peers'),
    addPeer: (body: { name: string; allowed_ips?: string[]; note?: string }) =>
      post<{ peer: WGPeer; config: string }>('/vpn/peers', body),
    deletePeer: (id: string) => del<{ ok: boolean }>(`/vpn/peers/${id}`),
    peerConfig: (id: string) => get<{ config: string }>(`/vpn/peers/${id}/config`),
    peerConfigURL: (id: string) => `/api/vpn/peers/${id}/config?format=file`,
    peerQRURL: (id: string) => `/api/vpn/peers/${id}/qr`,
    serverAction: (action: 'start' | 'stop' | 'keys') => post<Record<string, unknown>>(`/vpn/server/${action}`),
    clientAction: (name: string, action: 'start' | 'stop' | 'keys') =>
      post<Record<string, unknown>>(`/vpn/clients/${encodeURIComponent(name)}/${action}`),
  },

  tailscale: {
    status: () =>
      get<{
        status: TailscaleStatus
        config: Record<string, unknown>
        steering_active: string[]
        overlapping_routes: string[]
        gateway: {
          applied: boolean; interfaces: string[]; wan: string
          ip_forwarding: boolean; masquerade: boolean; dns_redirect: boolean
          last_error?: string; blockers?: string[]
        }
        warnings: string[]
        install_hint?: string
      }>('/tailscale/status'),
    up: (body?: Record<string, unknown>) => post<TailscaleStatus>('/tailscale/up', body ?? {}),
    down: () => post<TailscaleStatus>('/tailscale/down'),
    login: () => post<{ auth_url: string }>('/tailscale/login'),
    logout: () => post<{ ok: boolean }>('/tailscale/logout'),
    setExitNode: (node: string, allow_lan?: boolean) =>
      post<TailscaleStatus>('/tailscale/exit-node', { node, allow_lan }),
    advertiseExitNode: (enabled: boolean) =>
      post<{ status: TailscaleStatus; next_step?: string }>('/tailscale/advertise-exit-node', { enabled }),
    setRoutes: (routes: string[]) => post<TailscaleStatus>('/tailscale/routes', { routes }),
    steer: (clients: string[]) => post<{ steering_active: string[] }>('/tailscale/steer', { clients }),
    acceptRoutes: (enabled: boolean) => post<TailscaleStatus>('/tailscale/accept-routes', { enabled }),
  },

  egress: {
    status: () =>
      get<{
        tunnels: Array<{
          name: string; enabled: boolean; interface: string; addresses: string[]
          dns: string[]; mtu: number; peer_public_key: string; endpoint: string
          allowed_ips: string[]; keepalive: number; route_table: number
          kill_switch: boolean; note: string; has_preshared_key: boolean
        }>
        targets: Array<{
          id: string; name: string; kind: string; interface: string
          route_table: number; up: boolean; kill_switch: boolean; detail: string
        }>
        routes: Array<{ source: string; target: string; label: string; client_id: string }>
        status: { assignments: unknown[]; applied: string[]; active_rules: string[]; last_error: string }
        lan: string[]
        warnings: string[]
      }>('/vpn/out'),
    importTunnel: (body: { name: string; config: string; kill_switch: boolean; enable: boolean }) =>
      post<{ saved: boolean; ignored?: string[]; warning?: string }>('/vpn/out/tunnels/import', body),
    updateTunnel: (name: string, body: Record<string, unknown>) =>
      put<{ ok: boolean }>(`/vpn/out/tunnels/${encodeURIComponent(name)}`, body),
    deleteTunnel: (name: string) => del<{ ok: boolean }>(`/vpn/out/tunnels/${encodeURIComponent(name)}`),
    tunnelAction: (name: string, action: 'start' | 'stop') =>
      post<Record<string, unknown>>(`/vpn/out/tunnels/${encodeURIComponent(name)}/${action}`),
    assign: (client_id: string, target: string) =>
      post<{ ok: boolean }>('/vpn/out/assign', { client_id, target }),
    assignAll: (target: string) => post<{ ok: boolean }>('/vpn/out/assign-all', { target }),
  },

  network: {
    vlans: () =>
      get<{
        vlans: Array<{
          name: string; parent: string; id: number; address: string; mtu: number
          enabled: boolean; zone: string; description: string
          present: boolean; up: boolean; addresses: string[]
          rx_bytes: number; tx_bytes: number; error?: string
        }>
        available: boolean; reason: string; last_error: string; parents: string[]
      }>('/network/vlans'),
    saveVLAN: (v: Record<string, unknown>, name?: string) =>
      name
        ? put<{ saved: boolean; warning?: string }>(`/network/vlans/${encodeURIComponent(name)}`, v)
        : post<{ saved: boolean; warning?: string }>('/network/vlans', v),
    deleteVLAN: (name: string) => del<{ ok: boolean }>(`/network/vlans/${encodeURIComponent(name)}`),
  },

  proxy: {
    status: () => get<Record<string, unknown>>('/proxy/status'),
    readiness: () =>
      get<{
        checks: Array<{ name: string; ok: boolean; detail: string; fix?: string }>
        next_step: string
        stats: Record<string, unknown>
        intercept_hosts: string[]
        only_clients: string[]
        mode: string
      }>('/proxy/readiness'),
    ca: () =>
      get<{
        ca: Record<string, unknown>
        download: string
        mobileconfig: string
        setup_url: string
        instructions: Array<{ platform: string; steps: string }>
      }>('/proxy/ca'),
    action: (action: 'start' | 'stop') => post<Record<string, unknown>>(`/proxy/${action}`),
  },

  events: {
    list: (opts: { hours?: number; severity?: string; unack_only?: boolean; limit?: number } = {}) =>
      get<{ count: number; events: EventItem[] }>(`/events${qs(opts)}`),
    ack: (id: string) => post<{ ok: boolean }>(`/events/${id}/ack`),
  },

  ai: {
    models: () => get<AIModelsStatus>('/ai/models'),
    probe: () => post<{ started: boolean }>('/ai/probe'),
    briefs: (limit = 10) => get<{ briefs: AIBrief[] }>(`/ai/briefs${qs({ limit })}`),
    runBrief: (hours?: number) => post<AIBrief>('/ai/briefs/run', hours ? { hours } : {}),
    recommendations: (status = '') =>
      get<{ recommendations: Recommendation[]; review: { enabled: boolean; interval_hours: number } }>(`/ai/recommendations${qs({ status })}`),
    decide: (id: string, decision: 'accept' | 'dismiss' | 'reopen') =>
      post<{ recommendation: Recommendation }>(`/ai/recommendations/${id}`, { decision }),
    runReview: (hours?: number) => post<{ added: Recommendation[] }>('/ai/review/run', hours ? { hours } : {}),
    notes: () => get<{ notes: AINote[] }>('/ai/notes'),
    addNote: (note: string) => post<{ note: AINote }>('/ai/notes', { note }),
    deleteNote: (id: string) => del<{ ok: boolean }>(`/ai/notes/${id}`),
  },

  shortcuts: {
    list: () => get<{ shortcuts: DNSShortcut[]; node_port: string }>('/dns/shortcuts'),
    save: (sc: Partial<DNSShortcut>) => post<{ shortcut: DNSShortcut; open: string }>('/dns/shortcuts', sc),
    remove: (name: string) => post<{ ok: boolean }>('/dns/shortcuts/delete', { name }),
  },

  simple: {
    health: () => get<Health>('/health'),
    bundles: () => get<{ services: ServiceBundle[] }>('/dns/services'),
    pause: (id: string, minutes: number) => post<{ ok: boolean; until?: string }>(`/clients/${id}/pause`, { minutes }),
    resume: (id: string) => post<{ ok: boolean }>(`/clients/${id}/resume`),
    pauses: () => get<{ pauses: Record<string, string> }>('/pauses'),
  },

  services: {
    list: (hours = 24, client_id = '') => get<ServicesResponse>(`/services${qs({ hours, client_id })}`),
    detail: (service: string, hours = 24, client_id = '') =>
      get<ServiceDetail>(`/services/detail${qs({ service, hours, client_id })}`),
    devices: (hours = 24) => get<{ since: string; until: string; devices: ServiceDevice[] }>(`/services/devices${qs({ hours })}`),
    device: (client_id: string, hours = 24) =>
      get<{ client_id: string; device?: Record<string, unknown>; services: ServiceTotal[]; series: ServicePoint[] }>(`/services/devices${qs({ hours, client_id })}`),
    catalogue: () => get<{ services: Array<{ name: string; category: string }> }>('/services/catalogue'),
  },

  issues: {
    list: (status = '') => get<IssuesResponse>(`/issues${qs({ status })}`),
    create: (title: string, detail: string, report: boolean) =>
      post<{ issue: Issue; report_error?: string }>('/issues', { title, detail, report }),
    preview: (id: string) => get<{ title: string; body: string; labels: string[]; repo: string }>(`/issues/${id}/preview`),
    report: (id: string) => post<{ issue: Issue }>(`/issues/${id}/report`),
    setStatus: (id: string, status: 'open' | 'dismissed' | 'resolved') =>
      post<{ issue: Issue }>(`/issues/${id}/status`, { status }),
    remove: (id: string) => del<{ ok: boolean }>(`/issues/${id}`),
  },

  chat: {
    conversations: () =>
      get<{ conversations: Array<{ id: string; last: string; messages: number; title: string }> }>(
        '/chat/conversations',
      ),
    history: (id: string) => get<{ messages: import('./types').ChatMessage[] }>(`/chat/conversations/${id}`),
    remove: (id: string) => del<{ ok: boolean }>(`/chat/conversations/${id}`),
  },

  youtube: {
    status: () => get<YouTubeStatus>('/youtube/status'),
    discover: () => post<DiscoveredScreen[]>('/youtube/discover'),
    pair: (code: string, name?: string) => post<LoungeDevice>('/youtube/pair', { code, name }),
    adopt: (screen_id: string, name?: string, offset?: number) =>
      post<YouTubeStatus>('/youtube/adopt', { screen_id, name, offset }),
    forget: (screen_id: string) => post<YouTubeStatus>('/youtube/forget', { screen_id }),
    settings: (
      body: Partial<{
        enabled: boolean; auto_discover: boolean; skip_ads: boolean
        mute_ads: boolean; reload_unskippable: boolean; categories: string[]; min_skip_length: number
      }>,
    ) => post<YouTubeStatus>('/youtube/settings', body),
  },

  backup: {
    exportURL: '/api/backup',
    restore: (bundle: unknown, options?: Record<string, boolean>) =>
      post<{ applied: string[]; skipped: string[]; warnings: string[] }>('/backup/restore',
        options ? { bundle, options } : bundle),
  },

  notify: {
    get: () => get<NotifyConfig>('/notify'),
    test: () => post<{ ok: boolean }>('/notify/test'),
    saveWebhook: (h: Webhook) => post<NotifyConfig>('/notify/webhooks', h),
    deleteWebhook: (name: string) => del<NotifyConfig>(`/notify/webhooks/${encodeURIComponent(name)}`),
  },

  routes: {
    list: () => get<{ configured: StaticRoute[]; kernel: string[] }>('/routes'),
    save: (r: StaticRoute) => post<StaticRoute>('/routes', r),
    remove: (name: string) => del<{ ok: boolean }>(`/routes/${encodeURIComponent(name)}`),
    apply: () => post<{ ok: boolean }>('/routes/apply'),
  },

  wan: {
    status: () => get<WANStatus>('/wan'),
    save: (cfg: MultiWANConfig) => post<WANStatus>('/wan/settings', cfg),
  },

  shaping: {
    status: () => get<{ config: ShapingConfig; status: ShapingStatus }>('/shaping'),
    apply: (cfg: ShapingConfig) => post<{ config: ShapingConfig; status: ShapingStatus }>('/shaping', cfg),
  },

  portmap: {
    list: () => get<{ config: Record<string, unknown>; running: boolean; mappings: PortMapping[] }>('/portmap'),
    remove: (proto: string, port: number) => del<{ ok: boolean }>(`/portmap/${proto}/${port}`),
  },

  tools: {
    ping: (target: string, count = 4) => post<PingResult>('/tools/ping', { target, count }),
    traceroute: (target: string, max_hops = 20) =>
      post<{ hops: TracerouteHop[]; raw: string }>('/tools/traceroute', { target, max_hops }),
    wol: (mac: string, broadcast?: string) =>
      post<{ ok: boolean; broadcast: string }>('/tools/wol', { mac, broadcast }),
    speedtest: () => post<SpeedResult>('/tools/speedtest'),
  },

  consent: {
    status: () => get<ConsentStatus>('/consent'),
    decide: (id: string, decision: 'allow' | 'deny', scope: 'device' | 'network' = 'device') =>
      post<ConsentRule>('/consent/decide', { id, decision, scope }),
    enrol: (client_ids: string[]) => post<{ enrolled: string[] }>('/consent/enrol', { client_ids }),
    forget: (client_id: string, host: string, scope: string) =>
      post<{ ok: boolean }>('/consent/forget', { client_id, host, scope }),
    clear: () => post<{ cleared: number }>('/consent/clear'),
  },

  dnstools: {
    diagnose: (domain: string, opts: { client_id?: string; resolve?: boolean } = {}) =>
      post<Diagnosis>('/dnstools/diagnose', { domain, resolve: true, ...opts }),
    allow: (domain: string, note?: string) =>
      post<{ ok: boolean }>('/dnstools/allow', { domain, note }),
    block: (domain: string, wildcard = false, note?: string) =>
      post<{ ok: boolean }>('/dnstools/block', { domain, wildcard, note }),
    unblock: (domain: string) => post<{ ok: boolean }>('/dnstools/unblock', { domain }),
    importList: (text: string, opts: { action?: 'block' | 'allow'; dry_run?: boolean; note?: string } = {}) =>
      post<ImportResult>('/dnstools/import', { text, ...opts }),
  },

  onboarding: {
    get: () => get<OnboardingState>('/onboarding'),
    apply: (body: Record<string, unknown>) =>
      post<{ ok: boolean; onboarded: boolean; placement: PlacementCheck[] }>('/onboarding/apply', body),
    reset: () => post<{ ok: boolean }>('/onboarding/reset'),
  },

  topology: {
    get: () => get<TopoGraph>('/topology'),
    scan: () => post<TopoGraph>('/topology/scan'),
  },

  intercept: {
    get: () => get<InterceptStatus>('/intercept'),
    settings: (b: Partial<{ enabled: boolean; lan_interface: string; gateway: string; redirect_dns: boolean; redirect_http: boolean }>) =>
      post<InterceptStatus>('/intercept/settings', b),
    enroll: (ip: string, mac: string) => post<InterceptStatus>('/intercept/enroll', { ip, mac }),
    remove: (ip: string) => post<InterceptStatus>('/intercept/remove', { ip }),
  },

  dnsRecords: {
    list: () => get<{ records: DNSRecord[]; local_domain: string }>('/dns/records'),
    save: (rec: DNSRecord) => post<{ records: DNSRecord[] }>('/dns/records', rec),
    remove: (rec: DNSRecord) => post<{ records: DNSRecord[] }>('/dns/records/delete', rec),
  },

  alerts: {
    rules: () => get<{ rules: AlertRule[] }>('/notify/rules'),
    save: (rule: Partial<AlertRule>) => post<{ rules: AlertRule[] }>('/notify/rules', rule),
    remove: (id: string) => del<{ rules: AlertRule[] }>(`/notify/rules/${id}`),
  },

  report: {
    preview: (hours: number) => get<ReportData>(`/report${qs({ hours })}`),
    downloadURL: (hours: number, format: 'csv' | 'html') => `/api/report${qs({ hours, format })}`,
  },

  config: {
    get: () => get<AppConfig>('/config'),
    patch: (body: Record<string, unknown>) =>
      patch<{ applied: string[]; config: AppConfig }>('/config', body),
    interfaces: () => get<{ interfaces: InterfaceInfo[] }>('/config/interfaces'),
  },
}

/**
 * askAssistant streams a chat turn over SSE. The browser's EventSource cannot
 * POST, so the stream is parsed by hand off a fetch body reader.
 */
export async function askAssistant(
  conversation: string,
  message: string,
  onTurn: (turn: ChatTurn) => void,
  signal?: AbortSignal,
): Promise<string> {
  const res = await fetch('/api/chat/ask', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
    body: JSON.stringify({ conversation, message }),
    signal,
  })
  if (res.status === 401) {
    onUnauthorized?.()
    throw new ApiError(401, 'not signed in')
  }
  if (!res.ok || !res.body) {
    throw new ApiError(res.status, (await res.text()) || 'assistant request failed')
  }

  const reader = res.body.getReader()
  const decoder = new TextDecoder()
  let buffer = ''
  let convId = conversation

  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    buffer += decoder.decode(value, { stream: true })

    // SSE frames are separated by a blank line.
    let sep: number
    while ((sep = buffer.indexOf('\n\n')) >= 0) {
      const frame = buffer.slice(0, sep)
      buffer = buffer.slice(sep + 2)
      let event = 'message'
      const dataLines: string[] = []
      for (const line of frame.split('\n')) {
        if (line.startsWith(':')) continue
        if (line.startsWith('event:')) event = line.slice(6).trim()
        else if (line.startsWith('data:')) dataLines.push(line.slice(5).trim())
      }
      if (!dataLines.length) continue
      let payload: unknown
      try {
        payload = JSON.parse(dataLines.join('\n'))
      } catch {
        continue
      }
      if (event === 'start' || event === 'done') {
        const p = payload as { conversation?: string }
        if (p.conversation) convId = p.conversation
      } else if (event === 'turn') {
        onTurn(payload as ChatTurn)
      } else if (event === 'error') {
        const p = payload as { error?: string }
        onTurn({ kind: 'error', text: p.error ?? 'unknown error' })
      }
    }
  }
  return convId
}
