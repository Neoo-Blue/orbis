import type { ReactNode } from 'react'
import { Switch } from '../ui'

/** Shared pieces for the simple interface: one idea per card, plain words. */

export function BigSwitch({ icon, title, desc, checked, onChange, disabled, children }: {
  icon: ReactNode; title: string; desc: ReactNode; checked: boolean
  onChange: (v: boolean) => void; disabled?: boolean; children?: ReactNode
}) {
  return (
    <div className="bigswitch">
      <div className="icon" aria-hidden="true">{icon}</div>
      <div className="text">
        <div className="title">{title}</div>
        <div className="desc">{desc}</div>
        {children}
      </div>
      <div className="switch"><Switch checked={checked} onChange={onChange} disabled={disabled} /></div>
    </div>
  )
}

export function Tile({ big, label, sub, onClick }: { big: ReactNode; label: string; sub?: ReactNode; onClick?: () => void }) {
  return (
    <button className="tile" onClick={onClick} type="button">
      <div className="big">{big}</div>
      <div className="label">{label}</div>
      {sub && <div className="sub">{sub}</div>}
    </button>
  )
}

export function Section({ title, hint, children, actions }: { title: string; hint?: ReactNode; children: ReactNode; actions?: ReactNode }) {
  return (
    <section style={{ display: 'grid', gap: 10, marginBottom: 22 }}>
      <div style={{ display: 'flex', alignItems: 'baseline', gap: 12 }}>
        <h2 style={{ fontSize: 15.5, fontWeight: 600, margin: 0 }}>{title}</h2>
        {hint && <span className="hint" style={{ flex: 1 }}>{hint}</span>}
        {actions}
      </div>
      {children}
    </section>
  )
}

/** Plain wording for the things the daemon reports. */
export function plainCategory(cat: string): string {
  const map: Record<string, string> = {
    'anomaly:new_device': 'New device', 'anomaly:beacon': 'Device calling home on a schedule',
    'anomaly:exfil': 'Large upload', 'anomaly:portscan': 'Device scanning the network', 'anomaly:dga': 'Suspicious lookups',
    'ai:brief': 'Network check', 'ai:review': 'Blocklist suggestions', dns: 'DNS', capture: 'Traffic capture',
    mitm: 'Filter proxy', adblock: 'Blocklists', firewall: 'Firewall', vpn: 'VPN', tailscale: 'Tailscale',
    network: 'Network', alert: 'Alert rule', report: 'Report', intercept: 'Device interception', lounge: 'YouTube on TV',
  }
  return map[cat] ?? cat.replace(/[:_]/g, ' ')
}

export const PRESETS: Array<{
  id: string; name: string; description: string
  policy: { blocked_services: string[]; safe_search: boolean; block_doh: boolean; unfiltered: boolean }
}> = [
  {
    id: 'kids', name: 'Kids', description: 'Safe search on, social media and adult-leaning apps off. Ads and trackers blocked.',
    policy: { blocked_services: ['tiktok', 'instagram', 'snapchat', 'x', 'reddit', 'twitch', 'discord', 'tumblr'], safe_search: true, block_doh: true, unfiltered: false },
  },
  {
    id: 'homework', name: 'Homework', description: 'Everything in Kids, plus games and video off. Good for school hours.',
    policy: { blocked_services: ['tiktok', 'instagram', 'snapchat', 'x', 'reddit', 'twitch', 'discord', 'tumblr', 'youtube', 'netflix', 'roblox', 'steam', 'epicgames', 'disneyplus', 'primevideo'], safe_search: true, block_doh: true, unfiltered: false },
  },
  {
    id: 'guest', name: 'Guests', description: 'Normal protection. Nothing extra blocked, nothing exempt.',
    policy: { blocked_services: [], safe_search: false, block_doh: true, unfiltered: false },
  },
  {
    id: 'unfiltered', name: 'Unfiltered', description: 'No blocking at all for this device. For things that break when filtered.',
    policy: { blocked_services: [], safe_search: false, block_doh: false, unfiltered: true },
  },
]
