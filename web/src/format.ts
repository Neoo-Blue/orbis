/** Formatting helpers. Everything an operator compares column-to-column is
 *  rendered with a fixed number of significant digits so the eye can scan it. */

export function bytes(n: number | undefined | null, digits = 1): string {
  if (!n || n < 0) return '0 B'
  if (n < 1024) return `${Math.round(n)} B`
  const units = ['KB', 'MB', 'GB', 'TB', 'PB']
  let v = n / 1024
  let i = 0
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i++
  }
  return `${v.toFixed(v >= 100 ? 0 : digits)} ${units[i]}`
}

export function bits(bytesPerSec: number | undefined | null): string {
  const n = (bytesPerSec ?? 0) * 8
  if (n < 1000) return `${Math.round(n)} bps`
  const units = ['Kbps', 'Mbps', 'Gbps']
  let v = n / 1000
  let i = 0
  while (v >= 1000 && i < units.length - 1) {
    v /= 1000
    i++
  }
  return `${v.toFixed(v >= 100 ? 0 : 1)} ${units[i]}`
}

export function num(n: number | undefined | null): string {
  if (n === undefined || n === null) return '0'
  return n.toLocaleString('en-US')
}

export function compact(n: number | undefined | null): string {
  if (!n) return '0'
  if (n < 1000) return String(n)
  if (n < 1_000_000) return `${(n / 1000).toFixed(n < 10_000 ? 1 : 0)}k`
  if (n < 1_000_000_000) return `${(n / 1_000_000).toFixed(n < 10_000_000 ? 1 : 0)}M`
  return `${(n / 1_000_000_000).toFixed(1)}B`
}

export function pct(v: number | undefined | null, digits = 1): string {
  return `${((v ?? 0) * 100).toFixed(digits)}%`
}

export function duration(seconds: number | undefined | null): string {
  const s = Math.max(0, Math.floor(seconds ?? 0))
  if (s < 60) return `${s}s`
  const m = Math.floor(s / 60)
  if (m < 60) return `${m}m ${s % 60}s`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}h ${m % 60}m`
  const d = Math.floor(h / 24)
  return `${d}d ${h % 24}h`
}

export function ago(iso: string | undefined | null): string {
  if (!iso) return 'never'
  const t = new Date(iso).getTime()
  if (Number.isNaN(t)) return '—'
  const diff = (Date.now() - t) / 1000
  if (diff < 0) return 'just now'
  if (diff < 10) return 'just now'
  if (diff < 60) return `${Math.floor(diff)}s ago`
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`
  if (diff < 86400 * 30) return `${Math.floor(diff / 86400)}d ago`
  return new Date(t).toLocaleDateString()
}

export function clock(iso: string | undefined | null): string {
  if (!iso) return '—'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return '—'
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false })
}

export function dateTime(iso: string | undefined | null): string {
  if (!iso) return '—'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return '—'
  return d.toLocaleString([], {
    month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit', hour12: false,
  })
}

/** clientName picks the most human label available, in order of how much a
 *  person would recognise it. */
export function clientName(c: {
  label?: string; hostname?: string; vendor?: string; ip: string; mac?: string
}): string {
  if (c.label) return c.label
  if (c.hostname) return c.hostname
  if (c.vendor) return `${c.vendor} · ${c.ip}`
  return c.ip
}

export function flowTarget(f: { hostname?: string; sni?: string; dst_ip: string }): string {
  return f.hostname || f.sni || f.dst_ip
}

export function countryFlag(code: string | undefined): string {
  if (!code || code.length !== 2) return ''
  // Regional indicator symbols start at U+1F1E6 for 'A'.
  const base = 0x1f1e6
  const cc = code.toUpperCase()
  return String.fromCodePoint(base + (cc.charCodeAt(0) - 65), base + (cc.charCodeAt(1) - 65))
}

const DEVICE_GLYPHS: Record<string, string> = {
  phone: '▯', tablet: '▭', laptop: '▬', desktop: '▮', tv: '◫', console: '◈',
  speaker: '◉', camera: '◎', printer: '▤', iot: '◇', server: '▦', nas: '▧',
  'apple-device': '◍', unknown: '○',
}
export function deviceGlyph(type: string | undefined): string {
  return DEVICE_GLYPHS[type ?? 'unknown'] ?? '○'
}

/** riskColor maps a 0..1 score onto the palette, used for the globe arcs and
 *  the risk column. */
export function riskColor(risk: number): string {
  if (risk >= 0.75) return 'var(--red)'
  if (risk >= 0.45) return 'var(--amber)'
  if (risk >= 0.2) return 'var(--blue)'
  return 'var(--text-dim)'
}

export function scoreTone(score: number): 'block' | 'warn' | 'info' {
  if (score >= 0.85) return 'block'
  if (score >= 0.55) return 'warn'
  return 'info'
}
