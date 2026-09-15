/** What a connection is for, as far as the node can tell: the globe colours
 *  by this so a household can see streaming from browsing from DNS at a
 *  glance. Blocked connections keep their red in every colouring, because a
 *  rejected connection is the one thing the globe must never hide. */
export type ArcKind = 'streaming' | 'social' | 'gaming' | 'web' | 'dns' | 'other'
export type ColorBy = 'kind' | 'verdict'

export const KINDS: Array<{ id: ArcKind; label: string; color: string }> = [
  { id: 'streaming', label: 'streaming', color: '#ff8fa3' },
  { id: 'social', label: 'social & messaging', color: '#a98bff' },
  { id: 'gaming', label: 'gaming', color: '#ffc266' },
  { id: 'web', label: 'web', color: '#4ee8c0' },
  { id: 'dns', label: 'DNS', color: '#63b3ff' },
  { id: 'other', label: 'other', color: '#8a99ae' },
]
export const BLOCKED_COLOR = '#ff6b7a'

const STREAMING = /youtube|netflix|plex|jellyfin|emby|spotify|twitch|hulu|disney|hbo|\bmax\b|prime ?video|apple ?tv|tiktok|vimeo|pandora|tidal|peacock|paramount|crunchyroll|soundcloud|deezer/i
const SOCIAL = /facebook|instagram|whatsapp|wechat|telegram|signal|discord|snapchat|messenger|reddit|twitter|\bx\.com|threads|imessage|facetime|slack|teams|zoom|google ?meet|viber|line\b/i
const GAMING = /steam|xbox|playstation|nintendo|epic ?games|roblox|minecraft|riot|blizzard|battle\.net|ubisoft|rockstar/i
const DNS_HOST = /^dns\.|\.dns\.|dns-query|\bdoh\b|dns\.google|one\.one\.one\.one|quad9|nextdns|adguard-dns/i

export function arcKind(a: {
  port?: number; app?: string; service_category?: string; hostname?: string; label?: string
}): ArcKind {
  const port = a.port ?? 0
  if (port === 53 || port === 853 || port === 5353) return 'dns'
  const name = `${a.app ?? ''} ${a.hostname ?? ''} ${a.label ?? ''}`
  if (DNS_HOST.test(name)) return 'dns'
  const cat = (a.service_category ?? '').toLowerCase()
  if (cat === 'video' || cat === 'music') return 'streaming'
  if (cat === 'social' || cat === 'messaging') return 'social'
  if (cat === 'gaming') return 'gaming'
  if (STREAMING.test(name)) return 'streaming'
  if (SOCIAL.test(name)) return 'social'
  if (GAMING.test(name)) return 'gaming'
  if (port === 80 || port === 443 || port === 8080 || port === 8443) return 'web'
  return 'other'
}

export function kindColor(kind: string): string {
  return KINDS.find((k) => k.id === kind)?.color ?? KINDS[KINDS.length - 1].color
}

export function kindLabel(kind: string): string {
  return KINDS.find((k) => k.id === kind)?.label ?? 'other'
}
