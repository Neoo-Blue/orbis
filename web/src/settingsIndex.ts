/**
 * A curated index of what lives where in Settings, so a person can type
 * "password" or "upstream" instead of guessing which of fourteen sections
 * holds it. Labels are the on-screen labels; keywords are what people say.
 */
export type SettingsSection =
  | 'general' | 'dns' | 'adblock' | 'proxy' | 'firewall' | 'zones'
  | 'dhcp' | 'vpn' | 'tailscale' | 'threats' | 'hosted' | 'assistant' | 'problems' | 'capture' | 'storage' | 'security' | 'about'

export interface SettingsEntry { section: SettingsSection; label: string; keywords: string }

export const SETTINGS_INDEX: SettingsEntry[] = [
  { section: 'general', label: 'Operating mode', keywords: 'inline observe gateway routing enforce' },
  { section: 'general', label: 'Node name', keywords: 'hostname title' },
  { section: 'general', label: 'Timezone', keywords: 'time clock' },
  { section: 'general', label: 'Location', keywords: 'latitude longitude globe map home public ip' },
  { section: 'general', label: 'Interface default (simple or advanced)', keywords: 'ui mode simple advanced' },
  { section: 'dns', label: 'Upstream resolvers', keywords: 'upstream dns over tls doh dot cloudflare quad9 google 1.1.1.1 9.9.9.9 encrypted' },
  { section: 'dns', label: 'Resolution strategy', keywords: 'parallel fastest race failover' },
  { section: 'dns', label: 'Cache size and TTL', keywords: 'cache ttl minimum maximum' },
  { section: 'dns', label: 'Sinkhole addresses', keywords: 'blocked answer 0.0.0.0 nxdomain' },
  { section: 'dns', label: 'Query logging', keywords: 'log queries privacy history' },
  { section: 'dns', label: 'Local domain and records', keywords: 'lan .lan hostnames local records rewrite' },
  { section: 'dns', label: 'Shortcuts (name to host:port)', keywords: 'shortcut port redirect proxy name point url' },
  { section: 'dns', label: 'Encrypted DNS server (DoT, DoH)', keywords: 'serve dns over tls https 853 8443 certificate' },
  { section: 'dns', label: 'Rebind protection', keywords: 'rebinding private answers security' },
  { section: 'adblock', label: 'Ad blocking on or off', keywords: 'ads trackers enable disable' },
  { section: 'threats', label: 'Block known-bad addresses (threat feeds)', keywords: 'threat intelligence ip feed blocklist spamhaus drop feodo botnet c2 malware attackers reputation' },
  { section: 'threats', label: 'Ban an address or range', keywords: 'ban block ip cidr timed decision attacker scanner' },
  { section: 'threats', label: 'CrowdSec bouncer', keywords: 'crowdsec bouncer lapi local api key decisions community blocklist' },
  { section: 'threats', label: 'Never block these addresses', keywords: 'threat allow exception whitelist vpn endpoint server' },
  { section: 'threats', label: 'Block or allow countries', keywords: 'country geo block allow china russia geoblock whitelist blacklist region' },
  { section: 'hosted', label: 'Discover hosted apps (scan interval, extra ports)', keywords: 'discover scan services apps containers ports hosted nas storage' },
  { section: 'hosted', label: 'Docker hosts (Engine API)', keywords: 'docker socket containers engine api portainer synology 2375' },
  { section: 'hosted', label: 'Port forwarding via the router (UPnP)', keywords: 'port forward upnp router igd nat open port expose' },
  { section: 'adblock', label: 'Blocklists', keywords: 'lists subscriptions hagezi oisd stevenblack malware phishing update interval' },
  { section: 'adblock', label: 'Allowlist and denylist', keywords: 'allow deny whitelist blacklist exception' },
  { section: 'adblock', label: 'Block DNS bypass (private DNS)', keywords: 'doh bypass cloudflare-dns dns.google android private dns' },
  { section: 'adblock', label: 'Streaming and TV ads list', keywords: 'smart tv roku samsung ads telemetry' },
  { section: 'adblock', label: 'CNAME uncloaking', keywords: 'cname cloaking first party trackers' },
  { section: 'adblock', label: 'Smart capture (learn new ad hosts)', keywords: 'heuristic ai judge candidates auto block score' },
  { section: 'adblock', label: 'Import from Pi-hole or AdGuard Home', keywords: 'import pihole pi-hole adguard home teleporter gravity adlists yaml migrate' },
  { section: 'adblock', label: 'Popular blocklists (presets)', keywords: 'preset oisd hagezi adguard dns filter stevenblack urlhaus phishing list subscribe' },
  { section: 'proxy', label: 'Filter proxy on or off', keywords: 'mitm https interception in-stream youtube certificate' },
  { section: 'proxy', label: 'Which hosts are intercepted', keywords: 'intercept hosts bypass hosts patterns' },
  { section: 'proxy', label: 'Only these devices', keywords: 'only clients phone laptop certificate installed' },
  { section: 'proxy', label: 'Certificate authority download', keywords: 'ca certificate install iphone android mobileconfig setup' },
  { section: 'proxy', label: 'Filters (YouTube, JSON ads, cosmetic, beacons)', keywords: 'youtube in-page sponsorblock filters' },
  { section: 'firewall', label: 'Firewall on or off', keywords: 'nftables ruleset enforce' },
  { section: 'firewall', label: 'WAN interface', keywords: 'wan uplink interface eth0' },
  { section: 'firewall', label: 'Default forward policy', keywords: 'drop accept default policy' },
  { section: 'firewall', label: 'Logging dropped packets', keywords: 'log dropped nflog' },
  { section: 'zones', label: 'Zones', keywords: 'lan wan guest iot trust subnets vlan' },
  { section: 'dhcp', label: 'DHCP server', keywords: 'dhcp leases scopes static reservations gateway option' },
  { section: 'vpn', label: 'WireGuard server', keywords: 'wireguard vpn server peers keys port 51820' },
  { section: 'vpn', label: 'Outbound tunnels and routing', keywords: 'tunnel egress route devices through vpn' },
  { section: 'tailscale', label: 'Tailscale', keywords: 'tailscale exit node subnet routes auth key login' },
  { section: 'assistant', label: 'Assistant provider and API key', keywords: 'ai openrouter anthropic openai ollama api key model' },
  { section: 'assistant', label: 'Free models, probe, budget', keywords: 'free models openrouter probe ranking budget chain pin' },
  { section: 'assistant', label: 'Let the assistant make changes', keywords: 'write access permissions allow write' },
  { section: 'assistant', label: 'Network brief schedule', keywords: 'brief report check hours notify' },
  { section: 'assistant', label: 'Blocklist specialist review', keywords: 'review suggestions allow block daily' },
  { section: 'assistant', label: 'Anomaly detection', keywords: 'anomaly beacon exfiltration new device alert triage' },
  { section: 'assistant', label: 'AI threat check (threat intelligence)', keywords: 'threat intelligence assessment risk findings ai intel schedule' },
  { section: 'assistant', label: 'Active blocking by the assistant', keywords: 'active blocking automatic ban block confidence limits undo ai' },
  { section: 'problems', label: 'Problem recording and GitHub reporting', keywords: 'issues bugs report github token relay privacy scrub' },
  { section: 'capture', label: 'Packet capture interfaces', keywords: 'capture interfaces snaplen conntrack pcap' },
  { section: 'storage', label: 'Database path and retention', keywords: 'database sqlite retention days flows events prune' },
  { section: 'security', label: 'Admin password', keywords: 'password login session sign in' },
  { section: 'security', label: 'Metrics token', keywords: 'prometheus metrics token scrape' },
  { section: 'about', label: 'Version and diagnostics', keywords: 'version build health raw config backup restore' },
]

export function searchSettings(q: string): SettingsEntry[] {
  const needle = q.trim().toLowerCase()
  if (!needle) return []
  const words = needle.split(/\s+/)
  return SETTINGS_INDEX.filter((e) => {
    const hay = `${e.label} ${e.keywords} ${e.section}`.toLowerCase()
    return words.every((w) => hay.includes(w))
  })
}
