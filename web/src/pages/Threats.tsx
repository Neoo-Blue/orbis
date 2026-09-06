import { useState } from 'react'
import { api } from '../api'
import { usePoll } from '../hooks'
import { Banner, Card, Empty, Field, Icons, Loading, Segmented, Stat, Switch, useToast } from '../ui'
import { ago, countryFlag, num } from '../format'
import type { CountryStatus, IDSStatus, ThreatDecision, ThreatFeed, ThreatHit } from '../types'
import { bytes, countryFlag as flag } from '../format'

/**
 * Threats: IP-level threat intelligence. Where the DNS pages work on names,
 * this page works on addresses: the feeds that supply them, the bans the
 * operator (or the assistant, the scan detector, a CrowdSec engine) added,
 * and every connection that touched one of them. The enforcement banner is
 * the most important line on the page: a hit that was only recorded and a
 * hit that was dropped must never look the same.
 */
type Tab = 'attacks' | 'hits' | 'feeds' | 'bans' | 'countries' | 'crowdsec'

const CATEGORIES = ['c2', 'hijacked', 'attackers', 'compromised', 'spam', 'other']

export function ThreatsPage() {
  const [tab, setTab] = useState<Tab>('attacks')
  const [hours, setHours] = useState(24)
  const { data: status, refresh: refreshStatus } = usePoll(() => api.threat.status(), 15000)
  const { data: hitsData, refresh: refreshHits } = usePoll(() => api.threat.hits(hours, 300), 15000, [hours])
  const { data: feedsData, refresh: refreshFeeds } = usePoll(() => api.threat.feeds(), 30000)
  const { data: bansData, refresh: refreshBans } = usePoll(() => api.threat.decisions(), 15000)
  const { data: countryData, refresh: refreshCountry } = usePoll(() => api.country.get(), 15000)
  const { data: idsData, refresh: refreshIDS } = usePoll(() => api.ids.get(hours, 200), 15000, [hours])
  const toast = useToast()
  const [busy, setBusy] = useState<string | null>(null)

  const refreshAll = () => { refreshStatus(); refreshHits(); refreshFeeds(); refreshBans(); refreshCountry(); refreshIDS() }
  const act = async (key: string, fn: () => Promise<unknown>, ok: string) => {
    setBusy(key)
    try {
      await fn()
      toast(ok, 'ok')
      refreshAll()
    } catch (e) {
      toast(e instanceof Error ? e.message : 'That did not work', 'err')
    } finally {
      setBusy(null)
    }
  }

  if (!status) return <Loading what="threat intelligence" />
  const enf = status.enforcement
  const cs = status.crowdsec
  const sources = Object.entries(status.decisions_by_source ?? {}).map(([k, v]) => `${v} ${k}`).join(', ')

  return (
    <div style={{ display: 'grid', gap: 14 }}>
      {!status.enabled && (
        <Banner tone="warn" action={
          <button className="btn sm primary" disabled={busy === 'enable'}
            onClick={() => act('enable', () => api.config.patch({ 'threat.enabled': true }), 'Known-bad address blocking is on')}>Turn on</button>
        }>
          Known-bad address blocking is switched off. Feeds are kept up to date but nothing is matched or dropped.
        </Banner>
      )}
      {status.enabled && enf.detect_only && (
        <Banner tone="info">
          <strong style={{ display: 'block', marginBottom: 3 }}>Detecting, not dropping</strong>
          This node is not in the path for any device (observe mode, no intercepted devices), so a connection to a
          listed address is recorded here and in Events but not stopped. Intercept a device on the Interception page,
          or switch to inline mode, and its hits will be dropped.
        </Banner>
      )}
      {status.enabled && !enf.detect_only && (
        <Banner tone="info">
          {enf.inline
            ? 'Inline: listed addresses are dropped for every device, in the directions switched on in Settings.'
            : `Enforcing for ${enf.intercepted_clients} intercepted device${enf.intercepted_clients === 1 ? '' : 's'}. Other devices are watched: their hits are recorded, not dropped.`}
        </Banner>
      )}

      <div className="grid c4">
        <Stat label="Listed addresses" value={num(status.entries)}
          sub={status.excluded_by_allow > 0 ? `${status.excluded_by_allow} left out by your allow list` : status.last_build ? `built ${ago(status.last_build)}` : 'not built yet'} />
        <Stat label="Active bans" value={num(status.decisions)} sub={sources || 'none'} />
        <Stat label="Hits, last 24h" value={num(status.hits_24h)} tone={status.hits_24h > 0 ? 'amber' : undefined}
          sub={status.hits_24h > 0 ? `${status.dropped_24h} dropped, ${status.hits_24h - status.dropped_24h} recorded only` : 'nothing touched a listed address'} />
        <Stat label="Attacks, last 24h" value={num(idsData?.bans_24h ?? 0)} tone={(idsData?.bans_24h ?? 0) > 0 ? 'amber' : undefined}
          sub={idsData ? `${Object.values(idsData.alerts_24h ?? {}).reduce((a, b) => a + b, 0)} alert(s) from ${idsData.lines > 0 ? num(idsData.lines) + ' log lines' : 'logs and flows'}${cs.enabled ? ', CrowdSec on' : ''}` : 'detector starting'} />
      </div>

      <div className="toolbar">
        <Segmented value={tab} onChange={setTab} options={[
          { value: 'attacks', label: `Attacks (${idsData?.alerts?.length ?? 0})` },
          { value: 'hits', label: `Hits (${hitsData?.hits.length ?? 0})` },
          { value: 'feeds', label: `Feeds (${feedsData?.feeds.length ?? 0})` },
          { value: 'bans', label: `Bans (${bansData?.decisions.length ?? 0})` },
          { value: 'countries', label: `Countries (${countryData?.countries.length ?? 0})` },
          { value: 'crowdsec', label: 'CrowdSec' },
        ]} />
        <div className="spacer" />
        {(tab === 'hits' || tab === 'attacks') && (
          <Segmented value={String(hours)} onChange={(v) => setHours(Number(v))}
            options={[{ value: '24', label: '24h' }, { value: '168', label: '7d' }, { value: '720', label: '30d' }]} />
        )}
        {tab === 'feeds' && (
          <button className="btn" disabled={busy === 'refresh'}
            onClick={() => act('refresh', () => api.threat.refresh(), 'Refreshing every feed')}>
            <Icons.refresh size={14} /> Refresh feeds
          </button>
        )}
        <a className="btn" href="#/settings/threats">Settings</a>
      </div>

      {tab === 'attacks' && (idsData ? <AttacksTab data={idsData} busy={busy} act={act} /> : <Loading what="intrusion detection" />)}
      {tab === 'hits' && <HitsTable hits={hitsData?.hits ?? []} devices={hitsData?.devices ?? {}} hours={hours} />}
      {tab === 'feeds' && <FeedsTab feeds={feedsData?.feeds ?? []} busy={busy} act={act} />}
      {tab === 'bans' && <BansTab bans={bansData?.decisions ?? []} busy={busy} act={act} />}
      {tab === 'countries' && countryData && <CountriesTab data={countryData} busy={busy} act={act} />}
      {tab === 'crowdsec' && <CrowdSecTab status={status} />}
    </div>
  )
}

function HitsTable({ hits, devices, hours }: {
  hits: ThreatHit[]; devices: Record<string, { id: string; name: string; ip: string }>; hours: number
}) {
  if (hits.length === 0) {
    return (
      <Card>
        <Empty title={`No device touched a listed address in the last ${hours === 24 ? 'day' : hours === 168 ? 'week' : '30 days'}`}>
          That is the normal state of a healthy network. A hit here means a device connected to, or was reached from,
          an address on a threat feed or a ban list.
        </Empty>
      </Card>
    )
  }
  return (
    <Card flush>
      <div className="table-wrap">
        <table className="t">
          <thead>
            <tr><th>When</th><th>Device</th><th></th><th>Address</th><th>Listed by</th><th>Port</th><th>Result</th></tr>
          </thead>
          <tbody>
            {hits.map((h) => {
              const dev = h.client_id ? devices[h.client_id] : undefined
              return (
                <tr key={h.id}>
                  <td className="hint" style={{ whiteSpace: 'nowrap' }}>{ago(h.ts)}</td>
                  <td>{dev?.name || h.local_ip || 'unknown'}</td>
                  <td title={h.direction === 'in' ? 'inbound: the listed address connected in' : 'outbound: the device connected out'}>
                    {h.direction === 'in' ? '←' : '→'}
                  </td>
                  <td>
                    <span className="mono">{h.remote_ip}</span>
                    {(h.country || h.as_org) && (
                      <span className="hint" style={{ marginLeft: 6 }}>{h.country ? countryFlag(h.country) : ''} {h.as_org}</span>
                    )}
                  </td>
                  <td>{h.source}{h.reason ? <span className="hint"> · {h.reason}</span> : null}</td>
                  <td className="mono">{h.port ? `${h.port}/${h.proto || 'tcp'}` : ''}</td>
                  <td>
                    {h.enforced
                      ? <span className="tag ok">dropped</span>
                      : <span className="tag warn" title="This node is not in the path for that device, so it could only record the connection">recorded</span>}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </Card>
  )
}

function FeedsTab({ feeds, busy, act }: { feeds: ThreatFeed[]; busy: string | null; act: (k: string, fn: () => Promise<unknown>, ok: string) => Promise<void> }) {
  const [name, setName] = useState('')
  const [url, setUrl] = useState('')
  const [category, setCategory] = useState('other')
  return (
    <>
      <Card flush>
        <div className="table-wrap">
          <table className="t">
            <thead><tr><th>Feed</th><th>Category</th><th>Entries</th><th>Updated</th><th>On</th><th></th></tr></thead>
            <tbody>
              {feeds.map((f) => (
                <tr key={f.name}>
                  <td>
                    <div>{f.name}</div>
                    <div className="hint mono truncate" style={{ maxWidth: 360, fontSize: 11 }} title={f.url}>{f.url}</div>
                  </td>
                  <td><span className="tag">{f.category || 'other'}</span></td>
                  <td className="mono">{num(f.entries)}{f.skipped > 0 && <span className="hint" title="Lines that were not usable: local or reserved ranges, comments, unparseable"> +{f.skipped} skipped</span>}</td>
                  <td>
                    {f.last_error
                      ? <span className="tag err" title={f.last_error}>failed</span>
                      : f.fetched_at ? <span className="hint">{ago(f.fetched_at)}</span> : <span className="hint">never</span>}
                    {f.last_error && <div className="hint" style={{ fontSize: 11, maxWidth: 320 }}>{f.last_error}</div>}
                  </td>
                  <td>
                    <Switch checked={f.enabled} disabled={busy === 'feed:' + f.name}
                      onChange={(v) => act('feed:' + f.name, () => api.threat.saveFeed({ name: f.name, url: f.url, category: f.category, enabled: v }), v ? `${f.name} on` : `${f.name} off`)} />
                  </td>
                  <td>
                    <button className="btn sm" disabled={busy === 'del:' + f.name} title="Remove this feed"
                      onClick={() => act('del:' + f.name, () => api.threat.deleteFeed(f.name), 'Feed removed')}><Icons.trash size={13} /></button>
                  </td>
                </tr>
              ))}
              {feeds.length === 0 && <tr><td colSpan={6}><Empty title="No feeds configured" /></td></tr>}
            </tbody>
          </table>
        </div>
      </Card>
      <Card title="Add a feed">
        <div style={{ display: 'grid', gap: 12 }}>
          <div className="hint">One address or CIDR per line, comments after # or ;. Private and reserved ranges in a feed are ignored, and no feed can black out more than a /8.</div>
          <div style={{ display: 'grid', gap: 10, gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))' }}>
            <Field label="Name"><input className="input" value={name} onChange={(e) => setName(e.target.value)} placeholder="My blocklist" /></Field>
            <Field label="URL"><input className="input mono" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://…/list.txt" /></Field>
            <Field label="Category">
              <select className="input" value={category} onChange={(e) => setCategory(e.target.value)}>
                {CATEGORIES.map((c) => <option key={c} value={c}>{c}</option>)}
              </select>
            </Field>
          </div>
          <div>
            <button className="btn primary" disabled={!name.trim() || !url.trim() || busy === 'add'}
              onClick={() => act('add', async () => {
                await api.threat.saveFeed({ name: name.trim(), url: url.trim(), category, enabled: true })
                setName(''); setUrl('')
              }, 'Feed added; fetching it now')}>Add feed</button>
          </div>
        </div>
      </Card>
    </>
  )
}

function BansTab({ bans, busy, act }: { bans: ThreatDecision[]; busy: string | null; act: (k: string, fn: () => Promise<unknown>, ok: string) => Promise<void> }) {
  const [value, setValue] = useState('')
  const [hours, setHours] = useState('24')
  const [reason, setReason] = useState('')
  return (
    <>
      <Card title="Ban an address or range">
        <div style={{ display: 'grid', gap: 12 }}>
          <div style={{ display: 'grid', gap: 10, gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))' }}>
            <Field label="Address or CIDR"><input className="input mono" value={value} onChange={(e) => setValue(e.target.value)} placeholder="203.0.113.7 or 198.51.100.0/24" /></Field>
            <Field label="For">
              <select className="input" value={hours} onChange={(e) => setHours(e.target.value)}>
                <option value="1">1 hour</option><option value="24">1 day</option><option value="168">1 week</option><option value="720">30 days</option><option value="0">Permanently</option>
              </select>
            </Field>
            <Field label="Reason"><input className="input" value={reason} onChange={(e) => setReason(e.target.value)} placeholder="brute force against the NAS" /></Field>
          </div>
          <div className="hint">Local and reserved addresses are refused here: to cut a device off, pause or block it on the Devices page.</div>
          <div>
            <button className="btn primary" disabled={!value.trim() || busy === 'ban'}
              onClick={() => act('ban', async () => {
                await api.threat.ban({ value: value.trim(), hours: Number(hours), reason: reason.trim() })
                setValue(''); setReason('')
              }, 'Banned')}>Ban</button>
          </div>
        </div>
      </Card>
      <Card flush>
        <div className="table-wrap">
          <table className="t">
            <thead><tr><th>Address</th><th>Source</th><th>Reason</th><th>Added</th><th>Expires</th><th></th></tr></thead>
            <tbody>
              {bans.map((b) => (
                <tr key={b.id}>
                  <td className="mono">{b.value}</td>
                  <td><span className={`tag ${b.source === 'crowdsec' ? 'info' : ''}`}>{b.source}</span>{b.origin && b.origin !== b.source ? <span className="hint"> {b.origin}</span> : null}</td>
                  <td>{b.reason || <span className="hint">none given</span>}</td>
                  <td className="hint" style={{ whiteSpace: 'nowrap' }}>{ago(b.created)}{b.actor && b.actor !== b.source ? ` by ${b.actor}` : ''}</td>
                  <td className="hint" style={{ whiteSpace: 'nowrap' }}>{b.until ? `in ${ago(b.until).replace(' ago', '')}` : 'never'}</td>
                  <td>
                    {b.source === 'crowdsec'
                      ? <span className="hint" title="This decision belongs to the CrowdSec engine; lift it with cscli">from CrowdSec</span>
                      : <button className="btn sm" disabled={busy === 'unban:' + b.id}
                        onClick={() => act('unban:' + b.id, () => api.threat.unban(b.id), 'Ban lifted')}>Lift</button>}
                  </td>
                </tr>
              ))}
              {bans.length === 0 && <tr><td colSpan={6}><Empty title="No active bans">Bans added here, by the assistant, by the scan detector or by CrowdSec appear in this list with their expiry.</Empty></td></tr>}
            </tbody>
          </table>
        </div>
      </Card>
    </>
  )
}

function CrowdSecTab({ status }: { status: { crowdsec: { enabled: boolean; url: string; configured: boolean; poll_seconds: number; decisions: number; ignored: number; last_error: string; last_pull?: string } } }) {
  const cs = status.crowdsec
  return (
    <Card title="CrowdSec bouncer" actions={<a className="btn sm" href="#/settings/threats">Configure</a>}>
      <div style={{ display: 'grid', gap: 12 }}>
        <div className="hint" style={{ lineHeight: 1.7 }}>
          CrowdSec reads the logs of the servers you expose and turns brute force, scanning and credential stuffing into
          timed bans, then shares attacker addresses across its community. Orbis does not do any of that; it can act as
          the enforcement point, the bouncer: it pulls the engine's decisions and drops those addresses at the gateway.
          Run CrowdSec on the machine that serves the internet; point this node at its Local API.
        </div>
        <dl className="kv">
          <dt>State</dt><dd>{cs.enabled ? (cs.last_error ? `error: ${cs.last_error}` : cs.last_pull ? `connected, last pull ${ago(cs.last_pull)}` : 'waiting for the first pull') : 'off'}</dd>
          <dt>Local API</dt><dd>{cs.url || 'not set'}{cs.enabled && !cs.configured ? ' (url or key missing)' : ''}</dd>
          <dt>Active bans from CrowdSec</dt><dd>{num(cs.decisions)}</dd>
          <dt>Decisions ignored</dt><dd>{num(cs.ignored)} <span className="hint">(captcha and other non-ban types, or scopes a gateway cannot act on)</span></dd>
          <dt>Poll interval</dt><dd>{cs.poll_seconds}s</dd>
        </dl>
        <div className="hint">
          On the CrowdSec machine: <code>cscli bouncers add orbis</code>, then paste the key into Settings → Threat intelligence.
        </div>
      </div>
    </Card>
  )
}


const names = typeof Intl !== 'undefined' && 'DisplayNames' in Intl ? new Intl.DisplayNames(['en'], { type: 'region' }) : null
function countryName(code: string): string {
  try { return names?.of(code) ?? code } catch { return code }
}

function CountriesTab({ data, busy, act }: { data: CountryStatus; busy: string | null; act: (k: string, fn: () => Promise<unknown>, ok: string) => Promise<void> }) {
  const [code, setCode] = useState('')
  const [domains, setDomains] = useState((data.exempt_domains ?? []).join(', '))
  const [ips, setIps] = useState((data.exempt_ips ?? []).join(', '))
  const listed = new Set(data.countries)
  const seen = (data.seen ?? []).filter((s) => s.country)
  const verb = data.mode === 'allow' ? 'Only allowing' : 'Blocking'
  return (
    <>
      <Card title="Country rules" actions={
        <Switch checked={data.enabled} disabled={busy === 'toggle' || data.countries.length === 0}
          onChange={(v) => act('toggle', () => api.country.rule('', v ? 'enable' : 'disable'), v ? 'Country rules are on' : 'Country rules are off')} />
      }>
        <div style={{ display: 'grid', gap: 12 }}>
          <div className="hint" style={{ lineHeight: 1.7 }}>
            Decided by where an address is registered. Names that resolve into a blocked country are refused by the resolver for every device;
            connections to or from one are marked and, where this node is in the path, dropped; in block mode the countries' address ranges
            are also loaded into the packet filter. A CDN with servers in many countries may be affected: add its domain as an exception.
          </div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
            <Segmented value={data.mode} onChange={(v) => act('mode', () => api.country.rule('', v === 'allow' ? 'mode_allow' : 'mode_block'), v === 'allow' ? 'Allow mode: everything not listed is blocked' : 'Block mode: what is listed is blocked')}
              options={[{ value: 'block', label: 'Block listed' }, { value: 'allow', label: 'Allow only listed' }]} />
            <span className="hint">{data.enabled ? `${verb} ${data.countries.length} countr${data.countries.length === 1 ? 'y' : 'ies'}.` : 'Off.'}
              {data.packet_sets && data.set_total > 0 ? ` ${num(data.set_total)} address ranges loaded.` : ''}
              {data.building ? ' Building sets…' : ''}
              {data.mode === 'allow' ? ' Allow mode enforces at the resolver and per connection; the packet filter carries only exemptions.' : ''}
            </span>
          </div>
          {data.error && <Banner tone="warn">{data.error}</Banner>}
          {data.enabled && data.enforcement?.detect_only && (
            <Banner tone="info">Names are refused for every device that uses this resolver. Connections that bypass DNS are recorded, not dropped, because this node is not in the path.</Banner>
          )}
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
            {data.countries.map((c) => (
              <span key={c} className="tag" style={{ display: 'inline-flex', gap: 6, alignItems: 'center' }}>
                {flag(c)} {countryName(c)} <span className="hint mono">{c}</span>
                {data.set_sizes?.[c] ? <span className="hint">{num(data.set_sizes[c])} ranges</span> : null}
                <button className="btn sm" disabled={busy === 'rm:' + c} onClick={() => act('rm:' + c, () => api.country.rule(c, 'remove'), `${countryName(c)} removed`)} title="Remove">×</button>
              </span>
            ))}
            {data.countries.length === 0 && <span className="hint">no countries listed yet</span>}
          </div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
            <input className="input mono" style={{ width: 90 }} value={code} placeholder="CN" maxLength={2} onChange={(e) => setCode(e.target.value.toUpperCase())}
              onKeyDown={(e) => { if (e.key === 'Enter' && code.length === 2) act('add', () => api.country.rule(code, 'add'), `${countryName(code)} added`).then(() => setCode('')) }} />
            <button className="btn" disabled={code.length !== 2 || busy === 'add'} onClick={() => act('add', () => api.country.rule(code, 'add'), `${countryName(code)} added`).then(() => setCode(''))}>Add {code.length === 2 ? countryName(code) : 'country'}</button>
            <span className="hint">Two-letter code. Adding a country turns the rules on.</span>
          </div>
          <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
            <label style={{ display: 'flex', gap: 8, alignItems: 'center', fontSize: 13 }}><Switch checked={data.block_outbound} onChange={(v) => act('out', () => api.config.patch({ 'country.block_outbound': v }), 'Saved')} /> devices reaching those countries</label>
            <label style={{ display: 'flex', gap: 8, alignItems: 'center', fontSize: 13 }}><Switch checked={data.block_inbound} onChange={(v) => act('in', () => api.config.patch({ 'country.block_inbound': v }), 'Saved')} /> those countries reaching in</label>
            <label style={{ display: 'flex', gap: 8, alignItems: 'center', fontSize: 13 }}><Switch checked={data.dns} onChange={(v) => act('dns', () => api.config.patch({ 'country.dns': v }), 'Saved')} /> refuse names at the resolver</label>
          </div>
          <div style={{ display: 'grid', gap: 10, gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))' }}>
            <Field label="Exempt domains" hint="Comma-separated suffixes the rule ignores, e.g. a CDN or a game.">
              <input className="input mono" value={domains} onChange={(e) => setDomains(e.target.value)}
                onBlur={() => act('exd', () => api.config.patch({ 'country.exempt_domains': domains.split(',').map((x) => x.trim()).filter(Boolean) }), 'Exemptions saved')} />
            </Field>
            <Field label="Exempt addresses" hint="Comma-separated IPs or ranges.">
              <input className="input mono" value={ips} onChange={(e) => setIps(e.target.value)}
                onBlur={() => act('exi', () => api.config.patch({ 'country.exempt_ips': ips.split(',').map((x) => x.trim()).filter(Boolean) }), 'Exemptions saved')} />
            </Field>
          </div>
        </div>
      </Card>

      <Card title="Countries your traffic went to, last 7 days" flush>
        <div className="table-wrap">
          <table className="t">
            <thead><tr><th>Country</th><th>Connections</th><th>Bytes</th><th>Refused</th><th></th></tr></thead>
            <tbody>
              {seen.map((s) => (
                <tr key={s.country}>
                  <td>{flag(s.country)} {countryName(s.country)} <span className="hint mono">{s.country}</span></td>
                  <td className="mono">{num(s.connections)}</td>
                  <td className="mono">{bytes(s.bytes)}</td>
                  <td className="mono">{num((data.counters?.['dns:' + s.country] ?? 0) + (data.counters?.['flow:' + s.country] ?? 0))}</td>
                  <td>
                    {listed.has(s.country)
                      ? <button className="btn sm" onClick={() => act('rm:' + s.country, () => api.country.rule(s.country, 'remove'), `${countryName(s.country)} removed`)}>Remove</button>
                      : <button className="btn sm" onClick={() => act('add:' + s.country, () => api.country.rule(s.country, 'add'), `${countryName(s.country)} added`)}>{data.mode === 'allow' ? 'Allow' : 'Block'}</button>}
                  </td>
                </tr>
              ))}
              {seen.length === 0 && <tr><td colSpan={5}><Empty title="No country data yet" /></td></tr>}
            </tbody>
          </table>
        </div>
      </Card>
    </>
  )
}


const SOURCE_LABEL: Record<string, string> = { journal: 'this node', syslog: 'syslog', file: 'this node', orbis: 'Orbis login', flows: 'connections' }

function AttacksTab({ data, busy, act }: { data: IDSStatus; busy: string | null; act: (k: string, fn: () => Promise<unknown>, ok: string) => Promise<void> }) {
  const [line, setLine] = useState('')
  const [result, setResult] = useState<Record<string, unknown> | null>(null)
  const [ignore, setIgnore] = useState((data.ignore ?? []).join(', '))
  const toast = useToast()
  const nodeIP = typeof location !== 'undefined' ? location.hostname : 'orbis'
  const port = (data.syslog?.listen ?? ':514').split(':').pop()
  const titles = Object.fromEntries((data.rules ?? []).map((r) => [r.kind, r.title]))
  return (
    <>
      <Card title="Intrusion detection" actions={
        <Switch checked={data.enabled} disabled={busy === 'ids'} onChange={(v) => act('ids', () => api.config.patch({ 'ids.enabled': v }), v ? 'Detection is on' : 'Detection is off')} />
      }>
        <div style={{ display: 'grid', gap: 12 }}>
          <div className="hint" style={{ lineHeight: 1.7 }}>
            Repeated failures from one address become a timed ban at the gateway, longer each time it comes back: SSH, NAS, web and
            app logins, remote desktop and VPN handshakes from logs; port scans, host sweeps, floods and knocking on sensitive ports
            from the flow table. An address inside your network is reported, never banned. Bans land on the Bans tab and are enforced
            wherever this node is in the path.
          </div>
          <div className="grid c3">
            <div className="card" style={{ padding: 12 }}>
              <div className="stat-label">This node's log</div>
              <div style={{ marginTop: 4 }}>{data.journal || data.auth_log ? <span className="tag ok">reading {data.auth_log ? data.auth_log : 'the journal'}</span> : <span className="tag">off</span>}</div>
              <div className="hint" style={{ marginTop: 6 }}>{num(data.lines)} lines read{data.last_line ? `, last ${ago(data.last_line)}` : ''}. sshd, login, mail and VPN failures.</div>
            </div>
            <div className="card" style={{ padding: 12 }}>
              <div className="stat-label">Syslog from other hosts</div>
              <div style={{ marginTop: 4 }}>{data.syslog?.running ? <span className="tag ok">listening on {data.syslog.listen}</span> : data.syslog?.error ? <span className="tag err" title={data.syslog.error}>failed</span> : <span className="tag">off</span>}</div>
              <div className="hint" style={{ marginTop: 6 }}>
                {(data.syslog?.hosts ?? []).length > 0 ? `Hearing from ${(data.syslog?.hosts ?? []).join(', ')}.` : 'Nothing received yet.'} Forward with rsyslog: <code>*.* @{nodeIP}:{port}</code>, or a NAS's log forwarding.
              </div>
            </div>
            <div className="card" style={{ padding: 12 }}>
              <div className="stat-label">Connections</div>
              <div style={{ marginTop: 4 }}>{data.flows ? <span className="tag ok">watching inbound</span> : <span className="tag">off</span>}</div>
              <div className="hint" style={{ marginTop: 6 }}>Scans, sweeps, floods and sensitive ports, from what this node sees{data.enforcement?.detect_only ? ' (its own and intercepted traffic)' : ''}.</div>
            </div>
          </div>
          <div style={{ display: 'grid', gap: 10, gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))' }}>
            <Field label="Never act on" hint="Comma-separated addresses or ranges: your monitoring host, a scanner you run.">
              <input className="input mono" value={ignore} onChange={(e) => setIgnore(e.target.value)}
                onBlur={() => act('ign', () => api.config.patch({ 'ids.ignore': ignore.split(',').map((x) => x.trim()).filter(Boolean) }), 'Saved')} />
            </Field>
            <Field label="Test a log line" hint="Paste a line from a server to see whether it would count, before an attack proves it.">
              <div style={{ display: 'flex', gap: 6 }}>
                <input className="input mono" value={line} onChange={(e) => setLine(e.target.value)} placeholder="Failed password for root from 203.0.113.9 port 2 ssh2" />
                <button className="btn" disabled={!line.trim()} onClick={async () => {
                  try { setResult(await api.ids.test(line)) } catch (e) { toast(e instanceof Error ? e.message : 'Could not test', 'err') }
                }}>Test</button>
              </div>
              {result && (
                <div className="hint" style={{ marginTop: 6 }}>
                  {result.matched ? `Counts as ${String(result.title)} for ${String(result.ip)}${result.host ? ` (host ${String(result.host)})` : ''}: ${String(result.threshold)} in ${Math.round(Number(result.window_seconds) / 60)} min earns a ban.` : 'No scenario recognises that line.'}
                </div>
              )}
            </Field>
          </div>
          <details>
            <summary className="hint" style={{ cursor: 'pointer' }}>Scenarios and thresholds</summary>
            <div className="table-wrap" style={{ marginTop: 8 }}><table className="t">
              <thead><tr><th>Scenario</th><th>Fires at</th><th>Ban</th><th>Alerts 24h</th></tr></thead>
              <tbody>{(data.rules ?? []).map((r) => (
                <tr key={r.kind}><td>{r.title} <span className="hint mono">{r.kind}</span></td>
                  <td className="hint">{r.threshold} in {Math.round(r.window_seconds / 60)} min</td>
                  <td className="hint">{r.ban_seconds >= 3600 ? `${Math.round(r.ban_seconds / 3600)} h` : `${Math.round(r.ban_seconds / 60)} min`}, doubling for repeat offenders</td>
                  <td className="mono">{num(data.alerts_24h?.[r.kind] ?? 0)}</td></tr>
              ))}</tbody>
            </table></div>
          </details>
        </div>
      </Card>

      <Card title="Alerts" flush>
        <div className="table-wrap">
          <table className="t">
            <thead><tr><th>When</th><th>Address</th><th>What</th><th>Seen on</th><th>Result</th></tr></thead>
            <tbody>
              {(data.alerts ?? []).map((a) => (
                <tr key={a.id}>
                  <td className="hint" style={{ whiteSpace: 'nowrap' }}>{ago(a.ts)}</td>
                  <td><span className="mono">{a.ip}</span>{(a.country || a.as_org) && <span className="hint" style={{ marginLeft: 6 }}>{a.country ? flag(a.country) : ''} {a.as_org}</span>}</td>
                  <td>{titles[a.scenario] ?? a.scenario} <span className="hint">· {a.count} in window</span>{a.sample && <div className="hint mono" style={{ fontSize: 11, maxWidth: 420 }} title={a.sample}>{a.sample.slice(0, 90)}</div>}</td>
                  <td className="hint">{a.host || SOURCE_LABEL[a.source] || a.source}</td>
                  <td>{a.action === 'ban' ? <span className="tag ok">banned{a.ban_until ? ` until ${ago(a.ban_until).replace(' ago', '')}` : ''}</span> : a.action === 'reported' ? <span className="tag warn" title="Inside the network: reported, not banned">reported</span> : <span className="tag err">ban failed</span>}</td>
                </tr>
              ))}
              {(data.alerts ?? []).length === 0 && <tr><td colSpan={5}><Empty title="No attacks detected in this window">That is the normal state. When a scenario fires it appears here with the address, what it did, and the ban.</Empty></td></tr>}
            </tbody>
          </table>
        </div>
      </Card>

      {(data.offenders ?? []).length > 0 && (
        <Card title="Worst offenders" flush>
          <div className="table-wrap"><table className="t">
            <thead><tr><th>Address</th><th>Alerts</th><th>Bans</th><th>Scenarios</th><th>Last seen</th></tr></thead>
            <tbody>{(data.offenders ?? []).map((o) => (
              <tr key={o.ip}>
                <td><span className="mono">{o.ip}</span>{(o.country || o.as_org) && <span className="hint" style={{ marginLeft: 6 }}>{o.country ? flag(o.country) : ''} {o.as_org}</span>}</td>
                <td className="mono">{o.alerts}</td><td className="mono">{o.bans}</td>
                <td className="hint">{o.scenarios.map((k) => titles[k] ?? k).join(', ')}</td>
                <td className="hint">{ago(o.last)}</td>
              </tr>
            ))}</tbody>
          </table></div>
        </Card>
      )}
    </>
  )
}
