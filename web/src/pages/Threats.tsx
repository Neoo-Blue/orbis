import { useState } from 'react'
import { api } from '../api'
import { usePoll } from '../hooks'
import { Banner, Card, Empty, Field, Icons, Loading, Segmented, Stat, Switch, useToast } from '../ui'
import { ago, countryFlag, num } from '../format'
import type { ThreatDecision, ThreatFeed, ThreatHit } from '../types'

/**
 * Threats: IP-level threat intelligence. Where the DNS pages work on names,
 * this page works on addresses: the feeds that supply them, the bans the
 * operator (or the assistant, the scan detector, a CrowdSec engine) added,
 * and every connection that touched one of them. The enforcement banner is
 * the most important line on the page: a hit that was only recorded and a
 * hit that was dropped must never look the same.
 */
type Tab = 'hits' | 'feeds' | 'bans' | 'crowdsec'

const CATEGORIES = ['c2', 'hijacked', 'attackers', 'compromised', 'spam', 'other']

export function ThreatsPage() {
  const [tab, setTab] = useState<Tab>('hits')
  const [hours, setHours] = useState(24)
  const { data: status, refresh: refreshStatus } = usePoll(() => api.threat.status(), 15000)
  const { data: hitsData, refresh: refreshHits } = usePoll(() => api.threat.hits(hours, 300), 15000, [hours])
  const { data: feedsData, refresh: refreshFeeds } = usePoll(() => api.threat.feeds(), 30000)
  const { data: bansData, refresh: refreshBans } = usePoll(() => api.threat.decisions(), 15000)
  const toast = useToast()
  const [busy, setBusy] = useState<string | null>(null)

  const refreshAll = () => { refreshStatus(); refreshHits(); refreshFeeds(); refreshBans() }
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
        <Stat label="CrowdSec" value={cs.enabled ? (cs.last_error ? 'error' : cs.last_pull ? 'connected' : 'connecting') : 'off'}
          tone={cs.enabled && cs.last_error ? 'red' : cs.enabled && cs.last_pull ? 'accent' : undefined}
          sub={cs.enabled ? (cs.last_error || (cs.last_pull ? `${cs.decisions} bans, pulled ${ago(cs.last_pull)}` : 'waiting for the first pull')) : 'not acting as a bouncer'} />
      </div>

      <div className="toolbar">
        <Segmented value={tab} onChange={setTab} options={[
          { value: 'hits', label: `Hits (${hitsData?.hits.length ?? 0})` },
          { value: 'feeds', label: `Feeds (${feedsData?.feeds.length ?? 0})` },
          { value: 'bans', label: `Bans (${bansData?.decisions.length ?? 0})` },
          { value: 'crowdsec', label: 'CrowdSec' },
        ]} />
        <div className="spacer" />
        {tab === 'hits' && (
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

      {tab === 'hits' && <HitsTable hits={hitsData?.hits ?? []} devices={hitsData?.devices ?? {}} hours={hours} />}
      {tab === 'feeds' && <FeedsTab feeds={feedsData?.feeds ?? []} busy={busy} act={act} />}
      {tab === 'bans' && <BansTab bans={bansData?.decisions ?? []} busy={busy} act={act} />}
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
