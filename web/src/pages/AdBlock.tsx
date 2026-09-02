import { useMemo, useState } from 'react'
import { api } from '../api'
import { usePoll } from '../hooks'
import {
  Banner, Card, Empty, Icons, Loading, Search, Segmented, Stat, Switch, useToast,
} from '../ui'
import { ago, compact, pct, scoreTone } from '../format'
import type { AdCandidate, LocalRule } from '../types'

type Tab = 'overview' | 'discovered' | 'rules' | 'lists' | 'youtube'

export function AdBlockPage() {
  const [tab, setTab] = useState<Tab>('overview')
  const { data: summary } = usePoll(() => api.summary(24), 15000)
  const { data: candidates, refresh: refreshCandidates } = usePoll(
    () => api.adblock.candidates({ limit: 300 }), 20000,
  )

  const pending = (candidates?.candidates ?? []).filter(
    (c) => c.status === 'candidate' || c.status === 'review',
  ).length

  return (
    <div style={{ display: 'grid', gap: 14 }}>
      <div className="toolbar" style={{ marginBottom: 0 }}>
        <Segmented
          value={tab} onChange={setTab}
          options={[
            { value: 'overview', label: 'Overview' },
            { value: 'discovered', label: `Discovered${pending ? ` (${pending})` : ''}` },
            { value: 'rules', label: 'My rules' },
            { value: 'lists', label: 'Lists' },
            { value: 'youtube', label: 'In-stream ads' },
          ]}
        />
      </div>

      {tab === 'overview' && <Overview summary={summary} />}
      {tab === 'discovered' && (
        <Discovered candidates={candidates?.candidates ?? []} onChanged={refreshCandidates} />
      )}
      {tab === 'rules' && <LocalRules />}
      {tab === 'lists' && <Lists />}
      {tab === 'youtube' && <InStream />}
    </div>
  )
}

function Overview({ summary }: { summary: ReturnType<typeof usePoll<import('../types').Summary>>['data'] }) {
  const { data: topBlocked } = usePoll(() => api.adblock.topBlocked(24, 20), 30000)
  const { data: status } = usePoll(() => api.adblock.status(), 15000)
  const toast = useToast()

  if (!summary) return <Loading what="ad blocking" />

  return (
    <>
      <div className="grid c4">
        <Stat label="Blocked today" value={compact(summary.dns_blocked)} tone="amber"
          sub={`${pct(summary.block_rate, 1)} of all lookups`} />
        <Stat label="Rules indexed" value={compact(Number(status?.entries ?? 0))} tone="accent"
          sub={`${summary.blocklist_entries.toLocaleString()} from subscriptions`} />
        <Stat label="Awaiting review" value={String(summary.ad_candidates)}
          tone={summary.ad_candidates > 0 ? 'blue' : undefined}
          sub="domains smart capture flagged" />
        <Stat label="Matcher hits" value={compact(Number(status?.hits ?? 0))}
          sub={`${compact(Number(status?.misses ?? 0))} misses`} />
      </div>

      <Card title="Most blocked in the last 24 hours" actions={
        <button className="btn sm" onClick={async () => {
          await api.adblock.refresh()
          toast('Refreshing every enabled list in the background', 'ok')
        }}><Icons.refresh size={13} /> Update lists</button>
      } flush>
        {!topBlocked?.domains.length ? (
          <Empty title="Nothing blocked yet">
            If the lists have just been added, give the first download a minute.
          </Empty>
        ) : (
          <div className="table-wrap">
            <table className="t">
              <thead><tr><th>Domain</th><th>Blocked by</th><th className="num">Requests</th><th style={{ width: 90 }} /></tr></thead>
              <tbody>
                {topBlocked.domains.map((d) => (
                  <tr key={d.domain}>
                    <td className="mono truncate" style={{ fontSize: 12 }}>{d.domain}</td>
                    <td style={{ color: 'var(--text-faint)', fontSize: 11.5 }}>{d.source || 'list'}</td>
                    <td className="num">{compact(d.count)}</td>
                    <td>
                      <button className="btn sm" onClick={async () => {
                        await api.adblock.addRule({ domain: d.domain, action: 'allow', note: 'allowed from top-blocked list' })
                        await api.dns.flush(d.domain)
                        toast(`${d.domain} is now allowed`, 'ok')
                      }}>Allow</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </>
  )
}

/**
 * The smart-capture review queue. Each row shows the evidence behind the
 * score, because an operator asked to approve a block deserves to see why the
 * system thinks it is an ad server.
 */
function Discovered({ candidates, onChanged }: { candidates: AdCandidate[]; onChanged: () => void }) {
  const [statusFilter, setStatusFilter] = useState<'pending' | 'blocked' | 'dismissed'>('pending')
  const [query, setQuery] = useState('')
  const toast = useToast()

  const visible = useMemo(() => {
    const q = query.toLowerCase()
    return candidates
      .filter((c) => {
        if (statusFilter === 'pending') return c.status === 'candidate' || c.status === 'review'
        return c.status === statusFilter
      })
      .filter((c) => !q || c.domain.includes(q))
      .sort((a, b) => b.final_score - a.final_score)
  }, [candidates, statusFilter, query])

  const decide = async (domain: string, decision: 'block' | 'allow' | 'dismiss') => {
    try {
      await api.adblock.decide(domain, decision)
      toast(`${domain}: ${decision === 'block' ? 'blocked' : decision === 'allow' ? 'allowed' : 'dismissed'}`, 'ok')
      onChanged()
    } catch (e) {
      toast(e instanceof Error ? e.message : 'Could not apply that', 'err')
    }
  }

  return (
    <>
      <Banner tone="info">
        Smart capture watches which hostnames devices reach for, how they were referred, and how
        the responses behave. Domains it is confident about are blocked automatically; the ones
        below are the calls it did not want to make alone.
      </Banner>

      <div className="toolbar" style={{ marginBottom: 0 }}>
        <Search value={query} onChange={setQuery} placeholder="Filter domains…" />
        <Segmented value={statusFilter} onChange={setStatusFilter}
          options={[
            { value: 'pending', label: 'Needs review' },
            { value: 'blocked', label: 'Auto-blocked' },
            { value: 'dismissed', label: 'Dismissed' },
          ]} />
        <div style={{ flex: 1 }} />
        <button className="btn sm" onClick={async () => {
          await api.adblock.scan()
          toast('Scoring pass started', 'ok')
        }}><Icons.spark size={13} /> Score now</button>
      </div>

      {visible.length === 0 ? (
        <Card><Empty title="Nothing here">
          {statusFilter === 'pending'
            ? 'No domains are waiting on a decision. New candidates appear as devices reach hosts no list covers.'
            : 'Nothing in this category yet.'}
        </Empty></Card>
      ) : (
        <div style={{ display: 'grid', gap: 10 }}>
          {visible.map((c) => <CandidateCard key={c.domain} candidate={c} onDecide={decide} />)}
        </div>
      )}
    </>
  )
}

function CandidateCard({ candidate: c, onDecide }: {
  candidate: AdCandidate
  onDecide: (domain: string, d: 'block' | 'allow' | 'dismiss') => void
}) {
  const [expanded, setExpanded] = useState(false)
  const features = (c.features ?? {}) as Record<string, unknown>
  const referrers = (features.referrers as string[]) ?? []
  const keywords = (features.keywords as string[]) ?? []
  const tone = scoreTone(c.final_score)

  return (
    <div className="card">
      <div style={{ padding: '12px 14px', display: 'flex', gap: 13, alignItems: 'flex-start' }}>
        <div style={{ minWidth: 52, textAlign: 'center' }}>
          <div className={`stat-value ${tone === 'block' ? 'red' : tone === 'warn' ? 'amber' : 'blue'}`}
            style={{ fontSize: 21, margin: 0 }}>
            {Math.round(c.final_score * 100)}
          </div>
          <div style={{ fontSize: 9.5, color: 'var(--text-faint)', letterSpacing: '.08em' }}>SCORE</div>
        </div>

        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
            <span className="mono" style={{ fontSize: 13, color: 'var(--text)' }}>{c.domain}</span>
            {c.status === 'blocked' && <span className="tag block">auto-blocked</span>}
            {c.ai_score !== undefined && <span className="tag info">AI reviewed</span>}
          </div>

          {c.ai_reason && (
            <div style={{ fontSize: 12.5, color: 'var(--text-dim)', marginTop: 5 }}>{c.ai_reason}</div>
          )}

          <div style={{ display: 'flex', gap: 14, flexWrap: 'wrap', marginTop: 7, fontSize: 11.5, color: 'var(--text-faint)' }}>
            <span>{compact(c.observations)} requests</span>
            <span>{c.distinct_clients} device{c.distinct_clients === 1 ? '' : 's'}</span>
            {referrers.length > 0 && <span>{referrers.length} referring site{referrers.length === 1 ? '' : 's'}</span>}
            {typeof features.third_party_ratio === 'number' && features.third_party_ratio > 0 && (
              <span>{pct(features.third_party_ratio as number, 0)} third-party</span>
            )}
            {typeof features.avg_bytes === 'number' && (features.avg_bytes as number) > 0 && (
              <span>{compact(features.avg_bytes as number)} B average response</span>
            )}
            <span>first seen {ago(c.first_seen)}</span>
          </div>

          {expanded && (
            <div style={{ marginTop: 11, paddingTop: 11, borderTop: '1px solid var(--line-soft)' }}>
              <dl className="kv" style={{ fontSize: 12 }}>
                <dt>Heuristic score</dt><dd>{c.heuristic_score.toFixed(2)}</dd>
                {c.ai_score !== undefined && <><dt>Model score</dt><dd>{c.ai_score.toFixed(2)}</dd></>}
                {keywords.length > 0 && <><dt>Name keywords</dt><dd>{keywords.join(', ')}</dd></>}
                {features.as_org ? <><dt>Network</dt><dd>{String(features.as_org)}</dd></> : null}
                {referrers.length > 0 && (
                  <><dt>Referred from</dt><dd style={{ lineHeight: 1.7 }}>{referrers.join(', ')}</dd></>
                )}
                {Array.isArray(features.paths) && (features.paths as string[]).length > 0 && (
                  <><dt>Paths seen</dt><dd style={{ lineHeight: 1.7 }}>
                    {(features.paths as string[]).join('  ·  ')}
                  </dd></>
                )}
              </dl>
            </div>
          )}
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 6, alignItems: 'stretch' }}>
          {c.status !== 'blocked' && (
            <button className="btn sm danger" onClick={() => onDecide(c.domain, 'block')}>Block</button>
          )}
          <button className="btn sm" onClick={() => onDecide(c.domain, 'allow')}>Allow</button>
          {c.status !== 'dismissed' && (
            <button className="btn sm" onClick={() => onDecide(c.domain, 'dismiss')}>Dismiss</button>
          )}
          <button className="btn sm" onClick={() => setExpanded((v) => !v)}>
            {expanded ? 'Less' : 'Evidence'}
          </button>
        </div>
      </div>
    </div>
  )
}

function LocalRules() {
  const { data, refresh } = usePoll(() => api.adblock.rules(), 15000)
  const [domain, setDomain] = useState('')
  const [action, setAction] = useState<'block' | 'allow'>('block')
  const [wildcard, setWildcard] = useState(true)
  const [query, setQuery] = useState('')
  const toast = useToast()

  const add = async () => {
    if (!domain.trim()) return
    try {
      await api.adblock.addRule({ domain: domain.trim(), action, wildcard, note: 'added manually' })
      await api.dns.flush(domain.trim())
      toast(`${domain.trim()} ${action === 'block' ? 'blocked' : 'allowed'}`, 'ok')
      setDomain('')
      refresh()
    } catch (e) {
      toast(e instanceof Error ? e.message : 'Could not add that rule', 'err')
    }
  }

  const rules: LocalRule[] = useMemo(() => {
    const q = query.toLowerCase()
    return (data?.rules ?? []).filter((r) => !q || r.domain.includes(q))
  }, [data, query])

  return (
    <>
      <Card title="Add a rule">
        <div style={{ display: 'flex', gap: 9, alignItems: 'center', flexWrap: 'wrap' }}>
          <input className="input" style={{ flex: 1, minWidth: 220 }} value={domain}
            placeholder="ads.example.com" onChange={(e) => setDomain(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && add()} />
          <Segmented value={action} onChange={setAction}
            options={[{ value: 'block', label: 'Block' }, { value: 'allow', label: 'Allow' }]} />
          {action === 'block' && (
            <Switch checked={wildcard} onChange={setWildcard} label="Include subdomains" />
          )}
          <button className="btn primary" onClick={add} disabled={!domain.trim()}>
            <Icons.plus size={13} /> Add
          </button>
        </div>
        <div className="hint" style={{ marginTop: 8 }}>
          Local rules override every subscribed list, in both directions. An allow here is how you
          fix a site that a blocklist broke.
        </div>
      </Card>

      <div className="toolbar" style={{ marginBottom: 0 }}>
        <Search value={query} onChange={setQuery} placeholder="Filter rules…" />
        <div style={{ flex: 1 }} />
        <span className="tag">{rules.length} rules</span>
      </div>

      <Card flush>
        {rules.length === 0 ? (
          <Empty title="No local rules">
            Anything you block or allow by hand, or approve from the discovery queue, shows up here.
          </Empty>
        ) : (
          <div className="table-wrap">
            <table className="t">
              <thead>
                <tr><th>Domain</th><th style={{ width: 80 }}>Action</th><th>Source</th><th>Note</th>
                  <th>Added</th><th style={{ width: 44 }} /></tr>
              </thead>
              <tbody>
                {rules.map((r) => (
                  <tr key={r.domain}>
                    <td className="mono" style={{ fontSize: 12 }}>
                      {r.wildcard && <span style={{ color: 'var(--text-faint)' }}>*.</span>}{r.domain}
                    </td>
                    <td><span className={`tag ${r.action === 'block' ? 'block' : 'allow'}`}>{r.action}</span></td>
                    <td style={{ color: 'var(--text-faint)', fontSize: 11.5 }}>{r.origin}</td>
                    <td className="truncate" style={{ maxWidth: 260, color: 'var(--text-dim)', fontSize: 11.5 }}
                      title={r.note}>{r.note || '—'}</td>
                    <td style={{ color: 'var(--text-faint)', fontSize: 11.5 }}>{ago(r.created_at)}</td>
                    <td>
                      <button className="btn icon" title="Delete" onClick={async () => {
                        await api.adblock.deleteRule(r.domain)
                        await api.dns.flush(r.domain)
                        refresh()
                      }}><Icons.trash size={13} /></button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </>
  )
}

function Lists() {
  const { data, refresh } = usePoll(() => api.adblock.lists(), 20000)
  const [adding, setAdding] = useState(false)
  const [form, setForm] = useState({ name: '', url: '', category: 'ads' })
  const toast = useToast()

  return (
    <>
      <div className="toolbar" style={{ marginBottom: 0 }}>
        <button className="btn" onClick={() => setAdding((v) => !v)}>
          <Icons.plus size={13} /> Add a list
        </button>
        <div style={{ flex: 1 }} />
        <button className="btn sm" onClick={async () => {
          await api.adblock.refresh()
          toast('Refresh started', 'ok')
        }}><Icons.refresh size={13} /> Update all</button>
      </div>

      {adding && (
        <Card title="New subscription">
          <div style={{ display: 'grid', gap: 11 }}>
            <div className="grid c3">
              <div className="field">
                <label>Name</label>
                <input className="input" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
              </div>
              <div className="field" style={{ gridColumn: 'span 2' }}>
                <label>URL</label>
                <input className="input" value={form.url} placeholder="https://…"
                  onChange={(e) => setForm({ ...form, url: e.target.value })} />
              </div>
            </div>
            <div className="field" style={{ maxWidth: 200 }}>
              <label>Category</label>
              <select className="select" value={form.category} onChange={(e) => setForm({ ...form, category: e.target.value })}>
                <option value="ads">Ads</option>
                <option value="tracking">Tracking</option>
                <option value="malware">Malware &amp; phishing</option>
                <option value="adult">Adult</option>
                <option value="social">Social</option>
                <option value="bypass">DNS bypass</option>
              </select>
            </div>
            <div className="hint">
              Hosts files, plain domain lists, AdBlock-syntax network rules and dnsmasq
              address= lines are all understood. Cosmetic rules are skipped.
            </div>
            <div style={{ display: 'flex', gap: 8 }}>
              <button className="btn primary" disabled={!form.name || !form.url} onClick={async () => {
                try {
                  await api.adblock.addList({ ...form, enabled: true })
                  toast('List added, downloading now', 'ok')
                  setForm({ name: '', url: '', category: 'ads' })
                  setAdding(false)
                  setTimeout(refresh, 1500)
                } catch (e) {
                  toast(e instanceof Error ? e.message : 'Could not add', 'err')
                }
              }}>Add</button>
              <button className="btn" onClick={() => setAdding(false)}>Cancel</button>
            </div>
          </div>
        </Card>
      )}

      {data?.builtin && data.builtin.length > 0 && (
        <Card title="Built in">
          <div style={{ display: 'grid', gap: 12 }}>
            {data.builtin.map((b) => (
              <div key={b.id} style={{ display: 'flex', gap: 12, alignItems: 'flex-start' }}>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: 13, display: 'flex', gap: 8, alignItems: 'baseline', flexWrap: 'wrap' }}>
                    <span>{b.name}</span>
                    <span className="tag">{b.category}</span>
                    <span style={{ fontSize: 11, color: 'var(--text-faint)' }}>{compact(b.entries)} hosts, ships with Orbis</span>
                  </div>
                  <div style={{ fontSize: 11.5, color: 'var(--text-dim)', marginTop: 3, lineHeight: 1.55 }}>{b.description}</div>
                </div>
                <Switch checked={b.enabled} label={b.enabled ? 'On' : 'Off'} onChange={async (v) => {
                  try {
                    await api.config.patch({ [b.key]: v })
                    refresh()
                  } catch (e) {
                    toast(e instanceof Error ? e.message : 'Could not save', 'err')
                  }
                }} />
              </div>
            ))}
          </div>
        </Card>
      )}

      <Card flush>
        {!data ? <Loading what="lists" /> : (
          <div className="table-wrap">
            <table className="t">
              <thead>
                <tr><th>List</th><th>Category</th><th className="num">Entries</th>
                  <th>Updated</th><th>Status</th><th style={{ width: 44 }} /></tr>
              </thead>
              <tbody>
                {data.lists.map((l) => (
                  <tr key={l.name}>
                    <td>
                      <div>{l.name}</div>
                      <div className="truncate mono" style={{ fontSize: 10.5, color: 'var(--text-faint)', maxWidth: 380 }}
                        title={l.url}>{l.url}</div>
                    </td>
                    <td><span className="tag">{l.category || '—'}</span></td>
                    <td className="num">{compact(l.entries)}</td>
                    <td style={{ color: 'var(--text-faint)', fontSize: 11.5 }}>{ago(l.last_updated)}</td>
                    <td>
                      {l.last_error
                        ? <span className="tag block" title={l.last_error}>failed</span>
                        : l.enabled
                          ? <span className="tag allow">active</span>
                          : <span className="tag">disabled</span>}
                    </td>
                    <td>
                      <button className="btn icon" title="Remove" onClick={async () => {
                        await api.adblock.deleteList(l.name)
                        refresh()
                      }}><Icons.trash size={13} /></button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </>
  )
}

/** The in-stream (MITM) panel. This is where YouTube ad removal is explained
 *  and controlled, including the honest limits. */
function InStream() {
  const { data: config, refresh } = usePoll(() => api.config.get(), 0)
  const { data: proxy } = usePoll(() => api.proxy.status(), 8000)
  const { data: ca } = usePoll(() => api.proxy.ca(), 0)
  const { data: readiness } = usePoll(() => api.proxy.readiness(), 8000)
  const toast = useToast()

  const set = async (key: string, value: unknown) => {
    try {
      await api.config.patch({ [key]: value })
      refresh()
    } catch (e) {
      toast(e instanceof Error ? e.message : 'Could not save', 'err')
    }
  }

  const running = Boolean(proxy?.running)
  const filters = config?.mitm.filters

  return (
    <>
      <Banner tone={running ? 'info' : 'warn'}>
        <strong style={{ display: 'block', marginBottom: 3 }}>
          Why this is separate from the blocklists
        </strong>
        YouTube serves its ads from the same hosts as its video, over the same connection. There is
        no name to block, so DNS filtering cannot touch it. Removing those ads means terminating
        TLS on this node and editing the player response in flight — which requires installing the
        certificate below on every device you want filtered.
      </Banner>

      {readiness && (
        <Card title="Why am I still seeing ads?">
          <div className="hint" style={{ marginBottom: 12 }}>
            Four things all have to be true. The failure of any one of them looks identical from
            the sofa, so they are checked separately.
          </div>
          <div style={{ display: 'grid', gap: 10 }}>
            {readiness.checks.map((c) => (
              <div key={c.name} style={{ display: 'flex', gap: 10, alignItems: 'flex-start' }}>
                <span className={`dot ${c.ok ? 'on' : 'err'}`} style={{ marginTop: 5 }} />
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: 12.5 }}>
                    {c.name}
                    <span style={{ color: 'var(--text-faint)', marginLeft: 8, fontSize: 11.5 }}>
                      {c.detail}
                    </span>
                  </div>
                  {!c.ok && c.fix && (
                    <div style={{ fontSize: 11.5, color: 'var(--amber)', marginTop: 3, lineHeight: 1.55 }}>
                      {c.fix}
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </Card>
      )}

      <div className="grid c2">
        <Card title="Filter proxy" actions={
          <button className={`btn sm ${running ? 'danger' : 'primary'}`} onClick={async () => {
            try {
              await api.proxy.action(running ? 'stop' : 'start')
              toast(running ? 'Filter proxy stopped' : 'Filter proxy started', 'ok')
            } catch (e) {
              toast(e instanceof Error ? e.message : 'Could not change state', 'err')
            }
          }}>{running ? 'Stop' : 'Start'}</button>
        }>
          <div style={{ display: 'grid', gap: 11 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 9 }}>
              <span className={`dot ${running ? 'on' : 'off'}`} />
              <span>{running ? 'Intercepting' : 'Stopped'}</span>
            </div>
            {running && (
              <dl className="kv">
                <dt>Connections</dt><dd>{compact(Number(proxy?.accepted ?? 0))} seen</dd>
                <dt>Intercepted</dt><dd>{compact(Number(proxy?.intercepted ?? 0))}</dd>
                <dt>Passed through</dt><dd>{compact(Number(proxy?.spliced ?? 0))}</dd>
                <dt>Ads stripped</dt>
                <dd style={{ color: 'var(--accent)' }}>{compact(Number(proxy?.ads_stripped ?? 0))}</dd>
                <dt>Beacons dropped</dt><dd>{compact(Number(proxy?.beacons_killed ?? 0))}</dd>
                <dt>In-page: structures removed</dt><dd>{compact(Number(proxy?.inpage_stripped ?? 0))}</dd>
                <dt>In-page: ad breaks driven past</dt><dd>{compact(Number(proxy?.inpage_skipped ?? 0))}</dd>
                <dt>In-page: segments skipped</dt><dd>{compact(Number(proxy?.inpage_segments ?? 0))}</dd>
                <dt>Server-stitched responses</dt>
                <dd title="Player responses whose ads are muxed into the video itself. Nothing on a network can remove those; this counts how often it happened.">
                  {compact(Number(proxy?.server_stitched ?? 0))}
                </dd>
              </dl>
            )}
            <div style={{ display: 'grid', gap: 8, borderTop: '1px solid var(--line-soft)', paddingTop: 11 }}>
              <Switch checked={filters?.youtube ?? false} onChange={(v) => set('mitm.filters.youtube', v)}
                label="Strip YouTube ad slots" />
              <Switch checked={filters?.youtube_in_page ?? false} disabled={!(filters?.youtube ?? false)}
                onChange={(v) => set('mitm.filters.youtube_in_page', v)}
                label="YouTube in-page engine (drives the player past ads the filter missed)" />
              <Switch checked={filters?.youtube_sponsorblock ?? false} disabled={!(filters?.youtube ?? false) || !(filters?.youtube_in_page ?? false)}
                onChange={(v) => set('mitm.filters.youtube_sponsorblock', v)}
                label="SponsorBlock segments in the browser, no extension" />
              <Switch checked={filters?.tracker_beacons ?? false} onChange={(v) => set('mitm.filters.tracker_beacons', v)}
                label="Drop tracker beacons before they leave" />
              <Switch checked={filters?.generic_json_ads ?? false} onChange={(v) => set('mitm.filters.generic_json_ads', v)}
                label="Remove ad payloads from app JSON responses" />
              <Switch checked={filters?.html_cosmetic ?? false} onChange={(v) => set('mitm.filters.html_cosmetic', v)}
                label="Inject element-hiding CSS into pages" />
            </div>
          </div>
        </Card>

        <Card title="Certificate" actions={
          <a className="btn sm" href="/orbis-ca.crt" download><Icons.download size={13} /> Download</a>
        }>
          {!ca ? <Loading what="certificate" /> : (
            <div style={{ display: 'grid', gap: 11 }}>
              <dl className="kv">
                <dt>Subject</dt><dd>{String(ca.ca.subject)}</dd>
                <dt>Expires</dt><dd>{String(ca.ca.expires_in_days)} days</dd>
              </dl>
              <div className="field">
                <label>SHA-256 fingerprint</label>
                <div className="mono" style={{ fontSize: 10, wordBreak: 'break-all', color: 'var(--text-dim)' }}>
                  {String(ca.ca.fingerprint)}
                </div>
                <div className="hint">Check this matches what the device shows before you trust it.</div>
              </div>
              <details>
                <summary style={{ cursor: 'pointer', fontSize: 12.5, color: 'var(--text-dim)' }}>
                  How to install it on each platform
                </summary>
                <div style={{ display: 'grid', gap: 9, marginTop: 10 }}>
                  {ca.instructions.map((i) => (
                    <div key={i.platform}>
                      <div style={{ fontSize: 12, fontWeight: 560, marginBottom: 2 }}>{i.platform}</div>
                      <div style={{ fontSize: 11.5, color: 'var(--text-dim)', lineHeight: 1.6 }}>{i.steps}</div>
                    </div>
                  ))}
                </div>
              </details>
            </div>
          )}
        </Card>
      </div>

      <Card title="What this can and cannot do">
        <div style={{ display: 'grid', gap: 9, fontSize: 12.5, color: 'var(--text-dim)', lineHeight: 1.65 }}>
          <div>
            <strong style={{ color: 'var(--text)' }}>Works:</strong> pre-roll and mid-roll ad slots on
            YouTube web and the mobile apps (both read the same InnerTube player response), ad
            tracking pings, and ad payloads in most app APIs.
          </div>
          <div>
            <strong style={{ color: 'var(--text)' }}>Two layers on YouTube pages:</strong> the response
            filter removes ad structures by name before the page sees them; the in-page engine then
            watches the player itself and drives past any ad break that starts anyway, muted. When
            YouTube renames a field, the first layer misses and the second still catches it. The
            engine also skips SponsorBlock segments, asking Orbis (never SponsorBlock) for them.
          </div>
          <div>
            <strong style={{ color: 'var(--text)' }}>Does not work:</strong> server-side stitched ads,
            where the ad frames are muxed into the same video stream as the content. Nothing on the
            network can separate those — the ad and the video are literally the same bytes.
          </div>
          <div>
            <strong style={{ color: 'var(--text)' }}>Will not be intercepted:</strong> apps that pin
            their certificates (most banking apps, some streaming apps) and anything on the bypass
            list. Those connections pass through untouched rather than breaking.
          </div>
          <div>
            <strong style={{ color: 'var(--text)' }}>Android note:</strong> since Android 7, apps do
            not trust user-installed certificates. Interception works in browsers but not in most
            native apps unless the device is rooted.
          </div>
        </div>
      </Card>
    </>
  )
}
