import { useCallback, useEffect, useRef, useState } from 'react'
import { api } from '../api'
import { usePoll } from '../hooks'
import { Banner, Card, Empty, Icons, Segmented, Stat, useConfirm, useToast } from '../ui'
import { clientName, compact } from '../format'
import type { Diagnosis, ImportResult, LocalRule } from '../types'

type Tab = 'test' | 'rules' | 'import'

// The screen that answers "why is this site not loading". Everything here is
// built around one idea: never make someone read a 480,000-line rule set to
// find out what stopped a request.
export function DNSToolsPage() {
  const [tab, setTab] = useState<Tab>('test')
  return (
    <div style={{ display: 'grid', gap: 14 }}>
      <div className="toolbar" style={{ marginBottom: 0 }}>
        <Segmented
          value={tab} onChange={setTab}
          options={[
            { value: 'test', label: 'Test a domain' },
            { value: 'rules', label: 'My rules' },
            { value: 'import', label: 'Import a list' },
          ]}
        />
      </div>
      {tab === 'test' && <Tester />}
      {tab === 'rules' && <Rules />}
      {tab === 'import' && <Importer />}
    </div>
  )
}

/* ---------------- domain tester ---------------- */

function Tester() {
  const [domain, setDomain] = useState('')
  const [clientID, setClientID] = useState('')
  const [result, setResult] = useState<Diagnosis | null>(null)
  const [busy, setBusy] = useState(false)
  const [history, setHistory] = useState<string[]>([])
  const toast = useToast()
  const inputRef = useRef<HTMLInputElement>(null)
  const { data: clients } = usePoll(() => api.clients.list(), 60000)

  useEffect(() => { inputRef.current?.focus() }, [])

  const run = useCallback(async (raw?: string) => {
    const target = (raw ?? domain).trim()
    if (!target) return
    setBusy(true)
    try {
      const r = await api.dnstools.diagnose(target, { client_id: clientID || undefined })
      setResult(r)
      setHistory((h) => [target, ...h.filter((x) => x !== target)].slice(0, 8))
    } catch (e) {
      toast(e instanceof Error ? e.message : 'Lookup failed', 'err')
    } finally {
      setBusy(false)
    }
  }, [domain, clientID, toast])

  const act = async (fn: () => Promise<unknown>, msg: string) => {
    try {
      await fn()
      toast(msg, 'ok')
      run()
    } catch (e) {
      toast(e instanceof Error ? e.message : 'Failed', 'err')
    }
  }

  const blocked = result?.verdict === 'block'

  return (
    <>
      <Card title="Is this domain blocked?">
        <div className="hint" style={{ marginBottom: 11 }}>
          Traces the exact path a lookup takes: rewrites, this device's policy, blocked service
          bundles, your own rules, the subscriptions, and the CNAME chain. Whatever stopped it is
          named, with the rule that did it.
        </div>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          <input
            ref={inputRef}
            className="input mono"
            style={{ flex: '2 1 240px' }}
            placeholder="lh3.googleusercontent.com"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter') run() }}
          />
          <select className="input" style={{ flex: '1 1 160px' }}
            value={clientID} onChange={(e) => setClientID(e.target.value)}>
            <option value="">Any device (global rules)</option>
            {(clients?.clients ?? []).map((c) => (
              <option key={c.id} value={c.id}>{clientName(c)}</option>
            ))}
          </select>
          <button className="btn primary" disabled={busy || !domain.trim()} onClick={() => run()}>
            <Icons.search size={13} /> {busy ? 'Testing…' : 'Test'}
          </button>
        </div>

        {history.length > 0 && (
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginTop: 9 }}>
            {history.map((h) => (
              <button key={h} className="btn sm" style={{ fontSize: 11 }}
                onClick={() => { setDomain(h); run(h) }}>{h}</button>
            ))}
          </div>
        )}
      </Card>

      {result && (
        <Card
          title={result.domain}
          actions={
            <div style={{ display: 'flex', gap: 7 }}>
              {blocked ? (
                <>
                  <button className="btn sm primary"
                    onClick={() => act(() => api.dnstools.allow(result.domain), 'Allowed. It will load now.')}>
                    <Icons.check size={13} /> Let this through
                  </button>
                  <button className="btn sm"
                    onClick={() => act(() => api.dnstools.unblock(result.domain), 'Local rule removed')}
                    title="Remove any rule of your own for this name">
                    Remove my rule
                  </button>
                </>
              ) : (
                <button className="btn sm danger"
                  onClick={() => act(() => api.dnstools.block(result.domain, false), 'Blocked')}>
                  <Icons.block size={13} /> Block it
                </button>
              )}
            </div>
          }
        >
          <div style={{
            display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12,
            padding: '10px 12px', borderRadius: 8,
            background: blocked
              ? 'color-mix(in srgb, var(--red) 12%, transparent)'
              : 'color-mix(in srgb, var(--accent) 12%, transparent)',
            border: `1px solid ${blocked ? 'var(--red)' : 'var(--accent)'}`,
          }}>
            <span className={`dot ${blocked ? 'err' : 'on'}`} />
            <div>
              <div style={{ fontSize: 13.5, fontWeight: 600 }}>
                {blocked ? 'Blocked' : 'Not blocked'}
                {result.policy && (
                  <span style={{ fontWeight: 400, color: 'var(--text-dim)' }}> · policy {result.policy}</span>
                )}
              </div>
              <div style={{ fontSize: 12, color: 'var(--text-dim)', marginTop: 2 }}>{result.reason}</div>
            </div>
          </div>

          <div style={{ fontSize: 12, color: 'var(--text-dim)', marginBottom: 8 }}>
            How the decision was reached
          </div>
          <div style={{ display: 'grid', gap: 7 }}>
            {result.steps.map((st, i) => (
              <div key={i} style={{ display: 'flex', gap: 10, alignItems: 'flex-start' }}>
                <span className={`dot ${st.verdict === 'block' ? 'err' : st.verdict === 'allow' ? 'on' : 'off'}`}
                  style={{ marginTop: 5 }} />
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: 12.5 }}>
                    {st.stage}
                    {st.rule && (
                      <span className="mono" style={{ marginLeft: 8, fontSize: 11, color: 'var(--amber)' }}>
                        {st.rule}
                      </span>
                    )}
                  </div>
                  <div style={{ fontSize: 11.5, color: 'var(--text-faint)', lineHeight: 1.5 }}>{st.detail}</div>
                </div>
              </div>
            ))}
          </div>

          {(result.cname_chain?.length || result.answers?.length) ? (
            <div style={{ borderTop: '1px solid var(--line-soft)', marginTop: 12, paddingTop: 11 }}>
              <div style={{ fontSize: 12, color: 'var(--text-dim)', marginBottom: 6 }}>What it resolved to</div>
              <div className="mono" style={{ fontSize: 11.5, color: 'var(--text-dim)', lineHeight: 1.7 }}>
                {result.cname_chain?.map((c) => <div key={c}>CNAME → {c}</div>)}
                {result.answers?.map((a) => <div key={a}>{a}</div>)}
              </div>
            </div>
          ) : null}
        </Card>
      )}
    </>
  )
}

/* ---------------- local rules ---------------- */

function Rules() {
  const { data, refresh } = usePoll(() => api.adblock.rules(), 0)
  const [q, setQ] = useState('')
  const [draft, setDraft] = useState('')
  const [action, setAction] = useState<'block' | 'allow'>('allow')
  const toast = useToast()
  const confirm = useConfirm()

  const rules: LocalRule[] = (data?.rules ?? []) as LocalRule[]
  const filtered = q
    ? rules.filter((r) => r.domain.toLowerCase().includes(q.toLowerCase()))
    : rules

  const add = async () => {
    const d = draft.trim()
    if (!d) return
    try {
      if (action === 'allow') await api.dnstools.allow(d)
      else await api.dnstools.block(d, false)
      setDraft('')
      refresh()
      toast(action === 'allow' ? 'Allowed' : 'Blocked', 'ok')
    } catch (e) {
      toast(e instanceof Error ? e.message : 'Failed', 'err')
    }
  }

  const remove = async (domain: string) => {
    if (!(await confirm(`Remove your rule for ${domain}?`))) return
    try {
      await api.dnstools.unblock(domain)
      refresh()
    } catch (e) {
      toast(e instanceof Error ? e.message : 'Failed', 'err')
    }
  }

  const allows = rules.filter((r) => r.action === 'allow').length

  return (
    <>
      <div className="grid c3">
        <Stat label="My rules" value={String(rules.length)} />
        <Stat label="Allow" value={String(allows)} tone="accent" />
        <Stat label="Block" value={String(rules.length - allows)} tone="red" />
      </div>

      <Card title="Your own rules">
        <div className="hint" style={{ marginBottom: 10 }}>
          These always win over the subscriptions. An allow rule is how you rescue a site a list
          got wrong, and it survives every list refresh.
        </div>
        <div style={{ display: 'flex', gap: 8, marginBottom: 12, flexWrap: 'wrap' }}>
          <Segmented value={action} onChange={setAction}
            options={[{ value: 'allow', label: 'Allow' }, { value: 'block', label: 'Block' }]} />
          <input className="input mono" style={{ flex: '1 1 200px' }} placeholder="example.com"
            value={draft} onChange={(e) => setDraft(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter') add() }} />
          <button className="btn primary" disabled={!draft.trim()} onClick={add}>
            <Icons.plus size={13} /> Add
          </button>
        </div>

        {rules.length > 8 && (
          <input className="input" placeholder="Filter…" value={q}
            onChange={(e) => setQ(e.target.value)} style={{ marginBottom: 10 }} />
        )}

        {filtered.length === 0 ? (
          <Empty title={rules.length ? 'Nothing matches that filter' : 'No rules of your own yet'}>
            Test a domain and use "Let this through" to create one.
          </Empty>
        ) : (
          <div style={{ display: 'grid', gap: 6, maxHeight: 460, overflow: 'auto' }}>
            {filtered.map((r) => (
              <div key={`${r.action}-${r.domain}`}
                style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <span className={`dot ${r.action === 'allow' ? 'on' : 'err'}`} />
                <span className="mono" style={{ flex: 1, minWidth: 0, fontSize: 12.5 }}>
                  {r.wildcard ? '*.' : ''}{r.domain}
                </span>
                {r.origin && r.origin !== 'user' && (
                  <span className="tag" style={{ fontSize: 10 }}>{r.origin}</span>
                )}
                <button className="btn sm" onClick={() => remove(r.domain)}>
                  <Icons.trash size={13} />
                </button>
              </div>
            ))}
          </div>
        )}
      </Card>
    </>
  )
}

/* ---------------- list import ---------------- */

function Importer() {
  const [text, setText] = useState('')
  const [action, setAction] = useState<'block' | 'allow'>('block')
  const [preview, setPreview] = useState<ImportResult | null>(null)
  const [busy, setBusy] = useState(false)
  const toast = useToast()

  const onFile = async (f: File | undefined) => {
    if (!f) return
    // 20 MB covers any real blocklist; beyond that it belongs in a subscription
    // URL so it can refresh itself rather than being pasted once.
    if (f.size > 20 * 1024 * 1024) {
      toast('That file is over 20 MB. Add it as a subscription URL instead.', 'err')
      return
    }
    setText(await f.text())
    setPreview(null)
  }

  const check = async () => {
    setBusy(true)
    try {
      setPreview(await api.dnstools.importList(text, { action, dry_run: true }))
    } catch (e) {
      toast(e instanceof Error ? e.message : 'Could not parse', 'err')
    } finally {
      setBusy(false)
    }
  }

  const apply = async () => {
    setBusy(true)
    try {
      const r = await api.dnstools.importList(text, { action })
      toast(`Imported ${r.imported} rule(s)`, 'ok')
      setPreview(r)
      setText('')
    } catch (e) {
      toast(e instanceof Error ? e.message : 'Import failed', 'err')
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card title="Import a list">
      <div className="hint" style={{ marginBottom: 11 }}>
        Paste or upload a list in any common format and Orbis works out which one it is: hosts
        files (<span className="mono">0.0.0.0 ads.example.com</span>), plain domain lists, AdGuard
        and uBlock network rules (<span className="mono">||ads.example.com^</span>), dnsmasq
        (<span className="mono">address=/ads.example.com/</span>) and wildcards. Cosmetic rules and
        anything with a URL path are skipped, because DNS cannot honour them and pretending
        otherwise is what causes overblocking.
      </div>

      <div style={{ display: 'flex', gap: 8, marginBottom: 10, flexWrap: 'wrap', alignItems: 'center' }}>
        <Segmented value={action} onChange={(v) => { setAction(v); setPreview(null) }}
          options={[{ value: 'block', label: 'Import as block' }, { value: 'allow', label: 'Import as allow' }]} />
        <label className="btn sm" style={{ cursor: 'pointer' }}>
          <Icons.download size={13} /> Choose file
          <input type="file" accept=".txt,.list,.hosts,text/plain" style={{ display: 'none' }}
            onChange={(e) => onFile(e.target.files?.[0])} />
        </label>
      </div>

      <textarea
        className="input mono"
        style={{ width: '100%', minHeight: 190, resize: 'vertical', fontSize: 11.5, lineHeight: 1.6 }}
        placeholder={'0.0.0.0 ads.example.com\n||tracker.example^\naddress=/telemetry.example/\n*.doubleclick.net'}
        value={text}
        onChange={(e) => { setText(e.target.value); setPreview(null) }}
      />

      <div style={{ display: 'flex', gap: 8, marginTop: 10 }}>
        <button className="btn" disabled={busy || !text.trim()} onClick={check}>
          {busy ? 'Parsing…' : 'Preview'}
        </button>
        <button className="btn primary" disabled={busy || !preview || !!preview.risky?.length} onClick={apply}>
          Import {preview ? `${preview.total} rule(s)` : ''}
        </button>
      </div>

      {preview && (
        <div style={{ borderTop: '1px solid var(--line-soft)', marginTop: 13, paddingTop: 12 }}>
          {preview.risky?.length ? (
            <Banner tone="warn">
              <strong style={{ display: 'block', marginBottom: 3 }}>This list would take your network offline</strong>
              {preview.risky.join(', ')} would block an entire top-level domain. That is almost
              always a parse artefact rather than intent, so the import is refused. Remove those
              lines and preview again.
            </Banner>
          ) : (
            <div className="grid c3" style={{ marginBottom: 10 }}>
              <Stat label="Exact domains" value={compact(preview.exact)} />
              <Stat label="Wildcards" value={compact(preview.wildcard)} />
              <Stat label={preview.dry_run ? 'Ready to import' : 'Imported'}
                value={compact(preview.dry_run ? preview.total : preview.imported)}
                tone={preview.dry_run ? undefined : 'accent'} />
            </div>
          )}
          {preview.sample?.length > 0 && (
            <>
              <div style={{ fontSize: 12, color: 'var(--text-dim)', marginBottom: 6 }}>Sample of what was parsed</div>
              <div className="mono" style={{ fontSize: 11, color: 'var(--text-faint)', lineHeight: 1.75 }}>
                {preview.sample.map((d) => <div key={d}>{d}</div>)}
              </div>
            </>
          )}
        </div>
      )}
    </Card>
  )
}
