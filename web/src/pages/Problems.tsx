import { useState } from 'react'
import { api } from '../api'
import { usePoll } from '../hooks'
import { Banner, Card, Drawer, Empty, Field, Icons, Loading, Segmented, Spinner, useToast } from '../ui'
import { ago } from '../format'
import type { Issue } from '../types'

/**
 * Problems: what went wrong on this node, already scrubbed, with per-row
 * actions. The preview shows exactly the text that would leave the node, so
 * the decision to report is made with the payload in front of you.
 */
export function ProblemsPage() {
  const [filter, setFilter] = useState<'open' | 'reported' | 'all'>('open')
  const { data, refresh, loading } = usePoll(() => api.issues.list(filter === 'all' ? '' : filter), 20000, [filter])
  const [preview, setPreview] = useState<{ issue: Issue; title: string; body: string; labels: string[]; repo: string } | null>(null)
  const [busy, setBusy] = useState<string | null>(null)
  const [showForm, setShowForm] = useState(false)
  const toast = useToast()

  const act = async (id: string, fn: () => Promise<unknown>, ok: string) => {
    setBusy(id)
    try {
      await fn()
      toast(ok, 'ok')
      refresh()
    } catch (e) {
      toast(e instanceof Error ? e.message : 'That did not work', 'err')
    } finally {
      setBusy(null)
    }
  }

  const openPreview = async (issue: Issue) => {
    try {
      const p = await api.issues.preview(issue.id)
      setPreview({ issue, ...p })
    } catch (e) {
      toast(e instanceof Error ? e.message : 'Could not build the preview', 'err')
    }
  }

  const gh = data?.github
  const issues = data?.issues ?? []

  return (
    <>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 14, flexWrap: 'wrap' }}>
        <Segmented value={filter} onChange={setFilter}
          options={[{ value: 'open', label: 'Open' }, { value: 'reported', label: 'Reported' }, { value: 'all', label: 'All' }]} />
        <div style={{ flex: 1 }} />
        <button className="btn primary sm" onClick={() => setShowForm(true)}><Icons.plus size={13} /> Report a problem</button>
      </div>

      {data && !data.recording.enabled && (
        <Banner tone="warn">Problem recording is off. Turn it on in Settings → Problem reports to collect what goes wrong.</Banner>
      )}
      {gh && gh.enabled && !gh.ready && (
        <Banner tone="warn">GitHub reporting is enabled but has no token or relay URL. Add one in Settings → Problem reports.</Banner>
      )}
      {gh && !gh.enabled && issues.length > 0 && (
        <Banner tone="info">
          Reports stay on this node. Enable GitHub reporting in Settings to file them on <span className="mono">{gh.repo}</span>,
          scrubbed of addresses, device names and keys.
        </Banner>
      )}

      <Card title={`${issues.length} problem${issues.length === 1 ? '' : 's'}`} flush>
        {loading && !data ? <Loading what="problems" /> : issues.length === 0 ? (
          <Empty title={filter === 'open' ? 'Nothing open' : 'Nothing here'}>
            Warnings and failures the daemon notices land here automatically; you can also report one yourself.
          </Empty>
        ) : (
          <div className="table-wrap">
            <table className="t">
              <thead>
                <tr><th>Problem</th><th>Where</th><th>Seen</th><th>Status</th><th></th></tr>
              </thead>
              <tbody>
                {issues.map((i) => (
                  <tr key={i.id}>
                    <td style={{ maxWidth: 520 }}>
                      <div><span className={`issue-sev ${i.severity}`} />{i.title}</div>
                      {i.detail && <div className="hint truncate" style={{ fontSize: 11.5, maxWidth: 520 }} title={i.detail}>{i.detail}</div>}
                      {i.last_error && <div className="hint" style={{ fontSize: 11, color: 'var(--red)' }}>Report failed: {i.last_error}</div>}
                    </td>
                    <td><span className="mono" style={{ fontSize: 11.5 }}>{i.category}</span><div className="hint" style={{ fontSize: 11 }}>{i.source}</div></td>
                    <td className="mono" style={{ fontSize: 12 }}>
                      {i.occurrences}×<div className="hint" style={{ fontSize: 11 }}>{ago(i.last_seen)}</div>
                    </td>
                    <td>
                      {i.github_url ? (
                        <a href={i.github_url} target="_blank" rel="noreferrer" className="mono" style={{ fontSize: 12 }}>#{i.github_number}</a>
                      ) : <span className="hint">{i.status}</span>}
                    </td>
                    <td style={{ whiteSpace: 'nowrap', textAlign: 'right' }}>
                      <button className="btn sm" onClick={() => openPreview(i)}>Preview</button>{' '}
                      {gh?.ready && i.status !== 'resolved' && (
                        <button className="btn sm primary" disabled={busy === i.id}
                          onClick={() => act(i.id, () => api.issues.report(i.id), i.github_url ? 'Added a "seen again" comment' : 'Filed on GitHub')}>
                          {busy === i.id ? <Spinner /> : i.github_url ? 'Seen again' : 'Report'}
                        </button>
                      )}{' '}
                      {i.status !== 'dismissed' && i.status !== 'resolved' ? (
                        <button className="btn sm" onClick={() => act(i.id, () => api.issues.setStatus(i.id, 'dismissed'), 'Dismissed')}>Dismiss</button>
                      ) : (
                        <button className="btn sm" onClick={() => act(i.id, () => api.issues.setStatus(i.id, 'open'), 'Reopened')}>Reopen</button>
                      )}{' '}
                      <button className="btn sm danger" title="Delete this record" onClick={() => act(i.id, () => api.issues.remove(i.id), 'Deleted')}>
                        <Icons.close size={12} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {preview && (
        <Drawer title="What would be sent" onClose={() => setPreview(null)}
          actions={gh?.ready && preview.issue.status !== 'resolved' ? (
            <button className="btn primary" disabled={busy === preview.issue.id}
              onClick={() => act(preview.issue.id, () => api.issues.report(preview.issue.id), 'Filed on GitHub').then(() => setPreview(null))}>
              {preview.issue.github_url ? 'Post "seen again"' : `File on ${preview.repo}`}
            </button>
          ) : undefined}>
          <div className="hint" style={{ marginBottom: 10, lineHeight: 1.6 }}>
            This is the exact title and body. Addresses, MAC addresses, device names, hostnames outside the project's
            infrastructure, keys and email addresses were replaced with placeholders on this node.
          </div>
          <div style={{ fontWeight: 560, marginBottom: 8 }}>{preview.title}</div>
          <div className="preview-body">{preview.body}</div>
          <div className="hint" style={{ marginTop: 8 }}>Labels: {preview.labels.join(', ')}</div>
        </Drawer>
      )}

      {showForm && (
        <ReportForm canFile={Boolean(gh?.ready)} repo={gh?.repo ?? ''} onClose={() => setShowForm(false)} onDone={() => { setShowForm(false); refresh() }} />
      )}
    </>
  )
}

function ReportForm({ canFile, repo, onClose, onDone }: { canFile: boolean; repo: string; onClose: () => void; onDone: () => void }) {
  const [title, setTitle] = useState('')
  const [detail, setDetail] = useState('')
  const [file, setFile] = useState(canFile)
  const [busy, setBusy] = useState(false)
  const toast = useToast()
  return (
    <Drawer title="Report a problem" onClose={onClose}
      actions={
        <button className="btn primary" disabled={!title.trim() || busy} onClick={async () => {
          setBusy(true)
          try {
            const res = await api.issues.create(title.trim(), detail.trim(), file)
            if (res.report_error) toast(`Recorded, but filing failed: ${res.report_error}`, 'err')
            else toast(file ? 'Recorded and filed' : 'Recorded', 'ok')
            onDone()
          } catch (e) {
            toast(e instanceof Error ? e.message : 'Could not record that', 'err')
          } finally {
            setBusy(false)
          }
        }}>{busy ? <Spinner /> : file ? `Record and file on ${repo}` : 'Record'}</button>
      }>
      <div style={{ display: 'grid', gap: 14 }}>
        <Field label="What is wrong" hint="One line.">
          <input className="input" value={title} onChange={(e) => setTitle(e.target.value)} placeholder="YouTube ads still play on the living room TV" />
        </Field>
        <Field label="Details" hint="What you expected, what happened, how to reproduce. Device names and addresses are scrubbed before anything leaves this node, so write naturally.">
          <textarea className="input" rows={6} value={detail} onChange={(e) => setDetail(e.target.value)} />
        </Field>
        {canFile ? (
          <label style={{ display: 'flex', gap: 8, alignItems: 'center', fontSize: 13 }}>
            <input type="checkbox" checked={file} onChange={(e) => setFile(e.target.checked)} />
            File on GitHub now (the node snapshot is attached, scrubbed)
          </label>
        ) : (
          <div className="hint">GitHub reporting is not set up, so this stays on the node until you enable it in Settings.</div>
        )}
      </div>
    </Drawer>
  )
}
