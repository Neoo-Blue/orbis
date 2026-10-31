import { useCallback, useEffect, useRef, useState } from 'react'
import { api } from '../api'
import type { ConfigHistoryEntry, ConfigHistoryPending } from '../types'
import { Banner, Card, Empty, Icons, Loading, useConfirm, useToast } from '../ui'
import './ChangeTimeline.css'

const CONFIRM_WINDOW_SECONDS = 60

interface CachedText {
  loading: boolean
  text?: string
  error?: string
}

function formatRelative(iso: string, nowMs: number): string {
  const ts = Date.parse(iso)
  if (!Number.isFinite(ts)) return 'unknown time'
  const sec = Math.max(0, Math.round((nowMs - ts) / 1000))
  if (sec < 5) return 'just now'
  if (sec < 60) return `${sec}s ago`
  const min = Math.floor(sec / 60)
  if (min < 60) return `${min}m ago`
  const hr = Math.floor(min / 60)
  if (hr < 24) return `${hr}h ago`
  const days = Math.floor(hr / 24)
  return `${days}d ago`
}

function formatTimestamp(iso: string): string {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return 'unknown date'
  const pad = (n: number) => String(n).padStart(2, '0')
  return (
    `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ` +
    `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
  )
}

function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return '0 B'
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`
}

function classifyDiffLine(line: string): 'is-meta' | 'is-hunk' | 'is-add' | 'is-del' | '' {
  if (line.startsWith('--- ') || line.startsWith('+++ ') || line.startsWith('\\ ')) {
    return 'is-meta'
  }
  if (line.startsWith('@@ ')) {
    return 'is-hunk'
  }
  if (line.startsWith('+')) {
    return 'is-add'
  }
  if (line.startsWith('-')) {
    return 'is-del'
  }
  return ''
}

function countDiffChanges(diff: string): { added: number; removed: number } {
  let added = 0
  let removed = 0
  for (const line of diff.split('\n')) {
    if (line.startsWith('+++ ') || line.startsWith('--- ')) continue
    if (line.startsWith('+')) added++
    else if (line.startsWith('-')) removed++
  }
  return { added, removed }
}

export function ChangeTimelinePage() {
  const confirm = useConfirm()
  const toast = useToast()

  const [entries, setEntries] = useState<ConfigHistoryEntry[]>([])
  const [pending, setPending] = useState<ConfigHistoryPending>({ pending: false, remaining_seconds: 0 })
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [busyAction, setBusyAction] = useState<string | null>(null)
  const [nowMs, setNowMs] = useState(() => Date.now())

  const [confirmChecks, setConfirmChecks] = useState<Record<string, boolean>>({})
  const [expanded, setExpanded] = useState<Record<string, boolean>>({})
  const [viewMode, setViewMode] = useState<Record<string, 'diff' | 'yaml'>>({})
  const [diffs, setDiffs] = useState<Record<string, CachedText>>({})
  const [yamls, setYamls] = useState<Record<string, CachedText>>({})

  const deadlineRef = useRef<number | null>(null)
  const wasPendingRef = useRef(false)
  const [countdown, setCountdown] = useState(0)

  const syncPendingState = useCallback((next: ConfigHistoryPending) => {
    setPending(next)
    if (next.pending) {
      const serverExp = next.expires_at ? Date.parse(next.expires_at) : NaN
      const fallbackExp = Date.now() + Math.max(1, next.remaining_seconds) * 1000
      const target = Number.isFinite(serverExp) ? serverExp : fallbackExp
      deadlineRef.current = target
      setCountdown(Math.max(0, Math.ceil((target - Date.now()) / 1000)))
      wasPendingRef.current = true
    } else {
      deadlineRef.current = null
      setCountdown(0)
    }
  }, [])

  const loadHistory = useCallback(async (showSpinner = false) => {
    if (showSpinner) setLoading(true)
    try {
      const res = await api.configHistory.list()
      setEntries(res.entries)
      syncPendingState(res.pending)
      setError(null)
      // Clear cached diffs because the "current" head may have moved.
      setDiffs({})
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not load configuration history')
    } finally {
      if (showSpinner) setLoading(false)
    }
  }, [syncPendingState])

  useEffect(() => {
    void loadHistory(true)
  }, [loadHistory])

  // Keep relative timestamps fresh once every 15 seconds.
  useEffect(() => {
    const id = window.setInterval(() => setNowMs(Date.now()), 15_000)
    return () => window.clearInterval(id)
  }, [])

  // Live countdown and server sync while a commit-confirm restore is pending.
  useEffect(() => {
    if (!pending.pending) return

    const tickId = window.setInterval(() => {
      if (deadlineRef.current == null) return
      const rem = Math.max(0, Math.ceil((deadlineRef.current - Date.now()) / 1000))
      setCountdown(rem)
    }, 250)

    const pollId = window.setInterval(async () => {
      try {
        const latest = await api.configHistory.pending()
        if (!latest.pending) {
          const hadPending = wasPendingRef.current
          wasPendingRef.current = false
          syncPendingState(latest)
          await loadHistory(false)
          if (hadPending) {
            toast('Confirmation window expired; Orbis reverted to the previous configuration.', 'info')
          }
        } else {
          syncPendingState(latest)
        }
      } catch {
        // Transient network hiccup during a network change is expected; keep counting locally.
      }
    }, 1500)

    return () => {
      window.clearInterval(tickId)
      window.clearInterval(pollId)
    }
  }, [pending.pending, loadHistory, syncPendingState, toast])

  const shouldUseSafetyTimer = (entry: ConfigHistoryEntry): boolean => {
    const explicit = confirmChecks[entry.id]
    return explicit !== undefined ? explicit : entry.touches_network
  }

  const fetchDiff = useCallback(async (id: string) => {
    setDiffs((prev) => ({ ...prev, [id]: { loading: true } }))
    try {
      const res = await api.configHistory.diff(id)
      setDiffs((prev) => ({ ...prev, [id]: { loading: false, text: res.diff } }))
    } catch (err) {
      setDiffs((prev) => ({
        ...prev,
        [id]: { loading: false, error: err instanceof Error ? err.message : 'Failed to load diff' },
      }))
    }
  }, [])

  const fetchYaml = useCallback(async (id: string) => {
    setYamls((prev) => ({ ...prev, [id]: { loading: true } }))
    try {
      const res = await api.configHistory.get(id)
      setYamls((prev) => ({ ...prev, [id]: { loading: false, text: res.yaml } }))
    } catch (err) {
      setYamls((prev) => ({
        ...prev,
        [id]: { loading: false, error: err instanceof Error ? err.message : 'Failed to load YAML' },
      }))
    }
  }, [])

  const toggleCompare = (entry: ConfigHistoryEntry) => {
    const willOpen = !expanded[entry.id]
    setExpanded((prev) => ({ ...prev, [entry.id]: willOpen }))
    if (willOpen) {
      const mode = viewMode[entry.id] ?? 'diff'
      if (mode === 'diff' && !diffs[entry.id]) {
        void fetchDiff(entry.id)
      } else if (mode === 'yaml' && !yamls[entry.id]) {
        void fetchYaml(entry.id)
      }
    }
  }

  const switchTab = (id: string, nextMode: 'diff' | 'yaml') => {
    setViewMode((prev) => ({ ...prev, [id]: nextMode }))
    if (nextMode === 'diff' && !diffs[id]) {
      void fetchDiff(id)
    } else if (nextMode === 'yaml' && !yamls[id]) {
      void fetchYaml(id)
    }
  }

  const handleRestore = async (entry: ConfigHistoryEntry) => {
    const withConfirm = shouldUseSafetyTimer(entry)
    const stamp = formatTimestamp(entry.time)
    const promptText = withConfirm
      ? `Restore the configuration saved at ${stamp} (${entry.summary})? Orbis will apply it now and automatically roll back after ${CONFIRM_WINDOW_SECONDS} seconds unless you click Keep.`
      : `Restore the configuration saved at ${stamp} (${entry.summary})? Your current configuration will be archived first so you can undo this change.`

    const ok = await confirm(promptText)
    if (!ok) return

    setBusyAction(`restore:${entry.id}`)
    try {
      const res = await api.configHistory.restore(entry.id, withConfirm ? CONFIRM_WINDOW_SECONDS : 0)
      await loadHistory(false)
      if (res.pending.pending) {
        syncPendingState(res.pending)
        toast(`Configuration restored. Confirm within ${CONFIRM_WINDOW_SECONDS} seconds to keep it.`, 'info')
      } else {
        toast('Configuration restored and previous version archived.', 'ok')
      }
    } catch (err) {
      toast(err instanceof Error ? err.message : 'Restore failed', 'err')
    } finally {
      setBusyAction(null)
    }
  }

  const handleConfirmPending = async () => {
    setBusyAction('confirm')
    try {
      wasPendingRef.current = false
      await api.configHistory.confirm()
      await loadHistory(false)
      toast('Restored configuration confirmed and kept.', 'ok')
    } catch (err) {
      toast(err instanceof Error ? err.message : 'Could not confirm restore', 'err')
    } finally {
      setBusyAction(null)
    }
  }

  const handleUndoPendingNow = async () => {
    setBusyAction('revert')
    try {
      wasPendingRef.current = false
      await api.configHistory.revert()
      await loadHistory(false)
      toast('Rolled back to the pre-restore configuration.', 'ok')
    } catch (err) {
      toast(err instanceof Error ? err.message : 'Could not revert configuration', 'err')
    } finally {
      setBusyAction(null)
    }
  }

  return (
    <div className="ct-page">
      <div className="ct-head">
        <div className="ct-head-copy">
          <h1 className="ct-title">Change timeline</h1>
          <p className="ct-subtitle">
            Every saved configuration change is versioned locally (up to 200 snapshots), compared with secrets hidden, and reversible in one click.
          </p>
        </div>
        <div className="ct-head-actions">
          <button
            type="button"
            className="btn"
            onClick={() => void loadHistory(true)}
            disabled={loading || busyAction !== null}
          >
            <Icons.refresh size={14} /> Refresh
          </button>
        </div>
      </div>

      {error && (
        <Banner tone="err">
          Could not load configuration history: {error}
        </Banner>
      )}

      {pending.pending && (
        <div className="ct-pending-wrap">
          <Banner
            tone="warn"
            action={
              <div className="ct-pending-actions">
                <button
                  type="button"
                  className="btn primary"
                  disabled={busyAction !== null}
                  onClick={() => void handleConfirmPending()}
                >
                  <Icons.check size={14} /> Keep
                </button>
                <button
                  type="button"
                  className="btn danger"
                  disabled={busyAction !== null}
                  onClick={() => void handleUndoPendingNow()}
                >
                  <Icons.close size={14} /> Undo now
                </button>
              </div>
            }
          >
            <div className="ct-pending-body">
              <div className="ct-pending-headline">
                <span>Unconfirmed restore active</span>
                <span className="ct-countdown" aria-live="polite">
                  Reverting in {countdown}s
                </span>
              </div>
              <div className="ct-pending-detail">
                Changed keys: <span className="mono">{pending.summary || 'configuration'}</span>. Click Keep if your browser still reaches Orbis, or wait for the automatic rollback if connectivity was disrupted.
              </div>
            </div>
          </Banner>
        </div>
      )}

      {loading ? (
        <Card>
          <Loading what="saved configuration snapshots" />
          <p className="ct-teach-note">
            Orbis archives the previous YAML file whenever a setting changes on disk and replaces API keys, passwords, hashes and WireGuard keys with (hidden) before sending diffs to the browser.
          </p>
        </Card>
      ) : entries.length === 0 ? (
        <Card>
          <Empty title="No configuration changes recorded yet">
            <p className="ct-teach-note">
              Whenever you update DNS upstreams, ad-blocking lists, Wi-Fi, VPN tunnels or firewall settings, Orbis saves the previous configuration here automatically (up to 200 versions). Come back after your first change to compare added and removed lines or roll back safely with a 60-second confirmation timer.
            </p>
          </Empty>
        </Card>
      ) : (
        <ol className="ct-timeline" aria-label="Configuration change timeline">
          {entries.map((entry, idx) => {
            const isOpen = Boolean(expanded[entry.id])
            const activeTab = viewMode[entry.id] ?? 'diff'
            const diffState = diffs[entry.id]
            const yamlState = yamls[entry.id]
            const safetyOn = shouldUseSafetyTimer(entry)
            const isPendingEntry = pending.pending && pending.id === entry.id
            const counts = diffState?.text ? countDiffChanges(diffState.text) : null

            return (
              <li
                key={entry.id}
                className={`ct-item${idx === 0 ? ' is-latest' : ''}${isPendingEntry ? ' is-pending' : ''}`}
              >
                <span className="ct-marker" aria-hidden="true" />
                <Card className="ct-entry-card">
                  <div className="ct-entry-top">
                    <div className="ct-entry-meta">
                      <div className="ct-time-row">
                        <span className="ct-ago">{formatRelative(entry.time, nowMs)}</span>
                        <span className="ct-stamp">{formatTimestamp(entry.time)}</span>
                        <span className="ct-size">{formatBytes(entry.size)}</span>
                      </div>

                      <div className="ct-summary">{entry.summary}</div>

                      <div className="ct-badges">
                        {idx === 0 && <span className="tag live">Previous save</span>}
                        {entry.touches_network && <span className="tag warn">Touches network</span>}
                        {isPendingEntry && <span className="tag warn">Awaiting confirmation</span>}
                      </div>
                    </div>

                    <div className="ct-entry-controls">
                      <div className="ct-buttons">
                        <button
                          type="button"
                          className="btn"
                          aria-expanded={isOpen}
                          onClick={() => toggleCompare(entry)}
                        >
                          <Icons.activity size={14} />
                          {isOpen ? 'Hide diff' : 'Compare'}
                        </button>
                        <button
                          type="button"
                          className="btn"
                          disabled={pending.pending || busyAction !== null}
                          title={
                            pending.pending
                              ? 'Confirm or undo the pending restore before starting another one'
                              : 'Restore this configuration version'
                          }
                          onClick={() => void handleRestore(entry)}
                        >
                          <Icons.refresh size={14} />
                          {busyAction === `restore:${entry.id}` ? 'Restoring...' : 'Restore'}
                        </button>
                      </div>

                      <label className="ct-confirm-toggle">
                        <input
                          type="checkbox"
                          checked={safetyOn}
                          disabled={pending.pending || busyAction !== null}
                          onChange={(e) =>
                            setConfirmChecks((prev) => ({
                              ...prev,
                              [entry.id]: e.target.checked,
                            }))
                          }
                        />
                        <span>Keep it only if I confirm within 60 seconds</span>
                      </label>
                    </div>
                  </div>

                  {isOpen && (
                    <div className="ct-diff-panel">
                      <div className="ct-diff-toolbar">
                        <div className="ct-diff-legend">
                          {activeTab === 'diff' ? (
                            <>
                              <span>Compared against {idx === 0 ? 'current config' : 'next newer save'}</span>
                              {counts && (
                                <>
                                  <span className="ct-legend-add">+{counts.added}</span>
                                  <span className="ct-legend-del">-{counts.removed}</span>
                                </>
                              )}
                            </>
                          ) : (
                            <span>Archived YAML snapshot (secrets replaced with (hidden))</span>
                          )}
                        </div>

                        <div className="ct-view-tabs" role="group" aria-label="Comparison view">
                          <button
                            type="button"
                            className="ct-tab-btn"
                            aria-pressed={activeTab === 'diff'}
                            onClick={() => switchTab(entry.id, 'diff')}
                          >
                            Diff
                          </button>
                          <button
                            type="button"
                            className="ct-tab-btn"
                            aria-pressed={activeTab === 'yaml'}
                            onClick={() => switchTab(entry.id, 'yaml')}
                          >
                            Redacted YAML
                          </button>
                        </div>
                      </div>

                      {activeTab === 'diff' ? (
                        diffState?.loading ? (
                          <Loading what="line diff" />
                        ) : diffState?.error ? (
                          <Banner tone="err">{diffState.error}</Banner>
                        ) : !diffState?.text ? (
                          <div className="ct-diff-box">
                            <div className="ct-diff-empty">
                              No visible line differences after secret redaction (for example, only a secret value was rotated).
                            </div>
                          </div>
                        ) : (
                          <div className="ct-diff-box" role="region" aria-label={`Diff for ${entry.id}`}>
                            <div className="ct-diff-lines">
                              {diffState.text.replace(/\n$/, '').split('\n').map((line, lineIdx) => (
                                <div key={lineIdx} className={`ct-diff-line ${classifyDiffLine(line)}`}>
                                  {line || ' '}
                                </div>
                              ))}
                            </div>
                          </div>
                        )
                      ) : yamlState?.loading ? (
                        <Loading what="redacted YAML" />
                      ) : yamlState?.error ? (
                        <Banner tone="err">{yamlState.error}</Banner>
                      ) : (
                        <div className="ct-diff-box" role="region" aria-label={`YAML for ${entry.id}`}>
                          <div className="ct-diff-lines">
                            {(yamlState?.text ?? '').replace(/\n$/, '').split('\n').map((line, lineIdx) => (
                              <div key={lineIdx} className="ct-diff-line">
                                {line || ' '}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </Card>
              </li>
            )
          })}
        </ol>
      )}
    </div>
  )
}
