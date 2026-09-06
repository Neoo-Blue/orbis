import { useCallback, useEffect, useRef, useState } from 'react'
import { api } from '../api'
import { usePoll } from '../hooks'
import { Banner, Spinner, useToast } from '../ui'
import { ago } from '../format'
import type { UpdateStatus } from '../types'

// One place that knows how to talk about updates: the banner on every page,
// the card in About, and the row in simple Settings all read from here.

const stateLabel: Record<string, string> = {
  checking: 'Checking GitHub…',
  downloading: 'Downloading',
  verifying: 'Verifying the download',
  installing: 'Installing',
  restarting: 'Restarting Orbis. This page reloads when the new version is up.',
  installed: 'Installed. Restart the process to run the new version.',
}

export function useUpdate(intervalMs = 5 * 60_000) {
  const { data, refresh: reload } = usePoll(() => api.update.get(), intervalMs)
  const [busy, setBusy] = useState(false)
  const toast = useToast()
  const applying = data?.state && !['idle', 'error', 'installed'].includes(data.state)
  // While an update runs, watch closely; after the restart the version changes and we reload.
  const startVersion = useRef<string | null>(null)
  useEffect(() => {
    if (!applying) return
    if (!startVersion.current) startVersion.current = data?.current ?? null
    const t = setInterval(async () => {
      try {
        const s = await api.update.get()
        if (startVersion.current && s.current !== startVersion.current) location.reload()
        reload()
      } catch { /* the daemon is restarting */ }
    }, 1500)
    return () => clearInterval(t)
  }, [applying, data?.current, reload])

  const check = useCallback(async () => {
    setBusy(true)
    try {
      const s = await api.update.check()
      if (!s.available) toast(`You are on ${s.current}, the latest release.`)
      reload()
    } catch (e) { toast(String(e), 'err') } finally { setBusy(false) }
  }, [reload, toast])

  const apply = useCallback(async () => {
    setBusy(true)
    try {
      await api.update.apply()
      startVersion.current = data?.current ?? null
      reload()
    } catch (e) { toast(String(e), 'err') } finally { setBusy(false) }
  }, [data?.current, reload, toast])

  return { status: data, busy, applying: !!applying, check, apply, reload }
}

export function updateHint(s: UpdateStatus): string {
  switch (s.method) {
    case 'docker': return 'This node runs in a container. Pull the new image and recreate the container to update.'
    case 'dev': return 'Development build. Rebuild from source to update.'
    case 'binary': return 'Orbis will replace its binary and keep the old one as orbisd.prev. Restart the process afterwards.'
    case 'systemd': return 'Orbis downloads the release, verifies its checksum, keeps the old binary as orbisd.prev, and restarts the service. About half a minute offline.'
    default: return ''
  }
}

export function UpdateProgress({ status }: { status: UpdateStatus }) {
  const label = stateLabel[status.state] ?? status.state
  return (
    <div style={{ display: 'grid', gap: 6 }}>
      <div className="row" style={{ gap: 10 }}>
        <Spinner />
        <span>{label}{status.state === 'downloading' && status.progress > 0 ? ` ${Math.round(status.progress * 100)}%` : ''}</span>
      </div>
      {status.state === 'downloading' && (
        <div style={{ height: 6, borderRadius: 3, background: 'var(--line, #333)', overflow: 'hidden' }}>
          <div style={{ height: '100%', width: `${Math.max(2, Math.round(status.progress * 100))}%`, background: 'var(--accent, #4c8dff)', transition: 'width .3s' }} />
        </div>
      )}
    </div>
  )
}

/** The compact banner shown on every page when a newer release exists. */
export function UpdateBanner({ onSettings }: { onSettings?: () => void }) {
  const { status, busy, applying, apply } = useUpdate()
  const [dismissed, setDismissed] = useState<string | null>(() => sessionStorage.getItem('orbis.update.dismissed'))
  if (!status) return null
  if (applying) return <Banner tone="info"><UpdateProgress status={status} /></Banner>
  if (status.state === 'error' && status.error) {
    return <Banner tone="warn" action={onSettings && <button className="btn sm" onClick={onSettings}>Details</button>}>Update failed: {status.error}</Banner>
  }
  if (!status.available || !status.latest || dismissed === status.latest.version) return null
  const dismiss = () => { sessionStorage.setItem('orbis.update.dismissed', status.latest!.version); setDismissed(status.latest!.version) }
  return (
    <Banner tone="info" action={
      <span className="row" style={{ gap: 6 }}>
        {status.can_apply
          ? <button className="btn sm primary" disabled={busy} onClick={apply}>Update now</button>
          : <a className="btn sm primary" href={status.latest.url} target="_blank" rel="noreferrer">Release notes</a>}
        {onSettings && <button className="btn sm" onClick={onSettings}>Details</button>}
        <button className="btn sm ghost" onClick={dismiss} aria-label="Dismiss">✕</button>
      </span>
    }>
      Orbis {status.latest.version} is available. You are on {status.current}.
      {status.method === 'docker' ? ' Pull the new image to update.' : ''}
    </Banner>
  )
}

/** The full card: versions, notes, check and install. */
export function UpdateCard({ compact = false }: { compact?: boolean }) {
  const { status, busy, applying, check, apply } = useUpdate(60_000)
  const [showNotes, setShowNotes] = useState(false)
  if (!status) return null
  const latest = status.latest
  return (
    <div style={{ display: 'grid', gap: 12 }}>
      <div className="row" style={{ justifyContent: 'space-between', gap: 12, flexWrap: 'wrap' }}>
        <div>
          <div style={{ fontWeight: 600 }}>
            {status.available && latest ? `Orbis ${latest.version} is available` : `You are on ${status.current}`}
          </div>
          <div className="hint">
            {status.available && latest
              ? `Running ${status.current}. Published ${ago(latest.published_at)}.`
              : latest ? `Latest release ${latest.version}, checked ${status.checked_at ? ago(status.checked_at) : 'just now'}.` : status.check_error ? `Could not reach GitHub: ${status.check_error}` : 'Not checked yet.'}
          </div>
        </div>
        <span className="row" style={{ gap: 6 }}>
          <button className="btn sm" disabled={busy || applying} onClick={check}>Check now</button>
          {status.available && status.can_apply && (
            <button className="btn sm primary" disabled={busy || applying} onClick={apply}>Update now</button>
          )}
          {status.available && !status.can_apply && latest && (
            <a className="btn sm primary" href={latest.url} target="_blank" rel="noreferrer">Release page</a>
          )}
        </span>
      </div>
      {applying && <UpdateProgress status={status} />}
      {status.state === 'error' && status.error && <Banner tone="warn">Update failed: {status.error}</Banner>}
      {status.state === 'installed' && <Banner tone="info">{stateLabel.installed}</Banner>}
      {!compact && (
        <div className="hint">
          Installed as <b>{status.method}</b> on {status.arch}. {updateHint(status)}
          {status.method === 'docker' && (
            <pre style={{ marginTop: 8 }}>docker pull ghcr.io/neoo-blue/orbis:stable{'\n'}docker compose up -d</pre>
          )}
          {status.method === 'systemd' && <> Or from a shell: <code>sudo orbisd -update</code>.</>}
        </div>
      )}
      {latest?.notes && (
        <div>
          <button className="btn sm ghost" onClick={() => setShowNotes(v => !v)}>{showNotes ? 'Hide' : 'Show'} release notes for {latest.version}</button>
          {showNotes && <pre style={{ whiteSpace: 'pre-wrap', marginTop: 8, maxHeight: 320, overflow: 'auto' }}>{latest.notes}</pre>}
        </div>
      )}
    </div>
  )
}
