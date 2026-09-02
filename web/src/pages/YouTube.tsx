import { useMemo, useState } from 'react'
import { api } from '../api'
import { usePoll } from '../hooks'
import {
  Banner, Card, Empty, Icons, Loading, Stat, Switch, useConfirm, useToast,
} from '../ui'
import { clock, compact, duration } from '../format'
import type {
  AdRecord, CoverageRow, DiscoveredScreen, LoungeDeviceStats, YouTubeStatus,
} from '../types'

// The SponsorBlock categories we let the operator toggle, with plain labels.
const CATEGORIES: Array<{ id: string; label: string; hint: string }> = [
  { id: 'sponsor', label: 'Sponsor', hint: 'Paid promotions inside the video' },
  { id: 'selfpromo', label: 'Self-promo', hint: 'Creator merch / Patreon plugs' },
  { id: 'interaction', label: 'Interaction', hint: '"Like and subscribe" reminders' },
  { id: 'intro', label: 'Intro', hint: 'Intermission / intro animation' },
  { id: 'outro', label: 'Outro', hint: 'End cards and credits' },
  { id: 'preview', label: 'Preview', hint: 'Recap of what the video will cover' },
  { id: 'music_offtopic', label: 'Non-music', hint: 'Non-music parts of a music video' },
  { id: 'filler', label: 'Filler', hint: 'Tangents and jokes that add nothing' },
]

export function YouTubePage() {
  const { data: status, refresh } = usePoll<YouTubeStatus>(() => api.youtube.status(), 4000)
  const toast = useToast()

  const save = async (body: Parameters<typeof api.youtube.settings>[0]) => {
    try {
      await api.youtube.settings(body)
      refresh()
    } catch (e) {
      toast(e instanceof Error ? e.message : 'Could not save', 'err')
    }
  }

  if (!status) return <Loading what="YouTube status" />

  return (
    <div style={{ display: 'grid', gap: 14 }}>
      <Banner tone={status.enabled ? 'info' : 'warn'}>
        <strong style={{ display: 'block', marginBottom: 3 }}>
          Two engines, one for each kind of screen
        </strong>
        The <b>Lounge engine</b> attaches to a TV, Apple TV, console or Chromecast the way your phone
        does when it casts, then mutes and skips ads and sponsor segments by driving the player. No
        certificate, nothing installed. For browsers that trust the Orbis certificate, the{' '}
        <b>in-page engine</b> removes ad structures before the page sees them and drives past
        anything that still starts. The mobile YouTube app is the one thing neither can reach; the
        full picture is at the bottom.
      </Banner>

      <EngineControls status={status} onSave={save} />
      <Devices status={status} onChanged={refresh} />
      <InPageEngine />
      <Coverage rows={status.coverage} />
    </div>
  )
}

function EngineControls({
  status, onSave,
}: {
  status: YouTubeStatus
  onSave: (b: Parameters<typeof api.youtube.settings>[0]) => void
}) {
  const online = status.devices.filter((d) => d.connected && d.online).length
  const ads = status.devices.reduce((n, d) => n + d.ads_handled, 0)
  const cut = status.devices.reduce((n, d) => n + d.ads_skipped, 0)
  const lost = status.devices.reduce((n, d) => n + d.ads_lost, 0)
  const reloads = status.devices.reduce((n, d) => n + d.reloads, 0)
  const segs = status.devices.reduce((n, d) => n + d.segments_skipped + d.segments_muted, 0)
  const saved = status.devices.reduce((n, d) => n + d.seconds_saved, 0)

  const toggleCategory = (id: string, on: boolean) => {
    const set = new Set(status.categories)
    if (on) set.add(id)
    else set.delete(id)
    onSave({ categories: [...set] })
  }

  return (
    <Card
      title="Lounge engine"
      actions={
        <Switch
          checked={status.enabled}
          onChange={(v) => onSave({ enabled: v })}
          label={status.enabled ? 'On' : 'Off'}
        />
      }
    >
      <div className="grid c4" style={{ marginBottom: 14 }}>
        <Stat label="Screens on" value={String(online)} sub={`${status.devices.length} paired`} tone={online ? 'accent' : undefined} />
        <Stat label="Ads cut short" value={compact(cut)} sub={ads ? `of ${compact(ads)} seen${lost ? `, ${lost} lost` : ''}${reloads ? `, ${reloads} reloaded past` : ''}` : 'none seen yet'} tone={cut ? 'accent' : undefined} />
        <Stat label="Segments" value={compact(segs)} sub="SponsorBlock, skipped or muted" />
        <Stat label="Time saved" value={saved ? duration(Math.round(saved)) : '0s'} sub="since start" tone={saved ? 'accent' : undefined} />
      </div>

      <div style={{ display: 'grid', gap: 9, opacity: status.enabled ? 1 : 0.55, pointerEvents: status.enabled ? 'auto' : 'none' }}>
        <Switch checked={status.auto_discover} onChange={(v) => onSave({ auto_discover: v })}
          label="Auto-discover screens on the network" />
        <div className="hint" style={{ marginTop: -4, marginBottom: 4 }}>
          Adopts any TV that advertises a screen id over DIAL, with no code. Devices that keep their
          id private still work via the code below.
        </div>
        <Switch checked={status.skip_ads} onChange={(v) => onSave({ skip_ads: v })}
          label="Skip ads the moment YouTube allows it" />
        <Switch checked={status.mute_ads} onChange={(v) => onSave({ mute_ads: v })}
          label="Mute every ad from its first frame (covers the unskippable ones)" />
        <Switch checked={status.reload_unskippable} onChange={(v) => onSave({ reload_unskippable: v })}
          label="Reload past unskippable mid-rolls" />
        <div className="hint" style={{ marginTop: -4 }}>
          When an unskippable ad of ten seconds or more starts mid-video, Orbis asks the screen to
          load the video again at the same position, which on most screens resumes without the ad
          after a moment of buffering. A video that serves the ad again anyway is remembered and
          left to the mute. Pre-rolls are never reloaded; a fresh load is what causes them.
        </div>
      </div>

      <div style={{ borderTop: '1px solid var(--line-soft)', marginTop: 13, paddingTop: 12 }}>
        <div style={{ fontSize: 12.5, color: 'var(--text-dim)', marginBottom: 9 }}>
          Also skip these in-video SponsorBlock segments (shared by the Lounge and in-page engines,
          so they apply even with the Lounge engine off)
        </div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
          {CATEGORIES.map((c) => {
            const on = status.categories.includes(c.id)
            return (
              <button
                key={c.id}
                title={c.hint}
                onClick={() => toggleCategory(c.id, !on)}
                className={`chip ${on ? 'on' : ''}`}
                style={{
                  padding: '5px 11px', borderRadius: 999, cursor: 'pointer', fontSize: 12,
                  border: `1px solid ${on ? 'var(--accent)' : 'var(--line)'}`,
                  background: on ? 'color-mix(in srgb, var(--accent) 16%, transparent)' : 'transparent',
                  color: on ? 'var(--accent)' : 'var(--text-dim)',
                }}
              >
                {on ? '✓ ' : ''}{c.label}
              </button>
            )
          })}
        </div>
      </div>
    </Card>
  )
}

function Devices({ status, onChanged }: { status: YouTubeStatus; onChanged: () => void }) {
  const toast = useToast()
  const confirm = useConfirm()
  const [scanning, setScanning] = useState(false)
  const [discovered, setDiscovered] = useState<DiscoveredScreen[]>(status.discovered ?? [])
  const [code, setCode] = useState('')
  const [pairing, setPairing] = useState(false)

  const paired = useMemo(
    () => new Set(status.devices.map((d) => d.screen_id)),
    [status.devices],
  )

  const scan = async () => {
    setScanning(true)
    try {
      const found = await api.youtube.discover()
      setDiscovered(found ?? [])
      if (!found || found.length === 0) toast('No screens answered. Is the TV on with YouTube open?', 'info')
    } catch (e) {
      toast(e instanceof Error ? e.message : 'Scan failed', 'err')
    } finally {
      setScanning(false)
    }
  }

  const adopt = async (s: DiscoveredScreen) => {
    try {
      await api.youtube.adopt(s.screen_id, s.name)
      toast(`Added ${s.name}`, 'ok')
      onChanged()
    } catch (e) {
      toast(e instanceof Error ? e.message : 'Could not add', 'err')
    }
  }

  const pair = async () => {
    setPairing(true)
    try {
      const dev = await api.youtube.pair(code)
      toast(`Paired ${dev.name || 'device'}`, 'ok')
      setCode('')
      onChanged()
    } catch (e) {
      toast(e instanceof Error ? e.message : 'Pairing failed', 'err')
    } finally {
      setPairing(false)
    }
  }

  const forget = async (d: LoungeDeviceStats) => {
    if (!(await confirm(`Stop controlling "${d.name}"?`))) return
    try {
      await api.youtube.forget(d.screen_id)
      onChanged()
    } catch (e) {
      toast(e instanceof Error ? e.message : 'Could not remove', 'err')
    }
  }

  const newScreens = discovered.filter((s) => s.screen_id && !paired.has(s.screen_id))

  return (
    <Card
      title="Screens"
      actions={
        <button className="btn sm" onClick={scan} disabled={scanning}>
          <Icons.refresh size={13} /> {scanning ? 'Scanning…' : 'Scan network'}
        </button>
      }
    >
      {status.devices.length === 0 ? (
        <Empty title="No screens paired yet">
          Scan the network with a TV powered on and YouTube open, or enter its “Link with TV code”
          below.
        </Empty>
      ) : (
        <div style={{ display: 'grid', gap: 8 }}>
          {status.devices.map((d) => (
            <DeviceRow key={d.screen_id} d={d} onForget={() => forget(d)} />
          ))}
        </div>
      )}

      {newScreens.length > 0 && (
        <div style={{ marginTop: 14, borderTop: '1px solid var(--line-soft)', paddingTop: 12 }}>
          <div style={{ fontSize: 12.5, color: 'var(--text-dim)', marginBottom: 8 }}>
            Found on the network
          </div>
          <div style={{ display: 'grid', gap: 8 }}>
            {newScreens.map((s) => (
              <div key={s.screen_id || s.host} className="row" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <Icons.tv size={16} />
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: 13 }}>{s.name}</div>
                  <div style={{ fontSize: 11, color: 'var(--text-faint)' }}>
                    {s.model || s.host}{s.app_state ? ` · YouTube ${s.app_state}` : ''}
                  </div>
                </div>
                <button className="btn sm primary" onClick={() => adopt(s)}>
                  <Icons.plus size={13} /> Add
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      <div style={{ marginTop: 14, borderTop: '1px solid var(--line-soft)', paddingTop: 12 }}>
        <div style={{ fontSize: 12.5, color: 'var(--text-dim)', marginBottom: 8 }}>
          Pair by code <span style={{ color: 'var(--text-faint)' }}>
            (YouTube → Settings → Link with TV code)
          </span>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <input
            className="input"
            inputMode="numeric"
            placeholder="123 456 789 012"
            value={code}
            onChange={(e) => setCode(e.target.value)}
            style={{ flex: 1, fontVariantNumeric: 'tabular-nums', letterSpacing: '0.05em' }}
          />
          <button className="btn primary" disabled={pairing || code.replace(/\D/g, '').length < 12} onClick={pair}>
            {pairing ? 'Pairing…' : 'Pair'}
          </button>
        </div>
      </div>
    </Card>
  )
}

function deviceState(d: LoungeDeviceStats): { label: string; dot: 'on' | 'off' | 'warn' } {
  if (d.ad_active) return { label: 'handling an ad', dot: 'warn' }
  if (!d.connected) return { label: 'reconnecting', dot: 'off' }
  if (!d.online) return { label: 'screen away', dot: 'off' }
  if (d.video_id) return { label: 'watching', dot: 'on' }
  return { label: 'idle', dot: 'on' }
}

function DeviceRow({ d, onForget }: { d: LoungeDeviceStats; onForget: () => void }) {
  const [open, setOpen] = useState(false)
  const state = deviceState(d)
  const recent = d.recent ?? []
  const segs = d.segments_skipped + d.segments_muted
  return (
    <div className="row" style={{ padding: '2px 0' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <span className={`dot ${state.dot}`} />
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontSize: 13, display: 'flex', gap: 8, alignItems: 'baseline' }}>
            <span>{d.name}</span>
            <span style={{ fontSize: 11, color: 'var(--text-faint)' }}>{state.label}</span>
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-faint)' }}>
            {d.connected
              ? <>
                  {d.ads_skipped} of {d.ads_handled} ads cut short
                  {d.ads_lost ? ` (${d.ads_lost} lost)` : ''}
                  {' · '}{segs} segment{segs === 1 ? '' : 's'}
                  {d.seconds_saved ? ` · ${duration(Math.round(d.seconds_saved))} saved` : ''}
                  {d.video_id ? ` · at ${duration(Math.floor(d.position))}` : ''}
                  {d.segments_loaded ? ` · ${d.segments_loaded} segment(s) loaded` : ''}
                </>
              : (d.last_error || 'not connected')}
          </div>
        </div>
        <button className="btn sm" disabled={recent.length === 0} onClick={() => setOpen((v) => !v)}
          title={recent.length ? 'Every ad this screen has seen since Orbis started' : 'No ads seen yet'}>
          History{recent.length ? ` (${recent.length})` : ''}
        </button>
        <button className="btn sm" title="Stop controlling this device" onClick={onForget}>
          <Icons.trash size={13} />
        </button>
      </div>
      {open && recent.length > 0 && (
        <div className="table-wrap" style={{ marginTop: 8 }}>
          <table className="t" style={{ fontSize: 11.5 }}>
            <thead>
              <tr><th>When</th><th>Outcome</th><th>Ad</th><th className="num">Ran</th><th>Kind</th><th>Ended by</th></tr>
            </thead>
            <tbody>
              {recent.map((r, i) => <AdRow key={`${r.at}-${i}`} r={r} />)}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

function AdRow({ r }: { r: AdRecord }) {
  const tag = r.outcome === 'skipped' ? 'allow' : r.outcome === 'lost' ? 'warn' : r.outcome === 'abandoned' ? 'info' : ''
  const kind = [r.bumper ? 'bumper' : r.skippable ? 'skippable' : 'unskippable', r.muted ? 'muted' : null, r.reloaded ? 'reloaded' : null]
    .filter(Boolean).join(', ')
  return (
    <tr>
      <td style={{ whiteSpace: 'nowrap', color: 'var(--text-dim)' }}>{clock(r.at)}</td>
      <td><span className={`tag ${tag}`}>{r.outcome}</span></td>
      <td className="mono" style={{ color: 'var(--text-faint)' }}>
        {r.ad_video_id || '?'}
        {r.content_video_id ? <span title="during this video"> in {r.content_video_id}</span> : null}
      </td>
      <td className="num" style={{ whiteSpace: 'nowrap' }}>
        {r.watched}s{r.duration ? ` of ${Math.round(r.duration)}s` : ''}
      </td>
      <td style={{ color: 'var(--text-dim)' }}>{kind}</td>
      <td style={{ color: 'var(--text-faint)' }}>{r.reason}{r.attempts ? ` · ${r.attempts} skip${r.attempts === 1 ? '' : 's'} sent` : ''}</td>
    </tr>
  )
}

/** The browser-side engine, which lives under the in-stream filter but is
 *  controlled here too so the YouTube page is the one place for YouTube. */
function InPageEngine() {
  const { data: config, refresh } = usePoll(() => api.config.get(), 0)
  const { data: proxy } = usePoll(() => api.proxy.status(), 8000)
  const toast = useToast()
  const f = config?.mitm.filters
  const running = Boolean(proxy?.running)

  const set = async (key: string, value: unknown) => {
    try {
      await api.config.patch({ [key]: value })
      refresh()
    } catch (e) {
      toast(e instanceof Error ? e.message : 'Could not save', 'err')
    }
  }

  const stripped = Number(proxy?.ads_stripped ?? 0)
  const inpage = Number(proxy?.inpage_stripped ?? 0)
  const driven = Number(proxy?.inpage_skipped ?? 0)
  const segs = Number(proxy?.inpage_segments ?? 0)
  const stitched = Number(proxy?.server_stitched ?? 0)

  return (
    <Card title="In-page engine (browsers with the certificate)"
      actions={<span className={`tag ${running ? 'allow' : ''}`}>{running ? 'filter proxy on' : 'filter proxy off'}</span>}>
      <div className="grid c4" style={{ marginBottom: 14 }}>
        <Stat label="Removed before the page" value={compact(stripped)} sub="response filter" tone={stripped ? 'accent' : undefined} />
        <Stat label="Removed inside the page" value={compact(inpage)} sub="in-page engine" tone={inpage ? 'accent' : undefined} />
        <Stat label="Ad breaks driven past" value={compact(driven)} sub="skipped or fast-forwarded, muted" tone={driven ? 'accent' : undefined} />
        <Stat label="Segments in browsers" value={compact(segs)} sub={stitched ? `${compact(stitched)} server-stitched seen` : 'SponsorBlock, no extension'} />
      </div>
      <div style={{ display: 'grid', gap: 9 }}>
        <Switch checked={f?.youtube ?? false} onChange={(v) => set('mitm.filters.youtube', v)}
          label="Strip ad structures from YouTube responses" />
        <Switch checked={f?.youtube_in_page ?? false} disabled={!(f?.youtube ?? false)}
          onChange={(v) => set('mitm.filters.youtube_in_page', v)}
          label="In-page engine: drive the player past anything that still starts" />
        <Switch checked={f?.youtube_sponsorblock ?? false} disabled={!(f?.youtube ?? false) || !(f?.youtube_in_page ?? false)}
          onChange={(v) => set('mitm.filters.youtube_sponsorblock', v)}
          label="SponsorBlock in the browser, using the categories above" />
      </div>
      <div className="hint" style={{ marginTop: 10 }}>
        Needs the Orbis certificate trusted on the device and its traffic passing through this node.
        Install the certificate and check readiness under Ad blocking → In-stream ads. The counters
        here are reported by the engine from inside real pages, so a zero means no page has run it
        yet, not that it is broken.
      </div>
    </Card>
  )
}

function Coverage({ rows }: { rows: CoverageRow[] }) {
  return (
    <Card title="What is covered, honestly">
      <div style={{ display: 'grid', gap: 10 }}>
        {rows.map((r) => (
          <div key={r.device_class} style={{ display: 'flex', gap: 11, alignItems: 'flex-start' }}>
            <span className={`dot ${r.covered ? 'on' : 'err'}`} style={{ marginTop: 5 }} />
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontSize: 13, display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'baseline' }}>
                <strong>{r.device_class}</strong>
                <span className="tag" style={{ fontSize: 10.5 }}>{r.engine}</span>
                {r.no_ca
                  ? <span className="tag info" style={{ fontSize: 10.5 }}>no certificate</span>
                  : <span className="tag warn" style={{ fontSize: 10.5 }}>needs CA</span>}
              </div>
              <div style={{ fontSize: 11.5, color: 'var(--text-dim)', marginTop: 3, lineHeight: 1.55 }}>
                {r.note}
              </div>
            </div>
          </div>
        ))}
      </div>
    </Card>
  )
}
