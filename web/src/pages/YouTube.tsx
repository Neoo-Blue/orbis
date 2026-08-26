import { useMemo, useState } from 'react'
import { api } from '../api'
import { usePoll } from '../hooks'
import {
  Banner, Card, Empty, Icons, Loading, Stat, Switch, useConfirm, useToast,
} from '../ui'
import { compact, duration } from '../format'
import type { CoverageRow, DiscoveredScreen, LoungeDeviceStats, YouTubeStatus } from '../types'

// The SponsorBlock categories we let the operator toggle, with plain labels.
const CATEGORIES: Array<{ id: string; label: string; hint: string }> = [
  { id: 'sponsor', label: 'Sponsor', hint: 'Paid promotions inside the video' },
  { id: 'selfpromo', label: 'Self-promo', hint: 'Creator merch / Patreon plugs' },
  { id: 'interaction', label: 'Interaction', hint: '"Like and subscribe" reminders' },
  { id: 'intro', label: 'Intro', hint: 'Intermission / intro animation' },
  { id: 'outro', label: 'Outro', hint: 'End cards and credits' },
  { id: 'preview', label: 'Preview', hint: 'Recap of what the video will cover' },
  { id: 'music_offtopic', label: 'Non-music', hint: 'Non-music parts of a music video' },
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
          Remove YouTube ads with no certificate, nothing installed on the device
        </strong>
        The Lounge engine attaches to a TV, Apple TV or console the same way your phone does when it
        casts, then skips and mutes ads and sponsor segments by driving the player. It never
        decrypts the video, so it needs no CA. It cannot cover the mobile YouTube app, which pins
        its certificates and is not a castable screen. The full picture is below.
      </Banner>

      <EngineControls status={status} onSave={save} />
      <Devices status={status} onChanged={refresh} />
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
  const active = status.devices.filter((d) => d.connected).length
  const ads = status.devices.reduce((n, d) => n + d.ads_handled, 0)
  const segs = status.devices.reduce((n, d) => n + d.segments_skipped, 0)

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
      <div className="grid c3" style={{ marginBottom: 14 }}>
        <Stat label="Connected screens" value={String(active)} sub={`${status.devices.length} paired`} tone={active ? 'accent' : undefined} />
        <Stat label="Ads handled" value={compact(ads)} sub="since start" tone={ads ? 'accent' : undefined} />
        <Stat label="Segments skipped" value={compact(segs)} sub="SponsorBlock" />
      </div>

      <div style={{ display: 'grid', gap: 9, opacity: status.enabled ? 1 : 0.55, pointerEvents: status.enabled ? 'auto' : 'none' }}>
        <Switch checked={status.auto_discover} onChange={(v) => onSave({ auto_discover: v })}
          label="Auto-discover screens on the network" />
        <div className="hint" style={{ marginTop: -4, marginBottom: 4 }}>
          Adopts any TV that advertises a screen id over DIAL, with no code. Devices that keep their
          id private still work via the code below.
        </div>
        <Switch checked={status.skip_ads} onChange={(v) => onSave({ skip_ads: v })}
          label="Skip ads as soon as they are skippable" />
        <Switch checked={status.mute_ads} onChange={(v) => onSave({ mute_ads: v })}
          label="Mute ads during the unskippable opening seconds" />
      </div>

      <div style={{ borderTop: '1px solid var(--line-soft)', marginTop: 13, paddingTop: 12, opacity: status.enabled ? 1 : 0.55 }}>
        <div style={{ fontSize: 12.5, color: 'var(--text-dim)', marginBottom: 9 }}>
          Also seek past these in-video SponsorBlock segments
        </div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
          {CATEGORIES.map((c) => {
            const on = status.categories.includes(c.id)
            return (
              <button
                key={c.id}
                title={c.hint}
                disabled={!status.enabled}
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
      title="Devices"
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

function DeviceRow({ d, onForget }: { d: LoungeDeviceStats; onForget: () => void }) {
  const state = d.ad_active ? 'skipping ad' : d.connected ? (d.video_id ? 'watching' : 'idle') : 'reconnecting'
  return (
    <div className="row" style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '2px 0' }}>
      <span className={`dot ${d.connected ? (d.ad_active ? 'warn' : 'on') : 'off'}`} />
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: 13, display: 'flex', gap: 8, alignItems: 'baseline' }}>
          <span>{d.name}</span>
          <span style={{ fontSize: 11, color: 'var(--text-faint)' }}>{state}</span>
        </div>
        <div style={{ fontSize: 11, color: 'var(--text-faint)' }}>
          {d.connected
            ? <>
                {d.ads_handled} ads · {d.segments_skipped} segments skipped
                {d.video_id ? ` · at ${duration(Math.floor(d.position))}` : ''}
                {d.segments_loaded ? ` · ${d.segments_loaded} segment(s) loaded` : ''}
              </>
            : (d.last_error || 'not connected')}
        </div>
      </div>
      <button className="btn sm" title="Stop controlling this device" onClick={onForget}>
        <Icons.trash size={13} />
      </button>
    </div>
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
