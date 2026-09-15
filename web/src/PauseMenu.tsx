import { useState } from 'react'

const OPTIONS: Array<{ m: number; l: string }> = [
  { m: 30, l: '30 min' },
  { m: 60, l: '1 hour' },
  { m: 180, l: '3 hours' },
  { m: 0, l: 'Until I resume' },
]

export function pauseUntilLabel(until?: string) {
  if (!until) return 'paused'
  const t = new Date(until)
  if (Number.isNaN(t.getTime())) return 'paused'
  return `paused until ${t.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' })}`
}

export function pauseOkMessage(name: string, minutes: number) {
  if (!minutes) return `${name} paused until you resume it`
  if (minutes >= 60) {
    const hours = minutes / 60
    return `${name} paused for ${hours} hour${hours > 1 ? 's' : ''}`
  }
  return `${name} paused for ${minutes} minutes`
}

/** Timed internet pause: 30 min / 1 h / 3 h / until resumed. */
export function PauseMenu({ onPick, disabled }: { onPick: (minutes: number) => void; disabled?: boolean }) {
  const [open, setOpen] = useState(false)
  const stop = (e: { stopPropagation: () => void }) => { e.stopPropagation() }
  if (!open) {
    return (
      <button type="button" className="btn sm" disabled={disabled}
        onClick={(e) => { e.stopPropagation(); setOpen(true) }}>
        Pause internet
      </button>
    )
  }
  return (
    <span style={{ display: 'inline-flex', gap: 4, flexWrap: 'wrap' }} onClick={stop}>
      {OPTIONS.map((o) => (
        <button key={o.m} type="button" className="btn sm"
          onClick={() => { setOpen(false); onPick(o.m) }}>{o.l}</button>
      ))}
      <button type="button" className="btn sm" onClick={() => setOpen(false)}>Cancel</button>
    </span>
  )
}
