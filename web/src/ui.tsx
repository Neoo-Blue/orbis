import {
  Children, cloneElement, createContext, isValidElement, useCallback, useContext, useEffect, useId, useMemo, useRef, useState,
  type ReactElement, type ReactNode,
} from 'react'
import { useThumb } from './motion'

/* ---------- icons ----------
   Inline strokes rather than an icon package: eleven glyphs is not worth a
   dependency, and inline SVG inherits currentColor for free. */

type IconProps = { size?: number; className?: string }
const svg = (path: ReactNode) =>
  function Icon({ size = 16, className }: IconProps) {
    return (
      <svg viewBox="0 0 24 24" width={size} height={size} fill="none" stroke="currentColor"
        strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden="true">
        {path}
      </svg>
    )
  }

export const Icons = {
  globe: svg(<><circle cx="12" cy="12" r="9" /><path d="M3 12h18M12 3a15 15 0 0 1 0 18a15 15 0 0 1 0-18" /></>),
  grid: svg(<><rect x="3" y="3" width="7" height="7" rx="1.4" /><rect x="14" y="3" width="7" height="7" rx="1.4" /><rect x="3" y="14" width="7" height="7" rx="1.4" /><rect x="14" y="14" width="7" height="7" rx="1.4" /></>),
  devices: svg(<><rect x="2" y="4" width="14" height="10" rx="1.6" /><path d="M6 18h6" /><rect x="17" y="9" width="5" height="11" rx="1.4" /></>),
  activity: svg(<path d="M3 12h4l3-8 4 16 3-8h4" />),
  shield: svg(<path d="M12 3l7.5 3v6c0 4.6-3.1 8.3-7.5 9.5C7.6 20.3 4.5 16.6 4.5 12V6z" />),
  dns: svg(<><ellipse cx="12" cy="6" rx="8" ry="3" /><path d="M4 6v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6" /><path d="M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3" /></>),
  block: svg(<><circle cx="12" cy="12" r="9" /><path d="M5.6 5.6l12.8 12.8" /></>),
  key: svg(<><circle cx="8" cy="15" r="4" /><path d="M11 12l9-9M17 6l2.5 2.5M14.5 8.5L17 11" /></>),
  chat: svg(<path d="M20 14a3 3 0 0 1-3 3H9l-5 4V6a3 3 0 0 1 3-3h10a3 3 0 0 1 3 3z" />),
  bell: svg(<><path d="M18 8a6 6 0 1 0-12 0c0 6-2 7-2 7h16s-2-1-2-7" /><path d="M10.3 21a2 2 0 0 0 3.4 0" /></>),
  gear: svg(<><circle cx="12" cy="12" r="3" /><path d="M19.4 15a1.6 1.6 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.6 1.6 0 0 0-2.7 1.1v.3a2 2 0 1 1-4 0v-.2a1.6 1.6 0 0 0-2.8-1.1l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1A1.6 1.6 0 0 0 3.5 15H3a2 2 0 1 1 0-4h.2A1.6 1.6 0 0 0 4.3 8.2l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1A1.6 1.6 0 0 0 9.9 4.3V4a2 2 0 1 1 4 0v.2a1.6 1.6 0 0 0 2.7 1.1l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.6 1.6 0 0 0 1.1 2.7H21a2 2 0 1 1 0 4h-.2a1.6 1.6 0 0 0-1.4 1z" /></>),
  search: svg(<><circle cx="11" cy="11" r="7" /><path d="M20 20l-4-4" /></>),
  refresh: svg(<><path d="M21 12a9 9 0 1 1-2.6-6.4" /><path d="M21 3v6h-6" /></>),
  close: svg(<path d="M6 6l12 12M18 6L6 18" />),
  check: svg(<path d="M4 12.5l5 5L20 6.5" />),
  alert: svg(<><path d="M12 3l9.5 17H2.5z" /><path d="M12 9v5M12 17.5v.01" /></>),
  info: svg(<><circle cx="12" cy="12" r="9" /><path d="M12 11v5M12 8v.01" /></>),
  plus: svg(<path d="M12 5v14M5 12h14" />),
  trash: svg(<><path d="M4 7h16M9 7V5a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2" /><path d="M6 7l1 13a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1l1-13" /></>),
  download: svg(<><path d="M12 3v12M7 11l5 5 5-5" /><path d="M4 20h16" /></>),
  chevron: svg(<path d="M9 6l6 6-6 6" />),
  route: svg(<><circle cx="6" cy="6" r="3" /><circle cx="18" cy="18" r="3" /><path d="M6 9v4a5 5 0 0 0 5 5h4" /></>),
  spark: svg(<path d="M13 2L4.5 13H11l-1 9 8.5-11H12z" />),
  orbit: svg(<><circle cx="12" cy="12" r="9" /><ellipse cx="12" cy="12" rx="9" ry="3.4" /><circle cx="12" cy="12" r="1.6" /></>),
  stack: svg(<><path d="M12 3l9 5-9 5-9-5z" /><path d="M3 13l9 5 9-5" /></>),
  chart: svg(<path d="M4 20V10M10 20V4M16 20v-7M21 20H3" />),
  nodes: svg(<><circle cx="12" cy="5" r="2.4" /><circle cx="5" cy="19" r="2.4" /><circle cx="19" cy="19" r="2.4" /><path d="M11 7.2L6.2 17M13 7.2L17.8 17M7.4 19h9.2" /></>),
  pulse: svg(<><path d="M2 13h4l2-5 4 10 2.5-7 1.5 2h6" /></>),
  user: svg(<><circle cx="12" cy="8" r="4" /><path d="M4 21c1.2-4.4 4.2-6.5 8-6.5s6.8 2.1 8 6.5" /></>),
  question: svg(<><circle cx="12" cy="12" r="9" /><path d="M9.4 9.3a2.7 2.7 0 1 1 3.9 2.4c-.9.5-1.3 1-1.3 2M12 17v.01" /></>),
  target: svg(<><circle cx="12" cy="12" r="9" /><circle cx="12" cy="12" r="4" /><path d="M12 1.5V6M12 18v4.5M1.5 12H6M18 12h4.5" /></>),
  server: svg(<><rect x="3" y="4" width="18" height="7" rx="1.6" /><rect x="3" y="13" width="18" height="7" rx="1.6" /><path d="M7 7.5v.01M7 16.5v.01" /></>),
  cable: svg(<path d="M5 3v5a3 3 0 0 0 3 3h8a3 3 0 0 1 3 3v7M3 3h4M17 21h4" />),
  door: svg(<><path d="M5 21V4a1 1 0 0 1 1-1h12a1 1 0 0 1 1 1v17M3 21h18" /><path d="M15 12v.01" /></>),
  split: svg(<><path d="M3 12h7l4-6h7M10 12l4 6h7" /></>),
  flag: svg(<><path d="M5 21V4M5 4c5-3 9 3 14 0v10c-5 3-9-3-14 0" /></>),
  doc: svg(<><path d="M6 3h8l5 5v13H6z" /><path d="M14 3v5h5M9 13h7M9 17h7" /></>),
  history: svg(<><path d="M3 12a9 9 0 1 0 3-6.7" /><path d="M3 4v5h5M12 7v5l3 2" /></>),
  tv: svg(<><rect x="2.5" y="4" width="19" height="13" rx="1.8" /><path d="M8 21h8M12 17v4" /><path d="M10.5 8.5l4 2.5-4 2.5z" /></>),
}

/* ---------- toasts ---------- */

export interface ToastAction { label: string; onClick: () => void | Promise<void> }
interface Toast { id: number; message: string; tone: 'ok' | 'err' | 'info'; action?: ToastAction }
type ToastFn = (message: string, tone?: Toast['tone'], action?: ToastAction) => void
const ToastCtx = createContext<ToastFn>(() => {})
export const useToast = () => useContext(ToastCtx)

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([])
  const nextId = useRef(1)

  const push = useCallback<ToastFn>((message, tone = 'info', action) => {
    const id = nextId.current++
    setToasts((t) => [...t, { id, message, tone, action }])
    // Errors linger: they usually carry a detail worth reading twice. A
    // toast with an undo stays long enough to be used.
    const ms = tone === 'err' ? 8000 : action ? 7000 : 4000
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), ms)
  }, [])

  return (
    <ToastCtx.Provider value={push}>
      <ConfirmProvider>
        {children}
        <div className="toast-stack" role="status" aria-live="polite">
          {toasts.map((t) => (
            <div key={t.id} className={`toast ${t.tone}`}>
              <span>{t.message}</span>
              {t.action && (
                <button className="btn sm" style={{ marginLeft: 10 }} onClick={() => {
                  setToasts((all) => all.filter((x) => x.id !== t.id))
                  Promise.resolve().then(() => t.action!.onClick())
                    .catch((e) => push(e instanceof Error ? e.message : 'Undo did not work', 'err'))
                }}>{t.action.label}</button>
              )}
            </div>
          ))}
        </div>
      </ConfirmProvider>
    </ToastCtx.Provider>
  )
}

/* ---------- layout primitives ---------- */

export function Card({ title, actions, children, flush, className = '' }: {
  title?: ReactNode; actions?: ReactNode; children: ReactNode; flush?: boolean; className?: string
}) {
  return (
    <section className={`card ${className}`}>
      {(title || actions) && (
        <header className="card-head">
          {typeof title === 'string' ? <h2>{title}</h2> : title}
          <div className="spacer" />
          {actions}
        </header>
      )}
      <div className={`card-body${flush ? ' flush' : ''}`}>{children}</div>
    </section>
  )
}

export function Stat({ label, value, sub, tone, spark }: {
  label: string; value: ReactNode; sub?: ReactNode
  tone?: 'accent' | 'red' | 'amber' | 'blue'; spark?: number[]
}) {
  return (
    <div className="card stat">
      <div className="stat-label">{label}</div>
      <div className={`stat-value${tone ? ` ${tone}` : ''}`}>{value}</div>
      {sub && <div className="stat-sub">{sub}</div>}
      {spark && spark.length > 1 && <Sparkline points={spark} tone={tone} />}
    </div>
  )
}

/** Sparkline draws a normalised polyline. Flat series are drawn as a centred
 *  line rather than collapsing to the baseline, which reads as "no data". */
export function Sparkline({ points, tone, height = 34, readout }: {
  points: number[]; tone?: string; height?: number
  /** Turns the line into something to read: a pointer shows the value there. */
  readout?: (i: number) => string
}) {
  const [at, setAt] = useState<number | null>(null)
  const d = useMemo(() => {
    if (points.length < 2) return ''
    const max = Math.max(...points)
    const min = Math.min(...points)
    const span = max - min || 1
    const w = 100
    return points
      .map((p, i) => {
        const x = (i / (points.length - 1)) * w
        const y = max === min ? height / 2 : height - 2 - ((p - min) / span) * (height - 4)
        return `${i === 0 ? 'M' : 'L'}${x.toFixed(2)},${y.toFixed(2)}`
      })
      .join(' ')
  }, [points, height])
  if (!d) return null
  const color = tone === 'red' ? 'var(--red)' : tone === 'amber' ? 'var(--amber)'
    : tone === 'blue' ? 'var(--blue)' : 'var(--accent)'
  const line = (
    <svg className="spark" viewBox={`0 0 100 ${height}`} preserveAspectRatio="none" style={{ marginTop: 8 }} aria-hidden="true">
      <path d={d} fill="none" stroke={color} strokeWidth={1.4} vectorEffect="non-scaling-stroke" opacity={0.85} />
    </svg>
  )
  if (!readout) return line
  const x = at === null ? 0 : (at / (points.length - 1)) * 100
  return (
    <div className="spark-read" onPointerLeave={() => setAt(null)}
      onPointerMove={(e) => {
        const box = e.currentTarget.getBoundingClientRect()
        setAt(Math.round(((e.clientX - box.left) / box.width) * (points.length - 1)))
      }}>
      {line}
      {at !== null && (
        <>
          <i className="spark-cross" style={{ left: `${x}%` }} />
          <span className="spark-value" style={{ left: `clamp(0px, calc(${x}% - 50px), calc(100% - 100px))` }}>{readout(at)}</span>
        </>
      )}
    </div>
  )
}

export function Switch({ checked, onChange, label, disabled }: {
  checked: boolean; onChange: (v: boolean) => void; label?: ReactNode; disabled?: boolean
}) {
  return (
    <label className="switch" style={disabled ? { opacity: 0.5, cursor: 'not-allowed' } : undefined}>
      <input type="checkbox" checked={checked} disabled={disabled}
        onChange={(e) => onChange(e.target.checked)} />
      <span className="switch-track" />
      {label && <span>{label}</span>}
    </label>
  )
}

export function Field({ label, hint, children }: { label: string; hint?: ReactNode; children: ReactNode }) {
  const id = useId()
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      {bindControlId(children, id)}
      {hint && <div className="hint">{hint}</div>}
    </div>
  )
}

const CONTROL_TAGS = new Set(['input', 'select', 'textarea'])

function bindControlId(children: ReactNode, id: string): ReactNode {
  const items = Children.toArray(children)
  let bound = false
  return items.map((child) => {
    if (bound || !isValidElement(child)) return child
    const tagged = tagControl(child, id)
    if (tagged !== child) bound = true
    return tagged
  })
}

function tagControl(node: ReactElement, id: string): ReactElement {
  if (typeof node.type === 'string' && CONTROL_TAGS.has(node.type)) {
    const el = node as ReactElement<{ id?: string }>
    return el.props.id ? el : cloneElement(el, { id })
  }
  const nested = (node.props as { children?: ReactNode }).children
  if (nested == null) return node
  const kids = Children.toArray(nested)
  let changed = false
  const next = kids.map((k) => {
    if (changed || !isValidElement(k)) return k
    const t = tagControl(k, id)
    if (t !== k) changed = true
    return t
  })
  return changed ? cloneElement(node, { children: next } as { children: ReactNode }) : node
}

export function Segmented<T extends string>({ value, options, onChange }: {
  value: T; options: Array<{ value: T; label: string }>; onChange: (v: T) => void
}) {
  const thumb = useThumb<HTMLDivElement>(`${value}|${options.map((o) => o.label).join()}`)
  return (
    <div className="segmented" role="group" ref={thumb}>
      <span className="thumb" aria-hidden="true" />
      {options.map((o) => (
        <button key={o.value} type="button" aria-pressed={value === o.value} onClick={() => onChange(o.value)}>
          {o.label}
        </button>
      ))}
    </div>
  )
}

export function Search({ value, onChange, placeholder = 'Search…' }: {
  value: string; onChange: (v: string) => void; placeholder?: string
}) {
  return (
    <div className="search">
      <Icons.search />
      <input className="input" value={value} placeholder={placeholder} aria-label={placeholder}
        onChange={(e) => onChange(e.target.value)} />
    </div>
  )
}

export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="empty">
      <strong>{title}</strong>
      {children}
    </div>
  )
}

export function Banner({ tone = 'info', icon = true, children, action }: {
  tone?: 'info' | 'warn' | 'err'; icon?: boolean; children: ReactNode; action?: ReactNode
}) {
  const Glyph = tone === 'err' || tone === 'warn' ? Icons.alert : Icons.info
  return (
    <div className={`banner ${tone}`}>
      {icon && <Glyph />}
      <div style={{ flex: 1 }}>{children}</div>
      {action}
    </div>
  )
}

export function Drawer({ title, onClose, children, actions }: {
  title: ReactNode; onClose: () => void; children: ReactNode; actions?: ReactNode
}) {
  const closeRef = useRef<HTMLButtonElement>(null)
  const prevFocus = useRef<HTMLElement | null>(null)
  // It leaves the way it came, then the parent removes it.
  const [closing, setClosing] = useState(false)
  const close = useCallback(() => {
    setClosing(true)
    setTimeout(onClose, 170)
  }, [onClose])

  useEffect(() => {
    prevFocus.current = document.activeElement instanceof HTMLElement ? document.activeElement : null
    closeRef.current?.focus()
    return () => {
      const el = prevFocus.current
      if (el && document.contains(el)) el.focus()
    }
  }, [])

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') close() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [close])

  return (
    <>
      <div className={`scrim${closing ? ' closing' : ''}`} onClick={close} />
      <aside className={`drawer${closing ? ' closing' : ''}`} role="dialog" aria-modal="true">
        <header className="drawer-head">
          <h2 style={{ flex: 1, fontSize: 14 }}>{title}</h2>
          {actions}
          <button ref={closeRef} type="button" className="btn icon" onClick={close} aria-label="Close"><Icons.close /></button>
        </header>
        <div className="drawer-body">{children}</div>
      </aside>
    </>
  )
}

export function Bar({ value, max, tone }: { value: number; max: number; tone?: string }) {
  const w = max > 0 ? Math.min(100, (value / max) * 100) : 0
  return <div className="bar"><i className={tone} style={{ transform: `scaleX(${w / 100})` }} /></div>
}

export function Dot({ state, label }: { state: 'on' | 'off' | 'warn' | 'err'; label?: string }) {
  const meaning = label ?? { on: 'OK', off: 'Off', warn: 'Attention', err: 'Problem' }[state]
  return <span className={`dot ${state}`} role="img" aria-label={meaning} title={meaning} />
}

/** Confirm is a lightweight destructive-action guard. Blocking on a real
 *  dialog for "block this device" is friction; doing it with no confirmation
 *  at all is how someone kicks their own laptop off the network. */
type ConfirmFn = (message: string) => Promise<boolean>
const ConfirmCtx = createContext<ConfirmFn>((message) => Promise.resolve(window.confirm(message)))

export function useConfirm() {
  return useContext(ConfirmCtx)
}

function ConfirmProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<{ message: string; resolve: (v: boolean) => void } | null>(null)
  const panelRef = useRef<HTMLDivElement>(null)
  const prevFocus = useRef<HTMLElement | null>(null)

  const ask = useCallback<ConfirmFn>((message) => {
    return new Promise<boolean>((resolve) => {
      setState((current) => {
        if (current) {
          current.resolve(false)
        }
        prevFocus.current = document.activeElement instanceof HTMLElement ? document.activeElement : null
        return { message, resolve }
      })
    })
  }, [])

  const close = useCallback((ok: boolean) => {
    setState((s) => {
      s?.resolve(ok)
      return null
    })
    const el = prevFocus.current
    if (el && document.contains(el)) el.focus()
  }, [])

  useEffect(() => {
    if (!state) return
    panelRef.current?.focus()
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'Escape') return
      e.preventDefault()
      e.stopImmediatePropagation()
      close(false)
    }
    window.addEventListener('keydown', onKey, true)
    return () => window.removeEventListener('keydown', onKey, true)
  }, [state, close])

  return (
    <ConfirmCtx.Provider value={ask}>
      {children}
      {state && (
        <>
          <div className="scrim confirm-scrim" onClick={() => close(false)} />
          <div className="confirm-dialog">
            <div
              ref={panelRef}
              className="confirm-panel"
              role="dialog"
              aria-modal="true"
              aria-labelledby="confirm-title"
              aria-describedby="confirm-body"
              tabIndex={-1}
            >
              <h2 id="confirm-title">Confirm</h2>
              <p id="confirm-body">{state.message}</p>
              <div className="confirm-actions">
                <button type="button" className="btn" onClick={() => close(false)}>Cancel</button>
                <button type="button" className="btn danger" onClick={() => close(true)}>Confirm</button>
              </div>
            </div>
          </div>
        </>
      )}
    </ConfirmCtx.Provider>
  )
}

/** CopyButton gives feedback in place rather than via a toast, so the user's
 *  eye does not have to leave the value they just copied. */
export function CopyButton({ text, label = 'Copy' }: { text: string; label?: string }) {
  const [done, setDone] = useState(false)
  return (
    <button className="btn sm" onClick={async () => {
      try {
        await navigator.clipboard.writeText(text)
        setDone(true)
        setTimeout(() => setDone(false), 1600)
      } catch {
        setDone(false)
      }
    }}>
      {done ? <><Icons.check size={13} /> Copied</> : label}
    </button>
  )
}

export function Spinner() { return <span className="spinner" /> }

/** Loading holds the shape of what is coming, so the page does not jump when
 *  it arrives. */
export function Loading({ what = 'data' }: { what?: string }) {
  return <div className="skeleton" role="status" aria-label={`Loading ${what}`}><i /><i /><i /><i /></div>
}
