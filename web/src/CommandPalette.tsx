import { useEffect, useMemo, useRef, useState } from 'react'
import { api } from './api'
import { Icons } from './ui'

/**
 * ⌘K / Ctrl-K command palette.
 *
 * The keyboard-first way around a product that has grown a lot of surface.
 * It searches the pages, the devices Orbis knows, and a set of quick actions,
 * ranks by a cheap subsequence score, and runs the selection on Enter. It holds
 * no long-lived state and fetches nothing until it is opened, so it costs
 * nothing when unused.
 */

export interface Command {
  id: string
  title: string
  subtitle?: string
  group: string
  icon?: keyof typeof Icons
  run: () => void
}

export function CommandPalette({ pages, onNavigate }: {
  pages: Array<{ id: string; label: string; icon: keyof typeof Icons }>
  onNavigate: (id: string) => void
}) {
  const [open, setOpen] = useState(false)
  const [q, setQ] = useState('')
  const [sel, setSel] = useState(0)
  const [devices, setDevices] = useState<Array<{ id: string; label: string; ip: string }>>([])
  const inputRef = useRef<HTMLInputElement>(null)

  // Global hotkey.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault(); setOpen((o) => !o)
      }
      if (e.key === 'Escape') setOpen(false)
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  // Lazy-load devices the first time it opens.
  useEffect(() => {
    if (!open) { setQ(''); setSel(0); return }
    inputRef.current?.focus()
    if (devices.length === 0) {
      api.clients.list().then((r) =>
        setDevices((r.clients ?? []).map((c) => ({
          id: c.id, label: c.label || c.hostname || c.ip, ip: c.ip,
        })))
      ).catch(() => {})
    }
  }, [open])

  const commands = useMemo<Command[]>(() => {
    const list: Command[] = []
    for (const p of pages) {
      list.push({ id: `page:${p.id}`, title: p.label, group: 'Go to', icon: p.icon,
        run: () => onNavigate(p.id) })
    }
    for (const d of devices) {
      list.push({ id: `dev:${d.id}`, title: d.label, subtitle: d.ip, group: 'Devices',
        icon: 'devices', run: () => { location.hash = `#/clients`; onNavigate('clients') } })
    }
    // A few high-value actions.
    list.push(
      { id: 'act:scan', title: 'Scan network topology', group: 'Actions', icon: 'search',
        run: () => { onNavigate('topology'); api.topology.scan().catch(() => {}) } },
      { id: 'act:flush', title: 'Flush DNS cache', group: 'Actions', icon: 'refresh',
        run: () => api.dns.flush().catch(() => {}) },
      { id: 'act:speedtest', title: 'Run speed test', group: 'Actions', icon: 'activity',
        run: () => { onNavigate('gateway'); api.tools.speedtest().catch(() => {}) } },
    )
    return list
  }, [pages, devices, onNavigate])

  const results = useMemo(() => {
    if (!q.trim()) return commands.slice(0, 40)
    return commands
      .map((c) => ({ c, s: score(q, c.title + ' ' + (c.subtitle ?? '')) }))
      .filter((r) => r.s > 0)
      .sort((a, b) => b.s - a.s)
      .slice(0, 40)
      .map((r) => r.c)
  }, [q, commands])

  useEffect(() => { setSel(0) }, [q])

  if (!open) return null

  const groups: Record<string, Command[]> = {}
  for (const r of results) (groups[r.group] ??= []).push(r)
  const flat = results

  const run = (c?: Command) => { if (c) { c.run(); setOpen(false) } }

  return (
    <div onClick={() => setOpen(false)} style={{
      position: 'fixed', inset: 0, zIndex: 1000, display: 'flex', justifyContent: 'center',
      alignItems: 'flex-start', paddingTop: '14vh',
      background: 'rgba(3,6,11,.6)', backdropFilter: 'blur(4px)',
    }}>
      <div onClick={(e) => e.stopPropagation()} style={{
        width: 'min(620px, 92vw)', background: 'var(--bg-1)', border: '1px solid var(--line)',
        borderRadius: 14, boxShadow: 'var(--shadow)', overflow: 'hidden',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '13px 16px',
          borderBottom: '1px solid var(--line-soft)' }}>
          <Icons.search size={16} />
          <input
            ref={inputRef}
            value={q}
            onChange={(e) => setQ(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'ArrowDown') { e.preventDefault(); setSel((s) => Math.min(flat.length - 1, s + 1)) }
              if (e.key === 'ArrowUp') { e.preventDefault(); setSel((s) => Math.max(0, s - 1)) }
              if (e.key === 'Enter') { e.preventDefault(); run(flat[sel]) }
            }}
            placeholder="Search pages, devices, actions…"
            style={{ flex: 1, background: 'transparent', border: 'none', outline: 'none',
              color: 'var(--text)', fontSize: 15 }}
          />
          <kbd style={{ fontSize: 10.5, color: 'var(--text-faint)', border: '1px solid var(--line)',
            borderRadius: 5, padding: '1px 6px' }}>esc</kbd>
        </div>

        <div style={{ maxHeight: '52vh', overflow: 'auto', padding: 6 }}>
          {flat.length === 0 && (
            <div style={{ padding: '22px 16px', color: 'var(--text-faint)', fontSize: 13, textAlign: 'center' }}>
              Nothing matches “{q}”.
            </div>
          )}
          {Object.entries(groups).map(([group, items]) => (
            <div key={group}>
              <div style={{ fontSize: 10, letterSpacing: '.1em', textTransform: 'uppercase',
                color: 'var(--text-faint)', padding: '8px 10px 4px' }}>{group}</div>
              {items.map((c) => {
                const idx = flat.indexOf(c)
                const Icon = c.icon ? Icons[c.icon] : Icons.chevron
                return (
                  <button key={c.id} onMouseEnter={() => setSel(idx)} onClick={() => run(c)}
                    style={{
                      display: 'flex', alignItems: 'center', gap: 11, width: '100%', textAlign: 'left',
                      padding: '8px 10px', borderRadius: 8, border: 'none', cursor: 'pointer',
                      background: idx === sel ? 'color-mix(in srgb, var(--accent) 12%, transparent)' : 'transparent',
                      color: 'inherit',
                    }}>
                    <Icon size={15} />
                    <span style={{ flex: 1, fontSize: 13.5 }}>{c.title}</span>
                    {c.subtitle && <span className="mono" style={{ fontSize: 11, color: 'var(--text-faint)' }}>{c.subtitle}</span>}
                    {idx === sel && <kbd style={{ fontSize: 10, color: 'var(--text-faint)' }}>↵</kbd>}
                  </button>
                )
              })}
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

/** score is a cheap subsequence match: every query char must appear in order,
 *  with a bonus for contiguous runs and word-start hits, so "dns" ranks the DNS
 *  page above a device that merely contains those letters. */
function score(query: string, target: string): number {
  const q = query.toLowerCase(), t = target.toLowerCase()
  let ti = 0, s = 0, run = 0
  for (const ch of q) {
    if (ch === ' ') continue
    const found = t.indexOf(ch, ti)
    if (found < 0) return 0
    run = found === ti ? run + 1 : 0
    s += 1 + run * 2 + (found === 0 || t[found - 1] === ' ' || t[found - 1] === '.' ? 3 : 0)
    ti = found + 1
  }
  return s
}
