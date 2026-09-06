import { useState } from 'react'
import { api } from '../../api'
import { Icons, Spinner, useToast } from '../../ui'
import type { Explanation } from '../../types'

// "Explain this": one button that asks the assistant what a thing is, how
// dangerous it is, and what to do, shown inline where the thing is.

const dangerTone: Record<string, string> = { none: 'ok', low: '', medium: 'warn', high: 'block' }
const dangerLabel: Record<string, string> = { none: 'Nothing to worry about', low: 'Worth knowing', medium: 'Do something soon', high: 'Act now' }

export function ExplainPanel({ e }: { e: Explanation }) {
  return (
    <div style={{ marginTop: 9, padding: '10px 12px', borderRadius: 8, background: 'var(--bg-2)', border: '1px solid var(--line-soft)', display: 'grid', gap: 7 }}>
      <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
        <span className={`tag ${dangerTone[e.danger] ?? ''}`}>{dangerLabel[e.danger] ?? e.danger}</span>
        <span style={{ fontWeight: 600, fontSize: 13 }}>{e.title}</span>
      </div>
      <div style={{ fontSize: 12.5, lineHeight: 1.65, color: 'var(--text-dim)', whiteSpace: 'pre-wrap' }}>{e.explanation}</div>
      {e.steps?.length > 0 && (
        <ol style={{ margin: 0, paddingLeft: 18, fontSize: 12.5, lineHeight: 1.7 }}>
          {e.steps.map((s, i) => <li key={i}>{s}</li>)}
        </ol>
      )}
      <div className="hint" style={{ fontSize: 10.5 }}>Explained by {e.model}. The assistant can be wrong; it only sees what this node recorded.</div>
    </div>
  )
}

export function ExplainButton({ kind, id, size = 'sm', label = 'Explain' }: {
  kind: 'event' | 'alert' | 'ip' | 'domain'; id: string; size?: 'sm' | 'md'; label?: string
}) {
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState<Explanation | null>(null)
  const [open, setOpen] = useState(false)
  const toast = useToast()
  const ask = async (ev: React.MouseEvent) => {
    ev.stopPropagation()
    if (result) { setOpen((v) => !v); return }
    setBusy(true)
    try {
      const r = await api.ai.explain(kind, id)
      setResult(r.explanation)
      setOpen(true)
    } catch (e) {
      toast(e instanceof Error ? e.message : 'The assistant could not explain that', 'err')
    } finally { setBusy(false) }
  }
  return (
    <>
      <button className={`btn ${size === 'sm' ? 'sm' : ''}`} disabled={busy} onClick={ask} title="Ask the assistant what this is and what to do">
        {busy ? <Spinner /> : <Icons.info size={12} />} {result ? (open ? 'Hide' : label) : label}
      </button>
      {open && result && <div onClick={(e) => e.stopPropagation()}><ExplainPanel e={result} /></div>}
    </>
  )
}
