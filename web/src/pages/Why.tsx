import { useState } from 'react'
import { api } from '../api'
import { usePoll } from '../hooks'
import { Drawer, Loading, useToast } from '../ui'
import type { LocalRule } from '../types'

/** Allow or block a site from wherever it is showing. A quick rule replaces
 *  whatever rule the name had, so Undo puts that one back. */
export function useSiteActions(onChanged?: () => void) {
  const toast = useToast()
  const [busy, setBusy] = useState(false)
  const run = async (act: () => Promise<{ previous?: LocalRule | null }>, done: string, name: string) => {
    setBusy(true)
    try {
      const { previous: was } = await act()
      toast(done, 'ok', {
        label: 'Undo',
        onClick: async () => {
          await (was
            ? api.adblock.addRule({ domain: was.domain, action: was.action, wildcard: was.wildcard, note: was.note })
            : api.adblock.deleteRule(name))
          onChanged?.()
        },
      })
      onChanged?.()
    } catch (e) {
      toast(e instanceof Error ? e.message : 'That did not work', 'err')
    } finally {
      setBusy(false)
    }
  }
  return {
    busy,
    allow: (name: string) => run(() => api.dnstools.allow(name), `${name} is allowed`, name),
    block: (name: string) => run(() => api.dnstools.block(name, true), `${name} is blocked`, name),
  }
}

/** Why a name was stopped, and what to do about it, without leaving the page
 *  you were on. */
export function WhyDrawer({ name, clientId, onClose, onChanged }: {
  name: string; clientId?: string; onClose: () => void; onChanged?: () => void
}) {
  const { data, error, refresh } = usePoll(() => api.dnstools.diagnose(name, { client_id: clientId }), 0, [name, clientId])
  const sites = useSiteActions(() => { refresh(); onChanged?.() })
  return (
    <Drawer title={<span className="mono">{name}</span>} onClose={onClose}>
      {error && <p className="hint">{error}</p>}
      {!data && !error && <Loading what="the decision" />}
      {data && (
        <div style={{ display: 'grid', gap: 16 }}>
          <p style={{ fontSize: 15, lineHeight: 1.5 }}>{data.reason}</p>
          <ol className="trace" aria-label="How the decision was reached">
            {data.steps.map((st, i) => (
              <li key={i} className={`trace-stop ${st.verdict}`}>
                <div className="trace-title">{st.stage}{st.rule && <code>{st.rule}</code>}</div>
                <div className="trace-detail">{st.detail}</div>
              </li>
            ))}
          </ol>
          <div style={{ display: 'flex', gap: 8 }}>
            {data.verdict === 'block'
              ? <button className="btn primary" disabled={sites.busy} onClick={() => void sites.allow(name)}>Allow this site</button>
              : <button className="btn danger" disabled={sites.busy} onClick={() => void sites.block(name)}>Block this site</button>}
          </div>
        </div>
      )}
    </Drawer>
  )
}
