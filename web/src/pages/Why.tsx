import { useState } from 'react'
import { api } from '../api'
import { usePoll } from '../hooks'
import { Drawer, Loading, useToast } from '../ui'

/** Why a name was stopped, and what to do about it, without leaving the page
 *  you were on. */
export function WhyDrawer({ name, clientId, onClose, onChanged }: {
  name: string; clientId?: string; onClose: () => void; onChanged?: () => void
}) {
  const { data, error, refresh } = usePoll(() => api.dnstools.diagnose(name, { client_id: clientId }), 0, [name, clientId])
  const toast = useToast()
  const [busy, setBusy] = useState(false)
  const decide = async (act: () => Promise<unknown>, done: string, undo: () => Promise<unknown>) => {
    setBusy(true)
    try {
      await act()
      toast(done, 'ok', { label: 'Undo', onClick: async () => { await undo(); refresh(); onChanged?.() } })
      refresh()
      onChanged?.()
    } catch (e) {
      toast(e instanceof Error ? e.message : 'That did not work', 'err')
    } finally {
      setBusy(false)
    }
  }
  const allow = () => decide(() => api.dnstools.allow(name), `${name} is allowed`, () => api.adblock.deleteRule(name))
  const block = () => decide(() => api.dnstools.block(name), `${name} is blocked`, () => api.adblock.deleteRule(name))
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
              ? <button className="btn primary" disabled={busy} onClick={allow}>Allow this site</button>
              : <button className="btn danger" disabled={busy} onClick={block}>Block this site</button>}
          </div>
        </div>
      )}
    </Drawer>
  )
}
