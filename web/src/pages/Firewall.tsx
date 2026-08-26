import { useMemo, useState } from 'react'
import { api } from '../api'
import { usePoll } from '../hooks'
import { Banner, Card, Drawer, Empty, Field, Icons, Loading, Segmented, Switch, useToast } from '../ui'
import { bytes, compact } from '../format'
import type { Rule, SystemStatus } from '../types'

const CHAINS = ['forward', 'input', 'output', 'dnat', 'snat'] as const
type Chain = (typeof CHAINS)[number]

export function FirewallPage({ status }: { status: SystemStatus | null }) {
  const [chain, setChain] = useState<Chain>('forward')
  const [editing, setEditing] = useState<Partial<Rule> | null>(null)
  const [preview, setPreview] = useState(false)
  const { data, refresh } = usePoll(() => api.firewall.rules(), 15000)
  const { data: sysctl, refresh: refreshSysctl } = usePoll(() => api.firewall.sysctl(), 30000)
  const toast = useToast()

  const rules = useMemo(
    () => (data?.rules ?? []).filter((r) => r.chain === chain).sort((a, b) => a.position - b.position),
    [data, chain],
  )

  const fw = status?.firewall as Record<string, unknown> | undefined
  const applied = Boolean(fw?.applied)
  const nftAvailable = Boolean(fw?.available)
  const issues = (sysctl?.sysctl ?? []).filter((s) => !s.ok)

  const apply = async () => {
    try {
      await api.firewall.apply()
      toast('Ruleset compiled and loaded', 'ok')
      refresh()
    } catch (e) {
      toast(e instanceof Error ? e.message : 'Apply failed', 'err')
    }
  }

  const save = async (rule: Partial<Rule>) => {
    try {
      if (rule.id) await api.firewall.update(rule.id, rule)
      else await api.firewall.create(rule)
      toast('Rule saved. Apply to make it live.', 'ok')
      setEditing(null)
      refresh()
    } catch (e) {
      toast(e instanceof Error ? e.message : 'Could not save the rule', 'err')
    }
  }

  return (
    <div style={{ display: 'grid', gap: 14 }}>
      {!nftAvailable && (
        <Banner tone="err">
          <code>nft</code> is not available on this node, so no ruleset can be installed.
          Install <code>nftables</code> and restart Orbis.
        </Banner>
      )}
      {status?.mode === 'observe' && (
        <Banner tone="info">
          The node is in observe mode. Rules can be written and previewed, but nothing is loaded
          into the kernel until you switch to inline mode in Settings.
        </Banner>
      )}
      {issues.length > 0 && (
        <Banner tone={issues.some((i) => i.critical) ? 'err' : 'warn'} action={
          <button className="btn sm" onClick={async () => {
            const r = await api.firewall.applySysctl()
            const still = r.sysctl.filter((s) => !s.ok)
            toast(still.length ? `${still.length} setting(s) could not be changed` : 'Kernel settings applied',
              still.length ? 'err' : 'ok')
            refreshSysctl()
          }}>Apply</button>
        }>
          <strong style={{ display: 'block', marginBottom: 3 }}>Kernel settings need attention</strong>
          {issues.slice(0, 3).map((i) => (
            <div key={i.key} style={{ fontSize: 11.5 }}>
              <code>{i.key}</code> is <code>{i.current || '?'}</code>, should be <code>{i.want}</code> — {i.why}
            </div>
          ))}
        </Banner>
      )}

      <div className="toolbar" style={{ marginBottom: 0 }}>
        <Segmented value={chain} onChange={setChain}
          options={CHAINS.map((c) => ({
            value: c,
            label: `${c} (${(data?.rules ?? []).filter((r) => r.chain === c).length})`,
          }))} />
        <div style={{ flex: 1 }} />
        <span className="tag" title={String(fw?.last_error || '')}>
          <span className={`dot ${applied ? 'on' : 'off'}`} /> {applied ? 'ruleset live' : 'not applied'}
        </span>
        <button className="btn sm" onClick={() => setPreview(true)}>Preview ruleset</button>
        <button className="btn sm" onClick={() => setEditing({ chain, action: 'accept', enabled: true })}>
          <Icons.plus size={13} /> New rule
        </button>
        <button className="btn primary sm" onClick={apply} disabled={!nftAvailable}>Apply</button>
      </div>

      <Card flush>
        {!data ? <Loading what="rules" /> : rules.length === 0 ? (
          <Empty title={`No rules in the ${chain} chain`}>
            {chain === 'forward'
              ? 'Zone defaults still apply: LAN reaches the internet, guest and IoT zones are isolated.'
              : 'Add a rule to get started.'}
          </Empty>
        ) : (
          <div className="table-wrap">
            <table className="t">
              <thead>
                <tr>
                  <th style={{ width: 40 }}>#</th>
                  <th style={{ width: 46 }}>On</th>
                  <th>Name</th>
                  <th>Match</th>
                  <th style={{ width: 76 }}>Action</th>
                  <th className="num">Packets</th>
                  <th className="num">Bytes</th>
                  <th style={{ width: 78 }} />
                </tr>
              </thead>
              <tbody>
                {rules.map((r, i) => (
                  <tr key={r.id} className="clickable" onClick={() => setEditing(r)}>
                    <td className="num" style={{ color: 'var(--text-faint)' }}>{i + 1}</td>
                    <td onClick={(e) => e.stopPropagation()}>
                      <Switch checked={r.enabled} onChange={async (v) => {
                        await api.firewall.update(r.id, { ...r, enabled: v })
                        refresh()
                      }} />
                    </td>
                    <td>
                      <div className="truncate" style={{ maxWidth: 200 }}>{r.name}</div>
                      {r.description && (
                        <div className="truncate" style={{ fontSize: 11, color: 'var(--text-faint)', maxWidth: 260 }}>
                          {r.description}
                        </div>
                      )}
                    </td>
                    <td className="mono truncate" style={{ fontSize: 11.5, maxWidth: 300, color: 'var(--text-dim)' }}>
                      {describeMatch(r)}
                    </td>
                    <td>
                      <span className={`tag ${r.action === 'accept' ? 'allow' : 'block'}`}>{r.action}</span>
                    </td>
                    <td className="num">{compact(r.counter_pkts)}</td>
                    <td className="num">{bytes(r.counter_bytes)}</td>
                    <td onClick={(e) => e.stopPropagation()}>
                      <button className="btn icon" title="Delete" onClick={async () => {
                        await api.firewall.remove(r.id)
                        refresh()
                      }}><Icons.trash size={13} /></button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {editing && <RuleEditor rule={editing} onSave={save} onClose={() => setEditing(null)} />}
      {preview && <RulesetPreview onClose={() => setPreview(false)} />}
    </div>
  )
}

function describeMatch(r: Rule): string {
  const parts: string[] = []
  if (r.src_zone) parts.push(`from ${r.src_zone}`)
  if (r.src) parts.push(`src ${r.src}`)
  if (r.dst_zone) parts.push(`to ${r.dst_zone}`)
  if (r.dst) parts.push(`dst ${r.dst}`)
  if (r.proto && r.proto !== 'any') parts.push(r.proto)
  if (r.dst_port) parts.push(`port ${r.dst_port}`)
  if (r.schedule) parts.push(`when ${r.schedule}`)
  return parts.join(' · ') || 'any traffic';
}

function RuleEditor({ rule, onSave, onClose }: {
  rule: Partial<Rule>; onSave: (r: Partial<Rule>) => void; onClose: () => void
}) {
  const [draft, setDraft] = useState<Partial<Rule>>(rule)
  const { data: config } = usePoll(() => api.config.get(), 0)
  const zones = config?.firewall.zones ?? []
  const set = (patch: Partial<Rule>) => setDraft((d) => ({ ...d, ...patch }))
  const isNAT = draft.chain === 'dnat' || draft.chain === 'snat'

  return (
    <Drawer title={rule.id ? 'Edit rule' : 'New rule'} onClose={onClose}
      actions={<button className="btn primary sm" onClick={() => onSave(draft)}>Save</button>}>
      <div style={{ display: 'grid', gap: 13 }}>
        <Field label="Name">
          <input className="input" value={draft.name ?? ''} autoFocus
            placeholder="Block IoT from reaching the NAS"
            onChange={(e) => set({ name: e.target.value })} />
        </Field>
        <Field label="Description" hint="Why this rule exists — future you will want it.">
          <input className="input" value={draft.description ?? ''}
            onChange={(e) => set({ description: e.target.value })} />
        </Field>

        <div className="grid c2">
          <Field label="Chain">
            <select className="select" value={draft.chain ?? 'forward'}
              onChange={(e) => set({ chain: e.target.value })}>
              <option value="forward">forward — traffic passing through</option>
              <option value="input">input — traffic to this node</option>
              <option value="output">output — traffic from this node</option>
              <option value="dnat">dnat — port forwarding</option>
              <option value="snat">snat — source rewriting</option>
            </select>
          </Field>
          {!isNAT && (
            <Field label="Action">
              <select className="select" value={draft.action ?? 'accept'}
                onChange={(e) => set({ action: e.target.value })}>
                <option value="accept">Accept</option>
                <option value="drop">Drop (silent)</option>
                <option value="reject">Reject (send an error)</option>
              </select>
            </Field>
          )}
        </div>

        {!isNAT && (
          <div className="grid c2">
            <Field label="Source zone">
              <select className="select" value={draft.src_zone ?? ''} onChange={(e) => set({ src_zone: e.target.value })}>
                <option value="">Any</option>
                {zones.map((z) => <option key={z.name} value={z.name}>{z.name}</option>)}
              </select>
            </Field>
            <Field label="Destination zone">
              <select className="select" value={draft.dst_zone ?? ''} onChange={(e) => set({ dst_zone: e.target.value })}>
                <option value="">Any</option>
                {zones.map((z) => <option key={z.name} value={z.name}>{z.name}</option>)}
              </select>
            </Field>
          </div>
        )}

        <div className="grid c2">
          <Field label="Source address" hint="An IP, a CIDR, or several separated by commas.">
            <input className="input mono" value={draft.src ?? ''} placeholder="192.168.1.0/24"
              onChange={(e) => set({ src: e.target.value })} />
          </Field>
          <Field label={isNAT ? 'Forward to' : 'Destination address'}
            hint={isNAT ? 'host:port to send matching traffic to' : undefined}>
            <input className="input mono" value={draft.dst ?? ''}
              placeholder={isNAT ? '192.168.1.50:8080' : '10.0.0.0/8'}
              onChange={(e) => set({ dst: e.target.value })} />
          </Field>
        </div>

        <div className="grid c2">
          <Field label="Protocol">
            <select className="select" value={draft.proto ?? 'any'} onChange={(e) => set({ proto: e.target.value })}>
              <option value="any">Any</option>
              <option value="tcp">TCP</option>
              <option value="udp">UDP</option>
              <option value="icmp">ICMP</option>
            </select>
          </Field>
          <Field label="Destination port" hint="443, 80-90, or 80,443,8080">
            <input className="input mono" value={draft.dst_port ?? ''}
              onChange={(e) => set({ dst_port: e.target.value })} />
          </Field>
        </div>

        {!isNAT && (
          <Field label="Schedule"
            hint='Optional. Examples: "mon-fri 09:00-17:00", "sat-sun", "22:00-06:00". Leave blank for always.'>
            <input className="input mono" value={draft.schedule ?? ''} placeholder="mon-fri 09:00-17:00"
              onChange={(e) => set({ schedule: e.target.value })} />
          </Field>
        )}

        <div style={{ display: 'flex', gap: 18 }}>
          <Switch checked={draft.enabled ?? true} onChange={(v) => set({ enabled: v })} label="Enabled" />
          <Switch checked={draft.log ?? false} onChange={(v) => set({ log: v })} label="Log matches" />
        </div>

        <div className="banner info" style={{ marginBottom: 0 }}>
          <Icons.info />
          <div>Saving stores the rule. It does not reach the kernel until you press Apply.</div>
        </div>
      </div>
    </Drawer>
  )
}

function RulesetPreview({ onClose }: { onClose: () => void }) {
  const { data } = usePoll(() => api.firewall.preview(), 0)
  return (
    <Drawer title="Generated nftables ruleset" onClose={onClose}>
      {!data ? <Loading what="ruleset" /> : (
        <>
          <div className="hint" style={{ marginBottom: 11 }}>
            This is exactly what gets loaded with <code>nft -f</code>, in one atomic transaction.
            It is validated with <code>nft -c</code> before anything is committed.
          </div>
          <pre style={{
            background: 'var(--bg-2)', border: '1px solid var(--line-soft)', borderRadius: 8,
            padding: 12, overflow: 'auto', fontSize: 11, lineHeight: 1.6, maxHeight: '70vh',
          }}>{data.ruleset}</pre>
        </>
      )}
    </Drawer>
  )
}
