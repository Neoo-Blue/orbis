import { useMemo, useRef, useState, type CSSProperties, type KeyboardEvent } from 'react'
import { api } from '../api'
import { bytes, compact } from '../format'
import { usePoll } from '../hooks'
import type { MatrixCell, MatrixVerdict, MatrixZone, Rule } from '../types'
import { Banner, Card, Empty, Icons, Loading } from '../ui'
import './ZoneMatrix.css'

export interface ZoneMatrixPanelProps {
  onOpenRules?: (src: string, dst: string) => void
}

export function ZoneMatrixPanel({ onOpenRules }: ZoneMatrixPanelProps) {
  const { data, error, refresh } = usePoll(() => api.firewall.matrix(), 15000)
  const [selected, setSelected] = useState<{ src: string; dst: string } | null>(null)
  const [focusPos, setFocusPos] = useState<[number, number]>([0, 0])
  const btnRefs = useRef<Map<string, HTMLButtonElement>>(new Map())

  const zones = data?.zones ?? []
  const cellMap = useMemo(() => {
    const m = new Map<string, MatrixCell>()
    for (const c of data?.cells ?? []) {
      m.set(`${c.src}\0${c.dst}`, c)
    }
    return m
  }, [data])

  const maxFlowBytes = useMemo(() => {
    let max = 0
    for (const c of data?.cells ?? []) {
      if (c.flow_bytes > max) max = c.flow_bytes
    }
    return max
  }, [data])

  const selectedCell = selected ? cellMap.get(`${selected.src}\0${selected.dst}`) ?? null : null
  const allImplicit = zones.length > 0 && zones.every((z) => z.implicit)

  const focusCellAt = (rIdx: number, cIdx: number) => {
    if (zones.length === 0) return
    const nextR = Math.max(0, Math.min(zones.length - 1, rIdx))
    const nextC = Math.max(0, Math.min(zones.length - 1, cIdx))
    setFocusPos([nextR, nextC])
    const key = `${zones[nextR].name}\0${zones[nextC].name}`
    btnRefs.current.get(key)?.focus()
  }

  const handleCellKeyDown = (
    e: KeyboardEvent<HTMLButtonElement>,
    rIdx: number,
    cIdx: number,
    src: string,
    dst: string,
  ) => {
    switch (e.key) {
      case 'ArrowRight':
        e.preventDefault()
        focusCellAt(rIdx, cIdx + 1)
        break
      case 'ArrowLeft':
        e.preventDefault()
        focusCellAt(rIdx, cIdx - 1)
        break
      case 'ArrowDown':
        e.preventDefault()
        focusCellAt(rIdx + 1, cIdx)
        break
      case 'ArrowUp':
        e.preventDefault()
        focusCellAt(rIdx - 1, cIdx)
        break
      case 'Home':
        e.preventDefault()
        focusCellAt(rIdx, 0)
        break
      case 'End':
        e.preventDefault()
        focusCellAt(rIdx, zones.length - 1)
        break
      case 'Enter':
      case ' ':
        e.preventDefault()
        setSelected({ src, dst })
        break
    }
  }

  if (!data && error) {
    return (
      <Banner tone="err" action={
        <button type="button" className="btn sm zm-action-btn" onClick={refresh}>
          <Icons.refresh size={13} /> Retry
        </button>
      }>
        Could not load the zone matrix: {error}
      </Banner>
    )
  }

  if (!data) {
    return (
      <Card flush className="zm-card">
        <Loading what="zone matrix" />
        <div className="zm-teach-loading">
          Combining zone policies, enabled rule counters, and the last hour of flows into a source-to-destination grid.
        </div>
      </Card>
    )
  }

  if (zones.length === 0) {
    return (
      <Card flush className="zm-card">
        <Empty title="No zones available yet">
          Zones group interfaces and subnets by trust level (LAN, IoT, Guest, WAN) so traffic between segments has a clear default policy before individual rules run.
        </Empty>
      </Card>
    )
  }

  return (
    <div className="zm-root">
      {!data.enforced && (
        <div className="zm-observe-line" role="status">
          <Icons.info size={14} />
          <span>
            {data.mode === 'observe'
              ? 'This node is in observe mode, so this is what would apply rather than what is applied.'
              : 'The node is in observe posture because firewall enforcement is off, so this is what would apply rather than what is applied.'}
          </span>
        </div>
      )}

      {error && (
        <Banner tone="warn" action={
          <button type="button" className="btn sm zm-action-btn" onClick={refresh}>
            <Icons.refresh size={13} /> Refresh
          </button>
        }>
          Showing the last matrix snapshot because the latest poll failed: {error}
        </Banner>
      )}

      <Card flush className="zm-card">
        <div className="zm-meta-bar">
          <span>
            Rows are source zones, columns are destination zones. Arrow keys move between cells, Enter inspects rules.
          </span>
          <div className="zm-legend" aria-label="Legend">
            <span className="zm-legend-item">
              <VerdictBadge verdict="allow" /> permitted
            </span>
            <span className="zm-legend-item">
              <VerdictBadge verdict="mixed" /> partial rules
            </span>
            <span className="zm-legend-item">
              <VerdictBadge verdict="block" /> denied
            </span>
            <span className="zm-legend-item">
              <span className="zm-heat-swatch" aria-hidden="true" /> 1h traffic
            </span>
          </div>
        </div>

        <div className="zm-scroll" role="region" aria-label="Firewall zone matrix">
          <table className="zm-table">
            <thead>
              <tr>
                <th scope="col" className="zm-corner">
                  <div className="zm-corner-labels">
                    <span>To <Icons.chevron size={11} /></span>
                    <span>From <span className="zm-down"><Icons.chevron size={11} /></span></span>
                  </div>
                </th>
                {zones.map((dst) => (
                  <th key={dst.name} scope="col">
                    <ZoneHeader zone={dst} />
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {zones.map((src, rIdx) => (
                <tr key={src.name}>
                  <th scope="row">
                    <ZoneHeader zone={src} />
                  </th>
                  {zones.map((dst, cIdx) => {
                    const cellKey = `${src.name}\0${dst.name}`
                    const cell = cellMap.get(cellKey)
                    if (!cell) return <td key={dst.name} className="zm-td" />
                    const isSelected = selected?.src === src.name && selected?.dst === dst.name
                    const isRovingStop = focusPos[0] === rIdx && focusPos[1] === cIdx
                    const heat = heatPercent(cell.flow_bytes, maxFlowBytes)
                    const tdStyle = { '--zm-heat': `${heat}%` } as CSSProperties

                    return (
                      <td key={dst.name} className="zm-td" style={tdStyle}>
                        <button
                          type="button"
                          ref={(el) => {
                            if (el) btnRefs.current.set(cellKey, el)
                            else btnRefs.current.delete(cellKey)
                          }}
                          className="zm-cell-btn"
                          tabIndex={isRovingStop ? 0 : -1}
                          aria-pressed={isSelected}
                          aria-label={`${src.name} to ${dst.name}: ${cell.verdict}, ${pluralRules(cell.rule_count)}, ${bytes(cell.flow_bytes)} in the last hour`}
                          onFocus={() => setFocusPos([rIdx, cIdx])}
                          onClick={() => setSelected({ src: src.name, dst: dst.name })}
                          onKeyDown={(e) => handleCellKeyDown(e, rIdx, cIdx, src.name, dst.name)}
                        >
                          <div className="zm-cell-top">
                            <VerdictBadge verdict={cell.verdict} />
                            <span className="zm-cell-rules">{pluralRules(cell.rule_count)}</span>
                          </div>
                          <div className="zm-cell-bottom">
                            <span className={`zm-cell-bytes${cell.flow_bytes === 0 ? ' quiet' : ''}`}>
                              {bytes(cell.flow_bytes)}
                            </span>
                            <span className="zm-cell-flows">
                              {cell.flows > 0 ? `${compact(cell.flows)}/1h` : 'quiet'}
                            </span>
                          </div>
                        </button>
                      </td>
                    )
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {allImplicit && (
          <div className="zm-implicit-note">
            No custom zones are configured yet, so LAN, WAN, and This node are inferred from built-in defaults (RFC1918 private addresses map to LAN, public addresses map to WAN).
          </div>
        )}
      </Card>

      {selectedCell && (
        <Card
          flush
          className="zm-card"
          title={
            <div className="zm-detail-head">
              <h2>{selectedCell.src} → {selectedCell.dst}</h2>
              <VerdictBadge verdict={selectedCell.verdict} />
              <span className="mono" style={{ fontSize: 11.5, color: 'var(--text-dim)' }}>
                {selectedCell.chain} chain
              </span>
            </div>
          }
          actions={
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              {onOpenRules && (
                <button
                  type="button"
                  className="btn sm zm-action-btn"
                  onClick={() => onOpenRules(selectedCell.src, selectedCell.dst)}
                >
                  <Icons.shield size={13} /> Open in rules
                </button>
              )}
              <button
                type="button"
                className="btn icon zm-action-btn"
                aria-label="Close detail panel"
                onClick={() => setSelected(null)}
              >
                <Icons.close size={14} />
              </button>
            </div>
          }
        >
          <div className="zm-detail-summary">
            <span>
              Default policy: <strong style={{ color: 'var(--text)' }}>{selectedCell.default_action}</strong> ({selectedCell.default_reason})
            </span>
            <span className="mono">
              Last hour: {compact(selectedCell.flows)} flows · {bytes(selectedCell.flow_bytes)}
              {selectedCell.flows_blocked > 0 ? ` · ${compact(selectedCell.flows_blocked)} blocked` : ''}
            </span>
            {selectedCell.rule_count > 0 && (
              <span className="mono">
                Rule hits: {compact(selectedCell.counter_pkts)} pkts · {bytes(selectedCell.counter_bytes)}
              </span>
            )}
          </div>

          {selectedCell.rules.length === 0 ? (
            <Empty title={`No custom rules between ${selectedCell.src} and ${selectedCell.dst}`}>
              <div>
                Traffic in this direction follows the built-in default ({selectedCell.default_action}: {selectedCell.default_reason}).
                Add a rule in the <code>{selectedCell.chain}</code> chain to allow or block specific addresses, ports, or schedules.
              </div>
              {onOpenRules && (
                <div style={{ marginTop: 10 }}>
                  <button
                    type="button"
                    className="btn sm zm-action-btn"
                    onClick={() => onOpenRules(selectedCell.src, selectedCell.dst)}
                  >
                    <Icons.plus size={13} /> Manage rules for this pair
                  </button>
                </div>
              )}
            </Empty>
          ) : (
            <>
              <div className="table-wrap">
                <table className="t">
                  <thead>
                    <tr>
                      <th style={{ width: 44 }}>#</th>
                      <th>Rule</th>
                      <th>Match</th>
                      <th style={{ width: 92 }}>Action</th>
                      <th className="num">Packets</th>
                      <th className="num">Bytes</th>
                    </tr>
                  </thead>
                  <tbody>
                    {selectedCell.rules.map((r, idx) => {
                      const blocks = r.action === 'drop' || r.action === 'reject'
                      return (
                        <tr key={r.id}>
                          <td className="num" style={{ color: 'var(--text-dim)' }}>{idx + 1}</td>
                          <td>
                            <div className="truncate" style={{ maxWidth: 220 }}>{r.name}</div>
                            {r.description && (
                              <div className="truncate" style={{ fontSize: 11, color: 'var(--text-dim)', maxWidth: 260 }}>
                                {r.description}
                              </div>
                            )}
                          </td>
                          <td className="mono truncate" style={{ fontSize: 11.5, maxWidth: 280, color: 'var(--text-dim)' }}>
                            {describeRuleScope(r)}
                          </td>
                          <td>
                            <VerdictBadge verdict={blocks ? 'block' : 'allow'} label={r.action} />
                          </td>
                          <td className="num">{compact(r.counter_pkts)}</td>
                          <td className="num">{bytes(r.counter_bytes)}</td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
              <div className="zm-detail-foot">
                Rules run top to bottom; anything unmatched falls through to <strong>{selectedCell.default_action}</strong> ({selectedCell.default_reason}).
              </div>
            </>
          )}
        </Card>
      )}
    </div>
  )
}

function ZoneHeader({ zone }: { zone: MatrixZone }) {
  const detail = zone.subnets.length > 0
    ? zone.subnets.join(', ')
    : zone.interfaces.length > 0
      ? zone.interfaces.join(', ')
      : zone.implicit
        ? `${zone.trust} · implicit`
        : zone.trust

  return (
    <div className="zm-zone-head">
      <div className="zm-zone-title">
        <span>{zone.name}</span>
      </div>
      <div className="zm-zone-sub" title={detail}>{detail}</div>
    </div>
  )
}

function VerdictBadge({ verdict, label }: { verdict: MatrixVerdict; label?: string }) {
  const word = label ?? verdict
  const Glyph = verdict === 'allow' ? Icons.check : verdict === 'block' ? Icons.block : Icons.alert
  return (
    <span className={`zm-verdict ${verdict}`}>
      <Glyph size={11} />
      <span>{word}</span>
    </span>
  )
}

function pluralRules(n: number): string {
  return n === 1 ? '1 rule' : `${n} rules`
}

/** Scales 1-hour byte volume onto a 0-26% accent mix. Sub-4 KB background
 *  chatter stays at 0% and a 10 MB reference floor prevents an almost-idle
 *  network from painting its quietest trickle at full intensity. */
function heatPercent(flowBytes: number, maxBytes: number): number {
  const quietFloor = 4096
  if (flowBytes < quietFloor || maxBytes < quietFloor) return 0
  const ceiling = Math.max(maxBytes, 10 * 1024 * 1024)
  const num = Math.log1p(flowBytes - quietFloor)
  const den = Math.log1p(ceiling - quietFloor)
  if (den <= 0) return 0
  const ratio = Math.min(1, Math.max(0, num / den))
  return Math.round(Math.pow(ratio, 1.55) * 26)
}

function describeRuleScope(r: Rule): string {
  const parts: string[] = []
  if (r.src_zone) parts.push(`from ${r.src_zone}`)
  if (r.src) parts.push(`src ${r.src}`)
  if (r.dst_zone) parts.push(`to ${r.dst_zone}`)
  if (r.dst) parts.push(`dst ${r.dst}`)
  if (r.proto && r.proto !== 'any') parts.push(r.proto)
  if (r.src_port) parts.push(`sport ${r.src_port}`)
  if (r.dst_port) parts.push(`dport ${r.dst_port}`)
  if (r.schedule) parts.push(`when ${r.schedule}`)
  return parts.join(' · ') || 'all traffic in pair'
}
