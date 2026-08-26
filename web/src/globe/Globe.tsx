import { useEffect, useMemo, useRef, useState } from 'react'
import { GlobeScene, type ArcSpec, type PointSpec } from './scene'
import type { GlobeArc, GlobeData } from '../types'
import { bytes, countryFlag } from '../format'

interface Props {
  data: GlobeData | null
  /** Live arcs pushed over the WebSocket, merged with the polled set. */
  liveArcs?: GlobeArc[]
  onSelect?: (arc: GlobeArc | null) => void
  focus?: { lat: number; lng: number } | null
  autoRotate?: boolean
  className?: string
}

export function Globe({ data, liveArcs, onSelect, focus, autoRotate = true, className }: Props) {
  const hostRef = useRef<HTMLDivElement>(null)
  const sceneRef = useRef<GlobeScene | null>(null)
  const [hover, setHover] = useState<{ arc: GlobeArc; x: number; y: number } | null>(null)
  const arcIndex = useRef(new Map<string, GlobeArc>())

  // Mount the renderer exactly once; React strict-mode double-invocation is
  // handled by the disposal in the cleanup.
  useEffect(() => {
    if (!hostRef.current) return
    const scene = new GlobeScene(hostRef.current)
    sceneRef.current = scene

    scene.onHover = (spec, screen) => {
      if (!spec) {
        setHover(null)
        return
      }
      const arc = arcIndex.current.get(spec.id)
      if (arc) setHover({ arc, x: screen.x, y: screen.y })
    }
    return () => {
      scene.dispose()
      sceneRef.current = null
    }
  }, [])

  useEffect(() => {
    sceneRef.current?.setAutoRotate(autoRotate)
  }, [autoRotate])

  useEffect(() => {
    if (focus && sceneRef.current) sceneRef.current.focusOn(focus.lat, focus.lng)
  }, [focus])

  // Merge polled arcs with anything the socket delivered since the last poll,
  // preferring the live copy because it carries fresher byte counts.
  const merged = useMemo(() => {
    const map = new Map<string, GlobeArc>()
    for (const a of data?.arcs ?? []) map.set(a.id, a)
    for (const a of liveArcs ?? []) map.set(a.id, a)
    return [...map.values()]
  }, [data, liveArcs])

  useEffect(() => {
    const scene = sceneRef.current
    if (!scene) return

    arcIndex.current = new Map(merged.map((a) => [a.id, a]))
    const specs: ArcSpec[] = merged.map((a) => ({
      id: a.id,
      startLat: a.start_lat, startLng: a.start_lng,
      endLat: a.end_lat, endLng: a.end_lng,
      verdict: a.verdict, bytes: a.bytes, risk: a.risk, active: a.active,
      label: a.label, meta: {},
    }))
    scene.setArcs(specs)

    // Destination points are deduplicated by coordinate: forty connections to
    // one CDN edge should be one marker sized by total traffic, not forty
    // markers stacked on the same pixel.
    const byCoord = new Map<string, PointSpec>()
    for (const a of merged) {
      if (!a.end_lat && !a.end_lng) continue
      const key = `${a.end_lat.toFixed(1)},${a.end_lng.toFixed(1)}`
      const existing = byCoord.get(key)
      if (existing) {
        existing.weight += a.bytes
      } else {
        byCoord.set(key, { lat: a.end_lat, lng: a.end_lng, weight: Math.max(a.bytes, 1), label: a.label })
      }
    }
    scene.setPoints(
      [...byCoord.values()],
      data?.home ? { lat: data.home.lat, lng: data.home.lng, weight: 1, label: data.home.label } : undefined,
    )
  }, [merged, data?.home])

  useEffect(() => {
    if (!onSelect) return
    const scene = sceneRef.current
    if (!scene) return
    scene.onSelect = (spec) => onSelect(spec ? (arcIndex.current.get(spec.id) ?? null) : null)
  }, [onSelect])

  return (
    <div
      ref={hostRef}
      className={`globe-canvas ${className ?? ''}`}
      onClick={() => onSelect?.(hover?.arc ?? null)}
      role="img"
      aria-label={`Connection globe showing ${merged.length} connections`}
    >
      {hover && (
        <div
          className="globe-tooltip"
          style={{
            // Flip the tooltip when it would run off the right edge, so a
            // destination near the limb is still readable.
            left: hover.x > (hostRef.current?.clientWidth ?? 0) - 320 ? undefined : hover.x + 14,
            right: hover.x > (hostRef.current?.clientWidth ?? 0) - 320
              ? (hostRef.current?.clientWidth ?? 0) - hover.x + 14 : undefined,
            top: Math.max(8, hover.y - 10),
          }}
        >
          <div className="host">{hover.arc.label}</div>
          <div className="meta">
            {hover.arc.app && <>{hover.arc.app} · </>}
            {hover.arc.proto}/{hover.arc.port} · {bytes(hover.arc.bytes)}
          </div>
          <div className="meta">
            {hover.arc.country && <>{countryFlag(hover.arc.country)} {hover.arc.city || hover.arc.country} · </>}
            {hover.arc.org || hover.arc.dst}
          </div>
          {hover.arc.verdict !== 'allow' && (
            <div className="meta" style={{ color: 'var(--red)' }}>{hover.arc.verdict}</div>
          )}
        </div>
      )}
    </div>
  )
}
