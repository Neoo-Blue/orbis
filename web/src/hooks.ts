import { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react'
import { ApiError } from './api'

/** False while a kept-alive page sits hidden: it holds its data and its filters
 *  but asks the node for nothing until it is shown again. */
export const ViewVisible = createContext(true)

/** usePoll fetches on mount and on an interval, keeping the previous value
 *  visible while a refresh is in flight so the UI never flashes empty.
 *  An interval of 0 fetches once; null does not fetch at all, for a view that
 *  is hidden or paused. */
export function usePoll<T>(
  fn: () => Promise<T>,
  wantedMs: number | null,
  deps: unknown[] = [],
): { data: T | null; error: string | null; loading: boolean; refresh: () => void } {
  const visible = useContext(ViewVisible)
  const intervalMs = visible ? wantedMs : null
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const fnRef = useRef(fn)
  fnRef.current = fn
  // When the request in flight started, 0 when idle. A request that has
  // hung for longer than two intervals (a dropped Wi-Fi association leaves
  // fetch waiting on TCP for minutes) no longer blocks the next tick.
  const inFlightRef = useRef(0)
  const [tick, setTick] = useState(0)

  useEffect(() => {
    if (intervalMs === null) return
    let cancelled = false
    const run = async () => {
      inFlightRef.current = Date.now()
      try {
        const result = await fnRef.current()
        if (!cancelled) {
          setData(result)
          setError(null)
        }
      } catch (e) {
        // A 401 is handled globally by the auth shell; surfacing it in every
        // panel would paper the screen in the same message.
        if (!cancelled && !(e instanceof ApiError && e.status === 401)) {
          setError(e instanceof Error ? e.message : String(e))
        }
      } finally {
        if (!cancelled) {
          inFlightRef.current = 0
          setLoading(false)
        }
      }
    }
    run()
    if (intervalMs <= 0) {
      return () => {
        cancelled = true
        inFlightRef.current = 0
      }
    }
    const busy = () => inFlightRef.current !== 0 && Date.now() - inFlightRef.current < Math.max(2 * intervalMs, 30000)
    const onTick = () => {
      if (document.hidden || busy()) return
      run()
    }
    const onVisibility = () => {
      if (!document.hidden && !busy()) run()
    }
    const id = setInterval(onTick, intervalMs)
    document.addEventListener('visibilitychange', onVisibility)
    return () => {
      cancelled = true
      inFlightRef.current = 0
      clearInterval(id)
      document.removeEventListener('visibilitychange', onVisibility)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [intervalMs, tick, ...deps])

  const refresh = useCallback(() => setTick((t) => t + 1), [])
  return { data, error, loading, refresh }
}

/** useDebounced delays a rapidly-changing value, for search inputs. */
export function useDebounced<T>(value: T, ms = 250): T {
  const [v, setV] = useState(value)
  useEffect(() => {
    const id = setTimeout(() => setV(value), ms)
    return () => clearTimeout(id)
  }, [value, ms])
  return v
}

/** useLocalStorage persists small UI preferences (sort order, filters). */
export function useLocalStorage<T>(key: string, initial: T): [T, (v: T) => void] {
  const [value, setValue] = useState<T>(() => {
    try {
      const raw = localStorage.getItem(key)
      return raw ? (JSON.parse(raw) as T) : initial
    } catch {
      return initial
    }
  })
  const set = useCallback(
    (v: T) => {
      setValue(v)
      try {
        localStorage.setItem(key, JSON.stringify(v))
      } catch {
        /* private browsing or a full quota is not a reason to break the UI */
      }
    },
    [key],
  )
  return [value, set]
}

/** useMediaQuery tracks a CSS media query, for the few places where markup
 *  (not only style) has to differ on a phone. */
export function useMediaQuery(q: string): boolean {
  const [match, setMatch] = useState(() => typeof window !== 'undefined' && window.matchMedia(q).matches)
  useEffect(() => {
    const m = window.matchMedia(q)
    const on = () => setMatch(m.matches)
    m.addEventListener('change', on)
    return () => m.removeEventListener('change', on)
  }, [q])
  return match
}
