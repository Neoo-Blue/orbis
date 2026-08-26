import { useCallback, useEffect, useRef, useState } from 'react'
import { ApiError } from './api'

/** usePoll fetches on mount and on an interval, keeping the previous value
 *  visible while a refresh is in flight so the UI never flashes empty. */
export function usePoll<T>(
  fn: () => Promise<T>,
  intervalMs: number,
  deps: unknown[] = [],
): { data: T | null; error: string | null; loading: boolean; refresh: () => void } {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const fnRef = useRef(fn)
  fnRef.current = fn
  const [tick, setTick] = useState(0)

  useEffect(() => {
    let cancelled = false
    const run = async () => {
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
        if (!cancelled) setLoading(false)
      }
    }
    run()
    if (intervalMs <= 0) return () => { cancelled = true }
    const id = setInterval(run, intervalMs)
    return () => {
      cancelled = true
      clearInterval(id)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [intervalMs, tick, ...deps])

  const refresh = useCallback(() => setTick((t) => t + 1), [])
  return { data, error, loading, refresh }
}

export interface LiveEvent {
  type: string
  data?: unknown
  ts: number
}

/**
 * useLive keeps a WebSocket to /api/stream open, reconnecting with backoff.
 * Handlers are held in a ref so a consumer re-render never tears down the
 * socket — reconnect storms are the classic failure of this pattern.
 */
export function useLive(onEvent: (ev: LiveEvent) => void, types?: string[]) {
  const handlerRef = useRef(onEvent)
  handlerRef.current = onEvent
  const [connected, setConnected] = useState(false)
  const typeKey = types?.join(',') ?? ''

  useEffect(() => {
    let socket: WebSocket | null = null
    let retry = 0
    let timer: ReturnType<typeof setTimeout> | null = null
    let closed = false

    const connect = () => {
      if (closed) return
      const proto = location.protocol === 'https:' ? 'wss' : 'ws'
      const suffix = typeKey ? `?types=${encodeURIComponent(typeKey)}` : ''
      socket = new WebSocket(`${proto}://${location.host}/api/stream${suffix}`)

      socket.onopen = () => {
        retry = 0
        setConnected(true)
      }
      socket.onmessage = (e) => {
        try {
          handlerRef.current(JSON.parse(e.data) as LiveEvent)
        } catch {
          /* a malformed frame is not worth tearing the socket down for */
        }
      }
      socket.onclose = () => {
        setConnected(false)
        if (closed) return
        // Exponential backoff to 15s: a daemon restart should not produce a
        // reconnect flood from every open tab.
        const delay = Math.min(15000, 500 * 2 ** retry++)
        timer = setTimeout(connect, delay)
      }
      socket.onerror = () => socket?.close()
    }
    connect()

    return () => {
      closed = true
      if (timer) clearTimeout(timer)
      socket?.close()
    }
  }, [typeKey])

  return connected
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
