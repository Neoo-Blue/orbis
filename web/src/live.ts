import { useEffect, useRef, useSyncExternalStore } from 'react'

export interface LiveEvent {
  type: string
  data?: unknown
  ts: number
}

type Batch = (events: LiveEvent[]) => void
interface Subscriber { types: Set<string>; fn: Batch }

/** How often buffered events reach the page. A busy network sends hundreds a
 *  second; nothing on screen needs to change that often. */
const FLUSH_MS = 250

// One socket for the whole app. Each page says which event types it wants and
// the server is told the union, so the node only encodes what is on screen and
// nothing outside the page that asked for an event re-renders because of it.
const subscribers = new Set<Subscriber>()
const listeners = new Set<() => void>()
let socket: WebSocket | null = null
let connected = false
let retry = 0
let reconnect: ReturnType<typeof setTimeout> | null = null
let buffer: LiveEvent[] = []
let flushing: ReturnType<typeof setTimeout> | null = null

function wanted(): string[] {
  const all = new Set<string>()
  for (const s of subscribers) for (const t of s.types) all.add(t)
  // An empty filter means everything to the server, so ask for the rarest.
  return all.size ? [...all] : ['event.new']
}

function setConnected(v: boolean) {
  if (v === connected) return
  connected = v
  for (const l of listeners) l()
}

function flush() {
  flushing = null
  const batch = buffer
  buffer = []
  for (const s of subscribers) {
    const mine = batch.filter((e) => s.types.has(e.type))
    if (mine.length) s.fn(mine)
  }
}

function connect() {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws'
  socket = new WebSocket(`${proto}://${location.host}/api/stream?types=${encodeURIComponent(wanted().join(','))}`)
  socket.onopen = () => {
    retry = 0
    setConnected(true)
    // The set may have changed while this socket was connecting.
    socket?.send(JSON.stringify({ action: 'subscribe', types: wanted() }))
  }
  socket.onmessage = (e) => {
    try {
      buffer.push(JSON.parse(e.data) as LiveEvent)
      if (!flushing) flushing = setTimeout(flush, FLUSH_MS)
    } catch {
      /* a malformed frame is not worth tearing the socket down for */
    }
  }
  socket.onclose = () => {
    setConnected(false)
    socket = null
    // Exponential backoff to 15 s: a daemon restart should not produce a
    // reconnect flood from every open tab.
    reconnect = setTimeout(connect, Math.min(15000, 500 * 2 ** retry++))
  }
  socket.onerror = () => socket?.close()
}

function announce() {
  if (!socket && !reconnect) connect()
  else if (socket?.readyState === WebSocket.OPEN) socket.send(JSON.stringify({ action: 'subscribe', types: wanted() }))
}

/** subscribeLive registers for a set of event types; call the result to stop. */
export function subscribeLive(types: string[], fn: Batch): () => void {
  const sub: Subscriber = { types: new Set(types), fn }
  subscribers.add(sub)
  announce()
  return () => {
    subscribers.delete(sub)
    announce()
  }
}

/** useLiveBatch calls fn with each new batch of events of the given types.
 *  Every event arrives exactly once, and fn always sees current props. */
export function useLiveBatch(types: string[], fn: Batch) {
  const handler = useRef(fn)
  handler.current = fn
  const key = types.join(',')
  useEffect(() => subscribeLive(key.split(','), (b) => handler.current(b)), [key])
}

/** useLiveConnected reports whether the event stream is up. */
export function useLiveConnected(): boolean {
  return useSyncExternalStore((cb) => {
    listeners.add(cb)
    announce()
    return () => { listeners.delete(cb) }
  }, () => connected)
}
