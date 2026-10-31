import { useEffect, useLayoutEffect, useRef, useState, type RefObject } from 'react'

const reduced = () => matchMedia('(prefers-reduced-motion: reduce)').matches

/** useThumb slides one marker to whichever child is current, so moving between
 *  tabs reads as moving, not as two things changing colour. The container holds
 *  a `.thumb` span; `key` is whatever decides the current child. */
export function useThumb<T extends HTMLElement>(key: unknown): RefObject<T> {
  const ref = useRef<T>(null)
  useLayoutEffect(() => {
    const box = ref.current
    if (!box) return
    const place = () => {
      const on = box.querySelector<HTMLElement>('[aria-current="page"],[aria-pressed="true"]')
      box.style.setProperty('--thumb-o', on ? '1' : '0')
      if (!on) return
      box.style.setProperty('--thumb-x', `${on.offsetLeft}px`)
      box.style.setProperty('--thumb-y', `${on.offsetTop}px`)
      box.style.setProperty('--thumb-w', `${on.offsetWidth}px`)
      box.style.setProperty('--thumb-h', `${on.offsetHeight}px`)
      if (box.scrollWidth > box.clientWidth) box.scrollTo({ left: on.offsetLeft - box.clientWidth / 2 + on.offsetWidth / 2, behavior: 'smooth' })
    }
    place()
    // It lands in place on first paint and only slides after that.
    const armed = requestAnimationFrame(() => box.setAttribute('data-thumb', 'on'))
    const seen = new ResizeObserver(place)
    seen.observe(box)
    return () => { cancelAnimationFrame(armed); seen.disconnect() }
  }, [key])
  return ref
}

/** Tween runs a number to its new value instead of swapping it. `rise` counts
 *  up from zero when it first appears. */
export function Tween({ value, format, rise }: { value: number; format: (n: number) => string; rise?: boolean }) {
  const start = rise && !reduced() ? 0 : value
  const [shown, setShown] = useState(start)
  const from = useRef(start)
  useEffect(() => {
    if (from.current === value) return
    if (reduced()) { from.current = value; setShown(value); return }
    const begin = performance.now(), a = from.current
    const ms = rise && a === 0 ? 900 : 420
    let raf = requestAnimationFrame(function step(t) {
      const p = Math.min(1, (t - begin) / ms)
      const v = a + (value - a) * (1 - (1 - p) ** 3)
      from.current = v
      setShown(v)
      if (p < 1) raf = requestAnimationFrame(step)
    })
    return () => cancelAnimationFrame(raf)
  }, [value, rise])
  return <>{format(shown)}</>
}

/** transition moves between pages along the way the navigation is laid out:
 *  sideways between tabs, up and down between sections. */
export function transition(dx: number, dy: number, update: () => void) {
  const doc = document as Document & { startViewTransition?: (cb: () => void) => unknown }
  if (!doc.startViewTransition || reduced()) { update(); return }
  const root = document.documentElement.style
  root.setProperty('--vt-x', `${dx * 28}px`)
  root.setProperty('--vt-y', `${dy * 20}px`)
  doc.startViewTransition(update)
}
