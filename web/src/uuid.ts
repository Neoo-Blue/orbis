/**
 * crypto.randomUUID is only defined in a secure context. Orbis is normally
 * reached over plain HTTP on a LAN address, where it is undefined — calling
 * it there throws and takes the whole page down.
 *
 * crypto.getRandomValues is available in every context, so it is the real
 * implementation; the Math.random path exists only so an ancient browser
 * degrades instead of crashing. These ids are conversation and message keys,
 * not security tokens.
 */
export function uuid(): string {
  const c = globalThis.crypto as Crypto | undefined

  if (c && typeof c.randomUUID === 'function') {
    return c.randomUUID()
  }

  const bytes = new Uint8Array(16)
  if (c && typeof c.getRandomValues === 'function') {
    c.getRandomValues(bytes)
  } else {
    for (let i = 0; i < 16; i++) bytes[i] = Math.floor(Math.random() * 256)
  }
  // Set the version (4) and variant bits so the output is a well-formed UUID.
  bytes[6] = (bytes[6] & 0x0f) | 0x40
  bytes[8] = (bytes[8] & 0x3f) | 0x80

  const hex: string[] = []
  for (let i = 0; i < 16; i++) hex.push(bytes[i].toString(16).padStart(2, '0'))
  return (
    hex.slice(0, 4).join('') + '-' +
    hex.slice(4, 6).join('') + '-' +
    hex.slice(6, 8).join('') + '-' +
    hex.slice(8, 10).join('') + '-' +
    hex.slice(10, 16).join('')
  )
}
