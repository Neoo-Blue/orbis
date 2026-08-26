import * as THREE from 'three'
import landRings from '../data/land.json'
import countryShapes from '../data/countries.json'

/**
 * The globe renderer.
 *
 * Design intent: this should read as an instrument, not a marketing graphic.
 * The sphere is nearly black with a thin atmospheric rim; landmasses are drawn
 * as hairlines rather than a texture, so the arcs stay the brightest thing on
 * screen. Every arc is one live connection, and its colour encodes the verdict
 * — that mapping is the whole point of the view.
 *
 * Performance: arcs are drawn as a small number of merged LineSegments rather
 * than one object per connection. A busy network has thousands of concurrent
 * flows, and a thousand draw calls would drop the frame rate to single digits.
 */

export const GLOBE_RADIUS = 100

export interface ArcSpec {
  id: string
  startLat: number
  startLng: number
  endLat: number
  endLng: number
  verdict: string
  bytes: number
  risk: number
  active: boolean
  label: string
  /** 'out' = this network opened the connection, 'in' = something outside
   *  did. The colour gradient flows along the arc in that direction, which is
   *  the only way to tell an ordinary web request from an unsolicited inbound
   *  connection at a glance. */
  direction: 'in' | 'out' | 'local'
  meta: Record<string, unknown>
}

/** CountryShape is one ring of one country, as generated from Natural Earth
 *  with its ISO 3166-1 alpha-2 code attached. */
interface CountryShape {
  /** ISO 3166-1 alpha-2 */
  c: string
  /** English name, for debugging the data rather than for display */
  n: string
  /** flattened [lng, lat, lng, lat, ...] */
  r: number[]
}

/** CountryLoad is the per-country traffic summary the globe endpoint returns. */
export interface CountryLoad {
  country: string
  connections: number
  bytes: number
  blocked: number
}

export interface PointSpec {
  lat: number
  lng: number
  weight: number
  label: string
}

const COLORS = {
  allow: new THREE.Color('#4ee8c0'),
  block: new THREE.Color('#ff6b7a'),
  filtered: new THREE.Color('#a98bff'),
  pending: new THREE.Color('#ffc266'),
  home: new THREE.Color('#7fd3ff'),
  inbound: new THREE.Color('#ffc266'),
  land: new THREE.Color('#1d3550'),
  border: new THREE.Color('#152740'),
  atmosphere: new THREE.Color('#2a6f8f'),
  // The bright crest of the travelling gradient. Outbound runs cool (the
  // network reaching out), inbound runs warm (something reaching in) — so
  // direction is readable from a still frame, not only from the motion.
  flowOut: new THREE.Color('#eafffb'),
  flowIn: new THREE.Color('#ffd9a0'),
  countryLit: new THREE.Color('#4ee8c0'),
  countryBlocked: new THREE.Color('#ff6b7a'),
}

function verdictColor(v: string): THREE.Color {
  return COLORS[v as keyof typeof COLORS] ?? COLORS.allow
}

/** arcColor keeps verdict as the primary encoding but tints inbound arcs
 *  toward the inbound hue, so direction survives a paused animation and is
 *  legible to anyone who cannot perceive the motion. */
function arcColor(spec: { verdict: string; direction: string }): THREE.Color {
  const base = verdictColor(spec.verdict)
  if (spec.direction !== 'in') return base
  return base.clone().lerp(COLORS.inbound, 0.45)
}

/** latLngToVector places a geographic coordinate on the sphere. */
export function latLngToVector(lat: number, lng: number, radius = GLOBE_RADIUS): THREE.Vector3 {
  const phi = (90 - lat) * (Math.PI / 180)
  const theta = (lng + 180) * (Math.PI / 180)
  return new THREE.Vector3(
    -radius * Math.sin(phi) * Math.cos(theta),
    radius * Math.cos(phi),
    radius * Math.sin(phi) * Math.sin(theta),
  )
}

/**
 * arcCurve builds the great-circle-ish path between two points. The apex
 * height scales with distance so a short hop stays close to the surface and a
 * transcontinental link lifts clear of the globe instead of clipping through it.
 */
function arcCurve(start: THREE.Vector3, end: THREE.Vector3): THREE.QuadraticBezierCurve3 {
  const mid = start.clone().add(end).multiplyScalar(0.5)
  const distance = start.distanceTo(end)
  const lift = 1 + (distance / (GLOBE_RADIUS * 2)) * 0.85
  mid.normalize().multiplyScalar(GLOBE_RADIUS * lift)
  return new THREE.QuadraticBezierCurve3(start, mid, end)
}

/**
 * arcFlowMaterial builds the shader that replaces the old travelling dot.
 *
 * The dot was a poor encoding: at any moment it occupies one point on the
 * line, so a glance catches at most a handful of them and direction has to be
 * inferred from motion that may be off-screen. A gradient running along the
 * whole arc is readable everywhere at once, reads as direction even in a
 * screenshot, and costs one draw call instead of a second mesh per connection.
 *
 * `aProgress` is 0 at the home end and 1 at the remote end. The crest travels
 * toward 1 for outbound and toward 0 for inbound, so an unsolicited inbound
 * connection visibly runs the other way.
 */
function arcFlowMaterial(spec: ArcSpec, weight: number): THREE.ShaderMaterial {
  const inbound = spec.direction === 'in'
  return new THREE.ShaderMaterial({
    transparent: true,
    blending: THREE.AdditiveBlending,
    depthWrite: false,
    uniforms: {
      uBase: { value: arcColor(spec) },
      uCrest: { value: inbound ? COLORS.flowIn : COLORS.flowOut },
      uTime: { value: 0 },
      // Negative speed runs the crest from the remote end back to home.
      uSpeed: { value: (inbound ? -1 : 1) * (0.16 + Math.min(0.3, spec.bytes / 6_000_000)) },
      uPhase: { value: hashPhase(spec.id) },
      uOpacity: { value: 0.2 + weight * 0.5 },
      // An idle flow keeps its line but loses the crest, so "still connected"
      // and "actively moving data" are distinguishable.
      uActive: { value: spec.active ? 1 : 0 },
    },
    vertexShader: `
      attribute float aProgress;
      varying float vProgress;
      void main() {
        vProgress = aProgress;
        gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
      }`,
    fragmentShader: `
      uniform vec3 uBase;
      uniform vec3 uCrest;
      uniform float uTime;
      uniform float uSpeed;
      uniform float uPhase;
      uniform float uOpacity;
      uniform float uActive;
      varying float vProgress;

      void main() {
        // Position of the crest, wrapped into 0..1 and travelling in the
        // direction of the connection.
        float head = fract(uTime * uSpeed + uPhase);
        // Distance behind the crest, wrapped so the tail is continuous across
        // the seam rather than popping when the crest laps the arc.
        float d = fract(vProgress - head + 1.0);
        // A comet: bright at the crest, fading over roughly a third of the arc.
        float tail = smoothstep(0.34, 0.0, d) * uActive;
        // Taper both ends so an arc emerges from its endpoints instead of
        // stopping dead against the globe.
        float ends = smoothstep(0.0, 0.06, vProgress) * smoothstep(1.0, 0.94, vProgress);
        vec3 col = mix(uBase, uCrest, tail * 0.85);
        float alpha = uOpacity * (0.42 + tail * 1.25) * ends;
        gl_FragColor = vec4(col, alpha);
      }`,
  })
}

export class GlobeScene {
  readonly scene = new THREE.Scene()
  readonly camera: THREE.PerspectiveCamera
  private renderer: THREE.WebGLRenderer
  private container: HTMLElement

  private globeGroup = new THREE.Group()
  private arcGroup = new THREE.Group()
  private pointGroup = new THREE.Group()
  private countryGroup = new THREE.Group()

  /** One highlight layer per ISO country code, eased toward `target`. */
  private countryLayers = new Map<string, {
    lines: THREE.LineSegments
    mat: THREE.LineBasicMaterial
    current: number
    target: number
    blocked: boolean
  }>()

  private arcs: Array<{ spec: ArcSpec; line: THREE.Line; birth: number }> = []
  private arcById = new Map<string, number>()

  private raycaster = new THREE.Raycaster()
  private pointer = new THREE.Vector2()
  private hovered: ArcSpec | null = null

  // Camera orbit state. Kept as spherical coordinates so inertia and
  // auto-rotation compose without fighting each other.
  private targetRotation = { x: 0.35, y: 0 }
  private rotation = { x: 0.35, y: 0 }
  private targetDistance = 300
  private distance = 420
  private autoRotate = true
  private dragging = false
  private lastPointer = { x: 0, y: 0 }
  private velocity = { x: 0, y: 0 }

  private frameId = 0
  private clock = new THREE.Clock()
  private disposed = false
  private reducedMotion = false

  onHover?: (spec: ArcSpec | null, screen: { x: number; y: number }) => void
  onSelect?: (spec: ArcSpec | null) => void

  constructor(container: HTMLElement) {
    this.container = container
    this.reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches

    const width = container.clientWidth || 800
    const height = container.clientHeight || 600

    this.camera = new THREE.PerspectiveCamera(38, width / height, 1, 4000)
    this.camera.position.set(0, 0, this.distance)

    this.renderer = new THREE.WebGLRenderer({
      antialias: true,
      alpha: true,
      powerPreference: 'high-performance',
    })
    this.renderer.setSize(width, height)
    // Capping DPR at 2 keeps a 5K display from rendering 4x the pixels for a
    // difference nobody can see on hairlines.
    this.renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2))
    this.renderer.setClearColor(0x000000, 0)
    container.appendChild(this.renderer.domElement)

    this.scene.add(this.globeGroup)
    this.globeGroup.add(this.countryGroup)
    this.globeGroup.add(this.arcGroup)
    this.globeGroup.add(this.pointGroup)

    this.buildGlobe()
    this.attachEvents()
    this.animate()
  }

  // ---- construction ----

  private buildGlobe() {
    // Body: a dark sphere that occludes arcs on the far side. Without it the
    // globe reads as a wireframe ball and depth is impossible to judge.
    const body = new THREE.Mesh(
      new THREE.SphereGeometry(GLOBE_RADIUS * 0.995, 64, 48),
      new THREE.MeshBasicMaterial({ color: 0x060a11 }),
    )
    this.globeGroup.add(body)

    // Atmosphere: back-side sphere with a fresnel-ish falloff, which is what
    // gives the silhouette its glow without any post-processing.
    const atmosphere = new THREE.Mesh(
      new THREE.SphereGeometry(GLOBE_RADIUS * 1.14, 64, 48),
      new THREE.ShaderMaterial({
        transparent: true,
        side: THREE.BackSide,
        depthWrite: false,
        blending: THREE.AdditiveBlending,
        uniforms: { uColor: { value: COLORS.atmosphere } },
        vertexShader: `
          varying vec3 vNormal;
          void main() {
            vNormal = normalize(normalMatrix * normal);
            gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
          }`,
        fragmentShader: `
          uniform vec3 uColor;
          varying vec3 vNormal;
          void main() {
            float intensity = pow(0.62 - dot(vNormal, vec3(0.0, 0.0, 1.0)), 3.0);
            gl_FragColor = vec4(uColor, 1.0) * intensity * 0.9;
          }`,
      }),
    )
    this.globeGroup.add(atmosphere)

    // Graticule: sparse lat/lon rings for orientation.
    this.globeGroup.add(this.buildGraticule())

    // Coastlines and borders, drawn slightly above the surface so they are
    // not z-fought by the body sphere.
    this.globeGroup.add(this.buildRings(landRings as number[][], COLORS.land, 0.62, GLOBE_RADIUS * 1.001))
    this.buildCountries()
  }

  /**
   * buildCountries draws every border once and, separately, a per-country
   * highlight layer that starts invisible.
   *
   * Two layers rather than one recoloured layer: the borders are a single
   * merged LineSegments (285 outlines as 285 objects would be 285 draw calls),
   * and a merged buffer cannot be recoloured per country without rewriting
   * vertex colours every frame. The highlight layer is built once per country
   * and only its material opacity changes, which is free.
   */
  private buildCountries() {
    const shapes = countryShapes as CountryShape[]

    // Borders: one merged object for the whole world.
    const border: number[] = []
    for (const shape of shapes) {
      const flat = shape.r
      for (let i = 0; i + 3 < flat.length; i += 2) {
        const a = latLngToVector(flat[i + 1], flat[i], GLOBE_RADIUS * 1.0015)
        const b = latLngToVector(flat[i + 3], flat[i + 2], GLOBE_RADIUS * 1.0015)
        border.push(a.x, a.y, a.z, b.x, b.y, b.z)
      }
    }
    const borderGeom = new THREE.BufferGeometry()
    borderGeom.setAttribute('position', new THREE.Float32BufferAttribute(border, 3))
    this.globeGroup.add(new THREE.LineSegments(
      borderGeom,
      new THREE.LineBasicMaterial({ color: COLORS.border, transparent: true, opacity: 0.3 }),
    ))

    // Highlight: one object per country, all rings of that country merged.
    const byCode = new Map<string, number[]>()
    for (const shape of shapes) {
      const flat = shape.r
      const acc = byCode.get(shape.c) ?? []
      for (let i = 0; i + 3 < flat.length; i += 2) {
        // Lifted slightly above the border layer so the glow is not z-fought
        // into invisibility by the line it traces.
        const a = latLngToVector(flat[i + 1], flat[i], GLOBE_RADIUS * 1.004)
        const b = latLngToVector(flat[i + 3], flat[i + 2], GLOBE_RADIUS * 1.004)
        acc.push(a.x, a.y, a.z, b.x, b.y, b.z)
      }
      byCode.set(shape.c, acc)
    }
    for (const [code, positions] of byCode) {
      const geom = new THREE.BufferGeometry()
      geom.setAttribute('position', new THREE.Float32BufferAttribute(positions, 3))
      const mat = new THREE.LineBasicMaterial({
        color: COLORS.countryLit,
        transparent: true,
        opacity: 0,
        blending: THREE.AdditiveBlending,
        depthWrite: false,
      })
      const lines = new THREE.LineSegments(geom, mat)
      lines.visible = false
      this.countryGroup.add(lines)
      this.countryLayers.set(code, { lines, mat, current: 0, target: 0, blocked: false })
    }
  }

  /**
   * setCountries lights up the countries this network is talking to, scaled by
   * share of traffic. A country carrying blocked traffic is lit red, because
   * "where is my network reaching" and "where is it being stopped" are the two
   * questions this view exists to answer.
   */
  setCountries(rows: CountryLoad[]) {
    for (const layer of this.countryLayers.values()) {
      layer.target = 0
      layer.blocked = false
    }
    if (!rows.length) return

    // Scale against the busiest country so the map adapts to the network
    // rather than to an absolute byte count that means nothing on its own.
    let peak = 0
    for (const r of rows) peak = Math.max(peak, r.connections)
    if (peak <= 0) return

    for (const r of rows) {
      const layer = this.countryLayers.get((r.country || '').toUpperCase())
      if (!layer) continue
      // Log scale: without it one busy country flattens every other to nothing.
      const share = Math.log10(1 + r.connections) / Math.log10(1 + peak)
      layer.target = clamp(0.18 + share * 0.72, 0, 0.9)
      layer.blocked = r.blocked > 0 && r.blocked >= r.connections * 0.4
    }
  }

  /** updateCountryGlow eases each country toward its target and adds a slow
   *  breath so a lit country reads as live rather than as a static fill. */
  private updateCountryGlow(t: number) {
    const breath = 0.9 + Math.sin(t * 1.1) * 0.1
    for (const layer of this.countryLayers.values()) {
      layer.current += (layer.target - layer.current) * 0.06
      if (layer.current < 0.004) {
        if (layer.lines.visible) layer.lines.visible = false
        continue
      }
      layer.lines.visible = true
      layer.mat.color.copy(layer.blocked ? COLORS.countryBlocked : COLORS.countryLit)
      layer.mat.opacity = layer.current * (this.reducedMotion ? 1 : breath)
    }
  }

  private buildGraticule(): THREE.LineSegments {
    const positions: number[] = []
    const step = 4
    for (let lat = -60; lat <= 60; lat += 30) {
      for (let lng = -180; lng < 180; lng += step) {
        const a = latLngToVector(lat, lng, GLOBE_RADIUS * 1.0005)
        const b = latLngToVector(lat, lng + step, GLOBE_RADIUS * 1.0005)
        positions.push(a.x, a.y, a.z, b.x, b.y, b.z)
      }
    }
    for (let lng = -180; lng < 180; lng += 30) {
      for (let lat = -88; lat < 88; lat += step) {
        const a = latLngToVector(lat, lng, GLOBE_RADIUS * 1.0005)
        const b = latLngToVector(lat + step, lng, GLOBE_RADIUS * 1.0005)
        positions.push(a.x, a.y, a.z, b.x, b.y, b.z)
      }
    }
    const geom = new THREE.BufferGeometry()
    geom.setAttribute('position', new THREE.Float32BufferAttribute(positions, 3))
    return new THREE.LineSegments(
      geom,
      new THREE.LineBasicMaterial({ color: 0x0e1a2b, transparent: true, opacity: 0.55 }),
    )
  }

  /** buildRings merges every polyline into one LineSegments object, because
   *  one object per outline would be one draw call per outline. */
  private buildRings(rings: number[][], color: THREE.Color, opacity: number, radius: number): THREE.LineSegments {
    const positions: number[] = []
    for (const flat of rings) {
      for (let i = 0; i + 3 < flat.length; i += 2) {
        const a = latLngToVector(flat[i + 1], flat[i], radius)
        const b = latLngToVector(flat[i + 3], flat[i + 2], radius)
        positions.push(a.x, a.y, a.z, b.x, b.y, b.z)
      }
    }
    const geom = new THREE.BufferGeometry()
    geom.setAttribute('position', new THREE.Float32BufferAttribute(positions, 3))
    return new THREE.LineSegments(
      geom,
      new THREE.LineBasicMaterial({ color, transparent: true, opacity }),
    )
  }

  // ---- arcs ----

  /**
   * setArcs reconciles the rendered set against the incoming list. Arcs are
   * kept across updates so an ongoing connection does not restart its
   * animation every poll — the flicker that causes is the fastest way to make
   * a live view feel broken.
   */
  setArcs(specs: ArcSpec[]) {
    if (this.disposed) return
    const now = this.clock.getElapsedTime()
    const incoming = new Set(specs.map((s) => s.id))

    // Remove arcs that are gone.
    for (let i = this.arcs.length - 1; i >= 0; i--) {
      if (!incoming.has(this.arcs[i].spec.id)) {
        this.disposeArc(i)
      }
    }
    this.reindex()

    for (const spec of specs) {
      const existing = this.arcById.get(spec.id)
      if (existing !== undefined) {
        // Update only what can change on a live flow.
        const entry = this.arcs[existing]
        const wasInbound = entry.spec.direction === 'in'
        entry.spec = spec
        const mat = entry.line.material as THREE.ShaderMaterial
        mat.uniforms.uBase.value = arcColor(spec)
        mat.uniforms.uActive.value = spec.active ? 1 : 0
        // A flow that reverses direction mid-life is rare but real (a peer
        // dialling back). Flip the crest rather than leaving it running the
        // wrong way until the flow expires.
        if (wasInbound !== (spec.direction === 'in') && !this.reducedMotion) {
          mat.uniforms.uSpeed.value = -mat.uniforms.uSpeed.value
          mat.uniforms.uCrest.value = spec.direction === 'in' ? COLORS.flowIn : COLORS.flowOut
        }
        continue
      }
      this.addArc(spec, now)
    }
  }

  private addArc(spec: ArcSpec, birth: number) {
    const start = latLngToVector(spec.startLat, spec.startLng)
    const end = latLngToVector(spec.endLat, spec.endLng)
    // Degenerate arcs (a destination that geolocated to our own coordinates)
    // would render as a dot and clutter the view.
    if (start.distanceTo(end) < 1.5) return

    const curve = arcCurve(start, end)
    // A denser sample than the old dot path needed: the gradient is evaluated
    // per fragment, but the progress attribute is interpolated between
    // vertices, so too few segments makes the crest visibly faceted.
    const segments = 96
    const points = curve.getPoints(segments)
    const geom = new THREE.BufferGeometry().setFromPoints(points)

    // aProgress runs 0 (home) to 1 (remote) so the shader knows which way
    // along the line it is looking.
    const progress = new Float32Array(points.length)
    for (let i = 0; i < points.length; i++) progress[i] = i / (points.length - 1)
    geom.setAttribute('aProgress', new THREE.BufferAttribute(progress, 1))

    // Heavier flows read brighter, expressed as opacity because WebGL ignores
    // linewidth on most platforms.
    const weight = Math.min(1, Math.log10(Math.max(spec.bytes, 1)) / 8)
    const mat = arcFlowMaterial(spec, weight)
    // With motion suppressed the crest would sit frozen at an arbitrary point,
    // which reads as a rendering fault. Park it at the remote end instead so
    // the arc still shows a direction.
    if (this.reducedMotion) mat.uniforms.uSpeed.value = 0

    const line = new THREE.Line(geom, mat)
    line.userData.curve = curve
    line.userData.id = spec.id
    this.arcGroup.add(line)

    this.arcs.push({ spec, line, birth })
    this.arcById.set(spec.id, this.arcs.length - 1)
  }

  private disposeArc(index: number) {
    const entry = this.arcs[index]
    this.arcGroup.remove(entry.line)
    entry.line.geometry.dispose()
    ;(entry.line.material as THREE.Material).dispose()
    this.arcs.splice(index, 1)
  }

  private reindex() {
    this.arcById.clear()
    this.arcs.forEach((a, i) => this.arcById.set(a.spec.id, i))
  }

  /** setPoints draws destination markers sized by traffic volume. */
  setPoints(points: PointSpec[], home?: PointSpec) {
    while (this.pointGroup.children.length) {
      const child = this.pointGroup.children[0] as THREE.Mesh
      this.pointGroup.remove(child)
      child.geometry.dispose()
      ;(child.material as THREE.Material).dispose()
    }

    for (const p of points) {
      const size = 0.9 + Math.min(3.2, Math.log10(Math.max(p.weight, 1)) * 0.55)
      const mesh = new THREE.Mesh(
        new THREE.SphereGeometry(size, 10, 10),
        new THREE.MeshBasicMaterial({
          color: COLORS.allow, transparent: true, opacity: 0.5,
          blending: THREE.AdditiveBlending, depthWrite: false,
        }),
      )
      mesh.position.copy(latLngToVector(p.lat, p.lng, GLOBE_RADIUS * 1.004))
      mesh.userData.label = p.label
      this.pointGroup.add(mesh)
    }

    if (home) {
      const ring = new THREE.Mesh(
        new THREE.RingGeometry(2.4, 3.4, 24),
        new THREE.MeshBasicMaterial({
          color: COLORS.home, transparent: true, opacity: 0.85,
          side: THREE.DoubleSide, depthWrite: false,
        }),
      )
      const pos = latLngToVector(home.lat, home.lng, GLOBE_RADIUS * 1.006)
      ring.position.copy(pos)
      ring.lookAt(0, 0, 0)
      ring.userData.isHome = true
      this.pointGroup.add(ring)
    }
  }

  // ---- interaction ----

  private attachEvents() {
    const el = this.renderer.domElement
    el.style.touchAction = 'none'
    el.style.cursor = 'grab'

    el.addEventListener('pointerdown', this.onPointerDown)
    window.addEventListener('pointermove', this.onPointerMove)
    window.addEventListener('pointerup', this.onPointerUp)
    el.addEventListener('wheel', this.onWheel, { passive: false })
    window.addEventListener('resize', this.onResize)
  }

  private onPointerDown = (e: PointerEvent) => {
    this.dragging = true
    this.autoRotate = false
    this.lastPointer = { x: e.clientX, y: e.clientY }
    this.renderer.domElement.style.cursor = 'grabbing'
  }

  private onPointerMove = (e: PointerEvent) => {
    const rect = this.renderer.domElement.getBoundingClientRect()
    this.pointer.x = ((e.clientX - rect.left) / rect.width) * 2 - 1
    this.pointer.y = -((e.clientY - rect.top) / rect.height) * 2 + 1

    if (!this.dragging) {
      this.updateHover(e.clientX - rect.left, e.clientY - rect.top)
      return
    }
    const dx = e.clientX - this.lastPointer.x
    const dy = e.clientY - this.lastPointer.y
    this.lastPointer = { x: e.clientX, y: e.clientY }
    this.velocity = { x: dy * 0.005, y: dx * 0.005 }
    this.targetRotation.y += this.velocity.y
    // Clamping pitch stops the globe from flipping over, which is
    // disorienting and makes the arcs unreadable.
    this.targetRotation.x = clamp(this.targetRotation.x + this.velocity.x, -1.2, 1.2)
  }

  private onPointerUp = () => {
    if (!this.dragging) return
    this.dragging = false
    this.renderer.domElement.style.cursor = 'grab'
  }

  private onWheel = (e: WheelEvent) => {
    e.preventDefault()
    this.autoRotate = false
    this.targetDistance = clamp(this.targetDistance * (1 + e.deltaY * 0.0011), 145, 620)
  }

  private onResize = () => {
    if (this.disposed) return
    const w = this.container.clientWidth
    const h = this.container.clientHeight
    if (!w || !h) return
    this.camera.aspect = w / h
    this.camera.updateProjectionMatrix()
    this.renderer.setSize(w, h)
  }

  private updateHover(x: number, y: number) {
    this.raycaster.setFromCamera(this.pointer, this.camera)
    // Lines need a generous threshold or hovering a 1px arc is impossible.
    this.raycaster.params.Line = { threshold: 2.6 }
    const hits = this.raycaster.intersectObjects(this.arcGroup.children, false)

    let found: ArcSpec | null = null
    for (const hit of hits) {
      const id = (hit.object as THREE.Line).userData?.id
      if (!id) continue
      const idx = this.arcById.get(id)
      if (idx !== undefined) {
        found = this.arcs[idx].spec
        break
      }
    }
    if (found?.id !== this.hovered?.id) {
      this.hovered = found
      this.renderer.domElement.style.cursor = found ? 'pointer' : 'grab'
    }
    this.onHover?.(found, { x, y })
  }

  /** focusOn animates the camera to centre a coordinate, used when the user
   *  clicks a destination in a table. */
  focusOn(lat: number, lng: number) {
    this.autoRotate = false
    this.targetRotation.y = -((lng + 180) * Math.PI) / 180 - Math.PI / 2
    this.targetRotation.x = clamp((lat * Math.PI) / 180, -1.2, 1.2)
    this.targetDistance = 230
  }

  setAutoRotate(on: boolean) { this.autoRotate = on }
  isAutoRotating() { return this.autoRotate }

  resetView() {
    this.targetRotation = { x: 0.35, y: 0 }
    this.targetDistance = 300
    this.autoRotate = true
  }

  // ---- loop ----

  private animate = () => {
    if (this.disposed) return
    this.frameId = requestAnimationFrame(this.animate)
    const t = this.clock.getElapsedTime()

    if (this.autoRotate && !this.dragging && !this.reducedMotion) {
      this.targetRotation.y += 0.0009
    }
    // Critically-damped-ish easing: responsive to input without overshoot.
    this.rotation.x += (this.targetRotation.x - this.rotation.x) * 0.09
    this.rotation.y += (this.targetRotation.y - this.rotation.y) * 0.09
    this.distance += (this.targetDistance - this.distance) * 0.08

    this.globeGroup.rotation.x = this.rotation.x
    this.globeGroup.rotation.y = this.rotation.y
    this.camera.position.z = this.distance

    // Advance every arc's gradient. Each arc carries its own phase and signed
    // speed, so this is one uniform write per arc rather than any geometry
    // work, and a burst of new connections does not produce a synchronised rank.
    for (const entry of this.arcs) {
      const mat = entry.line.material as THREE.ShaderMaterial
      mat.uniforms.uTime.value = t - entry.birth
    }

    // Countries fade toward their target intensity rather than snapping, so a
    // poll that changes the traffic mix does not flash the whole map.
    this.updateCountryGlow(t)

    this.renderer.render(this.scene, this.camera)
  }

  dispose() {
    this.disposed = true
    cancelAnimationFrame(this.frameId)
    const el = this.renderer.domElement
    el.removeEventListener('pointerdown', this.onPointerDown)
    window.removeEventListener('pointermove', this.onPointerMove)
    window.removeEventListener('pointerup', this.onPointerUp)
    el.removeEventListener('wheel', this.onWheel)
    window.removeEventListener('resize', this.onResize)

    while (this.arcs.length) this.disposeArc(0)
    this.scene.traverse((obj) => {
      const mesh = obj as THREE.Mesh
      mesh.geometry?.dispose?.()
      const mat = mesh.material
      if (Array.isArray(mat)) mat.forEach((m) => m.dispose())
      else mat?.dispose?.()
    })
    this.renderer.dispose()
    el.remove()
  }
}

function clamp(v: number, lo: number, hi: number) {
  return Math.max(lo, Math.min(hi, v))
}

/** hashPhase derives a stable 0..1 offset from a string. */
function hashPhase(s: string): number {
  let h = 2166136261
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i)
    h = Math.imul(h, 16777619)
  }
  return ((h >>> 0) % 1000) / 1000
}
