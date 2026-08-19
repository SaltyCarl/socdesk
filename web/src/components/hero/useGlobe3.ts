/**
 * useGlobe3 — the three.js hero globe engine.
 *
 * WHY three.js: real material control fixes light mode — the sphere BODY is a
 * transparent ShaderMaterial (near-invisible on slate, warm-greige on cool
 * light) with a view-anchored fresnel RIM; a colour-write-off depth OCCLUDER
 * gives the dots + pins FREE back-hemisphere occlusion via the depth buffer.
 *
 * Engine (preserved): critically-damped spring FLY-TO (stepSpring drives globe
 * rotation + a compositor zoom), pointer PARALLAX, a verdict landed marker that
 * rises + pulses once, and the gating (IntersectionObserver + visibilitychange
 * + DPR cap + reduced-motion static frame + dispose on unmount). Rotation is the
 * exact M(phi,theta) the dot-sample uses, so unitVec-placed pins align.
 *
 * DATA (honest): the pins are REAL, sourced points injected by the caller
 * (heroLayers.ts) — the reported-IP scatter (abuse.ch) + ransomware-by-victim-
 * country (ransomware.live). Both periwinkle (a single shader uniform). The
 * fabricated mock PINS + the mock GEO fly-to table + the ambient "attack arcs"
 * (which implied attack traffic) are GONE — no invented intel, no asserted flows.
 *
 * ENRICH LANDING: the engine listens for `socdesk:enrich-result`, lands on the
 * live result's REAL coordinates, and reveals the real sourced verdict card
 * (verdict tone drives the marker + card accent). No geo → no landing.
 *
 * CSP: three core + hand-wired GLSL (compile ≠ eval). No R3F/drei, no loaders/
 * workers, no external assets (landmask is a bundled data: URI). The tooltip
 * stays the DOM .sdh-tip, re-driven by Vector3.project(camera); every DOM write
 * is setProperty/classList — zero style= attributes in JSX.
 */

import { useEffect, useRef, useState } from 'react'
import type { RefObject } from 'react'
import {
  Scene,
  PerspectiveCamera,
  WebGLRenderer,
  Group,
  BufferGeometry,
  Float32BufferAttribute,
  Points,
  Mesh,
  SphereGeometry,
  RingGeometry,
  ShaderMaterial,
  MeshBasicMaterial,
  Raycaster,
  Vector2,
  Vector3,
  Matrix4,
  DoubleSide,
  CatmullRomCurve3,
  TubeGeometry,
} from 'three'
import { resolveTheme, onSystemThemeChange } from '@socdesk/shared/lib/theme'
import { buildLandPositions, tierColor3 } from './globe3'
import { unitVec, flyTargets, type Tier, type FlyTarget, type Vec3 } from './pins'
import {
  parseCoords,
  buildEnrichCard,
  type HeroPin,
  type EnrichCard,
  type EnrichApiResult,
} from './heroLayers'
import type { HeroCard } from './TipCard'

/* -- rotation / camera / spring tunables (ported) -- */
const THETA = 0.18
const OMEGA = 7.2
const ZMIN = 1.0
const ZMAX = 1.6
const FLY_ZOOM = 1.42
const BASE_Z = 3.3
const FOV = 45
const DPR_CAP = 2
const OVERSAMPLE = 1.5 // backing-store oversample → crisp under the CSS zoom
const PAR_MAX = 0.06 // pointer parallax (radians)

/* -- look knobs -- */
const DOT_SIZE = 5.6
const LIGHT_DIR: [number, number, number] = [-0.5, 0.55, 0.78] // view-space key light
const PIN_LIFT = 1.012 // pins/marker sit just above the surface
const HOVER_GRACE_MS = 130 // hover→card bridge (lets the pointer reach the card)

/* -- critically-damped spring (ported verbatim) -- */
interface Spring {
  x: number
  v: number
  t: number
}
function newSpring(): Spring {
  return { x: 0, v: 0, t: 0 }
}
function stepSpring(s: Spring, dt: number, omega: number): void {
  const x0 = s.x - s.t
  const c2 = s.v + omega * x0
  const e = Math.exp(-omega * dt)
  s.x = s.t + (x0 + c2 * dt) * e
  s.v = (c2 - omega * (x0 + c2 * dt)) * e
}
function settled(s: Spring, ep = 0.004, ev = 0.03): boolean {
  return Math.abs(s.x - s.t) < ep && Math.abs(s.v) < ev
}

interface Anim {
  phi: number
  targetPhi: number
  theta: number
  gz: number
  gzTarget: number
  spinFactor: number
  lastT: number
  dragging: boolean
  lastX: number
  lastY: number
  userTilt: boolean
  hovering: boolean
  cursorNDC: { x: number; y: number } | null
  hoverIdx: number
  flying: boolean
  flyBackMode: boolean
  spinSuspended: boolean
  landedShown: boolean
  landed: FlyTarget | null
  parPhi: number
  parTheta: number
  flyPhi: Spring
  flyTheta: Spring
  flyGz: Spring
}
function newAnim(): Anim {
  return {
    phi: 0, targetPhi: 0, theta: THETA,
    gz: 1, gzTarget: 1, spinFactor: 1, lastT: 0,
    dragging: false, lastX: 0, lastY: 0, userTilt: false, hovering: false, cursorNDC: null, hoverIdx: -1,
    flying: false, flyBackMode: false, spinSuspended: false, landedShown: false,
    landed: null, parPhi: 0, parTheta: 0,
    flyPhi: newSpring(), flyTheta: newSpring(), flyGz: newSpring(),
  }
}

/* -- per-theme look (mirrors tokens.css families; numeric for three) -- */
interface Theme3 {
  dot: [number, number, number]
  dotShade: [number, number, number]
  pin: [number, number, number]
  /** high-contrast ink (--paper) — the compare arc, visible in both themes. */
  paper: [number, number, number]
  body: [number, number, number]
  bodyAlpha: number
  rim: [number, number, number]
  rimStrength: number
  rimPower: number
}
function theme3(dark: boolean): Theme3 {
  return dark
    ? {
        dot: [0.57, 0.62, 1.0],
        dotShade: [0.34, 0.37, 0.66],
        pin: [0.62, 0.66, 1.0],
        paper: [0.91, 0.93, 0.96],
        body: [0.1, 0.09, 0.13],
        bodyAlpha: 0.04,
        rim: [0.49, 0.54, 1.0],
        rimStrength: 0.5,
        rimPower: 3.0,
      }
    : {
        dot: [0.16, 0.18, 0.72],
        dotShade: [0.29, 0.3, 0.5],
        pin: [0.17, 0.19, 0.7],
        paper: [0.075, 0.1, 0.14],
        body: [0.6, 0.585, 0.66],
        bodyAlpha: 0.24,
        rim: [0.29, 0.31, 0.82],
        rimStrength: 0.34,
        rimPower: 3.2,
      }
}

/** verdict tone → the tooltip accent custom-property. Periwinkle for the
 *  reported layers; verdict red/amber/green ONLY for the real enrich tally. */
function accentFor(card: HeroCard): string {
  if (card.kind !== 'enrich') return 'var(--accent)'
  return card.tone === 'red'
    ? 'var(--red)'
    : card.tone === 'amber'
      ? 'var(--gold)'
      : card.tone === 'green'
        ? 'var(--green)'
        : 'var(--muted)'
}

/** live-enrich result → fly target (real coords + real tone). null = no geo. */
function targetFromResult(result: EnrichApiResult | undefined): FlyTarget | null {
  const co = parseCoords(result)
  if (!co) return null
  const tier: Tier =
    result?.tone === 'red' ? 'crit' : result?.tone === 'amber' ? 'susp' : 'low'
  const ratio = result?.consulted ? (result.flagged ?? 0) / result.consulted : 0
  return { r: unitVec(co.lat, co.lng), tier, sev: Math.round(ratio * 100) }
}

/* -- GLSL (ShaderMaterial injects projection/modelView/normalMatrix + attrs) -- */
const DOT_VERT = `
  uniform float uSize; uniform float uPix; uniform vec3 uLightDir;
  varying float vShade;
  void main() {
    vec3 vn = normalize(normalMatrix * normalize(position));
    vShade = smoothstep(-0.55, 0.85, dot(vn, uLightDir));
    vec4 mv = modelViewMatrix * vec4(position, 1.0);
    gl_Position = projectionMatrix * mv;
    gl_PointSize = uSize * uPix * (1.0 / -mv.z);
  }`
const DOT_FRAG = `
  precision mediump float;
  uniform vec3 uColor; uniform vec3 uShade;
  varying float vShade;
  void main() {
    vec2 c = gl_PointCoord - 0.5;
    if (dot(c, c) > 0.25) discard;
    gl_FragColor = vec4(mix(uShade, uColor, vShade), 1.0);
  }`

const PIN_VERT = `
  uniform float uPix; uniform vec3 uLightDir;
  attribute float aSize;
  varying float vShade;
  void main() {
    vec3 vn = normalize(normalMatrix * normalize(position));
    vShade = smoothstep(-0.3, 0.9, dot(vn, uLightDir));
    vec4 mv = modelViewMatrix * vec4(position, 1.0);
    gl_Position = projectionMatrix * mv;
    gl_PointSize = aSize * uPix * (1.0 / -mv.z);
  }`
const PIN_FRAG = `
  precision mediump float;
  uniform vec3 uColor;
  varying float vShade;
  void main() {
    vec2 c = gl_PointCoord - 0.5;
    float d = dot(c, c);
    if (d > 0.25) discard;
    float a = smoothstep(0.25, 0.15, d);
    gl_FragColor = vec4(uColor * (0.6 + 0.4 * vShade), a);
  }`

const BODY_VERT = `
  varying vec3 vN; varying vec3 vV;
  void main() {
    vec4 mv = modelViewMatrix * vec4(position, 1.0);
    vN = normalize(normalMatrix * normal);
    vV = normalize(-mv.xyz);
    gl_Position = projectionMatrix * mv;
  }`
const BODY_FRAG = `
  precision mediump float;
  uniform vec3 uBodyColor; uniform float uBodyAlpha;
  uniform vec3 uRimColor; uniform float uRimStrength; uniform float uRimPower;
  uniform vec3 uLightDir;
  varying vec3 vN; varying vec3 vV;
  void main() {
    vec3 n = normalize(vN);
    float ndv = clamp(dot(n, normalize(vV)), 0.0, 1.0);
    float fres = pow(1.0 - ndv, uRimPower);
    float lit = mix(0.5, 1.0, smoothstep(-0.5, 0.85, dot(n, uLightDir)));
    vec3 col = uBodyColor * lit + uRimColor * fres * uRimStrength;
    float a = clamp(uBodyAlpha * lit + fres * uRimStrength, 0.0, 1.0);
    gl_FragColor = vec4(col, a);
  }`

const MARK_VERT = `
  uniform float uSize; uniform float uPix;
  void main() {
    vec4 mv = modelViewMatrix * vec4(position, 1.0);
    gl_Position = projectionMatrix * mv;
    gl_PointSize = uSize * uPix * (1.0 / -mv.z);
  }`
const MARK_FRAG = `
  precision mediump float;
  uniform vec3 uColor; uniform float uAlpha;
  void main() {
    vec2 c = gl_PointCoord - 0.5;
    float d = dot(c, c);
    if (d > 0.25) discard;
    float e = smoothstep(0.25, 0.13, d);
    gl_FragColor = vec4(uColor, e * uAlpha);
  }`

export interface GlobeApi {
  /** Programmatic land on real coordinates (verdict tone optional). */
  flyToLatLng(lat: number, lng: number, opts?: { tier?: Tier; sev?: number }): void
  /** Return home (also fired by Escape). */
  flyBack(): void
  /** Draw the great-circle route between two real coordinates + a marker at B,
   *  and rotate it into view. Used by the landing Compare-IP result. */
  drawArc(a: { lat: number; lng: number }, b: { lat: number; lng: number }): void
  /** Remove the compare arc + marker and resume the idle spin. */
  clearArc(): void
  /** Stop the render loop without losing state — used when the current
   *  cockpit result has no geography to show (design spec §3.8). Safe to
   *  call repeatedly. */
  suspend(): void
  /** Restart the render loop, but only if the globe is still on-screen
   *  (mirrors the IntersectionObserver gate the mount effect already uses). */
  resume(): void
}
export interface UseGlobe3Result {
  rootRef: RefObject<HTMLElement | null>
  stageRef: RefObject<HTMLDivElement | null>
  canvasRef: RefObject<HTMLCanvasElement | null>
  tipRef: RefObject<HTMLDivElement | null>
  activeCard: HeroCard | null
  api: GlobeApi
}

export function useGlobe3(
  pins: HeroPin[],
  apiRef?: RefObject<GlobeApi | null>,
): UseGlobe3Result {
  const rootRef = useRef<HTMLElement | null>(null)
  const stageRef = useRef<HTMLDivElement | null>(null)
  const canvasRef = useRef<HTMLCanvasElement | null>(null)
  const tipRef = useRef<HTMLDivElement | null>(null)
  const [activeCard, setActiveCard] = useState<HeroCard | null>(null)

  // Latest pins, read by the engine effect (which mounts once). A dedicated
  // effect below rebuilds the pin geometry whenever this changes.
  const pinsRef = useRef<HeroPin[]>(pins)
  const rebuildRef = useRef<(() => void) | null>(null)

  const apiHolder = useRef<GlobeApi>({
    flyToLatLng: () => {},
    flyBack: () => {},
    drawArc: () => {},
    clearArc: () => {},
    suspend: () => {},
    resume: () => {},
  })
  const apiRefStable = useRef<GlobeApi>({
    flyToLatLng: (...a) => apiHolder.current.flyToLatLng(...a),
    flyBack: (...a) => apiHolder.current.flyBack(...a),
    drawArc: (...a) => apiHolder.current.drawArc(...a),
    clearArc: (...a) => apiHolder.current.clearArc(...a),
    suspend: (...a) => apiHolder.current.suspend(...a),
    resume: (...a) => apiHolder.current.resume(...a),
  })

  useEffect(() => {
    if (apiRef) apiRef.current = apiRefStable.current
    return () => {
      if (apiRef) apiRef.current = null
    }
  }, [apiRef])

  // Rebuild the pin buffer when the (async-loaded) data changes.
  useEffect(() => {
    pinsRef.current = pins
    rebuildRef.current?.()
  }, [pins])

  useEffect(() => {
    const canvas = canvasRef.current
    const stage = stageRef.current
    const root = rootRef.current
    if (!canvas || !stage || !root) return

    const reducedMq = window.matchMedia('(prefers-reduced-motion: reduce)')
    const reduced = () => reducedMq.matches
    const anim = newAnim()
    let dark = resolveTheme() === 'dark'

    /* ---------- renderer / scene / camera ---------- */
    let renderer: WebGLRenderer
    try {
      renderer = new WebGLRenderer({ canvas, alpha: true, antialias: true, powerPreference: 'high-performance' })
    } catch {
      return
    }
    const dpr = Math.min(window.devicePixelRatio || 1, DPR_CAP)
    const pr = Math.min(dpr * OVERSAMPLE, 2.4)
    renderer.setPixelRatio(pr)
    renderer.setClearColor(0x000000, 0)
    let size = stage.clientWidth || 1
    renderer.setSize(size, size, false)

    const scene = new Scene()
    const camera = new PerspectiveCamera(FOV, 1, 0.1, 100)
    camera.position.set(0, 0, BASE_Z)
    camera.lookAt(0, 0, 0)

    const globeGroup = new Group()
    scene.add(globeGroup)

    /* ---------- sphere body (fresnel rim + greige/near-invisible body) ---------- */
    const t3 = theme3(dark)
    const bodyMat = new ShaderMaterial({
      vertexShader: BODY_VERT,
      fragmentShader: BODY_FRAG,
      transparent: true,
      depthWrite: false,
      uniforms: {
        uBodyColor: { value: t3.body },
        uBodyAlpha: { value: t3.bodyAlpha },
        uRimColor: { value: t3.rim },
        uRimStrength: { value: t3.rimStrength },
        uRimPower: { value: t3.rimPower },
        uLightDir: { value: new Vector3(...LIGHT_DIR).normalize() },
      },
    })
    const bodyMesh = new Mesh(new SphereGeometry(0.99, 64, 48), bodyMat)
    scene.add(bodyMesh)

    // depth-only occluder → dots/pins behind the sphere are culled for FREE
    const occluder = new Mesh(
      new SphereGeometry(0.98, 48, 32),
      new MeshBasicMaterial({ colorWrite: false }),
    )
    scene.add(occluder)

    /* ---------- dot sphere (async: landmask sample) ---------- */
    const dotMat = new ShaderMaterial({
      vertexShader: DOT_VERT,
      fragmentShader: DOT_FRAG,
      uniforms: {
        uSize: { value: DOT_SIZE },
        uPix: { value: pr },
        uColor: { value: t3.dot },
        uShade: { value: t3.dotShade },
        uLightDir: { value: new Vector3(...LIGHT_DIR).normalize() },
      },
    })
    let dots: Points | null = null
    let disposed = false
    buildLandPositions().then((pos) => {
      if (disposed) return
      const g = new BufferGeometry()
      g.setAttribute('position', new Float32BufferAttribute(pos, 3))
      dots = new Points(g, dotMat)
      dots.frustumCulled = false
      globeGroup.add(dots)
      renderOnce()
    })

    /* ---------- pins (Points; periwinkle; Raycaster hit-test) ----------
       The pin buffer is REBUILT from the injected data whenever it changes
       (data streams in from the state snapshots after mount). */
    const pinMat = new ShaderMaterial({
      vertexShader: PIN_VERT,
      fragmentShader: PIN_FRAG,
      transparent: true,
      depthWrite: false,
      uniforms: {
        uPix: { value: pr },
        uColor: { value: t3.pin },
        uLightDir: { value: new Vector3(...LIGHT_DIR).normalize() },
      },
    })
    function buildPinGeo(list: HeroPin[]): BufferGeometry {
      const g = new BufferGeometry()
      const pos = new Float32Array(list.length * 3)
      const sz = new Float32Array(list.length)
      for (let i = 0; i < list.length; i++) {
        const r = list[i].r
        pos[i * 3] = r[0] * PIN_LIFT
        pos[i * 3 + 1] = r[1] * PIN_LIFT
        pos[i * 3 + 2] = r[2] * PIN_LIFT
        sz[i] = list[i].sizePx
      }
      g.setAttribute('position', new Float32BufferAttribute(pos, 3))
      g.setAttribute('aSize', new Float32BufferAttribute(sz, 1))
      return g
    }
    let currentPins: HeroPin[] = pinsRef.current
    const pinsPoints = new Points(buildPinGeo(currentPins), pinMat)
    pinsPoints.frustumCulled = false
    globeGroup.add(pinsPoints)
    let pinPosAttr = pinsPoints.geometry.getAttribute('position')

    /* ---------- landed marker (verdict) + pulse ring ---------- */
    const markGeo = new BufferGeometry()
    markGeo.setAttribute('position', new Float32BufferAttribute(new Float32Array([0, 0, 1]), 3))
    const markMat = new ShaderMaterial({
      vertexShader: MARK_VERT,
      fragmentShader: MARK_FRAG,
      transparent: true,
      depthWrite: false,
      uniforms: {
        uSize: { value: 0 },
        uPix: { value: pr },
        uColor: { value: [0.55, 0.6, 1.0] },
        uAlpha: { value: 0 },
      },
    })
    const markPoint = new Points(markGeo, markMat)
    markPoint.frustumCulled = false
    markPoint.visible = false
    globeGroup.add(markPoint)

    const pulseMat = new MeshBasicMaterial({ color: 0x7c8aff, transparent: true, opacity: 0, side: DoubleSide, depthWrite: false })
    const pulse = new Mesh(new RingGeometry(0.03, 0.042, 40), pulseMat)
    pulse.visible = false
    globeGroup.add(pulse)
    const landAnim = { active: false, rise: 0, pulse: 0, target: [0, 0, 1] as Vec3, size: 24 }

    /* ---------- compare arc: two-IP great-circle route + a hollow B marker ----------
       The route is --paper (high contrast over the periwinkle globe, both themes);
       the B marker is periwinkle. Both sit just above the surface at ARC_LIFT so the
       depth occluder culls their back-hemisphere halves for free, exactly like pins. */
    const ARC_LIFT = 1.02
    const arcMat = new MeshBasicMaterial({ color: 0xffffff, transparent: true, opacity: 0.92, depthWrite: false })
    arcMat.color.setRGB(t3.paper[0], t3.paper[1], t3.paper[2])
    const arcMesh = new Mesh(new BufferGeometry(), arcMat)
    arcMesh.frustumCulled = false
    arcMesh.visible = false
    globeGroup.add(arcMesh)
    const arcBMat = new MeshBasicMaterial({ color: 0x7c8aff, transparent: true, opacity: 0.95, side: DoubleSide, depthWrite: false })
    ;(arcBMat.color as { setRGB: (r: number, g: number, b: number) => void }).setRGB(t3.pin[0], t3.pin[1], t3.pin[2])
    const arcB = new Mesh(new RingGeometry(0.012, 0.02, 28), arcBMat)
    arcB.frustumCulled = false
    arcB.visible = false
    globeGroup.add(arcB)
    // draw-on reveal + a periwinkle pulse that travels A→B along the route.
    const arcAnim = { reveal: 0, revealing: false, pulse: 0, curve: null as CatmullRomCurve3 | null }
    const arcPulseMat = new ShaderMaterial({
      vertexShader: MARK_VERT,
      fragmentShader: MARK_FRAG,
      transparent: true,
      depthWrite: false,
      uniforms: {
        uSize: { value: 13 },
        uPix: { value: pr },
        uColor: { value: t3.pin },
        uAlpha: { value: 0 },
      },
    })
    const arcPulseGeo = new BufferGeometry()
    arcPulseGeo.setAttribute('position', new Float32BufferAttribute(new Float32Array([0, 0, ARC_LIFT]), 3))
    const arcPulse = new Points(arcPulseGeo, arcPulseMat)
    arcPulse.frustumCulled = false
    arcPulse.visible = false
    globeGroup.add(arcPulse)

    // The pending / active enrich card (sticky; revealed on landing).
    let pendingEnrich: EnrichCard | null = null
    let enrichCard: EnrichCard | null = null

    /* ---------- rotation matrix = M(phi,theta) ---------- */
    const m4 = new Matrix4()
    function applyRotation(phi: number, theta: number): void {
      const cp = Math.cos(phi), sp = Math.sin(phi)
      const ct = Math.cos(theta), st = Math.sin(theta)
      m4.set(
        cp, 0, sp, 0,
        sp * st, ct, -cp * st, 0,
        -sp * ct, st, cp * ct, 0,
        0, 0, 0, 1,
      )
      globeGroup.quaternion.setFromRotationMatrix(m4)
    }

    /* ---------- tooltip / active-card model ---------- */
    const _v = new Vector3()
    const _pw = new Vector3()
    const raycaster = new Raycaster()
    if (raycaster.params.Points) raycaster.params.Points.threshold = 0.03
    const _ndc = new Vector2()
    let cardHover = false // pointer is over the card (freeze + keep it up)
    let clearTimer = 0
    let lastCard: HeroCard | null = null

    function pinWorld(idx: number, out: Vector3): void {
      out.fromBufferAttribute(pinPosAttr, idx).applyMatrix4(pinsPoints.matrixWorld)
    }
    /** current active card = the sticky enrich card, else the hovered pin. */
    function currentCard(): HeroCard | null {
      if (enrichCard) return enrichCard
      if (anim.hoverIdx >= 0) return currentPins[anim.hoverIdx] ?? null
      return null
    }
    function renderActiveCard(): void {
      const target = currentCard()
      if (target === lastCard) {
        if (target) positionTip()
        return
      }
      lastCard = target
      const tip = tipRef.current
      if (target) tip?.style.setProperty('--tip-accent', accentFor(target))
      setActiveCard(target)
      if (target) positionTip()
    }
    function positionTip(): void {
      const tip = tipRef.current
      const target = lastCard
      if (!tip || !target) return
      if (cardHover) return // frozen while the pointer inspects the card
      if (target.kind === 'enrich') {
        if (!anim.landed) return
        const r = anim.landed.r
        _pw.set(r[0] * PIN_LIFT, r[1] * PIN_LIFT, r[2] * PIN_LIFT).applyMatrix4(globeGroup.matrixWorld)
      } else {
        if (anim.hoverIdx < 0) return
        pinWorld(anim.hoverIdx, _pw)
      }
      _v.copy(_pw).project(camera)
      const rect = canvas!.getBoundingClientRect()
      const sx = rect.left + (_v.x * 0.5 + 0.5) * rect.width
      const sy = rect.top + (-_v.y * 0.5 + 0.5) * rect.height
      const TW = tip.offsetWidth || 300
      const TH = tip.offsetHeight || 260
      const gap = 18
      let tx = sx + gap
      if (tx + TW > window.innerWidth - 12) tx = sx - TW - gap
      if (tx < 12) tx = 12
      let ty = sy - 44
      if (ty + TH > window.innerHeight - 12) ty = window.innerHeight - 12 - TH
      if (ty < 12) ty = 12
      tip.style.setProperty('--tx', tx.toFixed(1) + 'px')
      tip.style.setProperty('--ty', ty.toFixed(1) + 'px')
    }
    function clearHover(): void {
      if (anim.hoverIdx !== -1) {
        anim.hoverIdx = -1
        renderActiveCard()
      }
    }
    function scheduleClear(): void {
      if (clearTimer || cardHover || anim.hoverIdx < 0) return
      clearTimer = window.setTimeout(() => {
        clearTimer = 0
        if (!cardHover) clearHover()
      }, HOVER_GRACE_MS)
    }
    function cancelClear(): void {
      if (clearTimer) {
        clearTimeout(clearTimer)
        clearTimer = 0
      }
    }
    function hitTest(): void {
      if (enrichCard || cardHover) return // enrich landed / inspecting card → hover off
      if (anim.dragging || anim.flying) {
        cancelClear()
        clearHover()
        return
      }
      if (!anim.cursorNDC) {
        scheduleClear() // pointer left the stage → grace (may be heading to the card)
        return
      }
      _ndc.set(anim.cursorNDC.x, anim.cursorNDC.y)
      raycaster.setFromCamera(_ndc, camera)
      const hits = raycaster.intersectObject(pinsPoints, false)
      let best = -1
      for (const h of hits) {
        const idx = h.index
        if (idx == null) continue
        pinWorld(idx, _pw)
        if (_pw.z > 0.04) {
          best = idx // hits are sorted near→far; first front-facing wins
          break
        }
      }
      if (best >= 0) {
        cancelClear()
        if (best !== anim.hoverIdx) {
          anim.hoverIdx = best
          renderActiveCard()
        } else {
          positionTip()
        }
      } else {
        scheduleClear() // on the globe but off any pin → grace, then clear
      }
    }

    /* ---------- rebuild the pin buffer on data change ---------- */
    function rebuildPins(): void {
      cancelClear()
      anim.hoverIdx = -1
      currentPins = pinsRef.current
      const g = buildPinGeo(currentPins)
      pinsPoints.geometry.dispose()
      pinsPoints.geometry = g
      pinPosAttr = g.getAttribute('position')
      renderActiveCard() // drops a stale hover card (enrich card, if any, survives)
      if (!running) renderOnce()
    }
    rebuildRef.current = rebuildPins

    /* ---------- landed beat (rise + pulse once; reveal the enrich card) ---------- */
    function beat(): void {
      if (!anim.landed) return
      anim.landedShown = true
      const r = anim.landed.r
      landAnim.target = [r[0], r[1], r[2]]
      landAnim.active = true
      landAnim.rise = reduced() ? 1 : 0
      landAnim.pulse = 0
      landAnim.size = 16 + (anim.landed.sev / 100) * 12
      const col = tierColor3(anim.landed.tier, dark)
      ;(markMat.uniforms.uColor.value as number[]) = col
      pulseMat.color.setRGB(col[0], col[1], col[2])
      markPoint.geometry.getAttribute('position').setXYZ(0, r[0] * PIN_LIFT, r[1] * PIN_LIFT, r[2] * PIN_LIFT)
      markPoint.geometry.getAttribute('position').needsUpdate = true
      markPoint.visible = true
      pulse.position.set(r[0] * 1.008, r[1] * 1.008, r[2] * 1.008)
      pulse.quaternion.setFromUnitVectors(new Vector3(0, 0, 1), new Vector3(r[0], r[1], r[2]).normalize())
      pulse.visible = !reduced()
      // reveal the real sourced verdict card at the landed point
      if (pendingEnrich) {
        enrichCard = pendingEnrich
        pendingEnrich = null
        renderActiveCard()
      }
    }
    function clearLanded(): void {
      landAnim.active = false
      anim.landedShown = false
      anim.landed = null
      markPoint.visible = false
      pulse.visible = false
      markMat.uniforms.uAlpha.value = 0
      pendingEnrich = null
      if (enrichCard) {
        enrichCard = null
        renderActiveCard()
      }
    }
    function stepLanded(dt: number): void {
      if (!landAnim.active) return
      if (landAnim.rise < 1) landAnim.rise = Math.min(1, landAnim.rise + dt / 0.4)
      markMat.uniforms.uSize.value = landAnim.size * (0.4 + 0.6 * landAnim.rise)
      markMat.uniforms.uAlpha.value = Math.min(1, landAnim.rise * 1.5)
      if (pulse.visible) {
        landAnim.pulse = Math.min(1, landAnim.pulse + dt / 0.9)
        const s = 1 + landAnim.pulse * 3.2
        pulse.scale.setScalar(s)
        pulseMat.opacity = 0.6 * (1 - landAnim.pulse)
        if (landAnim.pulse >= 1) pulse.visible = false
      }
    }
    /** Compare arc: draw the tube on (grow its draw range), then loop a pulse A→B. */
    function stepArcAnim(dt: number): void {
      if (!arcMesh.visible) return
      const geo = arcMesh.geometry
      if (arcAnim.revealing) {
        arcAnim.reveal = Math.min(1, arcAnim.reveal + dt / 0.75)
        const idx = geo.index
        const total = idx ? idx.count : geo.getAttribute('position').count
        geo.setDrawRange(0, Math.max(0, Math.floor(total * arcAnim.reveal)))
        if (arcAnim.reveal >= 1) {
          geo.setDrawRange(0, Infinity)
          arcAnim.revealing = false
        }
      }
      if (arcPulse.visible && arcAnim.curve && !arcAnim.revealing) {
        arcAnim.pulse += dt / 2.4
        if (arcAnim.pulse > 1) arcAnim.pulse -= 1
        const p = arcAnim.curve.getPointAt(arcAnim.pulse)
        const pos = arcPulse.geometry.getAttribute('position')
        pos.setXYZ(0, p.x, p.y, p.z)
        pos.needsUpdate = true
        // fade in/out toward the endpoints so it reads as a travelling signal.
        arcPulseMat.uniforms.uAlpha.value = 0.35 + 0.6 * Math.sin(Math.PI * arcAnim.pulse)
      }
    }

    /* ---------- render one composed frame ---------- */
    function applyGrow(): void {
      stage!.style.setProperty('--globe-grow', anim.gz.toFixed(4))
    }
    function composeAndRender(): void {
      applyGrow()
      applyRotation(anim.phi + anim.parPhi, Math.max(-1.45, Math.min(1.45, anim.theta + anim.parTheta)))
      renderer.render(scene, camera)
    }
    function renderOnce(): void {
      composeAndRender()
    }

    /* ---------- the loop ---------- */
    let raf = 0
    let running = false
    let visible = false
    function frame(): void {
      const now = performance.now()
      let dt = anim.lastT ? (now - anim.lastT) / 1000 : 0.0167
      anim.lastT = now
      if (dt > 0.05) dt = 0.05

      if (anim.flying) {
        stepSpring(anim.flyPhi, dt, OMEGA)
        anim.phi = anim.flyPhi.x
        anim.targetPhi = anim.phi
        stepSpring(anim.flyTheta, dt, OMEGA)
        anim.theta = anim.flyTheta.x
        stepSpring(anim.flyGz, dt, OMEGA)
        anim.gz = anim.flyGz.x
        if (!anim.flyBackMode && !anim.landedShown && anim.landed) {
          const r = anim.landed.r
          const fz = -Math.sin(anim.phi) * Math.cos(anim.theta) * r[0] + Math.sin(anim.theta) * r[1] + Math.cos(anim.phi) * Math.cos(anim.theta) * r[2]
          if (fz > 0.82) beat()
        }
        if (settled(anim.flyPhi) && settled(anim.flyTheta) && settled(anim.flyGz, 0.004, 0.05)) {
          anim.flying = false
          if (anim.flyBackMode) {
            anim.flyBackMode = false
            anim.spinSuspended = false
            clearLanded()
          } else {
            anim.gzTarget = anim.gz
            if (!anim.landedShown) beat()
          }
        }
      } else {
        let ts = 1
        if (anim.dragging || anim.spinSuspended) ts = 0
        else if (anim.hoverIdx >= 0) ts = 0
        else if (anim.hovering) ts = 0.3
        anim.spinFactor += (ts - anim.spinFactor) * (1 - Math.exp(-dt * 7))
        if (!anim.dragging) anim.targetPhi += 0.0035 * (dt * 60) * anim.spinFactor
        anim.phi += (anim.targetPhi - anim.phi) * (1 - Math.exp(-dt * 6.5))
        if (!anim.landed && !anim.userTilt) anim.theta += (THETA - anim.theta) * (1 - Math.exp(-dt * 6.5))
        if (Math.abs(anim.gzTarget - anim.gz) > 4e-4) anim.gz += (anim.gzTarget - anim.gz) * (1 - Math.exp(-dt * 9))
        else anim.gz = anim.gzTarget
      }

      // pointer parallax — off during drag/fly and while inspecting a pin
      let ptX = 0
      let ptY = 0
      if (anim.hovering && anim.cursorNDC && !anim.dragging && !anim.flying && anim.hoverIdx < 0 && !enrichCard) {
        ptX = anim.cursorNDC.x * 0.5
        ptY = anim.cursorNDC.y * 0.5
      }
      const kPar = 1 - Math.exp(-dt * 5)
      anim.parPhi += (ptX * PAR_MAX - anim.parPhi) * kPar
      anim.parTheta += (ptY * PAR_MAX - anim.parTheta) * kPar

      stepLanded(dt)
      stepArcAnim(dt)
      composeAndRender()
      hitTest()
      positionTip()

      if (running) raf = requestAnimationFrame(frame)
    }
    function startLoop(): void {
      if (!visible || document.hidden) return
      if (reduced()) {
        running = false
        renderOnce()
        return
      }
      if (running) return
      running = true
      anim.lastT = 0
      raf = requestAnimationFrame(frame)
    }
    function stopLoop(): void {
      running = false
      if (raf) cancelAnimationFrame(raf)
      raf = 0
    }
    /** Suspend the loop entirely — a geoless cockpit result stops the globe
     *  animating instead of merely dimming it behind CSS (design spec §3.8:
     *  IntersectionObserver-based gating doesn't see a CSS opacity change, so
     *  without this the loop keeps burning GPU behind the .is-geoless dim). */
    function suspend(): void {
      stopLoop()
    }
    /** Resume, but only if the globe is still on-screen — mirrors the
     *  existing onVisibility gate below (`if (document.hidden) stopLoop();
     *  else if (visible) startLoop()`). */
    function resume(): void {
      if (visible) startLoop()
    }

    /* ---------- fly-to (ported spring physics) ---------- */
    function flyToTarget(tt: FlyTarget): void {
      cancelClear()
      clearHover()
      const { phi: phiT0, theta: thetaT } = flyTargets(tt.r)
      let phiT = phiT0
      while (phiT - anim.phi > Math.PI) phiT -= 2 * Math.PI
      while (anim.phi - phiT > Math.PI) phiT += 2 * Math.PI
      anim.landed = { r: tt.r, tier: tt.tier, sev: tt.sev }
      anim.landedShown = false
      anim.userTilt = false // the landing owns theta now

      if (reduced()) {
        anim.phi = phiT
        anim.targetPhi = phiT
        anim.theta = thetaT
        anim.gz = FLY_ZOOM
        anim.gzTarget = FLY_ZOOM
        anim.flying = false
        anim.spinSuspended = true
        beat()
        renderOnce()
        positionTip() // place the card after the rotation is applied (no rAF here)
        return
      }
      anim.flyPhi.x = anim.phi
      anim.flyPhi.v = 0
      anim.flyPhi.t = phiT
      anim.flyTheta.x = anim.theta
      anim.flyTheta.v = 0
      anim.flyTheta.t = thetaT
      anim.flyGz.x = anim.gz
      anim.flyGz.v = 0
      anim.flyGz.t = FLY_ZOOM
      anim.flying = true
      anim.flyBackMode = false
      anim.spinSuspended = true
      startLoop()
    }
    function flyBack(): void {
      if (!anim.flying && !anim.landed && !anim.landedShown) return
      anim.userTilt = false // restore the resting-tilt auto-return
      if (reduced()) {
        anim.theta = THETA
        anim.gz = 1
        anim.gzTarget = 1
        anim.flying = false
        anim.spinSuspended = false
        clearLanded()
        renderOnce()
        return
      }
      anim.flyPhi.x = anim.phi
      anim.flyPhi.v = 0
      anim.flyPhi.t = anim.phi
      anim.flyTheta.x = anim.theta
      anim.flyTheta.v = 0
      anim.flyTheta.t = THETA
      anim.flyGz.x = anim.gz
      anim.flyGz.v = 0
      anim.flyGz.t = 1
      anim.gzTarget = 1
      anim.flying = true
      anim.flyBackMode = true
      anim.spinSuspended = true
      startLoop()
    }
    function flyToLatLng(lat: number, lng: number, opts: { tier?: Tier; sev?: number } = {}): void {
      if (!Number.isFinite(lat) || !Number.isFinite(lng)) return
      flyToTarget({
        r: unitVec(lat, lng),
        tier: opts.tier ?? 'crit',
        sev: Number.isFinite(opts.sev) ? (opts.sev as number) : 70,
      })
    }

    /* ---------- compare arc ---------- */
    const ARC_ZOOM = 1.15 // gentler than a landing so both endpoints stay framed

    /** Rotate a direction to the front of the globe WITHOUT a verdict beat — used
     *  to frame the arc's midpoint. Leaves any existing landed marker untouched. */
    function rotateTo(r: Vec3, zoom: number): void {
      const { phi: phiT0, theta: thetaT } = flyTargets(r)
      let phiT = phiT0
      while (phiT - anim.phi > Math.PI) phiT -= 2 * Math.PI
      while (anim.phi - phiT > Math.PI) phiT += 2 * Math.PI
      if (reduced()) {
        anim.phi = phiT
        anim.targetPhi = phiT
        anim.theta = thetaT
        anim.gz = zoom
        anim.gzTarget = zoom
        anim.flying = false
        anim.spinSuspended = true
        renderOnce()
        return
      }
      anim.flyPhi.x = anim.phi; anim.flyPhi.v = 0; anim.flyPhi.t = phiT
      anim.flyTheta.x = anim.theta; anim.flyTheta.v = 0; anim.flyTheta.t = thetaT
      anim.flyGz.x = anim.gz; anim.flyGz.v = 0; anim.flyGz.t = zoom
      anim.gzTarget = zoom
      anim.flying = true
      anim.flyBackMode = false
      anim.spinSuspended = true
      startLoop()
    }

    /** Great-circle sample points (slerp on unit vectors), lifted above the surface. */
    function arcPoints(rA: Vec3, rB: Vec3, n = 64): Vector3[] {
      const va = new Vector3(rA[0], rA[1], rA[2]).normalize()
      const vb = new Vector3(rB[0], rB[1], rB[2]).normalize()
      const omega = Math.acos(Math.max(-1, Math.min(1, va.dot(vb))))
      const sin = Math.sin(omega)
      const out: Vector3[] = []
      for (let i = 0; i <= n; i++) {
        const t = i / n
        const p =
          sin < 1e-4
            ? va.clone()
            : va.clone().multiplyScalar(Math.sin((1 - t) * omega) / sin).add(vb.clone().multiplyScalar(Math.sin(t * omega) / sin))
        out.push(p.normalize().multiplyScalar(ARC_LIFT))
      }
      return out
    }

    function drawArc(a: { lat: number; lng: number }, b: { lat: number; lng: number }): void {
      if (disposed) return
      if (![a.lat, a.lng, b.lat, b.lng].every(Number.isFinite)) return
      const rA = unitVec(a.lat, a.lng)
      const rB = unitVec(b.lat, b.lng)
      const curve = new CatmullRomCurve3(arcPoints(rA, rB, 64))
      arcMesh.geometry.dispose()
      arcMesh.geometry = new TubeGeometry(curve, 96, 0.009, 8, false)
      arcMesh.visible = true
      // draw-on: grow the tube's draw range 0→full, then the pulse rides it.
      arcAnim.curve = curve
      arcAnim.reveal = reduced() ? 1 : 0
      arcAnim.revealing = !reduced()
      arcAnim.pulse = 0
      if (arcAnim.revealing) arcMesh.geometry.setDrawRange(0, 0)
      arcPulse.visible = !reduced()
      arcPulseMat.uniforms.uAlpha.value = 0
      const bv = new Vector3(rB[0], rB[1], rB[2]).normalize()
      arcB.position.set(bv.x * ARC_LIFT, bv.y * ARC_LIFT, bv.z * ARC_LIFT)
      arcB.quaternion.setFromUnitVectors(new Vector3(0, 0, 1), bv)
      arcB.visible = true
      const mid = new Vector3(rA[0] + rB[0], rA[1] + rB[1], rA[2] + rB[2])
      if (mid.lengthSq() > 1e-6) rotateTo([mid.x, mid.y, mid.z], ARC_ZOOM)
      else if (!running) renderOnce()
    }

    function clearArc(): void {
      const wasShown = arcMesh.visible
      arcMesh.visible = false
      arcB.visible = false
      arcPulse.visible = false
      arcAnim.revealing = false
      arcAnim.curve = null
      // resume the idle spin we suspended to frame the arc (unless a verdict
      // landing is currently holding the view — then leave it be).
      if (wasShown && !anim.landed && !anim.landedShown) {
        if (reduced()) {
          anim.theta = THETA
          anim.gz = 1
          anim.gzTarget = 1
          anim.spinSuspended = false
          renderOnce()
        } else {
          anim.flyPhi.x = anim.phi; anim.flyPhi.v = 0; anim.flyPhi.t = anim.phi
          anim.flyTheta.x = anim.theta; anim.flyTheta.v = 0; anim.flyTheta.t = THETA
          anim.flyGz.x = anim.gz; anim.flyGz.v = 0; anim.flyGz.t = 1
          anim.gzTarget = 1
          anim.flying = true
          anim.flyBackMode = true // settle → clearLanded() → spinSuspended = false
          anim.spinSuspended = true
          startLoop()
        }
      } else if (!running) {
        renderOnce()
      }
    }

    apiHolder.current = { flyToLatLng, flyBack, drawArc, clearArc, suspend, resume }

    /* ---------- input ---------- */
    function ndcFromEvent(e: PointerEvent): void {
      const rect = canvas!.getBoundingClientRect()
      if (!rect.width) return
      anim.cursorNDC = {
        x: ((e.clientX - rect.left) / rect.width) * 2 - 1,
        y: -(((e.clientY - rect.top) / rect.height) * 2 - 1),
      }
    }
    function onWheel(e: WheelEvent): void {
      e.preventDefault()
      const step = reduced() ? (e.deltaY < 0 ? 0.2 : -0.2) : -e.deltaY * 0.0016
      anim.gzTarget = Math.max(ZMIN, Math.min(ZMAX, anim.gzTarget + step))
      if (reduced()) {
        anim.gz = anim.gzTarget
        renderOnce()
      }
    }
    stage.addEventListener('wheel', onWheel, { passive: false })

    const pointers = new Map<number, { x: number; y: number }>()
    let pinchBase = 0
    function onStageDown(e: PointerEvent): void {
      pointers.set(e.pointerId, { x: e.clientX, y: e.clientY })
      if (pointers.size === 2) {
        const it = [...pointers.values()]
        pinchBase = Math.hypot(it[0].x - it[1].x, it[0].y - it[1].y)
      }
    }
    function onStageMove(e: PointerEvent): void {
      if (pointers.has(e.pointerId)) {
        pointers.set(e.pointerId, { x: e.clientX, y: e.clientY })
        if (pointers.size === 2 && pinchBase > 0) {
          const it = [...pointers.values()]
          const d = Math.hypot(it[0].x - it[1].x, it[0].y - it[1].y)
          anim.gzTarget = Math.max(ZMIN, Math.min(ZMAX, anim.gzTarget + (d - pinchBase) * 0.0022))
          pinchBase = d
        }
      }
      ndcFromEvent(e)
      if (!running) {
        hitTest()
        renderOnce()
        positionTip()
      }
    }
    function onStageUp(e: PointerEvent): void {
      pointers.delete(e.pointerId)
      if (pointers.size < 2) pinchBase = 0
    }
    stage.addEventListener('pointerdown', onStageDown)
    stage.addEventListener('pointermove', onStageMove, { passive: true })
    stage.addEventListener('pointerup', onStageUp)
    stage.addEventListener('pointercancel', onStageUp)
    stage.addEventListener('pointerenter', () => {
      anim.hovering = true
    })
    stage.addEventListener('pointerleave', () => {
      anim.hovering = false
      anim.cursorNDC = null
      if (!running) {
        hitTest()
        renderOnce()
      }
    })

    // interactive tooltip — keep the card up while the pointer inspects it
    const tipEl = tipRef.current
    function onTipEnter(): void {
      cardHover = true
      cancelClear()
    }
    function onTipLeave(): void {
      cardHover = false
      if (!enrichCard) scheduleClear()
    }
    tipEl?.addEventListener('pointerenter', onTipEnter)
    tipEl?.addEventListener('pointerleave', onTipLeave)

    function onCanvasDown(e: PointerEvent): void {
      if (reduced()) return
      anim.dragging = true
      anim.lastX = e.clientX
      anim.lastY = e.clientY
      if (anim.flying && !anim.flyBackMode) anim.flying = false
      stage!.classList.add('is-dragging')
      try {
        canvas!.setPointerCapture(e.pointerId)
      } catch {
        /* no-op */
      }
    }
    function onWinMove(e: PointerEvent): void {
      if (!anim.dragging) return
      anim.targetPhi += (e.clientX - anim.lastX) * 0.005
      anim.lastX = e.clientX
      // vertical drag tilts the globe (theta); clamp shy of the poles. The tilt
      // persists (userTilt suspends the resting-tilt auto-return until flyBack).
      const dy = e.clientY - anim.lastY
      if (dy !== 0) {
        anim.theta = Math.max(-1.2, Math.min(1.2, anim.theta + dy * 0.005))
        anim.userTilt = true
      }
      anim.lastY = e.clientY
    }
    function endDrag(): void {
      anim.dragging = false
      stage!.classList.remove('is-dragging')
    }
    canvas.addEventListener('pointerdown', onCanvasDown)
    window.addEventListener('pointermove', onWinMove, { passive: true })
    window.addEventListener('pointerup', endDrag)
    window.addEventListener('pointercancel', endDrag)

    function onKeyDown(e: KeyboardEvent): void {
      if (e.key !== 'Escape') return
      if (arcMesh.visible) clearArc()
      else flyBack()
    }
    window.addEventListener('keydown', onKeyDown)

    function onEnrich(e: Event): void {
      try {
        const detail = (e as CustomEvent).detail as EnrichApiResult
        const target = targetFromResult(detail)
        if (!target) return // no geolocation → no fabricated landing
        pendingEnrich = buildEnrichCard(detail)
        flyToTarget(target)
      } catch {
        /* no-op */
      }
    }
    document.addEventListener('socdesk:enrich-result', onEnrich)

    /* ---------- theme recolour (uniforms only, no rebuild) ---------- */
    function recolor(): void {
      dark = resolveTheme() === 'dark'
      const c = theme3(dark)
      ;(dotMat.uniforms.uColor.value as number[]) = c.dot
      ;(dotMat.uniforms.uShade.value as number[]) = c.dotShade
      ;(pinMat.uniforms.uColor.value as number[]) = c.pin
      arcMat.color.setRGB(c.paper[0], c.paper[1], c.paper[2])
      ;(arcBMat.color as { setRGB: (r: number, g: number, b: number) => void }).setRGB(c.pin[0], c.pin[1], c.pin[2])
      ;(arcPulseMat.uniforms.uColor.value as number[]) = c.pin
      ;(bodyMat.uniforms.uBodyColor.value as number[]) = c.body
      bodyMat.uniforms.uBodyAlpha.value = c.bodyAlpha
      ;(bodyMat.uniforms.uRimColor.value as number[]) = c.rim
      bodyMat.uniforms.uRimStrength.value = c.rimStrength
      bodyMat.uniforms.uRimPower.value = c.rimPower
      if (!running) renderOnce()
    }
    const themeObserver = new MutationObserver(recolor)
    themeObserver.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] })
    const offSystemTheme = onSystemThemeChange(() => {
      if (!document.documentElement.getAttribute('data-theme')) recolor()
    })

    function onReducedChange(): void {
      if (reduced()) {
        stopLoop()
        renderOnce()
      } else startLoop()
    }
    reducedMq.addEventListener('change', onReducedChange)

    /* ---------- resize ---------- */
    function onResize(): void {
      const s = stage!.clientWidth
      if (!s || s === size) {
        if (!running) renderOnce()
        return
      }
      size = s
      renderer.setSize(size, size, false)
      if (!running) renderOnce()
    }
    window.addEventListener('resize', onResize, { passive: true })

    /* ---------- gating: intersection + visibility ---------- */
    const io = new IntersectionObserver(
      (entries) => {
        for (const en of entries) {
          if (en.isIntersecting) {
            visible = true
            canvas!.classList.add('is-ready')
            startLoop()
          } else {
            visible = false
            stopLoop()
          }
        }
      },
      { threshold: 0 },
    )
    io.observe(root)

    function onVisibility(): void {
      if (document.hidden) stopLoop()
      else if (visible) startLoop()
    }
    document.addEventListener('visibilitychange', onVisibility)

    renderOnce()

    /* ---------- teardown ---------- */
    return () => {
      disposed = true
      rebuildRef.current = null
      cancelClear()
      stopLoop()
      stage.removeEventListener('wheel', onWheel)
      stage.removeEventListener('pointerdown', onStageDown)
      stage.removeEventListener('pointermove', onStageMove)
      stage.removeEventListener('pointerup', onStageUp)
      stage.removeEventListener('pointercancel', onStageUp)
      tipEl?.removeEventListener('pointerenter', onTipEnter)
      tipEl?.removeEventListener('pointerleave', onTipLeave)
      canvas.removeEventListener('pointerdown', onCanvasDown)
      window.removeEventListener('pointermove', onWinMove)
      window.removeEventListener('pointerup', endDrag)
      window.removeEventListener('pointercancel', endDrag)
      window.removeEventListener('keydown', onKeyDown)
      window.removeEventListener('resize', onResize)
      document.removeEventListener('socdesk:enrich-result', onEnrich)
      document.removeEventListener('visibilitychange', onVisibility)
      reducedMq.removeEventListener('change', onReducedChange)
      themeObserver.disconnect()
      offSystemTheme()
      io.disconnect()
      // dispose GL resources
      dots?.geometry.dispose()
      dotMat.dispose()
      pinsPoints.geometry.dispose()
      pinMat.dispose()
      bodyMesh.geometry.dispose()
      bodyMat.dispose()
      occluder.geometry.dispose()
      ;(occluder.material as MeshBasicMaterial).dispose()
      markGeo.dispose()
      markMat.dispose()
      pulse.geometry.dispose()
      pulseMat.dispose()
      arcMesh.geometry.dispose()
      arcMat.dispose()
      arcB.geometry.dispose()
      arcBMat.dispose()
      arcPulseGeo.dispose()
      arcPulseMat.dispose()
      renderer.dispose()
      renderer.forceContextLoss()
    }
  }, [])

  return {
    rootRef,
    stageRef,
    canvasRef,
    tipRef,
    activeCard,
    api: apiRefStable.current,
  }
}
