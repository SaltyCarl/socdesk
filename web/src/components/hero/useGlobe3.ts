/**
 * useGlobe3 — the three.js hero globe (A/B candidate alongside the cobe globe).
 *
 * WHY three.js: cobe renders an OPAQUE sphere, so light mode is a persistent
 * dark-orb-on-cream bug. Real material control fixes it: the sphere BODY is a
 * transparent ShaderMaterial (near-invisible on espresso, warm-greige on cream)
 * with a view-anchored fresnel RIM; a colour-write-off depth OCCLUDER gives the
 * dots + arcs FREE back-hemisphere occlusion via the depth buffer.
 *
 * Ported from the cobe build: critically-damped spring FLY-TO (stepSpring drives
 * globe rotation + a real camera dolly), sparse great-circle ARCS (periwinkle;
 * verdict tone ONLY on the scored endpoint), verdict landed marker that rises +
 * pulses once, pointer PARALLAX, and the same gating (IntersectionObserver +
 * visibilitychange + DPR cap + reduced-motion static frame + dispose on unmount).
 *
 * Rotation matches cobe EXACTLY: the globe group's matrix is cobe's M(phi,theta)
 * so flyTargets()/unitVec() carry over and the dots align with the landmask.
 *
 * CSP: three core + hand-wired GLSL (compile ≠ eval). No R3F/drei, no loaders/
 * workers, no external assets (landmask is a bundled data: URI). Tooltip stays
 * the DOM .sdh-tip, re-driven by Vector3.project(camera). Every DOM write is
 * setProperty/classList — zero style= attributes in JSX.
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
  Line,
  Mesh,
  SphereGeometry,
  RingGeometry,
  ShaderMaterial,
  LineBasicMaterial,
  MeshBasicMaterial,
  Raycaster,
  Vector2,
  Vector3,
  Matrix4,
  DoubleSide,
} from 'three'
import { resolveTheme, onSystemThemeChange } from '@socdesk/shared/lib/theme'
import { buildLandPositions, tierColor3 } from './globe3'
import {
  PINS,
  GEO,
  unitVec,
  flyTargets,
  ambientDiameter,
  slerp,
  arcAngle,
  ARC_NODES,
  HOME_VEC,
  tierInk,
  type Tier,
  type Pin,
  type FlyTarget,
  type Vec3,
} from './pins'

/* -- rotation / camera / spring tunables (ported) -- */
const THETA = 0.18
const OMEGA = 7.2
const ZMIN = 1.0
const ZMAX = 1.6
const FLY_ZOOM = 1.42
// camera distance — sphere ≈ 0.78 of the canvas so it never clips the frame at
// rest. Zoom is a compositor CSS scale on the stage (cobe's --globe-grow), NOT a
// camera dolly, so the sphere renders at a stable size and can't hit the canvas
// rectangle at any zoom; the growth bleeds off the right edge (like cobe).
const BASE_Z = 3.3
const FOV = 45
const DPR_CAP = 2
const OVERSAMPLE = 1.5 // backing-store oversample → crisp under the CSS zoom
const PAR_MAX = 0.06 // pointer parallax (radians)

/* -- arc tunables (ported: SPARSE, slow cadence) -- */
const ARC_SAMPLES = 40
const MAX_AMBIENT = 4
const SCORED = MAX_AMBIENT
const AMBIENT_SPAWN_MIN = 4.6
const AMBIENT_SPAWN_JITTER = 3.0

/* -- look knobs -- */
const DOT_SIZE = 5.6 // base dot point-size — fuller continents (denser sample too)
const LIGHT_DIR: [number, number, number] = [-0.5, 0.55, 0.78] // view-space key light

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
  hovering: boolean
  cursorNDC: { x: number; y: number } | null
  activeId: number
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
    dragging: false, lastX: 0, hovering: false, cursorNDC: null, activeId: -1,
    flying: false, flyBackMode: false, spinSuspended: false, landedShown: false,
    landed: null, parPhi: 0, parTheta: 0,
    flyPhi: newSpring(), flyTheta: newSpring(), flyGz: newSpring(),
  }
}

interface Arc3 {
  active: boolean
  scored: boolean
  a: Vec3
  b: Vec3
  omega: number
  sinOmega: number
  alt: number
  progress: number
  phase: 0 | 1 | 2
  age: number
  peak: number
  drawDur: number
  holdDur: number
  fadeDur: number
}
function newArc3(): Arc3 {
  return {
    active: false, scored: false, a: [0, 0, 1], b: [0, 0, 1],
    omega: 0, sinOmega: 0, alt: 0, progress: 0, phase: 0, age: 0,
    peak: 0.5, drawDur: 1.3, holdDur: 1.0, fadeDur: 1.1,
  }
}

/* -- per-theme look (mirrors index.css token families; numeric for three) -- */
interface Theme3 {
  dot: [number, number, number]
  dotShade: [number, number, number]
  pin: [number, number, number]
  body: [number, number, number]
  bodyAlpha: number
  rim: [number, number, number]
  rimStrength: number
  rimPower: number
}
function theme3(dark: boolean): Theme3 {
  return dark
    ? {
        // DARK — bright periwinkle land on near-invisible espresso body; a brighter
        // shaded floor so continents stay legible across the whole sphere.
        dot: [0.57, 0.62, 1.0],
        dotShade: [0.34, 0.37, 0.66],
        pin: [0.62, 0.66, 1.0],
        body: [0.1, 0.09, 0.13],
        bodyAlpha: 0.04,
        rim: [0.49, 0.54, 1.0],
        rimStrength: 0.5,
        rimPower: 3.0,
      }
    : {
        // ⭐ light mode is the whole point: greige body + periwinkle dots, NOT a dark orb.
        // Land dots deepened/saturated to pop hard on the greige, and bodyAlpha cut so
        // the ocean recedes and the continents DEFINE the sphere (less "flat ball").
        dot: [0.16, 0.18, 0.72],
        dotShade: [0.29, 0.3, 0.5],
        pin: [0.17, 0.19, 0.7],
        body: [0.6, 0.585, 0.66],
        bodyAlpha: 0.24,
        rim: [0.29, 0.31, 0.82],
        rimStrength: 0.34,
        rimPower: 3.2,
      }
}

/* -- live-enrich result → fly target (dormant on the static tier) -- */
interface EnrichSource {
  kind?: string
  facts?: Array<[string, string]>
}
interface EnrichResult {
  tone?: string
  flagged?: number
  consulted?: number
  sources?: EnrichSource[]
}
function geoFromResult(result: EnrichResult | undefined): FlyTarget | null {
  if (!result || !Array.isArray(result.sources)) return null
  const ctx = result.sources.find((s) => s && s.kind === 'context')
  if (!ctx || !Array.isArray(ctx.facts)) return null
  const co = ctx.facts.find((f) => Array.isArray(f) && /coordinates/i.test(f[0]))
  if (!co) return null
  const m = String(co[1]).match(/^\s*(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)\s*$/)
  if (!m) return null
  const tier: Tier =
    result.tone === 'red' ? 'crit' : result.tone === 'amber' ? 'susp' : 'low'
  const ratio = result.consulted ? (result.flagged ?? 0) / result.consulted : 0
  return { r: unitVec(parseFloat(m[1]), parseFloat(m[2])), tier, sev: Math.round(ratio * 100) }
}

/* -- GLSL (ShaderMaterial injects projection/modelView/normalMatrix + position/normal) -- */
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
  flyToLatLng(lat: number, lng: number, opts?: { tier?: Tier; sev?: number }): void
  flyToIndicator(raw: string): boolean
  flyBack(): void
}
export interface UseGlobe3Result {
  rootRef: RefObject<HTMLElement | null>
  stageRef: RefObject<HTMLDivElement | null>
  canvasRef: RefObject<HTMLCanvasElement | null>
  tipRef: RefObject<HTMLDivElement | null>
  activePin: Pin | null
  api: GlobeApi
}

export function useGlobe3(apiRef?: RefObject<GlobeApi | null>): UseGlobe3Result {
  const rootRef = useRef<HTMLElement | null>(null)
  const stageRef = useRef<HTMLDivElement | null>(null)
  const canvasRef = useRef<HTMLCanvasElement | null>(null)
  const tipRef = useRef<HTMLDivElement | null>(null)
  const [activePin, setActivePin] = useState<Pin | null>(null)

  const apiHolder = useRef<GlobeApi>({
    flyToLatLng: () => {},
    flyToIndicator: () => false,
    flyBack: () => {},
  })
  const apiRefStable = useRef<GlobeApi>({
    flyToLatLng: (...a) => apiHolder.current.flyToLatLng(...a),
    flyToIndicator: (...a) => apiHolder.current.flyToIndicator(...a),
    flyBack: (...a) => apiHolder.current.flyBack(...a),
  })

  useEffect(() => {
    if (apiRef) apiRef.current = apiRefStable.current
    return () => {
      if (apiRef) apiRef.current = null
    }
  }, [apiRef])

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
    const pr = Math.min(dpr * OVERSAMPLE, 2.4) // oversample so the CSS zoom stays crisp
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

    // depth-only occluder → dots/arcs behind the sphere are culled for FREE
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

    /* ---------- pins (Points; periwinkle; Raycaster hit-test) ---------- */
    const pinPos = new Float32Array(PINS.length * 3)
    const pinSize = new Float32Array(PINS.length)
    for (let i = 0; i < PINS.length; i++) {
      const r = PINS[i].r
      pinPos[i * 3] = r[0] * 1.012
      pinPos[i * 3 + 1] = r[1] * 1.012
      pinPos[i * 3 + 2] = r[2] * 1.012
      pinSize[i] = ambientDiameter(PINS[i].sev)
    }
    const pinGeo = new BufferGeometry()
    pinGeo.setAttribute('position', new Float32BufferAttribute(pinPos, 3))
    pinGeo.setAttribute('aSize', new Float32BufferAttribute(pinSize, 1))
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
    const pinsPoints = new Points(pinGeo, pinMat)
    pinsPoints.frustumCulled = false
    globeGroup.add(pinsPoints)
    const pinPosAttr = pinGeo.getAttribute('position')

    /* ---------- arcs (Lines; occlusion FREE via depth) ---------- */
    const arcs: Arc3[] = Array.from({ length: MAX_AMBIENT + 1 }, newArc3)
    const arcLines: Line[] = []
    for (let i = 0; i < arcs.length; i++) {
      const g = new BufferGeometry()
      g.setAttribute('position', new Float32BufferAttribute(new Float32Array(ARC_SAMPLES * 3), 3))
      g.setDrawRange(0, 0)
      const mat = new LineBasicMaterial({
        color: 0x7c8aff,
        transparent: true,
        opacity: 0,
        depthWrite: false,
      })
      const line = new Line(g, mat)
      line.frustumCulled = false
      globeGroup.add(line)
      arcLines.push(line)
    }
    let nextSpawn = 0
    let lastLandedVec: Vec3 | null = null

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

    /* ---------- rotation matrix = cobe's M(phi,theta) ---------- */
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

    /* ---------- tooltip (DOM, projected) ---------- */
    const _v = new Vector3()
    const _pw = new Vector3()
    const raycaster = new Raycaster()
    if (raycaster.params.Points) raycaster.params.Points.threshold = 0.03
    const _ndc = new Vector2()

    function pinWorld(idx: number, out: Vector3): void {
      out.fromBufferAttribute(pinPosAttr, idx).applyMatrix4(pinsPoints.matrixWorld)
    }
    function positionTip(idx: number): void {
      const tip = tipRef.current
      if (!tip) return
      pinWorld(idx, _pw)
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
    function setActive(id: number): void {
      if (id !== anim.activeId) {
        anim.activeId = id
        if (id >= 0) {
          const tip = tipRef.current
          tip?.style.setProperty('--tip-accent', tierInk(PINS[id].tier))
          tip?.style.setProperty('--sev', PINS[id].sev + '%')
          setActivePin(PINS[id])
        } else {
          setActivePin(null)
        }
      }
      if (anim.activeId >= 0) positionTip(anim.activeId)
    }
    function hitTest(): void {
      if (!anim.cursorNDC || anim.dragging || anim.flying) {
        setActive(-1)
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
      setActive(best)
    }

    /* ---------- landed beat (rise + pulse once) ---------- */
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
      markPoint.geometry.getAttribute('position').setXYZ(0, r[0] * 1.012, r[1] * 1.012, r[2] * 1.012)
      markPoint.geometry.getAttribute('position').needsUpdate = true
      markPoint.visible = true
      // pulse ring flat on the surface at the target
      pulse.position.set(r[0] * 1.008, r[1] * 1.008, r[2] * 1.008)
      pulse.quaternion.setFromUnitVectors(new Vector3(0, 0, 1), new Vector3(r[0], r[1], r[2]).normalize())
      pulse.visible = !reduced()
    }
    function clearLanded(): void {
      landAnim.active = false
      anim.landedShown = false
      anim.landed = null
      markPoint.visible = false
      pulse.visible = false
      markMat.uniforms.uAlpha.value = 0
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

    /* ---------- arcs: build / step / spawn / draw-on ---------- */
    function buildArcGeometry(arc: Arc3, line: Line): void {
      const attr = line.geometry.getAttribute('position')
      const av: Vec3 = [0, 0, 1]
      for (let k = 0; k < ARC_SAMPLES; k++) {
        const t = k / (ARC_SAMPLES - 1)
        slerp(arc.a, arc.b, t, arc.omega, arc.sinOmega, av)
        const lift = 1 + arc.alt * Math.sin(Math.PI * t)
        attr.setXYZ(k, av[0] * lift, av[1] * lift, av[2] * lift)
      }
      attr.needsUpdate = true
      line.geometry.setDrawRange(0, 0)
    }
    function spawnAmbientArc(): boolean {
      let slot = -1
      for (let i = 0; i < MAX_AMBIENT; i++)
        if (!arcs[i].active) {
          slot = i
          break
        }
      if (slot < 0) return false
      const n = ARC_NODES.length
      if (n < 2) return false
      let a: Vec3 | null = null
      let b: Vec3 | null = null
      let omega = 0
      for (let tries = 0; tries < 8; tries++) {
        const ia = (Math.random() * n) | 0
        let ib = (Math.random() * n) | 0
        if (ib === ia) ib = (ib + 1) % n
        const ang = arcAngle(ARC_NODES[ia], ARC_NODES[ib])
        if (ang > 0.45 && ang < 2.5) {
          a = ARC_NODES[ia]
          b = ARC_NODES[ib]
          omega = ang
          break
        }
      }
      if (!a || !b) return false
      const arc = arcs[slot]
      arc.active = true
      arc.scored = false
      arc.a = a
      arc.b = b
      arc.omega = omega
      arc.sinOmega = Math.sin(omega)
      arc.alt = 0.06 + Math.random() * 0.06
      arc.progress = 0
      arc.phase = 0
      arc.age = 0
      arc.peak = 0.5
      arc.drawDur = 1.2 + Math.random() * 0.5
      arc.holdDur = 0.9 + Math.random() * 0.6
      arc.fadeDur = 1.0 + Math.random() * 0.5
      buildArcGeometry(arc, arcLines[slot])
      return true
    }
    function maybeSpawnAmbient(now: number): void {
      if (anim.flying || now < nextSpawn) return
      let alive = 0
      let drawing = false
      for (let i = 0; i < MAX_AMBIENT; i++) {
        if (arcs[i].active) {
          alive++
          if (arcs[i].phase === 0) drawing = true
        }
      }
      if (alive >= MAX_AMBIENT || drawing) return
      const ok = spawnAmbientArc()
      nextSpawn = now + (ok ? AMBIENT_SPAWN_MIN + Math.random() * AMBIENT_SPAWN_JITTER : 1.5) * 1000
    }
    function stepArcs(dt: number): void {
      for (let i = 0; i < arcs.length; i++) {
        const arc = arcs[i]
        const line = arcLines[i]
        const mat = line.material as LineBasicMaterial
        if (!arc.active) {
          mat.opacity = 0
          continue
        }
        arc.age += dt
        if (arc.phase === 0) {
          arc.progress = Math.min(1, arc.age / arc.drawDur)
          if (arc.age >= arc.drawDur) {
            arc.phase = 1
            arc.age = 0
            arc.progress = 1
          }
        } else if (arc.phase === 1) {
          if (arc.age >= arc.holdDur) {
            arc.phase = 2
            arc.age = 0
          }
        }
        let op = arc.peak
        if (arc.phase === 2) {
          const k = Math.min(1, arc.age / arc.fadeDur)
          op = arc.peak * (1 - k)
          if (k >= 1) {
            arc.active = false
            op = 0
          }
        }
        const count = Math.max(0, Math.floor(arc.progress * ARC_SAMPLES))
        line.geometry.setDrawRange(0, count)
        const flyDim = !arc.scored && anim.flying ? 0.1 : 1
        mat.opacity = op * flyDim
      }
    }

    /* ---------- render one composed frame ---------- */
    // Zoom is a compositor CSS scale on the stage (cobe's --globe-grow), NOT a
    // camera dolly — the camera stays fixed at BASE_Z so the sphere renders at a
    // stable ~0.78 of the canvas and never clips the canvas rectangle; the scaled
    // stage bleeds off the right edge (overflow-visible), like the cobe hero.
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
          // fire the beat as the point swings near front-centre
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
        else if (anim.activeId >= 0) ts = 0
        else if (anim.hovering) ts = 0.3
        anim.spinFactor += (ts - anim.spinFactor) * (1 - Math.exp(-dt * 7))
        if (!anim.dragging) anim.targetPhi += 0.0035 * (dt * 60) * anim.spinFactor
        anim.phi += (anim.targetPhi - anim.phi) * (1 - Math.exp(-dt * 6.5))
        if (!anim.landed) anim.theta += (THETA - anim.theta) * (1 - Math.exp(-dt * 6.5))
        if (Math.abs(anim.gzTarget - anim.gz) > 4e-4) anim.gz += (anim.gzTarget - anim.gz) * (1 - Math.exp(-dt * 9))
        else anim.gz = anim.gzTarget
      }

      // pointer parallax — off during drag/fly and while inspecting a pin
      let ptX = 0
      let ptY = 0
      if (anim.hovering && anim.cursorNDC && !anim.dragging && !anim.flying && anim.activeId < 0) {
        ptX = anim.cursorNDC.x * 0.5
        ptY = anim.cursorNDC.y * 0.5
      }
      const kPar = 1 - Math.exp(-dt * 5)
      anim.parPhi += (ptX * PAR_MAX - anim.parPhi) * kPar
      anim.parTheta += (ptY * PAR_MAX - anim.parTheta) * kPar

      stepArcs(dt)
      maybeSpawnAmbient(now)
      stepLanded(dt)
      composeAndRender()
      hitTest()

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
      nextSpawn = performance.now() + 1800
      raf = requestAnimationFrame(frame)
    }
    function stopLoop(): void {
      running = false
      if (raf) cancelAnimationFrame(raf)
      raf = 0
    }

    /* ---------- fly-to (ported spring physics) ---------- */
    function flyToTarget(tt: FlyTarget): void {
      setActive(-1)
      const { phi: phiT0, theta: thetaT } = flyTargets(tt.r)
      let phiT = phiT0
      while (phiT - anim.phi > Math.PI) phiT -= 2 * Math.PI
      while (anim.phi - phiT > Math.PI) phiT += 2 * Math.PI
      anim.landed = { r: tt.r, tier: tt.tier, sev: tt.sev }
      anim.landedShown = false

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
      // scored incoming beam — periwinkle; verdict only on the endpoint disc
      {
        const src: Vec3 = lastLandedVec ?? HOME_VEC
        const tvec: Vec3 = [tt.r[0], tt.r[1], tt.r[2]]
        const sc = arcs[SCORED]
        sc.active = true
        sc.scored = true
        sc.a = src
        sc.b = tvec
        sc.omega = arcAngle(src, tvec)
        sc.sinOmega = Math.sin(sc.omega)
        sc.alt = 0.3
        sc.progress = 0
        sc.phase = 0
        sc.age = 0
        sc.peak = 0.9
        sc.drawDur = 0.9
        sc.holdDur = 0.6
        sc.fadeDur = 0.8
        buildArcGeometry(sc, arcLines[SCORED])
        lastLandedVec = tvec
      }
      anim.flying = true
      anim.flyBackMode = false
      anim.spinSuspended = true
      startLoop()
    }
    function flyBack(): void {
      if (!anim.flying && !anim.landed && !anim.landedShown) return
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
    function flyToIndicator(raw: string): boolean {
      const v = String(raw || '').trim()
      if (!v) return false
      const rec = GEO[v]
      if (rec) {
        flyToTarget(rec)
        return true
      }
      return false
    }
    function flyToLatLng(lat: number, lng: number, opts: { tier?: Tier; sev?: number } = {}): void {
      if (!Number.isFinite(lat) || !Number.isFinite(lng)) return
      flyToTarget({
        r: unitVec(lat, lng),
        tier: opts.tier ?? 'crit',
        sev: Number.isFinite(opts.sev) ? (opts.sev as number) : 70,
      })
    }
    apiHolder.current = { flyToLatLng, flyToIndicator, flyBack }

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
        setActive(-1)
        renderOnce()
      }
    })

    function onCanvasDown(e: PointerEvent): void {
      if (reduced()) return
      anim.dragging = true
      anim.lastX = e.clientX
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
      if (e.key === 'Escape') flyBack()
    }
    window.addEventListener('keydown', onKeyDown)

    function onEnrich(e: Event): void {
      try {
        const gg = geoFromResult((e as CustomEvent).detail as EnrichResult)
        if (gg) flyToTarget(gg)
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
      stopLoop()
      stage.removeEventListener('wheel', onWheel)
      stage.removeEventListener('pointerdown', onStageDown)
      stage.removeEventListener('pointermove', onStageMove)
      stage.removeEventListener('pointerup', onStageUp)
      stage.removeEventListener('pointercancel', onStageUp)
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
      pinGeo.dispose()
      pinMat.dispose()
      bodyMesh.geometry.dispose()
      bodyMat.dispose()
      occluder.geometry.dispose()
      ;(occluder.material as MeshBasicMaterial).dispose()
      markGeo.dispose()
      markMat.dispose()
      pulse.geometry.dispose()
      pulseMat.dispose()
      for (const line of arcLines) {
        line.geometry.dispose()
        ;(line.material as LineBasicMaterial).dispose()
      }
      renderer.dispose()
      renderer.forceContextLoss()
    }
  }, [])

  return {
    rootRef,
    stageRef,
    canvasRef,
    tipRef,
    activePin,
    api: apiRefStable.current,
  }
}
