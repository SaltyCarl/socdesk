/**
 * useGlobe — the cobe lifecycle + interaction engine for the hero.
 *
 * Seated on the VENDORED cobe@0.6.3 (./vendor/cobe.js — the CSP-proven MIT file
 * the live site already ships), NOT the installed cobe@2. cobe@2's marker system
 * injects a <style> element on every update, which fires securitypolicyviolation
 * under our inviolate `style-src 'self'`; 0.6.3 injects none. See vendor/cobe.d.ts.
 *
 * 0.6.3 model: `createGlobe` returns the ENGINE, which self-schedules a single
 * rAF loop and calls our `onRender(state)` each frame — we run the physics and
 * assign phi/theta/width/height + the colour uniforms (0.6.3's uniform map
 * includes colours, so a theme recolour needs no destroy/rebuild). `toggle()`
 * pauses/resumes the loop; `render()` draws one frame off the loop; `destroy()`
 * stops + frees. DPR: 0.6.3's backing store is clientWidth × devicePixelRatio,
 * so width/height are passed pre-multiplied and kept in sync in onRender.
 *
 * CSP: every per-frame write goes through `el.style.setProperty` / `classList`
 * (never a `style=` attribute) — the sanctioned strict-CSP pattern. JSX carries
 * zero inline styles.
 *
 * GATING (perf): the loop runs only while the hero INTERSECTS the viewport
 * (IntersectionObserver), the tab is VISIBLE (visibilitychange), and reduced
 * motion is OFF. Off-screen/hidden → toggle(false) (pause, not destroy — built
 * once, freed on unmount). Reduced motion → a single static frame; fly-to/zoom snap.
 */

import { useEffect, useRef, useState } from 'react'
import type { RefObject } from 'react'
import createGlobe from './vendor/cobe'
import type { CobeState, CobeOptions, Globe } from './vendor/cobe'
import { resolveTheme, onSystemThemeChange } from '../../lib/theme'
import { globePalette, type GlobePalette } from './palette'
import {
  PINS,
  GEO,
  unitVec,
  project,
  flyTargets,
  ambientDiameter,
  landedDiameter,
  tierInk,
  slerp,
  arcAngle,
  ARC_NODES,
  HOME_VEC,
  type Projected,
  type Tier,
  type Pin,
  type FlyTarget,
  type Vec3,
} from './pins'

/* -- tunables (mirrored from the vanilla globe) -- */
const THETA = 0.18
const OMEGA = 7.2 // ~0.8s critically-damped fly settle
const ZMIN = 1.0
const ZMAX = 1.6
const FLY_ZOOM = 1.42
const SS = 1.2 // backing-store oversample (crisp compositor zoom)
const DPR_CAP = 2
const SIDE_CAP = 1200 // bound the backing store per side

/* -- attack-arc tunables (MOVE 1) — SPARSE, slow cadence (anti-firehose) -- */
const ARC_SAMPLES = 32 // slerp samples per arc
const ARC_ZCUT = 0.02 // occlusion: hide samples on the back hemisphere
const MAX_AMBIENT = 4 // ≤4 ambient arcs alive at once
const SCORED = MAX_AMBIENT // pool index of the single scored fly-to beam
const AMBIENT_SPAWN_MIN = 4.6 // seconds between ambient spawns (+ jitter)
const AMBIENT_SPAWN_JITTER = 3.0
/* -- pointer parallax (MOVE 4) -- */
const PAR_MAX = 0.06 // radians (~3.4°) max cursor-ward tilt

/* -- critically-damped spring (hand-rolled, on our own loop) -- */
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
  gzApplied: number
  spinFactor: number
  lastT: number
  dragging: boolean
  lastX: number
  hovering: boolean
  cursor: { x: number; y: number } | null
  activeId: number
  flying: boolean
  flyBackMode: boolean
  spinSuspended: boolean
  landedShown: boolean
  landed: FlyTarget | null
  flyPhi: Spring
  flyTheta: Spring
  flyGz: Spring
}
function newAnim(): Anim {
  return {
    phi: 0, targetPhi: 0, theta: THETA,
    gz: 1, gzTarget: 1, gzApplied: -1,
    spinFactor: 1, lastT: 0,
    dragging: false, lastX: 0,
    hovering: false, cursor: null, activeId: -1,
    flying: false, flyBackMode: false, spinSuspended: false, landedShown: false,
    landed: null,
    flyPhi: newSpring(), flyTheta: newSpring(), flyGz: newSpring(),
  }
}

/* -- attack arc (MOVE 1). Endpoints are unit vectors; each frame we slerp
   source→target, lift the mid-arc off the sphere (alt·sin(πt)), project with
   the SAME project() the pins use, and z-occlude the back hemisphere. Draw-on
   is a normalized stroke-dashoffset. Lifecycle: draw → hold → fade. -- */
interface Arc {
  active: boolean
  scored: boolean
  a: Vec3
  b: Vec3
  omega: number
  sinOmega: number
  alt: number
  progress: number // 0..1 draw-on
  phase: 0 | 1 | 2 // draw / hold / fade
  age: number // seconds in the current phase
  opacity: number
  peak: number
  drawDur: number
  holdDur: number
  fadeDur: number
}
function newArc(): Arc {
  return {
    active: false, scored: false,
    a: [0, 0, 1], b: [0, 0, 1], omega: 0, sinOmega: 0, alt: 0,
    progress: 0, phase: 0, age: 0, opacity: 0, peak: 0.5,
    drawDur: 1.3, holdDur: 1.0, fadeDur: 1.1,
  }
}

/* -- live-enrich result shape (dormant on the static tier) -- */
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

export interface GlobeApi {
  /** live path — plot real coordinates (enrich result). */
  flyToLatLng(lat: number, lng: number, opts?: { tier?: Tier; sev?: number }): void
  /** demo path — fly to a known indicator (GEO table). */
  flyToIndicator(raw: string): boolean
  /** return to the ambient spin + drop the landed pin. */
  flyBack(): void
}

export interface UseGlobeResult {
  rootRef: RefObject<HTMLElement | null>
  stageRef: RefObject<HTMLDivElement | null>
  canvasRef: RefObject<HTMLCanvasElement | null>
  pinsRef: RefObject<HTMLDivElement | null>
  landedRef: RefObject<HTMLDivElement | null>
  tipRef: RefObject<HTMLDivElement | null>
  /** the SVG overlay holding the attack-arc <path> pool (inside the stage). */
  arcsRef: RefObject<SVGSVGElement | null>
  /** the currently-hovered pin (drives the React-rendered tooltip content). */
  activePin: Pin | null
  api: GlobeApi
}

/**
 * @param apiRef optional caller ref to receive the imperative fly-to API.
 */
export function useGlobe(apiRef?: RefObject<GlobeApi | null>): UseGlobeResult {
  const rootRef = useRef<HTMLElement | null>(null)
  const stageRef = useRef<HTMLDivElement | null>(null)
  const canvasRef = useRef<HTMLCanvasElement | null>(null)
  const pinsRef = useRef<HTMLDivElement | null>(null)
  const landedRef = useRef<HTMLDivElement | null>(null)
  const tipRef = useRef<HTMLDivElement | null>(null)
  const arcsRef = useRef<SVGSVGElement | null>(null)

  const [activePin, setActivePin] = useState<Pin | null>(null)

  // stable API wrapper — delegates to the live impls installed by the effect.
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

  // publish the API to an optional caller ref.
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

    const anim = newAnim()
    const paletteRef: { current: GlobePalette } = {
      current: globePalette(resolveTheme()),
    }
    const proj: Projected[] = PINS.map(() => ({ x: -1, y: -1, z: -1 }))
    const _o: Projected = { x: 0, y: 0, z: 0 }

    // arc pool (MOVE 1): [0..MAX_AMBIENT-1] ambient + [SCORED] the fly-to beam
    const arcs: Arc[] = Array.from({ length: MAX_AMBIENT + 1 }, newArc)
    const _oa: Projected = { x: 0, y: 0, z: 0 } // arc projection scratch
    const _av: Vec3 = [0, 0, 1] // slerp scratch
    const _lv: Vec3 = [0, 0, 1] // lifted-point scratch
    let nextSpawn = 0 // ambient cadence clock (set on build)
    let lastLandedVec: Vec3 | null = null // scored-beam origin = prior landing

    // pointer parallax (MOVE 4): damped micro-offset added to phi/theta at render
    let parPhi = 0
    let parTheta = 0

    let globe: Globe | null = null
    let running = false
    let cobeDpr = 1
    let visible = false

    const reducedMq = window.matchMedia('(prefers-reduced-motion: reduce)')
    const reduced = () => reducedMq.matches

    /* -- size the ambient pins once (px diameter from severity) -- */
    const pinEls = () => (pinsRef.current?.children ?? []) as HTMLCollection
    for (let i = 0; i < PINS.length; i++) {
      const el = pinEls()[i] as HTMLElement | undefined
      el?.style.setProperty('--d', ambientDiameter(PINS[i].sev).toFixed(1) + 'px')
    }

    /* ---------- zoom (compositor scale on the stage) ---------- */
    function applyGrow(): void {
      stage!.style.setProperty('--globe-grow', anim.gz.toFixed(4))
      anim.gzApplied = anim.gz
    }
    function stepZoom(dt: number): void {
      if (reduced()) anim.gz = anim.gzTarget
      else if (Math.abs(anim.gzTarget - anim.gz) > 4e-4)
        anim.gz += (anim.gzTarget - anim.gz) * (1 - Math.exp(-dt * 9))
      else anim.gz = anim.gzTarget
      if (Math.abs(anim.gz - anim.gzApplied) > 4e-4) applyGrow()
    }
    function nudgeZoom(delta: number): void {
      anim.gzTarget = Math.max(ZMIN, Math.min(ZMAX, anim.gzTarget + delta))
      if (reduced()) {
        anim.gz = anim.gzTarget
        applyGrow()
        renderOnce()
      }
    }

    /* ---------- projection: ambient pins ---------- */
    function projectPins(phi: number, theta: number): void {
      const w = canvas!.clientWidth
      const h = canvas!.clientHeight
      if (!w) return
      const dim = anim.flying ? 0.1 : 1
      const els = pinEls()
      for (let i = 0; i < PINS.length; i++) {
        project(PINS[i].r, phi, theta, w, h, _o)
        proj[i].x = _o.x
        proj[i].y = _o.y
        proj[i].z = _o.z
        const el = els[i] as HTMLElement | undefined
        if (!el) continue
        if (_o.z > 0.02) {
          const s = 0.82 + _o.z * 0.18
          el.style.setProperty(
            'transform',
            `translate3d(${_o.x.toFixed(1)}px,${_o.y.toFixed(1)}px,0) scale(${s.toFixed(3)})`,
          )
          el.style.setProperty('opacity', ((0.42 + _o.z * 0.58) * dim).toFixed(3))
        } else {
          el.style.setProperty('opacity', '0')
        }
      }
    }

    /* ---------- projection: landed fly-to pin ---------- */
    let landedDepth = -1
    function projectLanded(phi: number, theta: number): void {
      const el = landedRef.current
      const landed = anim.landed
      if (!el || !landed) return
      project(landed.r, phi, theta, canvas!.clientWidth, canvas!.clientHeight, _o)
      if (_o.z > -0.02) {
        const s = 0.9 + Math.max(0, _o.z) * 0.1
        el.style.setProperty(
          'transform',
          `translate3d(${_o.x.toFixed(1)}px,${_o.y.toFixed(1)}px,0) scale(${s.toFixed(3)})`,
        )
      }
      // stash depth for the fly-to beat timing
      landedDepth = _o.z
    }

    /* ---------- great-circle attack arcs (MOVE 1) ---------- */
    const arcEls = () => (arcsRef.current?.children ?? []) as HTMLCollection

    /** advance every live arc's draw → hold → fade lifecycle. */
    function stepArcs(dt: number): void {
      for (let i = 0; i < arcs.length; i++) {
        const arc = arcs[i]
        if (!arc.active) continue
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
        } else {
          const k = Math.min(1, arc.age / arc.fadeDur)
          arc.opacity = arc.peak * (1 - k)
          if (k >= 1) {
            arc.active = false
            arc.opacity = 0
          }
        }
      }
    }

    /** spawn ONE sparse ambient arc between two earned (crit/susp) nodes. */
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
      arc.opacity = 0.5
      arc.drawDur = 1.2 + Math.random() * 0.5
      arc.holdDur = 0.9 + Math.random() * 0.6
      arc.fadeDur = 1.0 + Math.random() * 0.5
      return true
    }

    /** slow cadence: at most one ambient arc *drawing* at a time, ≤MAX alive,
     *  never during the fly-to (the single cinematic beat owns the moment). */
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
      nextSpawn =
        now +
        (ok ? AMBIENT_SPAWN_MIN + Math.random() * AMBIENT_SPAWN_JITTER : 1.5) * 1000
    }

    /** build each arc's <path> d (z-occluded to the front hemisphere) + write
     *  the draw-on (stroke-dashoffset) + opacity — all CSP-safe attribute/CSSOM
     *  writes, never a style= attribute. */
    function renderArcs(phi: number, theta: number): void {
      const els = arcEls()
      for (let i = 0; i < arcs.length; i++) {
        const el = els[i] as SVGPathElement | undefined
        if (!el) continue
        const arc = arcs[i]
        if (!arc.active) {
          el.style.setProperty('opacity', '0')
          continue
        }
        let d = ''
        let pen = false
        for (let k = 0; k < ARC_SAMPLES; k++) {
          const t = k / (ARC_SAMPLES - 1)
          slerp(arc.a, arc.b, t, arc.omega, arc.sinOmega, _av)
          const lift = 1 + arc.alt * Math.sin(Math.PI * t)
          _lv[0] = _av[0] * lift
          _lv[1] = _av[1] * lift
          _lv[2] = _av[2] * lift
          project(_lv, phi, theta, 1000, 1000, _oa)
          if (_oa.z > ARC_ZCUT) {
            // front hemisphere → draw; back → lift the pen (never through earth)
            d += (pen ? 'L' : 'M') + _oa.x.toFixed(1) + ' ' + _oa.y.toFixed(1) + ' '
            pen = true
          } else {
            pen = false
          }
        }
        el.setAttribute('d', d)
        // ambient arcs yield during the fly-to; the scored beam stays bright
        const flyDim = !arc.scored && anim.flying ? 0.1 : 1
        el.style.setProperty('stroke-dashoffset', (1 - arc.progress).toFixed(4))
        el.style.setProperty('opacity', (arc.opacity * flyDim).toFixed(3))
      }
    }

    /* ---------- hover hit-test + tooltip ---------- */
    function positionTip(i: number): void {
      const tip = tipRef.current
      if (!tip || !canvas) return
      const rect = canvas.getBoundingClientRect()
      const sx = rect.left + proj[i].x * (rect.width / canvas.clientWidth)
      const sy = rect.top + proj[i].y * (rect.height / canvas.clientHeight)
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
    function updateActive(): void {
      let best = -1
      let bestD = Infinity
      if (anim.hovering && !anim.dragging && !anim.flying && anim.cursor) {
        for (let i = 0; i < PINS.length; i++) {
          if (proj[i].z <= 0.04) continue
          const dx = proj[i].x - anim.cursor.x
          const dy = proj[i].y - anim.cursor.y
          const dist = Math.hypot(dx, dy)
          const thr = ambientDiameter(PINS[i].sev) / 2 + 9
          if (dist < thr && dist < bestD) {
            bestD = dist
            best = i
          }
        }
      }
      if (best !== anim.activeId) {
        const els = pinEls()
        if (anim.activeId >= 0) (els[anim.activeId] as HTMLElement | undefined)?.classList.remove('is-active')
        anim.activeId = best
        if (best >= 0) {
          ;(els[best] as HTMLElement | undefined)?.classList.add('is-active')
          const tip = tipRef.current
          tip?.style.setProperty('--tip-accent', tierInk(PINS[best].tier))
          tip?.style.setProperty('--sev', PINS[best].sev + '%')
          setActivePin(PINS[best])
        } else {
          setActivePin(null)
        }
      }
      if (anim.activeId >= 0) positionTip(anim.activeId)
    }

    /* ---------- the fly-to landed pin: drop + pulse once ---------- */
    function beat(): void {
      const el = landedRef.current
      if (!el) return
      anim.landedShown = true
      el.classList.add('is-shown')
      void el.offsetWidth // retrigger the one-shot drop + pulse
      el.classList.add('is-dropping', 'is-pulsing')
    }

    /* ---------- cobe 0.6.3 per-frame hook ----------
       cobe owns the single rAF loop and hands us a fresh mutable state object
       each frame: we run the physics, then assign the recognised uniform keys.
       Colours are pushed every frame too (0.6.3's uniform map includes them),
       so a theme recolour needs no destroy/rebuild. `width` is the backing-store
       size (clientWidth × cobeDpr) — 0.6.3's convention (see build()). */
    function onRender(state: CobeState): void {
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
        applyGrow()
        if (!anim.flyBackMode && !anim.landedShown) {
          projectLanded(anim.phi, anim.theta)
          if (anim.landed && landedDepth > 0.82) beat()
        }
        if (settled(anim.flyPhi) && settled(anim.flyTheta) && settled(anim.flyGz, 0.004, 0.05)) {
          anim.flying = false
          if (anim.flyBackMode) {
            anim.flyBackMode = false
            anim.spinSuspended = false
            anim.landed = null
          } else {
            anim.gzTarget = anim.gz
            if (!anim.landedShown) beat()
          }
        }
      } else {
        // ambient — graded 3-state spin (auto-spin gated off under reduced motion)
        let ts = 1
        if (anim.dragging || anim.spinSuspended) ts = 0
        else if (anim.activeId >= 0) ts = 0
        else if (anim.hovering) ts = 0.3
        anim.spinFactor += (ts - anim.spinFactor) * (1 - Math.exp(-dt * 7))
        if (!reduced() && !anim.dragging) anim.targetPhi += 0.0035 * (dt * 60) * anim.spinFactor
        anim.phi += (anim.targetPhi - anim.phi) * (1 - Math.exp(-dt * 6.5))
        if (!anim.landed) anim.theta += (THETA - anim.theta) * (1 - Math.exp(-dt * 6.5))
        stepZoom(dt)
      }

      // pointer parallax (MOVE 4) — subliminal cursor-ward tilt on the ambient
      // globe; off during drag/fly and under reduced motion (damps back to 0).
      let ptX = 0
      let ptY = 0
      if (
        !reduced() &&
        anim.hovering &&
        anim.cursor &&
        !anim.dragging &&
        !anim.flying &&
        anim.activeId < 0 && // hold still while inspecting a pin
        canvas!.clientWidth
      ) {
        ptX = anim.cursor.x / canvas!.clientWidth - 0.5
        ptY = anim.cursor.y / canvas!.clientHeight - 0.5
      }
      const kPar = 1 - Math.exp(-dt * 5)
      parPhi += (ptX * PAR_MAX - parPhi) * kPar
      parTheta += (-ptY * PAR_MAX - parTheta) * kPar
      const rPhi = anim.phi + parPhi
      const rTheta = Math.max(-1.45, Math.min(1.45, anim.theta + parTheta))

      // arcs (MOVE 1) — advance lifecycles + sparse ambient cadence. Gated on
      // !reduced so an off-loop renderOnce() under reduced motion can't spawn or
      // advance arcs (the static honest frame has none; .sdh-arcs is display:none).
      if (!reduced()) {
        stepArcs(dt)
        maybeSpawnAmbient(now)
      }

      const p = paletteRef.current
      const w = canvas!.clientWidth * cobeDpr
      state.phi = rPhi
      state.theta = rTheta
      state.width = w
      state.height = w
      state.baseColor = p.base
      state.markerColor = p.marker
      state.glowColor = p.glow
      state.dark = p.dark
      state.diffuse = p.diffuse
      state.mapBrightness = p.mapBrightness
      state.mapBaseBrightness = p.mapBaseBrightness
      state.opacity = p.opacity

      projectPins(rPhi, rTheta)
      projectLanded(rPhi, rTheta)
      renderArcs(rPhi, rTheta)
      updateActive()
    }

    /** draw a single frame off the loop (reduced-motion / paused paths). */
    function renderOnce(): void {
      if (globe) globe.render()
      else {
        projectPins(anim.phi, anim.theta)
        projectLanded(anim.phi, anim.theta)
        updateActive()
      }
    }

    /* ---------- loop control (cobe self-schedules; we gate via toggle) ---------- */
    function startLoop(): void {
      if (!globe || !visible || document.hidden) return
      if (reduced()) {
        running = false
        renderOnce()
        return
      }
      if (running) return
      running = true
      anim.lastT = 0
      globe.toggle(true)
    }
    function stopLoop(): void {
      running = false
      globe?.toggle(false)
    }

    /* ---------- build / destroy ---------- */
    function build(): void {
      if (globe || !canvas!.clientWidth) return
      const size = canvas!.clientWidth
      const dpr = Math.min(window.devicePixelRatio || 1, DPR_CAP)
      cobeDpr = Math.min(dpr * SS, SIDE_CAP / size)
      const p = paletteRef.current
      const opts: CobeOptions = {
        devicePixelRatio: cobeDpr,
        // cobe@0.6.3 backing store = clientWidth × devicePixelRatio; pass it pre-multiplied
        width: size * cobeDpr,
        height: size * cobeDpr,
        phi: anim.phi,
        theta: anim.theta,
        dark: p.dark,
        diffuse: p.diffuse,
        mapSamples: 22000,
        mapBrightness: p.mapBrightness,
        mapBaseBrightness: p.mapBaseBrightness,
        baseColor: p.base,
        markerColor: p.marker,
        glowColor: p.glow,
        opacity: p.opacity,
        markers: [], // pins are our DOM overlay
        onRender,
      }
      try {
        globe = createGlobe(canvas!, opts)
      } catch {
        globe = null
        return
      }
      // cobe's constructor auto-starts its self-scheduled loop.
      running = true
      nextSpawn = performance.now() + 1800 // let the globe settle before arcs
      requestAnimationFrame(() => canvas!.classList.add('is-ready'))
      if (reduced()) {
        stopLoop()
        renderOnce()
      }
    }
    function destroy(): void {
      stopLoop()
      if (globe) {
        try {
          globe.destroy()
        } catch {
          /* no-op */
        }
        globe = null
      }
    }

    /* ---------- fly-to ---------- */
    function flyToTarget(t: FlyTarget): void {
      // clear any hover tooltip before the fly
      if (anim.activeId >= 0) {
        ;(pinEls()[anim.activeId] as HTMLElement | undefined)?.classList.remove('is-active')
      }
      anim.activeId = -1
      setActivePin(null)
      const { phi: phiT0, theta: thetaT } = flyTargets(t.r)
      let phiT = phiT0
      while (phiT - anim.phi > Math.PI) phiT -= 2 * Math.PI
      while (anim.phi - phiT > Math.PI) phiT += 2 * Math.PI

      anim.landed = { r: t.r, tier: t.tier, sev: t.sev }
      const d = landedDiameter(t.sev)
      const el = landedRef.current
      if (el) {
        el.style.setProperty('--d', d.toFixed(1) + 'px')
        el.style.setProperty('--pin', tierInk(t.tier))
        el.classList.remove('is-shown', 'is-dropping', 'is-pulsing')
      }
      anim.landedShown = false

      if (reduced()) {
        anim.phi = phiT
        anim.targetPhi = phiT
        anim.theta = thetaT
        anim.gz = FLY_ZOOM
        anim.gzTarget = FLY_ZOOM
        applyGrow()
        anim.flying = false
        anim.flyBackMode = false
        anim.spinSuspended = true
        renderOnce()
        beat()
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
      // scored incoming beam (MOVE 1): neutral origin → target. PERIWINKLE only —
      // the verdict tone lives solely on the landed endpoint disc. Draws on over
      // ~the spring settle, rises off the surface at its apex, then fades, leaving
      // the dropped pin. (Reduced motion returns above, so no beam there.)
      {
        const src: Vec3 = lastLandedVec ?? HOME_VEC
        const tvec: Vec3 = [t.r[0], t.r[1], t.r[2]]
        const sc = arcs[SCORED]
        sc.active = true
        sc.scored = true
        sc.a = src
        sc.b = tvec
        sc.omega = arcAngle(src, tvec)
        sc.sinOmega = Math.sin(sc.omega)
        sc.alt = 0.28 // dramatic apex
        sc.progress = 0
        sc.phase = 0
        sc.age = 0
        sc.peak = 0.9
        sc.opacity = 0.9
        sc.drawDur = 0.9 // ~in sync with the critically-damped spring
        sc.holdDur = 0.6
        sc.fadeDur = 0.8
        lastLandedVec = tvec
      }
      anim.flying = true
      anim.flyBackMode = false
      anim.spinSuspended = true
      startLoop()
    }
    function flyBack(): void {
      if (!anim.flying && !anim.landed && !anim.landedShown) return
      landedRef.current?.classList.remove('is-shown', 'is-dropping', 'is-pulsing')
      anim.landedShown = false
      if (reduced()) {
        anim.theta = THETA
        anim.gz = 1
        anim.gzTarget = 1
        applyGrow()
        anim.flying = false
        anim.spinSuspended = false
        anim.landed = null
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

    /* ---------- input: wheel + pinch zoom ---------- */
    function onWheel(e: WheelEvent): void {
      e.preventDefault()
      if (reduced()) {
        nudgeZoom(e.deltaY < 0 ? 0.2 : -0.2)
        return
      }
      if (anim.flying) return
      nudgeZoom(-e.deltaY * 0.0016)
    }
    stage.addEventListener('wheel', onWheel, { passive: false })

    const pointers = new Map<number, { x: number; y: number }>()
    let pinchBase = 0
    const pinchDist = () => {
      const it = [...pointers.values()]
      return Math.hypot(it[0].x - it[1].x, it[0].y - it[1].y)
    }
    function onStagePointerDown(e: PointerEvent): void {
      pointers.set(e.pointerId, { x: e.clientX, y: e.clientY })
      if (pointers.size === 2) pinchBase = pinchDist()
    }
    function onStagePointerMove(e: PointerEvent): void {
      if (pointers.has(e.pointerId)) {
        pointers.set(e.pointerId, { x: e.clientX, y: e.clientY })
        if (pointers.size === 2 && pinchBase > 0) {
          const d = pinchDist()
          nudgeZoom((d - pinchBase) * 0.0022)
          pinchBase = d
        }
      }
      // hover cursor (canvas-local px) for hit-testing
      if (canvas!.clientWidth) {
        const rect = canvas!.getBoundingClientRect()
        anim.cursor = {
          x: ((e.clientX - rect.left) / rect.width) * canvas!.clientWidth,
          y: ((e.clientY - rect.top) / rect.height) * canvas!.clientHeight,
        }
        if (!running) {
          projectPins(anim.phi, anim.theta)
          updateActive()
        }
      }
    }
    function onStagePointerUp(e: PointerEvent): void {
      pointers.delete(e.pointerId)
      if (pointers.size < 2) pinchBase = 0
    }
    stage.addEventListener('pointerdown', onStagePointerDown)
    stage.addEventListener('pointermove', onStagePointerMove, { passive: true })
    stage.addEventListener('pointerup', onStagePointerUp)
    stage.addEventListener('pointercancel', onStagePointerUp)
    stage.addEventListener('pointerenter', () => {
      anim.hovering = true
    })
    stage.addEventListener('pointerleave', () => {
      anim.hovering = false
      anim.cursor = null
      if (!running) updateActive()
    })

    /* ---------- input: drag to rotate (non-reduced only) ---------- */
    function onCanvasPointerDown(e: PointerEvent): void {
      if (reduced()) return
      anim.dragging = true
      anim.lastX = e.clientX
      if (anim.flying && !anim.flyBackMode) anim.flying = false
      stage!.classList.add('is-dragging')
      if (e.pointerId != null) {
        try {
          canvas!.setPointerCapture(e.pointerId)
        } catch {
          /* no-op */
        }
      }
    }
    function onWinPointerMove(e: PointerEvent): void {
      if (!anim.dragging) return
      anim.targetPhi += (e.clientX - anim.lastX) * 0.005
      anim.lastX = e.clientX
    }
    function endDrag(): void {
      anim.dragging = false
      stage!.classList.remove('is-dragging')
    }
    canvas.addEventListener('pointerdown', onCanvasPointerDown)
    window.addEventListener('pointermove', onWinPointerMove, { passive: true })
    window.addEventListener('pointerup', endDrag)
    window.addEventListener('pointercancel', endDrag)

    /* ---------- escape → fly back; scroll hides the tooltip ---------- */
    function onKeyDown(e: KeyboardEvent): void {
      if (e.key === 'Escape') flyBack()
    }
    function onScroll(): void {
      if (anim.activeId >= 0) {
        anim.hovering = false
        anim.cursor = null
      }
    }
    window.addEventListener('keydown', onKeyDown)
    window.addEventListener('scroll', onScroll, { passive: true })

    /* ---------- live enrich geo (dormant on the static tier) ---------- */
    function onEnrich(e: Event): void {
      try {
        const g = geoFromResult((e as CustomEvent).detail as EnrichResult)
        if (g) flyToTarget(g)
      } catch {
        /* no-op */
      }
    }
    document.addEventListener('socdesk:enrich-result', onEnrich)

    /* ---------- theme recolour (no rebuild — cobe@2 update()) ---------- */
    function recolor(): void {
      paletteRef.current = globePalette(resolveTheme())
      if (globe && !running) renderOnce() // looping path picks it up next frame
    }
    const themeObserver = new MutationObserver(recolor)
    themeObserver.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ['data-theme'],
    })
    const offSystemTheme = onSystemThemeChange(() => {
      if (!document.documentElement.getAttribute('data-theme')) recolor()
    })

    /* ---------- reduced-motion changes ---------- */
    function onReducedChange(): void {
      if (reduced()) {
        stopLoop()
        renderOnce()
      } else {
        startLoop()
      }
    }
    reducedMq.addEventListener('change', onReducedChange)

    /* ---------- resize → one-shot refresh when idle; late build if the globe
       couldn't init earlier (e.g. mobile→desktop, canvas was 0-width) ---------- */
    function onResize(): void {
      if (!globe && visible) build()
      else if (!running) renderOnce()
    }
    window.addEventListener('resize', onResize, { passive: true })

    /* ---------- lifecycle gates: intersection + visibility ----------
       NOTE: cobe@2's destroy() leaves the wrapper <div> it inserts around the
       canvas, so destroy/rebuild on every scroll would nest wrappers. Instead we
       build once and PAUSE the loop off-screen (no update() calls = zero ongoing
       cost); the GL context is freed only on unmount. */
    const io = new IntersectionObserver(
      (entries) => {
        for (const en of entries) {
          if (en.isIntersecting) {
            visible = true
            if (!globe) build()
            else startLoop()
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

    /* ---------- teardown ---------- */
    return () => {
      stage.removeEventListener('wheel', onWheel)
      stage.removeEventListener('pointerdown', onStagePointerDown)
      stage.removeEventListener('pointermove', onStagePointerMove)
      stage.removeEventListener('pointerup', onStagePointerUp)
      stage.removeEventListener('pointercancel', onStagePointerUp)
      canvas.removeEventListener('pointerdown', onCanvasPointerDown)
      window.removeEventListener('pointermove', onWinPointerMove)
      window.removeEventListener('pointerup', endDrag)
      window.removeEventListener('pointercancel', endDrag)
      window.removeEventListener('keydown', onKeyDown)
      window.removeEventListener('scroll', onScroll)
      window.removeEventListener('resize', onResize)
      document.removeEventListener('socdesk:enrich-result', onEnrich)
      document.removeEventListener('visibilitychange', onVisibility)
      reducedMq.removeEventListener('change', onReducedChange)
      themeObserver.disconnect()
      offSystemTheme()
      io.disconnect()
      destroy()
    }
  }, [])

  return {
    rootRef,
    stageRef,
    canvasRef,
    pinsRef,
    landedRef,
    tipRef,
    arcsRef,
    activePin,
    api: apiRefStable.current,
  }
}
