/**
 * Type surface for the vendored cobe@0.6.3 (`./cobe.js`).
 *
 * Why 0.6.3 and not the installed cobe@2: cobe@2's marker/anchor system does
 * `document.createElement('style')` + `styleEl.textContent = ':root{…}'` on
 * create and every `update()`. A script-injected inline <style> is blocked
 * under our inviolate `style-src 'self'` (no 'unsafe-inline') and fires
 * `securitypolicyviolation`. 0.6.3 (the exact MIT file the live site already
 * ships) drives frames through an `onRender(state)` callback and injects no
 * <style> — it is CSP-proven in production. See useGlobe.ts.
 *
 * API shape (matches the vendored esm.sh build): `createGlobe` returns the
 * ENGINE (the `,h` comma-operator return), which self-schedules a single rAF
 * loop and exposes `toggle` / `render` / `destroy` / `resize`. `onRender` is
 * handed a fresh mutable state object each frame; assign the recognised keys
 * (phi, theta, width, height, and the colour/appearance uniforms) and cobe
 * copies them into its uniforms — including the colour keys, so a theme
 * recolour needs no rebuild.
 */

/** Per-frame state the caller mutates inside `onRender`. Colours are [r,g,b] 0..1. */
export interface CobeState {
  phi?: number
  theta?: number
  width?: number
  height?: number
  baseColor?: number[]
  markerColor?: number[]
  glowColor?: number[]
  dark?: number
  diffuse?: number
  mapBrightness?: number
  mapBaseBrightness?: number
  opacity?: number
  scale?: number
  offset?: [number, number]
  markers?: Array<{ location: [number, number]; size: number }>
}

export interface CobeOptions {
  devicePixelRatio?: number
  /** cobe@0.6.3 backing-store size: pass clientWidth * devicePixelRatio. */
  width: number
  height: number
  phi: number
  theta: number
  dark: number
  diffuse: number
  mapSamples: number
  mapBrightness: number
  mapBaseBrightness?: number
  baseColor: number[]
  markerColor: number[]
  glowColor: number[]
  opacity?: number
  markers: Array<{ location: [number, number]; size: number }>
  onRender: (state: CobeState) => void
  context?: Record<string, unknown>
}

/** The returned engine handle. */
export interface Globe {
  /** Pause (false) / resume (true) the self-scheduled render loop. */
  toggle(run?: boolean): void
  /** Draw a single frame now (reschedules only while the loop is running). */
  render(): void
  /** Stop the loop and free GL resources. */
  destroy(): void
  resize(): void
}

export default function createGlobe(
  canvas: HTMLCanvasElement,
  opts: CobeOptions,
): Globe
