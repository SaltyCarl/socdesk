/**
 * Globe geometry core — the CSP-safe, framework-agnostic math the three.js hero
 * (useGlobe3) shares with the pure data layer (heroLayers.ts).
 *
 * NO fabricated intel lives here anymore. This module used to carry a mock PINS
 * table (invented "Cobalt Strike C2 beacon" indicators) and a GEO demo fly-to
 * table — both deleted. The hero now plots ONLY real, sourced data (see
 * heroLayers.ts), and the fly-to lands on the live /api/enrich result's real
 * coordinates. What remains is pure geometry:
 *   • unitVec   — lat/lng → model-space unit vector (matches the dot-sphere).
 *   • project   — model-space r → screen px (cobe@2's transform, square canvas).
 *   • flyTargets— bring a point to front-centre (phi/theta for the spring).
 *   • tierInk   — verdict tone → a CSS custom-property expression (reserved for
 *                 the REAL enrich landing; ambient pins stay periwinkle).
 */

export type Tier = 'crit' | 'susp' | 'low'
export type Vec3 = [number, number, number]

/** A minimal fly-to target (the landed marker needs only geometry + tone). */
export interface FlyTarget {
  r: Vec3
  tier: Tier
  sev: number
}

const PI = Math.PI

/** lat/lng → unit model-space vector (matches the dot-sphere's projection:
 *  lat→i rad, lng→s=rad−PI; r = [−cos(i)cos(s), sin(i), cos(i)sin(s)]). */
export function unitVec(lat: number, lng: number): Vec3 {
  const i = (lat * PI) / 180
  const s = (lng * PI) / 180 - PI
  const cl = Math.cos(i)
  return [-cl * Math.cos(s), Math.sin(i), cl * Math.sin(s)]
}

export interface Projected {
  x: number
  y: number
  z: number
}

/**
 * model-space r → screen px, for a SQUARE backing store, scale 1, offset 0.
 * Projects a surface point as
 *   c = cos(phi)·x + sin(phi)·z            (→ ndc x, ÷ aspect = 1 here)
 *   s = sin(phi)sin(theta)·x + cos(theta)·y − cos(phi)sin(theta)·z  (→ ndc y)
 * on a sphere of radius 0.8, so the disc edge lands at |ndc| = 0.8. Depth `z`
 * culls the back face.
 */
export function project(
  r: readonly [number, number, number],
  phi: number,
  theta: number,
  w: number,
  h: number,
  out: Projected,
): void {
  const cp = Math.cos(phi)
  const sp = Math.sin(phi)
  const ct = Math.cos(theta)
  const st = Math.sin(theta)
  const fx = cp * r[0] + sp * r[2]
  const fy = sp * st * r[0] + ct * r[1] - cp * st * r[2]
  const fz = -sp * ct * r[0] + st * r[1] + cp * ct * r[2]
  out.x = ((fx * 0.8 + 1) / 2) * w
  out.y = ((1 - fy * 0.8) / 2) * h
  out.z = fz
}

/** fly-to targets that bring pin.r to front-centre (from `project`). */
export function flyTargets(r: readonly [number, number, number]): {
  phi: number
  theta: number
} {
  const phi = Math.atan2(-r[0], r[2])
  const theta = Math.max(
    -1.05,
    Math.min(1.05, Math.asin(Math.max(-1, Math.min(1, r[1])))),
  )
  return { phi, theta }
}

/** CSS custom-property expression for a tier's ink (verdict tones + neutral).
 *  RESERVED for the REAL enrich landing card — `low`/neutral maps to --muted. */
export function tierInk(tier: Tier): string {
  return tier === 'crit'
    ? 'var(--red)'
    : tier === 'susp'
      ? 'var(--gold)'
      : 'var(--muted)'
}
