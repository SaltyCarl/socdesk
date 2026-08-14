/**
 * globe3 — pure helpers for the three.js dot-sphere (no three import here so it
 * stays cheap to reason about). Two jobs:
 *   • buildLandPositions — Fibonacci-sample the sphere, keep the points that
 *     fall on LAND per the SAME equirectangular landmask cobe uses (extracted to
 *     vendor/landmask.ts). Sampled with cobe's exact texture mapping so the
 *     continents land where cobe draws them AND where the unitVec pins sit.
 *   • tierColor3 — verdict tone → [r,g,b] 0..1 (RESERVED: only the scored
 *     landed marker uses this; ambient dots/pins/arcs stay periwinkle).
 *
 * CSP: the landmask is a bundled data: URI (img-src 'self' data:); decoding it
 * on a 2D canvas + getImageData is not eval and needs no worker/loader.
 */

import { LANDMASK_URI } from './vendor/landmask'
import type { Tier } from './pins'

const GOLDEN = Math.PI * (3 - Math.sqrt(5))

/** a full uniform dot-sphere (fallback when the landmask can't be decoded). */
function fallbackSphere(samples: number): Float32Array {
  const out = new Float32Array(samples * 3)
  for (let i = 0; i < samples; i++) {
    const y = 1 - (i / (samples - 1)) * 2
    const rad = Math.sqrt(Math.max(0, 1 - y * y))
    const th = GOLDEN * i
    out[i * 3] = Math.cos(th) * rad
    out[i * 3 + 1] = y
    out[i * 3 + 2] = Math.sin(th) * rad
  }
  return out
}

/**
 * Fibonacci-sample `samples` directions; keep those whose landmask red channel
 * is bright. The lat/lon → uv mapping mirrors cobe's fragment shader exactly
 * (n = asin(y); lon = ±acos(-x/cos n); u = lon·0.5/π; v = -(n/π + 0.5)) so the
 * dots align with cobe's continents and with unitVec()-placed pins.
 */
export function buildLandPositions(samples = 60000): Promise<Float32Array> {
  return new Promise((resolve) => {
    const img = new Image()
    img.onload = () => {
      const w = img.naturalWidth || 256
      const h = img.naturalHeight || 128
      const cnv = document.createElement('canvas')
      cnv.width = w
      cnv.height = h
      const ctx = cnv.getContext('2d')
      if (!ctx) return resolve(fallbackSphere(samples))
      ctx.drawImage(img, 0, 0)
      let data: Uint8ClampedArray
      try {
        data = ctx.getImageData(0, 0, w, h).data
      } catch {
        return resolve(fallbackSphere(samples))
      }
      const pts: number[] = []
      for (let i = 0; i < samples; i++) {
        const y = 1 - (i / (samples - 1)) * 2
        const rad = Math.sqrt(Math.max(0, 1 - y * y))
        const th = GOLDEN * i
        const x = Math.cos(th) * rad
        const z = Math.sin(th) * rad
        const lat = Math.asin(Math.max(-1, Math.min(1, y)))
        const cl = Math.cos(lat) || 1e-4
        let lon = Math.acos(Math.max(-1, Math.min(1, -x / cl)))
        if (z < 0) lon = -lon
        let u = (lon * 0.5) / Math.PI
        let v = -(lat / Math.PI + 0.5)
        u -= Math.floor(u)
        v -= Math.floor(v)
        const px = Math.min(w - 1, Math.max(0, (u * w) | 0))
        const py = Math.min(h - 1, Math.max(0, (v * h) | 0))
        if (data[(py * w + px) * 4] > 90) pts.push(x, y, z)
      }
      resolve(pts.length ? new Float32Array(pts) : fallbackSphere(samples))
    }
    img.onerror = () => resolve(fallbackSphere(samples))
    img.src = LANDMASK_URI
  })
}

/** verdict tone → [r,g,b] 0..1, theme-aware (mirrors index.css token hexes).
 *  RESERVED for the scored landed endpoint only. crit→red, susp→amber,
 *  low→green (a benign scored result reads green). */
export function tierColor3(tier: Tier, dark: boolean): [number, number, number] {
  if (dark) {
    if (tier === 'crit') return [0.96, 0.34, 0.42] // #F5566B
    if (tier === 'susp') return [0.95, 0.66, 0.12] // #F2A81E
    return [0.31, 0.79, 0.48] // #4FC97A
  }
  if (tier === 'crit') return [0.83, 0.23, 0.31] // #D33A50
  if (tier === 'susp') return [0.71, 0.45, 0.05] // #B4740C
  return [0.12, 0.62, 0.34] // #1E9E57
}
