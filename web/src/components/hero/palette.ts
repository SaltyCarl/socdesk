/**
 * Globe palette — cobe bakes colours as numeric [r,g,b] 0..1 arrays (it can't
 * read CSS custom properties), so the periwinkle/greige treatment is mirrored
 * here from the token hexes in src/index.css (which themselves mirror the live
 * site's RADAR tokens). Keep in sync by hand with the `--accent` / `--ink`
 * families — the JS side has no build-time access to `@theme` values.
 *
 * The halo is KILLED in both themes (glowColor === the page ink) — anti-slop:
 * a matte instrument, no over-bloom.
 */

import type { EffectiveTheme } from '../../lib/theme'

export interface GlobePalette {
  base: [number, number, number]
  marker: [number, number, number]
  glow: [number, number, number]
  dark: number
  mapBrightness: number
  mapBaseBrightness: number
  diffuse: number
  opacity: number
}

export function globePalette(theme: EffectiveTheme): GlobePalette {
  if (theme === 'dark') {
    // DARK — periwinkle dots on an invisible ocean over warm espresso.
    return {
      base: [0.42, 0.46, 0.78], // matte periwinkle land dots
      marker: [0.49, 0.54, 1.0], // --accent #7C8AFF
      glow: [0.08, 0.06, 0.04], // --ink #15100A → kills the halo
      dark: 1,
      mapBrightness: 6.4,
      mapBaseBrightness: 0,
      diffuse: 1.25,
      opacity: 0.95,
    }
  }
  // LIGHT — cobe renders an OPAQUE sphere, so mirror the dark theme's "dots on
  // an invisible ocean" as a WARM GREIGE INSTRUMENT: a low `dark` keeps the
  // body a warm mid-tone; a periwinkle-leaning greige base + brighter markers
  // keep the DOTS reading as the signal; reduced opacity lets it sit as an
  // elegant element on paper. Halo still killed (glow == paper ink).
  return {
    base: [0.51, 0.49, 0.585], // warm greige w/ a periwinkle lean
    marker: [0.3, 0.33, 0.9], // saturated periwinkle markers (~--accent #4A4FD0)
    glow: [0.96, 0.91, 0.83], // --ink #F2E6D0 (paper) → kills the halo
    dark: 0.5,
    mapBrightness: 5.6,
    mapBaseBrightness: 0.3,
    diffuse: 1.3,
    opacity: 0.72,
  }
}
