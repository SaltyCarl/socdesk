// palette.ts — the escalation card's canvas palette + font stacks.
//
// A <canvas> cannot read CSS custom properties, so the warm-espresso / warm-
// paper + periwinkle system has to be materialised here as literal hexes. These
// are copied from web/src/index.css — THE source of truth — and must never drift
// from the tokens (or from the on-screen React card, which paints from the vars).
// A tiny drift test would be cheap later; for now the values are annotated with
// the token they mirror so a reviewer can diff them by eye.
//
// Pure data + colour maths. No React, no DOM writes (detectTheme only reads).

export type CanvasTheme = 'light' | 'dark'

/** The materialised palette for one theme (mirrors the index.css var block). */
export interface Palette {
  bg: string
  panel: string
  panel2: string
  field: string
  border: string
  border2: string
  border3: string
  text: string
  textDim: string
  textFaint: string
  accent: string
  accent2: string
  vRed: string
  vAmber: string
  vGreen: string
}

/** Hexes mirror index.css `:root`/`[data-theme]` (light) + the dark block. */
export const THEMES: Record<CanvasTheme, Palette> = {
  light: {
    bg: '#F2E6D0', // --ink
    panel: '#FBF4E6', // --panel
    panel2: '#F0E2C9', // --panel-soft
    field: '#FDF8EE', // --field
    border: '#DFC9A2', // --line
    border2: '#CDB183', // --line-bright
    border3: '#B8975F', // --line-strong
    text: '#2C2013', // --paper
    textDim: '#6A5638', // --muted
    textFaint: '#98835D', // --faint
    accent: '#4A4FD0', // --accent
    accent2: '#6E74E0', // --accent-dim
    vRed: '#D33A50', // --red
    vAmber: '#B4740C', // --gold
    vGreen: '#1E9E57', // --green
  },
  dark: {
    bg: '#15100A',
    panel: '#1E1710',
    panel2: '#2A2015',
    field: '#120D07',
    border: '#34281B',
    border2: '#473721',
    border3: '#5E4829',
    text: '#F1E8D8',
    textDim: '#B7A488',
    textFaint: '#877253',
    accent: '#7C8AFF',
    accent2: '#ADB6FF',
    vRed: '#F5566B',
    vAmber: '#F2A81E',
    vGreen: '#4FC97A',
  },
}

/** The active theme: an explicit [data-theme] wins, else the OS preference, else
 *  dark (the product's default look). Same tri-state as index.css. */
export function detectTheme(): CanvasTheme {
  try {
    const t = document.documentElement.dataset.theme
    if (t === 'light' || t === 'dark') return t
    if (window.matchMedia?.('(prefers-color-scheme: light)').matches) return 'light'
  } catch {
    /* non-DOM context — fall through to the default */
  }
  return 'dark'
}

/** The self-hosted brand faces, as canvas font shorthands can name them. */
export const SANS = '"Archivo", "Segoe UI", system-ui, sans-serif'
export const MONO = '"IBM Plex Mono", ui-monospace, "Cascadia Mono", Consolas, monospace'

function hexToRgb(h: string): [number, number, number] {
  const s = h.replace('#', '')
  return [
    parseInt(s.slice(0, 2), 16),
    parseInt(s.slice(2, 4), 16),
    parseInt(s.slice(4, 6), 16),
  ]
}

/** Blend `a` over `b` at weight `t` (t of a). Returns an #rrggbb string — the
 *  canvas equivalent of the CSS `color-mix(in srgb, a t%, b)` the tokens use. */
export function mix(a: string, b: string, t: number): string {
  const A = hexToRgb(a)
  const B = hexToRgb(b)
  const c = A.map((v, i) => Math.round(v * t + B[i] * (1 - t)))
  return '#' + c.map((v) => v.toString(16).padStart(2, '0')).join('')
}
