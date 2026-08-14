// palette.ts — the escalation card's canvas palette + font stacks.
//
// A <canvas> cannot read CSS custom properties, so the cool-slate DARK / cool
// off-white LIGHT + periwinkle system has to be materialised here as literal
// hexes. These are copied from shared/tokens.css — THE source of truth — and
// must never drift from the tokens (or from the on-screen React card, which
// paints from the vars). Each value is annotated with the token it mirrors so a
// reviewer can diff them by eye; palette.test.ts pins them so a drift back to
// the legacy warm palette fails CI.
//
// Retuned 2026-08-14 from the legacy warm-espresso ground to the cool-slate
// palette the web app moved to (tokens.css §A/§B/§C). The accent + verdict hues
// were already periwinkle/red-amber-green; this pass brings the neutral ground,
// surfaces, lines and text into the slate scheme so the copy-card PNG matches
// the app it is generated in.
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

/** Hexes mirror shared/tokens.css §A (light) + §B/§C (dark). Slate scheme. */
export const THEMES: Record<CanvasTheme, Palette> = {
  light: {
    bg: '#EDF1F6', // --ink
    panel: '#F8FAFC', // --panel
    panel2: '#E8EDF3', // --panel-soft
    field: '#FFFFFF', // --field
    border: '#D6DCE5', // --line
    border2: '#C2CAD6', // --line-bright
    border3: '#A2AEBE', // --line-strong
    text: '#131A24', // --paper
    textDim: '#55606F', // --muted
    textFaint: '#8996A6', // --faint
    accent: '#4A4FD0', // --accent
    accent2: '#6E74E0', // --accent-dim
    vRed: '#D33A50', // --red
    vAmber: '#B4740C', // --gold
    vGreen: '#1E9E57', // --green
  },
  dark: {
    bg: '#0E121A', // --ink
    panel: '#161C27', // --panel
    panel2: '#212936', // --panel-soft
    field: '#0A0E15', // --field
    border: '#29323F', // --line
    border2: '#3A4557', // --line-bright
    border3: '#4E5C72', // --line-strong
    text: '#E9EDF4', // --paper
    textDim: '#98A3B4', // --muted
    textFaint: '#697486', // --faint
    accent: '#7C8AFF', // --accent
    accent2: '#ADB6FF', // --accent-dim
    vRed: '#F5566B', // --red
    vAmber: '#F2A81E', // --gold
    vGreen: '#4FC97A', // --green
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
