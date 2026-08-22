// contrast — the automatable half of the Part E eye-test. WCAG 2.x relative-
// luminance + contrast-ratio, plus the dark/light token hexes (mirrored from
// shared/tokens.css) and which text tokens are "readable" (meaning-bearing).
// The visual eye-test (rendering each surface/state) is the documented live
// dogfood pass. Do NOT retune the shared --faint token — fix the USAGE.

function channel(c: number): number {
  const s = c / 255
  return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4)
}
function luminance(hex: string): number {
  const n = hex.replace('#', '')
  const r = parseInt(n.slice(0, 2), 16)
  const g = parseInt(n.slice(2, 4), 16)
  const b = parseInt(n.slice(4, 6), 16)
  return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b)
}
export function contrastRatio(a: string, b: string): number {
  const la = luminance(a)
  const lb = luminance(b)
  const hi = Math.max(la, lb)
  const lo = Math.min(la, lb)
  return (hi + 0.05) / (lo + 0.05)
}

// Mirrored from shared/tokens.css (dark: lines ~120-130; light: ~87-100).
export const DARK_TOKENS = {
  ink: '#0E121A', panel: '#161C27', panelSoft: '#212936', raised: '#1B2230', field: '#0A0E15',
  paper: '#E9EDF4', muted: '#98A3B4', faint: '#697486', accent: '#7C8AFF',
} as const
export const LIGHT_TOKENS = {
  ink: '#EDF1F6', panel: '#F8FAFC', panelSoft: '#E8EDF3', raised: '#FFFFFF', field: '#FFFFFF',
  paper: '#131A24', muted: '#55606F', faint: '#8996A6', accent: '#4A4FD0',
} as const

export const SURFACES = ['ink', 'panel', 'panelSoft', 'raised', 'field'] as const
export const READABLE_TEXT = ['muted', 'paper', 'accent'] as const
export const AA_NORMAL = 4.5
