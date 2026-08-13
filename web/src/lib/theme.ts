/**
 * Theme control — the tri-state pattern shared with the site:
 *   'light' | 'dark'  → explicit, written to <html data-theme>
 *   'system'          → no attribute; CSS media query + bare :root decide
 *
 * The CSS in index.css owns the actual paint; this module only manages
 * the <html data-theme> attribute + persistence, and reports the
 * effective theme for JS-side consumers (e.g. a future cobe globe that
 * bakes colours at build time).
 */

export type ThemePref = 'light' | 'dark' | 'system'
export type EffectiveTheme = 'light' | 'dark'

const STORAGE_KEY = 'socdesk-theme'

/** The user's stored preference, or 'system' when unset/blocked. */
export function getThemePref(): ThemePref {
  try {
    const v = localStorage.getItem(STORAGE_KEY)
    if (v === 'light' || v === 'dark' || v === 'system') return v
  } catch {
    /* storage blocked (private mode / no DOM) — fall through */
  }
  return 'system'
}

/** Does the OS currently prefer dark? (false when unknown, matching the
 *  CSS default which paints LIGHT on a bare :root with no signal.) */
export function systemPrefersDark(): boolean {
  try {
    return window.matchMedia('(prefers-color-scheme: dark)').matches
  } catch {
    return false
  }
}

/** Resolve a preference to the theme that will actually paint. */
export function resolveTheme(pref: ThemePref = getThemePref()): EffectiveTheme {
  if (pref === 'light' || pref === 'dark') return pref
  return systemPrefersDark() ? 'dark' : 'light'
}

/** Apply a preference: set/clear <html data-theme> and persist it. */
export function applyThemePref(pref: ThemePref): void {
  const root = document.documentElement
  if (pref === 'system') root.removeAttribute('data-theme')
  else root.setAttribute('data-theme', pref)
  try {
    localStorage.setItem(STORAGE_KEY, pref)
  } catch {
    /* persistence is best-effort */
  }
}

/** Call once, as early as possible, to avoid a theme flash. */
export function initTheme(): void {
  applyThemePref(getThemePref())
  // Deterministic screenshots / deep-links: ?theme=dark|light|system wins.
  try {
    const q = new URLSearchParams(window.location.search).get('theme')
    if (q === 'light' || q === 'dark' || q === 'system') applyThemePref(q)
  } catch {
    /* no-op */
  }
}

/** Subscribe to OS theme changes (only meaningful while pref==='system').
 *  Returns an unsubscribe fn. */
export function onSystemThemeChange(cb: () => void): () => void {
  try {
    const mq = window.matchMedia('(prefers-color-scheme: dark)')
    mq.addEventListener('change', cb)
    return () => mq.removeEventListener('change', cb)
  } catch {
    return () => {}
  }
}
