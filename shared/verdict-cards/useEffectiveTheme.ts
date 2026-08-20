// useEffectiveTheme — the effective ('light'|'dark') theme, reactive to the
// toggle (a data-theme mutation) and to the OS preference while pref==='system'.
//
// Threaded into the escalation-card components so the deterministic copy-card
// PNG re-renders in the app's CURRENT theme rather than a stale mount-time
// sample. Extracted from Lookup.tsx so BOTH the /lookup triptych and the landing
// inline card share one implementation.

import { useEffect, useState } from 'react'
import { systemPrefersDark, onSystemThemeChange, type EffectiveTheme } from '@socdesk/shared/lib/theme'

export type { EffectiveTheme }

/** The theme actually PAINTED right now: the explicit <html data-theme> when set
 *  (exactly what the CSS reads), else the OS preference. Reading the attribute —
 *  not the stored preference (resolveTheme) — keeps the copy-card canvas in step
 *  with the visible theme even when the attribute is set independently of
 *  localStorage (e.g. a ?theme= deep link). */
function paintedTheme(): EffectiveTheme {
  const attr = document.documentElement.getAttribute('data-theme')
  if (attr === 'light' || attr === 'dark') return attr
  return systemPrefersDark() ? 'dark' : 'light'
}

export function useEffectiveTheme(): EffectiveTheme {
  const [theme, setTheme] = useState<EffectiveTheme>(paintedTheme)
  useEffect(() => {
    const update = () => setTheme(paintedTheme())
    const obs = new MutationObserver(update)
    obs.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] })
    const off = onSystemThemeChange(update)
    return () => {
      obs.disconnect()
      off()
    }
  }, [])
  return theme
}
