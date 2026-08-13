import { useEffect, useState, type ReactElement } from 'react'
import { cx } from '../../lib/cx'
import {
  applyThemePref,
  getThemePref,
  onSystemThemeChange,
  type ThemePref,
} from '../../lib/theme'

/**
 * ThemeToggle — a Light / Dark / System segmented control. Writing
 * <html data-theme> (or clearing it for System) is all it does; the CSS
 * tri-state owns the paint. The active segment gets a quiet periwinkle
 * (product) tint — accent, never a verdict.
 */

const OPTIONS: { value: ThemePref; label: string; icon: ReactElement }[] = [
  { value: 'light', label: 'Light', icon: <SunIcon /> },
  { value: 'dark', label: 'Dark', icon: <MoonIcon /> },
  { value: 'system', label: 'System', icon: <MonitorIcon /> },
]

export function ThemeToggle({ className }: { className?: string }) {
  const [pref, setPref] = useState<ThemePref>('system')

  // Read the persisted pref on mount (client-only).
  useEffect(() => setPref(getThemePref()), [])
  // Re-render on OS changes so a 'system' selection stays honest.
  useEffect(() => onSystemThemeChange(() => setPref((p) => p)), [])

  const choose = (value: ThemePref) => {
    applyThemePref(value)
    setPref(value)
  }

  return (
    <div
      role="group"
      aria-label="Theme"
      className={cx(
        'inline-flex items-center gap-0.5 rounded-md border border-line bg-panel p-0.5',
        className,
      )}
    >
      {OPTIONS.map((opt) => {
        const active = pref === opt.value
        return (
          <button
            key={opt.value}
            type="button"
            title={opt.label}
            aria-label={opt.label}
            aria-pressed={active}
            onClick={() => choose(opt.value)}
            className={cx(
              'inline-flex size-7 items-center justify-center rounded-sm transition-colors duration-150 ease-brand',
              'outline-offset-2 focus-visible:outline-2 focus-visible:outline-accent',
              active
                ? 'bg-[var(--tint-accent)] text-accent'
                : 'text-muted hover:text-paper',
            )}
          >
            {opt.icon}
          </button>
        )
      })}
    </div>
  )
}

/* -- icons (inline SVG, currentColor — no inline style) -- */

function SunIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <circle cx="12" cy="12" r="4.2" stroke="currentColor" strokeWidth="1.6" />
      <path
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinecap="round"
        d="M12 2.5v2.4M12 19.1v2.4M4.6 4.6l1.7 1.7M17.7 17.7l1.7 1.7M2.5 12h2.4M19.1 12h2.4M4.6 19.4l1.7-1.7M17.7 6.3l1.7-1.7"
      />
    </svg>
  )
}

function MoonIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinejoin="round"
        d="M20 14.2A8.2 8.2 0 1 1 9.8 4a6.4 6.4 0 0 0 10.2 10.2Z"
      />
    </svg>
  )
}

function MonitorIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <rect x="3" y="4.5" width="18" height="12" rx="1.6" stroke="currentColor" strokeWidth="1.6" />
      <path stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" d="M8.5 20.5h7M12 16.5v4" />
    </svg>
  )
}
