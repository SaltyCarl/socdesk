import { useRef } from 'react'
import { cx } from '../../lib/cx'
import { usePressScale } from '../../lib/motion'

/**
 * Omnibox — the topbar lookup entry. A search-field-shaped button that
 * summons the command palette (also bound to ⌘K / `/`). It only opens the
 * palette; the real input lives inside the dialog. Full field on ≥sm,
 * icon-only on mobile.
 */

function isMac(): boolean {
  try {
    return /mac|iphone|ipad/i.test(navigator.platform || navigator.userAgent)
  } catch {
    return false
  }
}

export function Omnibox({
  onOpen,
  className,
}: {
  onOpen: () => void
  className?: string
}) {
  const ref = useRef<HTMLButtonElement>(null)
  usePressScale(ref)
  const mod = isMac() ? '⌘' : 'Ctrl'

  return (
    <button
      ref={ref}
      type="button"
      onClick={onOpen}
      aria-keyshortcuts="Meta+K Control+K"
      aria-label="Open command palette"
      className={cx(
        'group inline-flex h-9 items-center gap-2 rounded-md border border-line bg-field px-2.5',
        'text-muted transition-colors duration-150 ease-brand',
        'hover:border-line-bright hover:text-paper',
        'outline-offset-2 focus-visible:outline-2 focus-visible:outline-accent',
        'sm:w-64',
        className,
      )}
    >
      <SearchGlyph />
      <span className="hidden font-sans text-base text-muted group-hover:text-paper sm:inline">
        Lookup an indicator…
      </span>
      <span className="ml-auto hidden items-center gap-0.5 sm:inline-flex" aria-hidden="true">
        <kbd className="rounded-sm border border-line bg-panel px-1.5 py-0.5 font-mono text-micro font-semibold text-faint">
          {mod}
        </kbd>
        <kbd className="rounded-sm border border-line bg-panel px-1.5 py-0.5 font-mono text-micro font-semibold text-faint">
          K
        </kbd>
      </span>
    </button>
  )
}

function SearchGlyph() {
  return (
    <svg
      width="15"
      height="15"
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden="true"
      className="shrink-0"
    >
      <circle cx="11" cy="11" r="6.5" stroke="currentColor" strokeWidth="1.7" />
      <path
        d="M16 16l4.5 4.5"
        stroke="currentColor"
        strokeWidth="1.7"
        strokeLinecap="round"
      />
    </svg>
  )
}
