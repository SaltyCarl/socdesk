import { cx } from '@socdesk/shared/lib/cx'
import { openAndScrollTo } from './useProfileNav'
import type { NavSection } from './useProfileNav'

/**
 * The profile jump-nav — a sticky landmark bar under the app header (56px),
 * orienting the analyst across the decision layer + collapsed reference sections
 * without a 7,000px scroll. The app is HASH-ROUTED (`#g=<slug>`), so these are
 * BUTTONS that scroll+open by id (not `#id` anchors, which would wipe the route);
 * scrollspy sets `aria-current` on the section in view. On mobile it folds into a
 * "Jump to ▾" disclosure so a long collapsed scroll stays clean.
 *
 * Offsets are the shared sticky stack: header `top-0 h-14` (56px) → this bar
 * `top-14 h-11` (→ 100px), matched by every section's `scroll-mt-[6.5rem]`.
 */
export function ProfileNav({ sections, activeId }: { sections: NavSection[]; activeId: string }) {
  if (sections.length <= 1) return null // only Overview — nothing to orient with

  const link = (s: NavSection) => (
    <button
      key={s.id}
      type="button"
      onClick={() => openAndScrollTo(s.id)}
      aria-current={activeId === s.id ? 'true' : undefined}
      className={cx(
        'whitespace-nowrap rounded-md px-2.5 py-1 font-mono text-micro uppercase tracking-label',
        'outline-offset-2 transition-colors duration-150 ease-brand focus-visible:outline-2 focus-visible:outline-accent',
        activeId === s.id ? 'bg-[var(--tint-accent)] text-accent' : 'text-muted hover:text-paper',
      )}
    >
      {s.label}
    </button>
  )

  return (
    <nav aria-label="Profile sections" className="sd-glass sticky top-14 z-30 rounded-md border border-line">
      {/* >= sm: horizontal landmark bar */}
      <div className="hidden h-11 items-center gap-1 overflow-x-auto px-2 sm:flex">
        {sections.map(link)}
      </div>
      {/* mobile: a compact "Jump to" disclosure */}
      <details className="group px-2 py-2 sm:hidden">
        <summary className="flex cursor-pointer list-none select-none items-center gap-1 font-mono text-micro uppercase tracking-label text-muted marker:content-none [&::-webkit-details-marker]:hidden">
          Jump to
          <span aria-hidden="true" className="transition-transform duration-150 ease-brand group-open:rotate-90">
            ▸
          </span>
        </summary>
        <div className="mt-2 flex flex-wrap gap-1">{sections.map(link)}</div>
      </details>
    </nav>
  )
}
