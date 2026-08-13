import { useEffect, useRef, useState, type ReactNode } from 'react'
import { cx } from '../lib/cx'
import { usePressScale } from '../lib/motion'
import { FeedRoute } from './FeedRoute'
import { VulnsRoute } from './VulnsRoute'
import { ActorsRoute } from './ActorsRoute'
import { HealthRoute } from './HealthRoute'
import { SourcesRoute } from './SourcesRoute'
import { ToolbeltRoute } from './ToolbeltRoute'

/**
 * The data desk — a single route that hosts the five data surfaces + the
 * toolbelt stub behind an in-content tab bar (a secondary nav, distinct from
 * the app topbar). It exists so the whole deliverable is demoable and
 * deep-linkable behind one route (#feed, #vulnerabilities, …) even before the
 * shell wires each surface to a top-level nav item.
 *
 * Only the active tab mounts, so the heavy catalog (cves.json) is fetched
 * lazily — opening the desk on the feed never pulls the 5 MB CVE file.
 *
 * Motion split: entrances/reveals are CSS scroll-driven (`.sd-reveal` on the
 * rows/cards inside each view — gated + static fallback); the tab press here is
 * the WAAPI interaction (Motion.dev spring scale, no inline style).
 */

const TABS = [
  { key: 'feed', label: 'Feed' },
  { key: 'vulnerabilities', label: 'Vulnerabilities' },
  { key: 'actors', label: 'Actors' },
  { key: 'health', label: 'Health' },
  { key: 'sources', label: 'Sources' },
  { key: 'toolbelt', label: 'Toolbelt' },
] as const

const KEYS = TABS.map((t) => t.key) as readonly string[]
const FALLBACK = 'feed'

function currentHash(): string {
  const h = window.location.hash.replace(/^#/, '')
  return KEYS.includes(h) ? h : FALLBACK
}

function TabButton({
  active,
  onClick,
  children,
}: {
  active: boolean
  onClick: () => void
  children: ReactNode
}) {
  const ref = useRef<HTMLButtonElement>(null)
  usePressScale(ref, { down: 0.96 })
  return (
    <button
      ref={ref}
      type="button"
      onClick={onClick}
      aria-current={active ? 'page' : undefined}
      className={cx(
        'inline-flex h-10 shrink-0 items-center px-3.5 font-sans text-base transition-colors duration-150 ease-brand',
        'outline-offset-[-2px] focus-visible:outline-2 focus-visible:outline-accent',
        active
          ? 'text-paper shadow-[inset_0_-2px_0_var(--accent)]'
          : 'text-muted hover:text-paper',
      )}
    >
      {children}
    </button>
  )
}

export function DataDeskRoute() {
  const [tab, setTab] = useState<string>(currentHash)

  useEffect(() => {
    const onHash = () => setTab(currentHash())
    window.addEventListener('hashchange', onHash)
    return () => window.removeEventListener('hashchange', onHash)
  }, [])

  const select = (key: string) => {
    if (currentHash() !== key) window.history.pushState(null, '', `#${key}`)
    setTab(key)
  }

  return (
    <div className="flex flex-col gap-8">
      <nav
        aria-label="Data desk"
        className="-mx-1 flex gap-1 overflow-x-auto border-b border-line"
      >
        {TABS.map((t) => (
          <TabButton key={t.key} active={tab === t.key} onClick={() => select(t.key)}>
            {t.label}
          </TabButton>
        ))}
      </nav>

      <div>
        {tab === 'feed' && <FeedRoute />}
        {tab === 'vulnerabilities' && <VulnsRoute />}
        {tab === 'actors' && <ActorsRoute />}
        {tab === 'health' && <HealthRoute />}
        {tab === 'sources' && <SourcesRoute />}
        {tab === 'toolbelt' && <ToolbeltRoute />}
      </div>
    </div>
  )
}
