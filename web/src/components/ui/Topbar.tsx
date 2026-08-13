import type { ReactNode } from 'react'
import { cx } from '@socdesk/shared/lib/cx'
import { SdMonogram } from '@socdesk/shared/ui'
import { ThemeToggle } from './ThemeToggle'

/**
 * Topbar + AppShell — the recessive app frame. The topbar is the shipped
 * glass precedent (backdrop blur under a hairline). Nav is quiet: the
 * active tab carries a periwinkle bottom spine (the site's inset-spine
 * technique) + paper ink; everything else is muted until hovered.
 */

export interface NavItem {
  label: string
  href?: string
  active?: boolean
}

function Wordmark() {
  return (
    <a
      href="/"
      className="group inline-flex items-center gap-2.5 outline-offset-2 focus-visible:outline-2 focus-visible:outline-accent"
    >
      <SdMonogram className="h-6 w-auto text-paper" />
      <span className="font-display text-base font-extrabold tracking-tight text-paper">
        SOCDESK
      </span>
    </a>
  )
}

function Nav({ items }: { items: NavItem[] }) {
  return (
    <nav className="hidden h-full items-stretch md:flex">
      {items.map((item) => (
        <a
          key={item.label}
          href={item.href ?? '#'}
          aria-current={item.active ? 'page' : undefined}
          className={cx(
            'inline-flex h-full items-center px-3.5 font-sans text-base transition-colors duration-150 ease-brand',
            'outline-offset-[-2px] focus-visible:outline-2 focus-visible:outline-accent',
            item.active
              ? 'text-paper shadow-[inset_0_-2px_0_var(--accent)]'
              : 'text-muted hover:text-paper',
          )}
        >
          {item.label}
        </a>
      ))}
    </nav>
  )
}

export function Topbar({
  items = [],
  right,
  className,
}: {
  items?: NavItem[]
  right?: ReactNode
  className?: string
}) {
  return (
    <header
      className={cx(
        'sd-glass sticky top-0 z-40 h-14 border-b border-line',
        className,
      )}
    >
      <div className="mx-auto flex h-full max-w-6xl items-center gap-6 px-5">
        <Wordmark />
        <Nav items={items} />
        <div className="ml-auto flex items-center gap-3">
          {right}
          <ThemeToggle />
        </div>
      </div>
    </header>
  )
}

export function AppShell({
  items,
  right,
  children,
}: {
  items?: NavItem[]
  right?: ReactNode
  children: ReactNode
}) {
  return (
    <div className="min-h-svh bg-ink text-paper">
      <Topbar items={items} right={right} />
      <main className="mx-auto max-w-6xl px-5 py-10">{children}</main>
    </div>
  )
}
