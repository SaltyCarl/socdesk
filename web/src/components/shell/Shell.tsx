import type { ReactNode } from 'react'
import { Topbar, type NavItem } from '../ui'
import { CommandPalette } from '../palette/CommandPalette'
import { useCommandPalette } from '../palette/useCommandPalette'
import type { CommandItem } from '../palette/types'
import { Omnibox } from './Omnibox'
import { MobileNav } from './MobileNav'
import { PageContainer, type ContainerSize } from './PageContainer'

/**
 * Shell — the refined app frame. A superset of the shipped `AppShell`
 * (which cannot host the palette itself): it composes the consumed
 * `Topbar` (with the Omnibox + the mobile hamburger menu wired into its
 * right slot ahead of the theme toggle), a `PageContainer` main column,
 * and the command palette. `MobileNav` only appears below `md`, where
 * Topbar's inline nav links hide.
 *
 * Drop-in swap: in App.tsx, replace `<AppShell items={items}>…</AppShell>`
 * with `<Shell items={items}>…</Shell>` — the `items` prop is identical.
 */

export interface ShellProps {
  items?: NavItem[]
  children: ReactNode
  /** Extra `view` rows to register in the palette (e.g. sibling routes). */
  views?: CommandItem[]
  containerSize?: ContainerSize
}

export function Shell({ items, children, views, containerSize = 'default' }: ShellProps) {
  const palette = useCommandPalette()

  return (
    <div className="flex min-h-svh flex-col bg-ink text-paper">
      <Topbar
        items={items}
        right={
          <>
            <Omnibox onOpen={palette.open} />
            <MobileNav items={items} />
          </>
        }
      />
      <PageContainer size={containerSize} className="flex-1">
        {children}
      </PageContainer>
      <SiteFooter />
      <CommandPalette open={palette.isOpen} onClose={palette.close} views={views} />
    </div>
  )
}

const FOOTER_LINK_CLS =
  'font-mono text-micro font-semibold uppercase tracking-label text-faint outline-offset-2 transition-colors duration-150 ease-brand hover:text-paper focus-visible:outline-2 focus-visible:outline-accent'

/**
 * Recessive site footer — a single hairline over a quiet attribution line and
 * the disclosure links (the app's legal / transparency surface). Kept in the
 * shell so it appears on every route.
 */
function SiteFooter() {
  return (
    <footer className="border-t border-line">
      <div className="mx-auto flex w-full max-w-6xl flex-col gap-2 px-5 py-6 sm:flex-row sm:items-center sm:justify-between">
        <span className="text-xs text-faint">
          SOCDesk — a non-commercial personal portfolio project.
        </span>
        <nav className="flex items-center gap-5">
          <a href="/about" className={FOOTER_LINK_CLS}>
            About
          </a>
          <a href="/privacy" className={FOOTER_LINK_CLS}>
            Privacy
          </a>
        </nav>
      </div>
    </footer>
  )
}
