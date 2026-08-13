import type { ReactNode } from 'react'
import { Topbar, type NavItem } from '../ui'
import { CommandPalette } from '../palette/CommandPalette'
import { useCommandPalette } from '../palette/useCommandPalette'
import type { CommandItem } from '../palette/types'
import { Omnibox } from './Omnibox'
import { PageContainer, type ContainerSize } from './PageContainer'

/**
 * Shell — the refined app frame. A superset of the shipped `AppShell`
 * (which cannot host the palette itself): it composes the consumed
 * `Topbar` (with the Omnibox wired into its right slot ahead of the theme
 * toggle), a `PageContainer` main column, and the command palette.
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
    <div className="min-h-svh bg-ink text-paper">
      <Topbar items={items} right={<Omnibox onOpen={palette.open} />} />
      <PageContainer size={containerSize}>{children}</PageContainer>
      <CommandPalette open={palette.isOpen} onClose={palette.close} views={views} />
    </div>
  )
}
