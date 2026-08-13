import type { ReactNode } from 'react'
import { cx } from '../../lib/cx'

/**
 * PageContainer — the shared content column. Centered, gutter-padded, with
 * three width registers (the default mirrors the shipped AppShell's
 * max-w-6xl so this is a drop-in). Renders the page `<main>` landmark.
 */

const SIZE = {
  narrow: 'max-w-3xl',
  default: 'max-w-6xl',
  wide: 'max-w-7xl',
} as const

export type ContainerSize = keyof typeof SIZE

export function PageContainer({
  children,
  size = 'default',
  className,
}: {
  children: ReactNode
  size?: ContainerSize
  className?: string
}) {
  return (
    <main className={cx('mx-auto w-full px-5 py-10', SIZE[size], className)}>
      {children}
    </main>
  )
}
