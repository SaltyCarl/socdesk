import { useCallback, useEffect, useState } from 'react'

/**
 * Owns palette open/closed state and installs the global summon shortcuts:
 *   • ⌘K / Ctrl+K — toggle from anywhere.
 *   • `/`          — open, but only when the user is NOT typing in a field
 *                    (so slashes in inputs pass through untouched).
 *
 * Hook-only module → no component export → react-refresh-clean.
 */

function isEditableTarget(target: EventTarget | null): boolean {
  const el = target as HTMLElement | null
  if (!el) return false
  const tag = el.tagName
  return tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || el.isContentEditable
}

export interface CommandPaletteController {
  isOpen: boolean
  open: () => void
  close: () => void
}

export function useCommandPalette(): CommandPaletteController {
  const [isOpen, setIsOpen] = useState(false)
  const open = useCallback(() => setIsOpen(true), [])
  const close = useCallback(() => setIsOpen(false), [])
  const toggle = useCallback(() => setIsOpen((v) => !v), [])

  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && (e.key === 'k' || e.key === 'K')) {
        e.preventDefault()
        toggle()
        return
      }
      if (
        e.key === '/' &&
        !e.metaKey &&
        !e.ctrlKey &&
        !e.altKey &&
        !isEditableTarget(e.target)
      ) {
        e.preventDefault()
        open()
      }
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [open, toggle])

  return { isOpen, open, close }
}
