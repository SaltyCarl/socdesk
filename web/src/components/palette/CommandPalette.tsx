import {
  useEffect,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent as ReactKeyboardEvent,
  type ReactNode,
} from 'react'
import { animate } from 'motion'
import { cx } from '@socdesk/shared/lib/cx'
import { DUR, EASE, prefersReducedMotion } from '@socdesk/shared/lib/motion'
import { Chip, MicroLabel } from '../ui'
import type { CommandItem, CommandKind } from './types'
import { INDICATOR_LABEL, classifyIndicator } from './classify'
import { fuzzyMatch } from './fuzzy'
import { getRecents } from './recents'
import {
  DEFAULT_ACTIONS,
  DEFAULT_VIEWS,
  navigate,
  runAction,
  submitLookup,
} from './commands'

/**
 * SOCDesk command palette — the T1/T2 lookup entry, reimplementing the
 * cmdk PATTERN in vanilla React (no `cmdk` dependency → CSP-clean, no
 * package.json churn).
 *
 * Anatomy: a native `<dialog>` (top-layer, real focus trap, backdrop) →
 * a combobox input → a fuzzy-filtered listbox grouped into Lookup /
 * Recent indicators / Actions / Views. Enter deep-links `#q=` for
 * indicators, navigates for views, dispatches for actions.
 *
 * Keyboard model — the WAI-ARIA combobox + `aria-activedescendant`
 * pattern, NOT literal DOM roving tabindex: the text input must retain
 * focus so the user can keep typing, so selection "roves" virtually via
 * activedescendant while ↑/↓/Home/End/Enter drive a single logical cursor.
 *
 * Motion: WAAPI (Motion.dev `animate`, same sanctioned path as lib/motion)
 * fades + lifts the panel on open/close; fully skipped under reduced
 * motion. Zero inline styles — Tailwind utilities only.
 */

const LISTBOX_ID = 'sd-command-listbox'

export interface CommandPaletteProps {
  open: boolean
  onClose: () => void
  /** Route map override — defaults to DEFAULT_VIEWS. */
  views?: CommandItem[]
  /** Action set override — defaults to DEFAULT_ACTIONS. */
  actions?: CommandItem[]
  placeholder?: string
}

interface RenderItem {
  item: CommandItem
  ranges: Array<[number, number]>
  index: number
}
interface RenderGroup {
  id: string
  heading: string
  items: RenderItem[]
}

const isIndicator = (kind: CommandKind): boolean =>
  kind === 'lookup' || kind === 'recent'

/** Rank a list against the query; empty query keeps declaration order. */
function rankItems(
  items: CommandItem[],
  q: string,
): Array<{ item: CommandItem; ranges: Array<[number, number]>; score: number }> {
  if (!q) return items.map((item) => ({ item, ranges: [], score: 0 }))
  const out: Array<{
    item: CommandItem
    ranges: Array<[number, number]>
    score: number
  }> = []
  for (const item of items) {
    const labelMatch = fuzzyMatch(q, item.label)
    let best = labelMatch ? labelMatch.score : -Infinity
    if (item.keywords) {
      for (const kw of item.keywords) {
        const km = fuzzyMatch(q, kw)
        if (km && km.score > best) best = km.score
      }
    }
    if (best > -Infinity) {
      out.push({ item, ranges: labelMatch ? labelMatch.ranges : [], score: best })
    }
  }
  out.sort((a, b) => b.score - a.score)
  return out
}

/** Assemble the ordered, indexed groups + a flat cursor list. */
function buildGroups(
  query: string,
  viewItems: CommandItem[],
  actionItems: CommandItem[],
): { groups: RenderGroup[]; flat: CommandItem[] } {
  const q = query.trim()
  const groups: RenderGroup[] = []
  let index = -1

  const pushGroup = (
    id: string,
    heading: string,
    ranked: Array<{ item: CommandItem; ranges: Array<[number, number]> }>,
  ) => {
    if (!ranked.length) return
    groups.push({
      id,
      heading,
      items: ranked.map((r) => {
        index += 1
        return { item: r.item, ranges: r.ranges, index }
      }),
    })
  }

  if (q) {
    const lookup: CommandItem = {
      id: `lookup:${q}`,
      kind: 'lookup',
      label: q,
      indicatorType: classifyIndicator(q),
      hint: 'Look up',
    }
    pushGroup('lookup', 'Lookup', [{ item: lookup, ranges: [] }])
  }

  const recents = getRecents().map<CommandItem>((r) => ({
    id: `recent:${r.value}`,
    kind: 'recent',
    label: r.value,
    indicatorType: r.type,
  }))
  pushGroup('recent', 'Recent indicators', rankItems(recents, q))
  pushGroup('actions', 'Actions', rankItems(actionItems, q))
  pushGroup('views', 'Views', rankItems(viewItems, q))

  const flat = groups.flatMap((g) => g.items.map((ri) => ri.item))
  return { groups, flat }
}

/** Wrap fuzzy-matched spans in accent <mark>s (transparent bg — ink only). */
function highlight(text: string, ranges: Array<[number, number]>): ReactNode {
  if (!ranges.length) return text
  const nodes: ReactNode[] = []
  let last = 0
  ranges.forEach(([start, end], i) => {
    if (start > last) nodes.push(<span key={`p${i}`}>{text.slice(last, start)}</span>)
    nodes.push(
      <mark key={`m${i}`} className="bg-transparent text-accent">
        {text.slice(start, end)}
      </mark>,
    )
    last = end
  })
  if (last < text.length) nodes.push(<span key="tail">{text.slice(last)}</span>)
  return nodes
}

export function CommandPalette({
  open,
  onClose,
  views,
  actions,
  placeholder = 'Search indicators, actions, views…',
}: CommandPaletteProps) {
  const dialogRef = useRef<HTMLDialogElement>(null)
  const panelRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  const [query, setQuery] = useState('')
  const [rawActive, setRawActive] = useState(0)

  const viewItems = views ?? DEFAULT_VIEWS
  const actionItems = actions ?? DEFAULT_ACTIONS

  const { groups, flat } = useMemo(
    () =>
      open
        ? buildGroups(query, viewItems, actionItems)
        : { groups: [] as RenderGroup[], flat: [] as CommandItem[] },
    [open, query, viewItems, actionItems],
  )

  const activeIndex = flat.length ? Math.min(rawActive, flat.length - 1) : 0

  // Open / close the native dialog + WAAPI panel choreography.
  useEffect(() => {
    const dlg = dialogRef.current
    const panel = panelRef.current
    if (!dlg) return

    if (open) {
      if (!dlg.open) {
        try {
          dlg.showModal()
        } catch {
          /* already open (StrictMode double-invoke) */
        }
      }
      setQuery('')
      setRawActive(0)
      requestAnimationFrame(() => inputRef.current?.focus())
      if (panel && !prefersReducedMotion()) {
        animate(
          panel,
          {
            opacity: [0, 1],
            transform: ['translateY(-8px) scale(0.985)', 'translateY(0px) scale(1)'],
          },
          { duration: DUR.base, ease: EASE.brand },
        )
      }
    } else if (dlg.open) {
      if (!panel || prefersReducedMotion()) {
        dlg.close()
      } else {
        const controls = animate(
          panel,
          {
            opacity: [1, 0],
            transform: ['translateY(0px) scale(1)', 'translateY(-6px) scale(0.99)'],
          },
          { duration: DUR.fast, ease: EASE.brandInOut },
        )
        controls.finished
          .then(() => {
            if (dlg.open) dlg.close()
          })
          .catch(() => {
            if (dlg.open) dlg.close()
          })
      }
    }
  }, [open])

  // Keep the active row scrolled into view as the cursor moves.
  useEffect(() => {
    if (!open) return
    document.getElementById(`sd-opt-${activeIndex}`)?.scrollIntoView({ block: 'nearest' })
  }, [activeIndex, open, query])

  const move = (delta: number) => {
    const n = flat.length
    if (!n) return
    setRawActive((i) => (Math.min(i, n - 1) + delta + n) % n)
  }

  const select = (item: CommandItem) => {
    switch (item.kind) {
      case 'view':
        if (item.href) navigate(item.href)
        break
      case 'action':
        runAction(item.id)
        break
      case 'recent':
      case 'lookup':
        submitLookup(item.label)
        break
    }
    onClose()
  }

  const onInputKeyDown = (e: ReactKeyboardEvent<HTMLInputElement>) => {
    switch (e.key) {
      case 'ArrowDown':
        e.preventDefault()
        move(1)
        break
      case 'ArrowUp':
        e.preventDefault()
        move(-1)
        break
      case 'Home':
        e.preventDefault()
        setRawActive(0)
        break
      case 'End':
        e.preventDefault()
        setRawActive(flat.length - 1)
        break
      case 'Enter': {
        e.preventDefault()
        const item = flat[activeIndex]
        if (item) select(item)
        else if (query.trim()) {
          submitLookup(query)
          onClose()
        }
        break
      }
      case 'Escape':
        e.preventDefault()
        onClose()
        break
    }
  }

  return (
    <dialog
      ref={dialogRef}
      aria-label="Command palette"
      onCancel={(e) => {
        e.preventDefault()
        onClose()
      }}
      onClick={(e) => {
        if (e.target === dialogRef.current) onClose()
      }}
      className="mx-auto mt-[12vh] w-[min(40rem,calc(100%-2rem))] max-w-full bg-transparent p-0 text-paper outline-none backdrop:bg-ink/75 backdrop:backdrop-blur-[3px] max-sm:mt-[8vh]"
    >
      <div
        ref={panelRef}
        className="flex max-h-[min(30rem,72vh)] w-full flex-col overflow-hidden rounded-lg border border-line bg-raised shadow-e3"
      >
        {/* input row */}
        <div className="flex items-center gap-2.5 border-b border-line px-4">
          <span className="shrink-0 text-faint" aria-hidden="true">
            <SearchGlyph />
          </span>
          <input
            ref={inputRef}
            type="text"
            role="combobox"
            aria-expanded="true"
            aria-controls={LISTBOX_ID}
            aria-activedescendant={flat.length ? `sd-opt-${activeIndex}` : undefined}
            aria-autocomplete="list"
            aria-label={placeholder}
            autoComplete="off"
            autoCorrect="off"
            spellCheck={false}
            value={query}
            onChange={(e) => {
              setQuery(e.target.value)
              setRawActive(0)
            }}
            onKeyDown={onInputKeyDown}
            placeholder={placeholder}
            className="h-14 w-full bg-transparent font-mono text-md text-paper placeholder:font-sans placeholder:text-faint focus:outline-none"
          />
          <kbd className="hidden shrink-0 rounded-sm border border-line bg-panel px-1.5 py-0.5 font-mono text-micro font-semibold text-faint sm:inline-block">
            esc
          </kbd>
        </div>

        {/* results */}
        <div
          id={LISTBOX_ID}
          role="listbox"
          aria-label="Command results"
          className="min-h-0 flex-1 overflow-y-auto overscroll-contain px-2 py-2"
        >
          {flat.length === 0 ? (
            <div className="px-3 py-10 text-center font-sans text-base text-faint">
              No matches
            </div>
          ) : (
            groups.map((group) => (
              <div key={group.id} role="presentation" className="mb-1.5 last:mb-0">
                <MicroLabel tone="faint" className="px-2 pb-1">
                  {group.heading}
                </MicroLabel>
                <div role="presentation" className="flex flex-col gap-0.5">
                  {group.items.map((ri) => {
                    const isActive = ri.index === activeIndex
                    return (
                      <div
                        key={ri.item.id}
                        id={`sd-opt-${ri.index}`}
                        role="option"
                        aria-selected={isActive}
                        onMouseMove={() => setRawActive(ri.index)}
                        onClick={() => select(ri.item)}
                        className={cx(
                          'flex cursor-pointer items-center gap-3 rounded-md px-3 py-2',
                          isActive ? 'bg-[var(--tint-accent)]' : 'hover:bg-panel-soft',
                        )}
                      >
                        <span
                          aria-hidden="true"
                          className={cx(
                            'flex size-4 shrink-0 items-center justify-center',
                            isActive ? 'text-accent' : 'text-faint',
                          )}
                        >
                          <LeadGlyph kind={ri.item.kind} />
                        </span>
                        <span
                          className={cx(
                            'min-w-0 flex-1 truncate',
                            isIndicator(ri.item.kind)
                              ? 'font-mono text-base'
                              : 'font-sans text-base',
                            isActive ? 'text-paper' : 'text-muted',
                          )}
                        >
                          {highlight(ri.item.label, ri.ranges)}
                        </span>
                        {ri.item.indicatorType ? (
                          <Chip variant="neutral" className="shrink-0">
                            {INDICATOR_LABEL[ri.item.indicatorType]}
                          </Chip>
                        ) : ri.item.hint ? (
                          <span className="shrink-0 font-mono text-micro uppercase tracking-label text-faint">
                            {ri.item.hint}
                          </span>
                        ) : null}
                      </div>
                    )
                  })}
                </div>
              </div>
            ))
          )}
        </div>

        {/* footer legend */}
        <div className="flex items-center gap-4 border-t border-line px-4 py-2.5">
          <FooterHint keys={['↑', '↓']} label="Navigate" />
          <FooterHint keys={['↵']} label="Select" />
          <FooterHint keys={['esc']} label="Close" />
          <span className="ml-auto font-mono text-micro font-semibold uppercase tracking-label text-faint">
            SOCDesk
          </span>
        </div>
      </div>
    </dialog>
  )
}

/* -- internal presentational bits (not exported) -- */

function FooterHint({ keys, label }: { keys: string[]; label: string }) {
  return (
    <span className="flex items-center gap-1.5">
      <span className="flex items-center gap-0.5">
        {keys.map((k) => (
          <kbd
            key={k}
            className="inline-flex min-w-4 items-center justify-center rounded-sm border border-line bg-panel px-1 py-0.5 font-mono text-micro font-semibold text-faint"
          >
            {k}
          </kbd>
        ))}
      </span>
      <span className="font-sans text-micro text-faint">{label}</span>
    </span>
  )
}

function LeadGlyph({ kind }: { kind: CommandKind }) {
  switch (kind) {
    case 'recent':
      return <ClockGlyph />
    case 'view':
      return <ArrowGlyph />
    case 'action':
      return <BoltGlyph />
    case 'lookup':
    default:
      return <SearchGlyph />
  }
}

function SearchGlyph() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" aria-hidden="true">
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

function ClockGlyph() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <circle cx="12" cy="12" r="8.5" stroke="currentColor" strokeWidth="1.7" />
      <path
        d="M12 7.5V12l3 2"
        stroke="currentColor"
        strokeWidth="1.7"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  )
}

function ArrowGlyph() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path
        d="M8 6h10v10M18 6L6 18"
        stroke="currentColor"
        strokeWidth="1.7"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  )
}

function BoltGlyph() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path
        d="M13 3L5 13h6l-1 8 8-10h-6l1-8Z"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinejoin="round"
      />
    </svg>
  )
}
