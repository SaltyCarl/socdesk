import type { CommandItem } from './types'
import { classifyIndicator } from './classify'
import { classifyCockpitInput } from '@socdesk/shared/intent'
import { clearRecents, pushRecent } from './recents'
import { applyThemePref, resolveTheme } from '@socdesk/shared/lib/theme'

/**
 * Static command registries + the side-effecting verbs the palette can
 * perform. Kept out of the component file so it exports no non-component
 * values (react-refresh discipline).
 *
 * Integration seam: `DEFAULT_VIEWS` is the route map. Sibling surfaces
 * (Feed, Vulnerabilities, Threat actors, the lookup result view) register
 * here — add a `view` row with its `href`, nothing else changes.
 */

export const DEFAULT_VIEWS: CommandItem[] = [
  {
    id: 'view:overview',
    kind: 'view',
    label: 'Overview',
    hint: '/',
    href: '/',
    keywords: ['home', 'start', 'landing', 'globe', 'threat surface', 'lookup', 'verdict', 'escalation', 'ip', 'domain', 'url', 'hash', 'cve'],
  },
  {
    id: 'view:analyzer',
    kind: 'view',
    label: 'PowerShell analyzer',
    hint: '/analyzer',
    href: '/analyzer',
    keywords: ['powershell', 'analyzer', 'decode', 'base64', 'encodedcommand', 'obfuscation', 'iocs'],
  },
  {
    id: 'view:desk',
    kind: 'view',
    label: 'Data desk',
    hint: '/desk',
    href: '/desk',
    keywords: ['feed', 'vulnerabilities', 'actors', 'health', 'sources', 'triage'],
  },
  {
    id: 'view:actor',
    kind: 'view',
    label: 'Threat Intelligence',
    hint: '/actor',
    href: '/actor',
    keywords: ['actor', 'ransomware', 'group', 'apt', 'malware', 'profile', 'adversary', 'attack'],
  },
  {
    id: 'view:gallery',
    kind: 'view',
    label: 'Design gallery',
    hint: '/gallery',
    href: '/gallery',
    keywords: ['tokens', 'primitives', 'components', 'design system', 'style'],
  },
  {
    id: 'view:privacy',
    kind: 'view',
    label: 'Privacy',
    hint: '/privacy',
    href: '/privacy',
    keywords: ['privacy', 'disclosure', 'data', 'tracking', 'cookies', 'policy', 'legal'],
  },
  {
    id: 'view:about',
    kind: 'view',
    label: 'About',
    hint: '/about',
    href: '/about',
    keywords: ['about', 'community reports', 'contributors', 'moderation', 'dispute', 'transparency'],
  },
]

export const DEFAULT_ACTIONS: CommandItem[] = [
  {
    id: 'action:theme-toggle',
    kind: 'action',
    label: 'Toggle light / dark theme',
    keywords: ['dark', 'light', 'appearance', 'contrast'],
  },
  {
    id: 'action:copy-url',
    kind: 'action',
    label: 'Copy current page URL',
    keywords: ['share', 'link', 'clipboard', 'permalink'],
  },
  {
    id: 'action:clear-recents',
    kind: 'action',
    label: 'Clear recent indicators',
    keywords: ['history', 'forget', 'reset', 'wipe'],
  },
]

/** The deep-link the lookup surface consumes: `#q=<encoded indicator>`. */
export function lookupHash(query: string): string {
  return `#q=${encodeURIComponent(query.trim())}`
}

/**
 * Submit an indicator lookup. Records it as recent, then routes to the cockpit
 * (`/`) with the indicator on the `#q=` deep link — from ANY route; the cockpit
 * seeds its omnibox from the hash (Overview.tsx sync). A command-shaped value
 * NEVER takes the enrich path: it routes to the standalone `/analyzer` instead,
 * with the command prefilled via the same `#q=` deep link so the paste is not
 * lost.
 */
export function submitLookup(query: string): void {
  const q = query.trim()
  if (!q) return
  if (classifyCockpitInput(q) === 'command') {
    navigate(`/analyzer${lookupHash(q)}`)
    return
  }
  pushRecent(q, classifyIndicator(q))
  navigate(`/${lookupHash(q)}`)
}

/**
 * In-app navigation with no router dependency: pushState + a synthetic
 * popstate, which App.tsx's `useRoute` already listens for. Hash targets
 * route through the hash instead.
 */
export function navigate(href: string): void {
  if (href.startsWith('#')) {
    window.location.hash = href
    return
  }
  window.history.pushState({}, '', href)
  window.dispatchEvent(new PopStateEvent('popstate'))
}

/** Dispatch a static `action` row by id. */
export function runAction(id: string): void {
  switch (id) {
    case 'action:theme-toggle':
      applyThemePref(resolveTheme() === 'dark' ? 'light' : 'dark')
      break
    case 'action:copy-url':
      try {
        void navigator.clipboard?.writeText(window.location.href)
      } catch {
        /* clipboard blocked — best-effort */
      }
      break
    case 'action:clear-recents':
      clearRecents()
      break
  }
}
