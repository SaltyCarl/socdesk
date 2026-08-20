// background.ts — MV3 module service worker.
//
// Two jobs, both event-driven so the worker can spin down between them:
//   1. Register the "Check in SOCDesk" context-menu item (on install).
//   2. On click: route the selection via routeSelection (shared/intent.ts —
//      the data-boundary guard), then either open the side panel with the
//      analyzer (command/script), hand the lookup to the toolbar popup
//      (enrichable indicator), or open the full report in a new tab (CVE /
//      email / anything else).
//
// No content script, no <all_urls>, no tabs read access. The selection text is
// handed to us by the contextMenus API itself.

import {
  detectType,
  normalizeOrigin,
  reportUrl,
  DEFAULT_ORIGIN,
} from '@socdesk/shared/indicators'
import { routeSelection } from '@socdesk/shared/intent'

const MENU_ID = 'socdesk-check'

// Create (or recreate) the menu item. removeAll first makes the handler
// idempotent across updates/reloads so we never throw "duplicate id".
function installMenu(): void {
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({
      id: MENU_ID,
      title: 'Check in SOCDesk: "%s"',
      contexts: ['selection'],
    })
  })
}

chrome.runtime.onInstalled.addListener(installMenu)
chrome.runtime.onStartup.addListener(installMenu)

async function getOrigin(): Promise<string> {
  try {
    const { origin } = await chrome.storage.sync.get('origin')
    return normalizeOrigin(origin)
  } catch {
    return DEFAULT_ORIGIN
  }
}

function openReport(origin: string, q: string): void {
  chrome.tabs.create({ url: reportUrl(origin, q) })
}

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId !== MENU_ID) return
  const route = routeSelection(info.selectionText || '')
  if (!route.q) return

  // ANALYZE — open the side panel ON THE GESTURE (open() must be called
  // synchronously in the listener; the stash is fire-and-forget and the panel
  // reads it on mount / via storage.onChanged).
  if (route.mode === 'analyze' && tab?.id != null && chrome.sidePanel?.open) {
    void chrome.storage.session.set({ pending: { mode: 'analyze', q: route.q, at: Date.now() } })
    void chrome.sidePanel.open({ tabId: tab.id })
    return
  }

  // LOOKUP / REPORT — the existing async flow (unchanged behaviour). An
  // 'analyze' route only reaches here when the side-panel gesture-path above
  // couldn't run (no chrome.sidePanel.open, or no tab id) — degrade it the
  // same way handleLookupOrReport already degrades any non-'lookup' route:
  // the report tab. Narrowing the literal here (rather than widening
  // handleLookupOrReport's param back to include 'analyze') keeps that
  // function's signature honest about what it actually branches on.
  void handleLookupOrReport({
    mode: route.mode === 'analyze' ? 'report' : route.mode,
    q: route.q,
  })
})

async function handleLookupOrReport(route: { mode: 'lookup' | 'report'; q: string }): Promise<void> {
  const origin = await getOrigin()
  if (route.mode !== 'lookup') return openReport(origin, route.q)
  // storage.session is trusted-context-only by default, so only our own popup /
  // options page can read the pending lookup — never a web page.
  try {
    await chrome.storage.session.set({ pending: { mode: 'lookup', q: route.q, type: detectType(route.q), at: Date.now() } })
  } catch {
    /* session storage unavailable — fall through to the report tab */
  }
  try {
    // Chrome 127+/Edge equivalent. A context-menu click is a user gesture, so
    // this is allowed; if the build lacks it, we degrade to the report tab,
    // which shows the very same live verdict.
    if (chrome.action.openPopup) {
      await chrome.action.openPopup()
      return
    }
  } catch {
    /* openPopup rejected — degrade below */
  }
  openReport(origin, route.q)
}
