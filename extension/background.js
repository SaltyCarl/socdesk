// background.js — MV3 module service worker.
//
// Two jobs, both event-driven so the worker can spin down between them:
//   1. Register the "Check in SOCDesk" context-menu item (on install).
//   2. On click: refang + type-detect the selection, then either open the
//      toolbar popup pre-loaded with the live verdict (enrichable indicators)
//      or open the full report in a new tab (CVE / email / anything else).
//
// No content script, no <all_urls>, no tabs read access. The selection text is
// handed to us by the contextMenus API itself.

import {
  refang, detectType, isEnrichable, normalizeOrigin, reportUrl, DEFAULT_ORIGIN,
} from "./lib/indicators.js";

const MENU_ID = "socdesk-check";

// Create (or recreate) the menu item. removeAll first makes the handler
// idempotent across updates/reloads so we never throw "duplicate id".
function installMenu() {
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({
      id: MENU_ID,
      title: 'Check in SOCDesk: "%s"',
      contexts: ["selection"],
    });
  });
}

chrome.runtime.onInstalled.addListener(installMenu);
chrome.runtime.onStartup.addListener(installMenu);

async function getOrigin() {
  try {
    const { origin } = await chrome.storage.sync.get("origin");
    return normalizeOrigin(origin);
  } catch {
    return DEFAULT_ORIGIN;
  }
}

function openReport(origin, q) {
  chrome.tabs.create({ url: reportUrl(origin, q) });
}

chrome.contextMenus.onClicked.addListener(async (info, _tab) => {
  if (info.menuItemId !== MENU_ID) return;

  const q = refang(info.selectionText || "");
  if (!q) return;
  const type = detectType(q);
  const origin = await getOrigin();

  // CVE, email, or anything we can't classify → the full report handles it.
  if (!isEnrichable(type)) return openReport(origin, q);

  // Enrichable → hand the lookup to the popup and try to open it in place.
  // storage.session is trusted-context-only by default, so only our own popup /
  // options page can read the pending lookup — never a web page.
  try {
    await chrome.storage.session.set({ pending: { q, type, at: Date.now() } });
  } catch { /* session storage unavailable — fall through to the report tab */ }

  try {
    // Chrome 127+/Edge equivalent. A context-menu click is a user gesture, so
    // this is allowed; if the build lacks it, we degrade to the report tab,
    // which shows the very same live verdict.
    if (chrome.action.openPopup) {
      await chrome.action.openPopup();
      return;
    }
  } catch { /* openPopup rejected — degrade below */ }

  openReport(origin, q);
});
