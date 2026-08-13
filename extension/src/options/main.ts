// options/main.ts — read/write the SOCDesk origin in chrome.storage.sync
// (TypeScript port of options.js; behaviour UNCHANGED). Now sources its
// indicator helpers from the shared module instead of extension/lib.
//
// Everything (popup fetches, context-menu report links) reads this value, so a
// self-hosted instance can be targeted without touching code.

import { normalizeOrigin, DEFAULT_ORIGIN } from '@socdesk/shared/indicators'

const input = document.getElementById('origin') as HTMLInputElement
const form = document.getElementById('form') as HTMLFormElement
const status = document.getElementById('status') as HTMLElement

function setStatus(text: string, cls = ''): void {
  status.className = 'status' + (cls ? ' ' + cls : '')
  status.textContent = text // textContent — never innerHTML
}

// Load the saved origin (or the default) into the field.
;(async function load() {
  try {
    const { origin } = (await chrome.storage.sync.get('origin')) as {
      origin?: string
    }
    input.value = origin || DEFAULT_ORIGIN
  } catch {
    input.value = DEFAULT_ORIGIN
  }
})()

form.addEventListener('submit', async (e) => {
  e.preventDefault()
  const raw = input.value.trim()
  const normalized = normalizeOrigin(raw)

  // normalizeOrigin silently falls back to the default on anything unparseable;
  // tell the user when what we stored isn't what they typed.
  if (
    raw &&
    normalized === DEFAULT_ORIGIN &&
    !/^https?:\/\/(www\.)?socdesk\.io\/?$/i.test(raw)
  ) {
    setStatus(`Not a valid https origin — saved the default (${DEFAULT_ORIGIN}).`, 'err')
  }

  try {
    await chrome.storage.sync.set({ origin: normalized })
    input.value = normalized
    if (!status.className.includes('err')) setStatus(`Saved · ${normalized}`, 'ok')
  } catch (err) {
    const message = err instanceof Error ? err.message : 'storage error'
    setStatus(`Could not save: ${message}`, 'err')
  }
})
