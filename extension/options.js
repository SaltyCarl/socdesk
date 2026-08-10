// options.js — read/write the SOCDesk origin in chrome.storage.sync.
// Everything (popup fetches, context-menu report links) reads this value, so a
// self-hosted instance can be targeted without touching code.

import { normalizeOrigin, DEFAULT_ORIGIN } from "./lib/indicators.js";

const input = document.getElementById("origin");
const form = document.getElementById("form");
const status = document.getElementById("status");

function setStatus(text, cls = "") {
  status.className = "status" + (cls ? " " + cls : "");
  status.textContent = text;   // textContent — never innerHTML
}

// Load the saved origin (or the default) into the field.
(async function load() {
  try {
    const { origin } = await chrome.storage.sync.get("origin");
    input.value = origin || DEFAULT_ORIGIN;
  } catch {
    input.value = DEFAULT_ORIGIN;
  }
})();

form.addEventListener("submit", async e => {
  e.preventDefault();
  const raw = input.value.trim();
  const normalized = normalizeOrigin(raw);

  // normalizeOrigin silently falls back to the default on anything unparseable;
  // tell the user when what we stored isn't what they typed.
  if (raw && normalized === DEFAULT_ORIGIN && !/^https?:\/\/(www\.)?socdesk\.io\/?$/i.test(raw)) {
    setStatus(`Not a valid https origin — saved the default (${DEFAULT_ORIGIN}).`, "err");
  }

  try {
    await chrome.storage.sync.set({ origin: normalized });
    input.value = normalized;
    if (!(status.className.includes("err")))
      setStatus(`Saved · ${normalized}`, "ok");
  } catch (err) {
    setStatus(`Could not save: ${(err && err.message) || "storage error"}`, "err");
  }
});
