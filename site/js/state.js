// state.js — per-analyst state. localStorage only: never transmitted, no
// backend exists to transmit it to. Every read is guarded so a quota or
// serialization failure degrades to in-memory state, never a broken page.
const NS = "socdesk:v1:";
const read = (k, fb) => {
  try { return JSON.parse(localStorage.getItem(NS + k)) ?? fb; } catch { return fb; }
};
const write = (k, v) => { try { localStorage.setItem(NS + k, JSON.stringify(v)); } catch {} };

export const state = {
  reviewed:  read("reviewed", {}),    // feed id -> ISO marked-at
  notable:   read("notable", {}),     // feed id -> {title,url,source,ts}
  watchlist: read("watchlist", []),   // lowercase vendor/product strings
  history:   read("history", []),     // [{q,type,verdict,ts}] most-recent-first
  lastVisit: "",                      // previous session start
};

export function beginSession() {
  state.lastVisit = read("sessionStart", "");
  write("sessionStart", new Date().toISOString());
}

export function toggleReviewed(id) {
  if (state.reviewed[id]) delete state.reviewed[id];
  else state.reviewed[id] = new Date().toISOString();
  write("reviewed", state.reviewed);
}

export function toggleNotable(item) {
  if (state.notable[item.id]) delete state.notable[item.id];
  else state.notable[item.id] = {
    title: item.title, url: item.url, source: item.source,
    ts: new Date().toISOString(),
  };
  write("notable", state.notable);
}

export const notableCount = () => Object.keys(state.notable).length;

export function setWatchlist(terms) {
  state.watchlist = [...new Set(terms.map(v => v.trim().toLowerCase()).filter(Boolean))];
  write("watchlist", state.watchlist);
}

export function addWatch(term) { setWatchlist([...state.watchlist, term]); }
export function removeWatch(term) {
  setWatchlist(state.watchlist.filter(t => t !== term.toLowerCase()));
}

/** Does a feed item or CVE row touch the analyst's watchlist? */
export function watchHit(strings) {
  if (!state.watchlist.length) return null;
  const hay = strings.filter(Boolean).join(" ").toLowerCase();
  return state.watchlist.find(t => hay.includes(t)) || null;
}

const HISTORY_MAX = 12;
export function pushHistory(q, type, verdict) {
  state.history = [{ q, type, verdict, ts: new Date().toISOString() },
                   ...state.history.filter(h => h.q !== q)].slice(0, HISTORY_MAX);
  write("history", state.history);
}

export function pruneReviewed(liveIds) {
  let dirty = false;
  for (const id of Object.keys(state.reviewed))
    if (!liveIds.has(id)) { delete state.reviewed[id]; dirty = true; }
  if (dirty) write("reviewed", state.reviewed);
}

/** Wipe everything this browser holds — the workstation-hygiene control. */
export function clearAll() {
  try {
    Object.keys(localStorage)
      .filter(k => k.startsWith(NS))
      .forEach(k => localStorage.removeItem(k));
  } catch {}
  state.reviewed = {}; state.notable = {}; state.watchlist = [];
  state.history = []; state.lastVisit = "";
}
