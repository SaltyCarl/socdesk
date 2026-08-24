// lib/enrich/budgets.mjs
// L2: per-source daily budget — the real upstream-quota guarantee (§4.2, §11.1).
// PURE decision core only; all KV I/O lives in the Function wrapper. Budgets are
// keyed by the source's env-var `.key` (lib/enrich.mjs) and sit BELOW the real
// free cap to absorb multi-isolate over-count / eventual-consistency slop.
// RDAP (keyless) and SOCDesk Community (local map) carry no upstream quota → not
// budgeted, so they naturally fall out of every computation below.
export const BUDGETS = {
  VT_API_KEY: 450,          // real free cap ~500/day (public API)
  ABUSEIPDB_API_KEY: 900,   // real 1,000/day
  IPINFO_TOKEN: 1500,       // real 50k/mo ≈ 1,600/day
  URLSCAN_API_KEY: 500,     // key raises a low keyless cap
  GREYNOISE_API_KEY: 300,   // ~community tier
  ABUSECH_API_KEY: 1000,    // generous/unpublished (soft)
  OTX_API_KEY: 1500,        // generous (soft)
}

// A Set of budget keys whose day-count has reached its budget. Fail-open:
// a missing/NaN count is 0 (under budget). Unbudgeted keys are ignored.
export function budgetBlockedSet(counts, budgets = BUDGETS) {
  const blocked = new Set()
  for (const key of Object.keys(budgets)) {
    const n = Number(counts?.[key]) || 0
    if (n >= budgets[key]) blocked.add(key)
  }
  return blocked
}

// The budget keys the wrapper must increment: sources that apply to `type`, are
// usable (optionalKey OR key set), are NOT budget-blocked, and ARE budgeted.
// = applicable − notConfigured − budgetBlocked, restricted to budgeted keys
// (§11.2). NEVER inferred from result.errors[] (a 429/timeout that DID call and
// a skip that did NOT both look like {source, reason}).
export function dispatchedBudgetKeys({ type, env, budgetBlocked, sources, budgets = BUDGETS }) {
  return sources
    .filter((s) => s.types.includes(type))
    .filter((s) => s.optionalKey || env[s.key])   // drops not-configured non-optional sources
    .filter((s) => !budgetBlocked.has(s.key))      // drops already-blocked sources
    .filter((s) => budgets[s.key] !== undefined)   // drops unbudgeted (RDAP/community)
    .map((s) => s.key)
}

// name → budget key. Rows in result.sources/errors carry `.name`, budgets are
// keyed by `.key` (§11.4). Only budgeted names appear.
export function nameToKey(sources, budgets = BUDGETS) {
  const map = {}
  for (const s of sources) if (budgets[s.key] !== undefined) map[s.name] = s.key
  return map
}
