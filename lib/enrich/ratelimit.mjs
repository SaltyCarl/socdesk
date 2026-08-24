// L1: per-IP soft latch for /api/enrich. IN-ISOLATE ONLY (§11.1) — this module
// is pure and the wrapper stores the two Maps in isolate-global memory; there
// is NO KV here. A silent 429 on a local flood; the WAF Block rule is the
// distributed-flood shield of record. Read path stays frictionless: a 429 is a
// bare status, never a challenge/cookie/login.
export const WINDOW_MS = 600_000       // 10-minute counting window
export const IP_LIMIT = 60             // cache-MISS requests per window per IP
export const BLOCK_TTL_MS = 900_000    // 15-minute soft block after crossing

// Pure per-IP state transition. Fail-open: absent state ⇒ first sight ⇒ allow.
export function ipDecision({
  now, windowStart, count, latchedUntil,
  windowMs = WINDOW_MS, limit = IP_LIMIT, blockTtlMs = BLOCK_TTL_MS,
}) {
  // Active latch → deny, do NOT recount (a flood must not extend its own block).
  if (latchedUntil && latchedUntil > now) {
    return { allow: false, newWindowStart: windowStart || now, newCount: count || 0, newLatchedUntil: latchedUntil }
  }
  // Roll the window on expiry or first sight.
  let ws = windowStart, c = count || 0
  if (!ws || now - ws >= windowMs) { ws = now; c = 0 }
  c += 1
  if (c > limit) {
    return { allow: false, newWindowStart: ws, newCount: c, newLatchedUntil: now + blockTtlMs }
  }
  return { allow: true, newWindowStart: ws, newCount: c, newLatchedUntil: 0 }
}
