# VIGIL Phase C½ — Enrichment Worker

**Date:** 2026-08-07 · **Status:** Spec, not started · **Depends on:** Phase B shipped

Upgrades VIGIL's core promise from *"we route you to the answer"* to *"we give
you the answer"* — without giving up the properties that make it credible.

## 1. The architectural rule

**The site stays static and stays incapable of transmitting.** All enrichment
goes through ONE stateless Cloudflare Worker on a separate origin. The site's
CSP gains exactly one entry: `connect-src 'self' https://api.vigil.<domain>`.

Consequences that must hold:
- The Worker holds the API keys. The browser never sees a key.
- Enrichment is **opt-in per lookup** — a user gesture ("Enrich ↗"), never
  automatic on page load and never a fan-out to several services at once.
  Auto-enrichment would silently disclose every pasted indicator.
- The Worker stores **no user identity, no request logs beyond Cloudflare's
  defaults, and no association between indicators and people**. Cache is keyed
  by indicator only.
- If the Worker is down, the site degrades to exactly today's behaviour:
  local verdict + pivot links. Nothing breaks.

## 2. Why this is MORE compliant than what we removed

The abuse.ch problem (COMPLIANCE.md R4) was **mirroring a corpus** — bulk
copying and republishing someone's dataset. Querying an API on demand, once,
because a user clicked a button, is the sanctioned use those APIs exist for.
Each source still needs its terms read before wiring:

| Source | Free tier | Notes to verify at build time |
|---|---|---|
| GreyNoise Community API | yes, free, no key for community endpoint | Explicitly for community use; best "is this just internet noise?" signal |
| abuse.ch (ThreatFox/URLhaus) | free with Auth-Key | Per-query lookup ≠ redistribution. Do NOT cache-and-republish results as our own dataset |
| urlscan.io | free API key | Search existing scans. **Never submit** — submission publishes (see §3) |
| VirusTotal | free key, 4 req/min | ToS forbids commercial use — fine for a personal tool, note the team-use edge |
| Shodan InternetDB | free, no key | Lightweight host facts, no rate pain |

Rate limits are the real constraint, which is what the cache is for.

## 3. urlscan preview — the flagship feature

**What:** when an analyst looks up a domain or URL, show the **screenshot from
an existing public urlscan scan** inline in the verdict card, with the scan
date, final URL after redirects, page title, and the IPs/ASNs contacted.

**Why it matters:** the analyst sees what the page looks like *without visiting
it and without submitting anything new*. This is the single most useful thing
we can add — it answers "is this a credential-harvest page?" in one glance,
which no amount of reputation scoring does.

**The hard rule: SEARCH ONLY, NEVER SUBMIT.**
- `GET https://urlscan.io/api/v1/search/?q=page.domain:<domain>` → take the
  most recent public result → render `result.screenshot`.
- Submitting a URL to urlscan **publishes it publicly** — that is a disclosure
  the analyst must make deliberately, on urlscan's own site, via the existing
  ⚠-marked pivot link. VIGIL must never submit on their behalf.
- If no public scan exists, say so plainly: *"No public scan on record. Use the
  pivot to submit — note that a public submission is visible to anyone."*

**Implementation notes:**
- Screenshot images are served from `urlscan.io`. Either proxy them through the
  Worker (keeps `img-src 'self'`, costs bandwidth) or add
  `img-src https://urlscan.io` to the CSP. **Proxy them** — it keeps the CSP
  tight and stops the browser making a third-party request the user didn't
  choose.
- Screenshots of malicious pages are still images of malicious content. Render
  them **blurred with a click-to-reveal**, and never auto-load.

## 4. Endpoint shape

```
GET /v1/enrich?type=<ipv4|domain|url|md5|sha1|sha256>&q=<indicator>
→ 200 {
    indicator, type, checked_at,
    sources: [ { name, verdict, confidence, summary, first_seen, last_seen,
                 url, attribution? } ],
    preview?: { screenshot_path, scanned_at, final_url, title, asn },
    partial: bool,          // true if some upstream failed or timed out
    errors: [ { source, reason } ]
  }
```

Rules:
- **Fault-isolated exactly like the collectors**: one upstream failing returns
  a partial result with a named error, never a 500.
- 4-second budget per upstream, 6 seconds total; late sources report as
  timed-out rather than blocking the response.
- Normalise verdicts to VIGIL's own vocabulary (`malicious / suspicious /
  benign / unknown`) but **always show the source's own wording too** — never
  launder someone else's assessment into ours.
- Every response carries per-source attribution. Provenance is the brand.

## 5. Caching

- Workers KV, keyed `enrich:<type>:<sha256(indicator)>`.
- TTL by volatility: IP reputation 6h, domain 12h, hash 7d, urlscan preview 30d.
- **Cache is keyed by indicator only** — no user, no session, no ordering.
  Two analysts checking the same IP share the benefit without sharing state.
- Cache hits are labelled in the UI with their age. A stale answer presented as
  fresh is the failure mode we care about.

## 6. UI integration

- Verdict card gains an **"Enrich ↗"** button. Nothing enriches on page load.
- On click: skeleton rows appear per source, filling in as each returns.
- Enriched rows sit in the existing evidence table, each tagged with its source
  and age; the local KEV/EPSS verdict remains the headline for CVEs.
- The escalation card gains an **"Enriched findings"** block when present, each
  line attributed to its source with its timestamp.
- The disclosure banner gains one sentence: enrichment queries these services
  from our server, so the indicator is seen by them — but not tied to you.

## 7. Non-goals

- No file uploads. No detonation. No fetching attacker-controlled URLs (see
  the delisting risk in COMPLIANCE.md — an attacker who notices can feed us
  content designed to get the domain flagged).
- No user accounts, no per-user history server-side.
- No auto-enrichment, no bulk auto-enrichment (bulk mode may enrich, but only
  on an explicit click, sequentially, with a visible count).

## 8. Definition of done

- [ ] Worker deployed, keys in Worker secrets, never in the repo.
- [ ] Site works identically with the Worker unreachable.
- [ ] Playwright: enrichment off by default; a mocked Worker response renders
      attributed rows; a Worker 500 degrades without breaking the verdict; a
      urlscan preview renders blurred and click-to-reveal.
- [ ] Terms for every wired source read and recorded in COMPLIANCE.md.
- [ ] CSP updated to exactly one new origin; `img-src` unchanged.
