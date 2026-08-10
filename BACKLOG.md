# SOCDesk Backlog

## North star (owner-set, 2026-08-10 — read before adding ANYTHING)

99% of a T1/T2 analyst's day is: paste an IP or hash into AbuseIPDB /
VirusTotal → read the reputation → screenshot it if escalating → paste into
the email. URLs get the same treatment in a safe viewer (Browserling).
**SOCDesk's job is to make that loop as painless and efficient as possible.**
Everything else — including CVE features, for now — is secondary until that
loop is excellent. Vendors an analyst doesn't open on shift (Shodan, Censys,
Spamhaus, sandbox grids) are fluff here; do not accrete them back
(`site-tests/specs/verdict.spec.js` pins the pivot set).

The loop, mapped to what exists:

| Step | SOCDesk feature | Status |
|---|---|---|
| Paste indicator | Omnibox, type auto-detect, refang, bulk, bookmarklet | Shipped |
| Get reputation | `/api/enrich` Pages Function → AbuseIPDB + VT + GreyNoise (IP), VT + MalwareBazaar (hash) | Built; **dormant until Cloudflare Pages exists + free keys set** |
| Screenshot for the email | Evidence card rendered to canvas → copy as PNG | Shipped |
| Paste into email | Copy image / markdown / text / .md download | Shipped |
| URL safe-view | urlscan existing-scan pivot + Browserling live-view pivot | Shipped (verify Browserling deep-link format at first live use); urlscan screenshot preview in worker spec |

## P0 — unblocks the entire loop (owner)
Stand up Cloudflare Pages (`socdesk` project, two secrets, socdesk.io) and add
the free-tier enrichment keys (ABUSEIPDB, VT, GreyNoise community) as Pages
env vars. Until then: no public URL, red cron deploys, dormant enrichment.

## P1 — hammer the loop (after P0, before anything else)
1. Live dogfood: 2-3 analysts run real alerts through it for a shift; fix
   what they trip on. The acceptance test: indicator → verdict → email
   evidence faster than the bookmark-folder workflow.
2. urlscan screenshot preview (search-only, never submit) from the
   enrichment worker spec — completes the URL leg.
3. Verify the Browserling deep-link format against their current URL scheme.

## P2 — next core component (only once the loop is excellent)
CVE / Threat-Intel feed as the second pillar (feed, KEV/EPSS triage — already
built, needs dogfood-driven sharpening rather than new construction).

## Parked (fluff until further notice)
- Wave-2 collectors (FeodoTracker, C2IntelFeeds, PhishTank, APTnotes)
- Relationship-index enhancements beyond the shipped RELATED block
- Client-side fuzzy search; CVE corpus sharding
- Phase C Framework brief loop
- Honeypot sensor (also gated on the employment-IP question)
