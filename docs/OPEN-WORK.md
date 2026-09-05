# Open work — review and implement

Forward-only worklist from an external review pass. Every item was verified
still open against this repo on **2026-09-05**; anything already shipped has
been dropped (the CI test gate and PR trigger, the session-HMAC guard and OAuth
nonce binding, favicon rate-limiting, the R3 re-rating, and the README/CLAUDE.md
accuracy fixes all landed and are not listed here).

Grouped by surface, ranked within each group. Each row states the acceptance
test that closes it. File anchors are given where they save a discovery pass.

---

## 1 · Enrichment KQL (Hunt Playbooks)

| P | Item | Do / acceptance |
|---|---|---|
| ✅ **1** | `column_ifexists` hardening | **DONE (2026-09-05, `baa7f17`).** The 6-step unfamiliar ladder wraps every optional/dynamic column (LocationDetails/DeviceDetail/MfaDetail/AutonomousSystemNumber/InitiatedBy/…); password-spray uses only core columns. Re-validated: binds against the real DDL AND a deliberately-broken unwrapped column FAILS the lane (exit 1). |
| ✅ **1** | Land the 6-step ladder | **DONE (2026-09-05, `baa7f17`).** Drop-in copied in + adversarially re-validated: 6/6 steps bind against the live Kusto emulator (69/69 lane); `{{upn}}` stays visible on steps 2–6 with the existing callout. |
| ✅ **1** | Empty state | **DONE (2026-09-05, `baa7f17`).** `HuntPlaybookPanel` renders "No SIEM playbook for `<type>` yet — IP indicators supported today." for enrichable-but-uncovered types; the wrapper gates on `status === 'ready'` so it never flashes while loading. |
| ✅ 2 | Same ladder for `password-spray` | **DONE (2026-09-05, `6ee13de`).** Upgraded to 5 steps: spray shape → landed accounts → the three persistence hunts (inbox rules/OAuth/device+MFA). Both IP playbooks now investigate, not just detect. |
| ✅ 2 | Confirm the CI gate walks playbooks | **DONE (2026-09-05).** `tools/validate_hunt_kql.py` folds playbook steps into the validated set (they appear as `<id>::<step>` in the lane); negative control confirmed — a broken unwrapped column returns exit 1. |
| ✅ 3 | Author hash + domain playbooks | **DONE (2026-09-05, `6ee13de`).** `file-hash-sightings` (sha256 → DeviceFileEvents/DeviceProcessEvents/DeviceImageLoadEvents) + `domain-callouts` (domain → DeviceNetworkEvents, incl. a beaconing-cadence step). Scoped to tables with committed DDL — DnsEvents/EmailAttachmentInfo/AlertEvidence have none, so those are deferred; all 5 new steps bind (77/77 lane). |
| ◐ 3 | Dialect toggle + copy-all | **"Copy whole playbook" DONE (`6ee13de`).** Dialect toggle **DEFERRED to v2**: a bare `TimeGenerated↔Timestamp` swap leaves Sentinel-only tables (SigninLogs/OfficeActivity/AuditLogs) in "Defender" output = invalid KQL. An honest toggle needs the advanced_hunting table mappings (the AH-DDL v2 work), else it ships a broken query. |

### What makes a playbook a playbook

The shipped `unfamiliar-signin-properties` is two queries answering the *same*
question — step 1 scopes the IP, step 2 scores novelty. Both confirm the anomaly
already seen; neither advances the investigation.

A playbook should encode the analyst's workflow: **confirm → scope → persistence
→ remediation decision.** Each step needs (a) a distinct investigative question
against a *different* table, (b) a `// Look for:` stating what a hit means and
its benign twin, and (c) a `// Next:` stating where it sends the analyst. The
authored ladder is: sign-in context (is this really compromise?) → novelty →
mailbox rules (`OfficeActivity`) → OAuth consent (`AuditLogs`) → device/MFA
registration (`AuditLogs`) → token replay (`SigninLogs`, one session from 2+ IPs).

Guidance must ride as KQL comments: the published step schema is
`additionalProperties: false` and `collectors/hunt.py` strips any field outside
it (it already strips `rationale` by design). Comments are valid KQL, survive
Copy, and pass the emulator.

Two table/type traps worth not repeating: mailbox rules live in
`OfficeActivity`, not `AuditLogs`; and `InitiatedBy` is dynamic, so compare with
`tostring(InitiatedBy.user.userPrincipalName) =~ …`, never `=~` directly.

---

## 2 · Adversary profiles

> **⚠️ ALREADY SHIPPED (2026-09-03/04) — this section is stale.** All four items
> landed and are live before this worklist was drafted (the reviewer did not
> account for the 2026-09-03 Adversaries re-run work). Verified in the current
> `ActorProfile.tsx` / `ProfileDirectory.tsx` on main. Only ONE genuine remnant:
> the `:target` deep-link auto-open, deliberately deferred — the app is
> HASH-ROUTED (`#g=<slug>`), so a `#hunt` fragment would wipe the route; shipped
> as scroll+open BUTTONS instead, with a `?s=` query-param channel logged for v2.

| P | Item | Status |
|---|---|---|
| ✅ **1** | Progressive disclosure | **SHIPPED** — `ProfileNav` (sticky scrollspy jump-nav) + `SynthesisBand` (one-screen synthesis lead) + collapsible `<details>` reference sections incl. the hunt pack. Remnant: `:target` deep-link (deferred, hash-router; `?s=` channel is v2). |
| ✅ 2 | Surface distinctive TTPs | **SHIPPED** — the "Distinctive TTPs · N" lead band is the first cell of `SynthesisBand`, above the collapsed matrix. |
| ✅ 2 | De-duplicate relationship lists | **SHIPPED** — `relatedMinusUsedBy` drops the redundant Related-entities actor rows on malware pages (reverse-index wins); actor-page software dedup via `feedOnlyMalware`. |
| ✅ 3 | Directory facets + seed-slug aliasing | **SHIPPED** — sector/country/seeded facets on the directory; `slug_aliases` aliases `lockbit`→`lockbit5`/etc; card heights normalized (`items-start` + min-h). |

---

## 3 · Desk / Feed

| P | Item | Do / acceptance |
|---|---|---|
| ◐ **1** | Cross-source clustering + "what changed" | **BACKEND DONE (2026-09-05, `8bea02b`).** Spec `docs/superpowers/specs/2026-09-05-feed-clustering-design.md` (adversarially vetted — 4 ship-breaking findings fixed: outlet-from-title dedup since all news shares `source="rss"`, ≥2-outlet corroboration threshold, `cve_rows` delta, build after trends). `pipeline/stories.py::build_stories` → sibling `stories.json` (feed.json unchanged); on live data **24 corroborated stories** (e.g. a CVE covered by CISA KEV + THN + BleepingComputer, KEV+EPSS delta). **CLIENT (Plan 2) PENDING owner sign-off** — the "Corroborated stories" strip changes the Desk default briefing (Lead + Sections), a taste-sensitive surface. |
| 3 | Collapse the Reports long tail | ~55% of the feed is near-zero-scored report items stacked in the default briefing. Put them behind their filter. |
| 3 | Right-size the ISP leaderboard | Full leaderboard chrome (rank column, bars) over ~8 data points where the maximum value is 2 — the bars cannot discriminate and the rank is a three-way tie. Either fold it into Sources as a sentence, or gate the leaderboard treatment on a data-volume threshold. |

---

## 4 · Escalation card — geolocation and compare-previous

Flagged 2026-08-25 and **not re-verified since** — confirm current state before working.

| P | Item | Do / acceptance |
|---|---|---|
| 2 | Tie the hosting signal into the geo block | The card computes a `HOSTING / DATACENTER` chip but never links it to the geo hero, so a datacenter IP renders a flag, a country name and a pin as the largest block on the card. Annotate: "hosting/announcement location, not the operator's." The data is already on the card; highest-value honesty fix here. |
| 2 | Compare-previous: gate or repurpose | Impossible travel is computed on hosting/VPN/Tor endpoints with no guard (the invalidating signal is on the same card and the second IP's full enrichment is fetched then discarded); the *plausible* path carries no caveat at all; and the copy text asserts "two sign-ins for this account", which the tool cannot know. **Either** gate the computation on both endpoints being non-hosting and put a caveat on the benign path, **or** repurpose the feature to "second IP reputation + hosting class + honest distance". This is a product decision, not an implementation detail. |
| 3 | Geo precision and globe colour | Drop 2-decimal coordinates for city-centroid data; stop colouring the globe's landed geo marker by verdict tone (the card's own pin is correctly neutral); fix the (20°N, 0°E) fallback pin and the "via ipinfo" label when the country came from another source. |
| 3 | Copy-card carries the caveat | The PNG model assigns `caveat` and `queried` but never paints them — the most-shared artifact is the only register without the honesty line. |

---

## 5 · Repo and release hygiene

| P | Item | Do / acceptance |
|---|---|---|
| 2 | R3 operational gaps | The dated R3 re-rating in `COMPLIANCE.md` lists these as still open: dispute/takedown path, personal-data stance, git-history retention of republished names, upstream API terms. Close them or record the accepted risk explicitly. |
| ✅ 2 | Documentation convention vs tracked docs | **DONE (2026-09-05).** Amended `CLAUDE.md` to match the owner's relaxed posture (2026-08-25): AI attribution IS permitted in internal engineering artifacts (commit trailers, `docs/`, code comments), kept OUT of the user-facing product surface. The repo no longer contradicts itself. |
| ✅ 2 | Remove the superseded legacy toolbelt | **DONE (2026-09-05).** Deleted `site/js/toolbelt/tools.js` (the `SNAPSHOT PORT from CARL` lineage-leak); the live app never referenced it (only the dead `site/sw.js` did), and BACKLOG.md had no refs to scrub. |
| 3 | Point the browser suite at `web/` | `site-tests/serve.js:10` still serves the legacy `site/`, so the e2e suite guards dead code and the live app has no browser coverage. Port `csp.spec.js` and `escaping.spec.js` first. |
| ◐ 3 | Versioning and tags | **DONE (2026-09-05).** `web/package.json` → `0.1.0`; root `VERSION` file added (`0.1.0`); repo tagged `v0.1.0`. |
| 3 | Drop dead weight | **DEFERRED — needs owner sign-off (large + interdependent).** Legacy `site/` deletion is coupled to the browser-suite port (site-tests serve `site/`), and `design/mockups/` (~33k LOC) is a big destructive change; both preserved in git history if removed. Root `node_modules/` is NOT tracked (0 files); `cves.json` churn is a P3 nicety. Left for an explicit go-ahead rather than deleting 33k LOC autonomously. |

---

## Suggested order

1. Enrichment KQL items 1–3 (harden, land the ladder, empty state) — hours, and the empty state removes the one behaviour that reads as a bug.
2. Adversary progressive disclosure — the largest remaining UX debt now that the profile content is rich.
3. Spec, then build, the feed clustering — the highest-value change on the site and the one most likely to be built wrong from a one-line description.
