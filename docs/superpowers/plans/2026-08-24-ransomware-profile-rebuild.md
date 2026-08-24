# Ransomware Profile Rebuild Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rebuild the ransomware group profile to fix coverage inversion + shallow presentation — coverage-by-activity seed, an attributed named-victim layer, richer aggregates, a proper design pass, holding the CISA-triage panel v1 shipped.

**Architecture:** Collector stops discarding victim identity → feed carries the claim facts → `profiles.ts` fuses a named-victim list + richer aggregates → a design-pass rebuild of the profile surface. Logos via a same-origin favicon proxy (no CSP loosening, no client→third-party leak). All data public-domain or own-aggregated leak-site facts attributed to the leak site.

**Tech Stack:** Python 3.12 pipeline; JSON Schema; React 19 + TS + Tailwind v4; Cloudflare Pages Functions; node-env Vitest; pytest; `ckm:ui-ux-pro-max` for the design pass.

**Spec:** `docs/superpowers/specs/2026-08-24-ransomware-profile-rebuild-design.md`

## Global Constraints

- **R3 boundary:** republish leak-site claim FACTS (victim, domain, sector, country, date, note filename, CVEs) **attributed to the leak site**, framed **unverified claim** — a claim record, never a SOCDesk verdict. Do NOT mirror ransomware.live's `description`/`screenshot`. Note images come from **CISA figures** (public domain). ATT&CK = Apache-2.0; abuse.ch = CC0.
- **Honesty doctrine:** attributed facts only; every section honest-empty; no synthesized verdict/prose/status.
- **Brand system held** ([[feedback_visual_ai_slop_pattern]]): dark; Archivo + IBM Plex Mono; periwinkle `#7C8AFF` the one reserved accent; verdict red/amber/green carry meaning only.
- **No AI attribution** on any `github.com/SaltyCarl/*` commit.
- **Schema-bound every string/array.** Committed-dataset tests assert shape/rules, never live content/row-count.
- Free-tier, deterministic. Local pytest `./.venv/Scripts/python.exe -m pytest`; vitest `cd web && npx vitest run`; JSX gate `cd web && npm run build && npm run lint`.
- **Design pass** uses `ckm:ui-ux-pro-max` + reference libraries (anime.js/motion.dev/kokonutui/reactbits/motion-primitives/swishy.ai/bklit.ui/Vantage CTI/Apple + repo `design/reference/REFERENCES.md`). **Final 3-lens review** (SOC Analyst / Data Analytics / UX Designer) before close-out.

---

## File Structure

- **Modify** `collectors/ransomwarelive.py` — emit `victim`/`domain` on the claim item (attributed, unverified).
- **Modify** `schemas/feed.schema.json` — optional bounded `victim`/`domain` on the feed item.
- **Modify** `web/src/components/views/types.ts` — `victim?`/`domain?` on `FeedItem`; `ClaimedVictim` on the profile.
- **Modify** `data/ransomware_intel.json` + `schemas/ransomware_intel.schema.json` — re-seed by activity + provenance/note-image fields.
- **Modify** `web/src/components/views/profiles.ts` — named-victim list, richer aggregates, reportsFor dictionary gate, `hasIntel`.
- **Create** `functions/api/favicon.ts` (or repo's functions path) — same-origin favicon proxy.
- **Modify** `web/src/components/views/ActorProfile.tsx` + directory — the design-pass rebuild, logo, `.onion` plain, provenance, seeded badge.
- **Modify** `tests/test_ransomwarelive.py`, `tests/test_validate.py`, `web/src/components/views/__tests__/profiles.test.ts`.
- **Create** `tests/test_intel_staleness.py` — provenance/drift check.

---

## Task 1: Collector emits attributed victim identity

**Files:** Modify `collectors/ransomwarelive.py`; Modify `schemas/feed.schema.json`; Test `tests/test_ransomwarelive.py`.

**Interfaces — Produces:** feed items from source `ransomwarelive` now carry optional `victim` (org name) and `domain` (org domain) strings, plus the existing `entities.actors=[group]`, category `ransomware`, `url`=claim_url. Task 3 reads these.

- [ ] **Step 1: Failing collector test** — add to `tests/test_ransomwarelive.py`:
```python
def test_claim_carries_attributed_victim_and_domain(fake_fetch):
    fetch = fake_fetch({ransomwarelive.URL: "ransomwarelive/recent.json"})
    r = ransomwarelive.collect(fetch, FIXED_NOW)
    it = r.items[0]
    assert it["victim"] == "Furnished Quarters"
    assert it["domain"] == "furnishedquarters.com"
    # attribution/framing stays: title names the group + "claim"; summary marks unverified
    assert "claim" in it["title"].lower()
    assert "unverified" in it["summary"].lower()
```
- [ ] **Step 2: Add the fixture** `tests/fixtures/ransomwarelive/recent.json`:
```json
[{"group":"akira","victim":"Furnished Quarters","domain":"www.furnishedquarters.com",
  "activity":"Hospitality","country":"US","discovered":"2026-08-24 17:51:12",
  "claim_url":"http://darkprn3d3udnhpuxknsrhft3376lrz5tenhgkrxge5hxqe46pkbrwid.onion/article?slug=x"}]
```
- [ ] **Step 3: Run — expect FAIL.** `./.venv/Scripts/python.exe -m pytest tests/test_ransomwarelive.py -q` (KeyError `victim`).
- [ ] **Step 4: Implement.** In `collectors/ransomwarelive.py`, replace the withhold-names summary + add victim/domain to the emitted item. Normalise the domain (strip leading `www.`). Change the `make_item(...)` call to pass `victim`/`domain` (make_item must forward unknown kwargs into the item dict — if it doesn't, set them on the returned dict). Concretely, after building the item, set:
```python
        item = make_item(
            SOURCE, f"{group}:{v.get('victim','')}:{v.get('discovered','')}",
            "ransomware", f"{group} posted a new victim claim",
            f"Unverified claim by {group}, per its leak site. "
            f"Sector: {sector} — Country: {country}.",
            v.get("claim_url") or "https://ransomware.live", "high",
            published + "Z" if published else iso(now), now,
            entities={"actors": [group], "malware": [], "vendors": [], "cves": []},
        )
        victim = (v.get("victim") or "").strip()
        domain = (v.get("domain") or "").strip().lower().removeprefix("www.")
        if victim:
            item["victim"] = victim[:200]
        if domain:
            item["domain"] = domain[:253]
        items.append(item)
```
Update the module docstring to reflect: victim identity is now republished, attributed to the leak site, framed unverified (OSINT posture).
- [ ] **Step 5: Schema.** In `schemas/feed.schema.json` item `properties`, add `"victim": {"type":"string","maxLength":200}` and `"domain": {"type":"string","maxLength":253}`. If the item object has `additionalProperties:false`, this is required; if not, add anyway for bounds.
- [ ] **Step 6: Run pytest** (`tests/test_ransomwarelive.py`, `tests/test_validate.py`, `tests/test_pipeline.py`) — PASS. Then full `tests/ -q` — PASS.
- [ ] **Step 7: Commit** `feat(ransomwarelive): republish attributed victim identity (leak-site fact)`.

## Task 2: Re-seed by activity + provenance + note figures

**Files:** Modify `data/ransomware_intel.json`; Modify `schemas/ransomware_intel.schema.json`; Test `tests/test_validate.py`. Spike: `ransomwatch`.

**Interfaces — Produces:** seed entries gain `advisory_date`, `last_reviewed` (ISO `YYYY-MM-DD`), optional `note_image` (a `cisa.gov` URL), optional `sources[]` (`{id,url}`); the group set is re-ranked by current activity.

- [ ] **Step 1: Get the active list.** Run: `curl -sL -A "Mozilla/5.0 … Chrome/124 Safari/537" https://api.ransomware.live/v2/recentvictims` → count claims per `group` over the returned window; take the busiest ~30-40. (Retry if the API returns an error object.)
- [ ] **Step 2: Extend the schema.** In `schemas/ransomware_intel.schema.json` `groups[]` properties add: `"advisory_date":{"type":"string","maxLength":10}`, `"last_reviewed":{"type":"string","maxLength":10}`, `"note_image":{"type":"string","maxLength":256,"pattern":"^https://.*cisa\\.gov/"}`, `"sources":{"type":"array","maxItems":8,"items":{"type":"object","additionalProperties":false,"required":["id","url"],"properties":{"id":{"type":"string","maxLength":32},"url":{"type":"string","maxLength":256}}}}`. Keep `additionalProperties:false`.
- [ ] **Step 3: Re-seed.** Rewrite `data/ransomware_intel.json`: keep the accurate existing entries that are still active; ADD the current busiest crews (Qilin first, then the rest of the top ~30-40) **that have a public-domain writeup** — verify each against its CISA #StopRansomware / FBI FLASH / joint-CERT advisory (curl+UA, as before); copy only stated facts; set `advisory_date` (the advisory's date), `last_reviewed` (today), `note_image` where the advisory prints a note screenshot, `sources[]` for multi-source. A busy group with NO writeup: omit (it still lists via feed claims + link-out). NO fabrication.
- [ ] **Step 4: Tests.** In `tests/test_validate.py` extend `test_ransomware_intel_seed_validates` to still pass, and add: every `last_reviewed`/`advisory_date` matches `^\d{4}-\d{2}-\d{2}$`; every `note_image` host is `cisa.gov`. Assert shape/rules, NOT the group list/count.
- [ ] **Step 5: Spike ransomwatch.** Briefly check `github.com/joshhighet/ransomwatch` (or its data repo) license + data shape as a more-permissive claim source than the ransomware.live API. Record findings in the ledger (keep or reject); do NOT switch sources in this task — it's a spike.
- [ ] **Step 6: Run pytest** — PASS.
- [ ] **Step 7: Commit** `feat(intel): re-seed ransomware groups by activity + provenance + CISA note figures`.

## Task 3: Fusion — named victims, richer aggregates, reportsFor gate

**Files:** Modify `web/src/components/views/types.ts`, `web/src/components/views/profiles.ts`; Test `web/src/components/views/__tests__/profiles.test.ts`.

**Interfaces:** Consumes Task 1's `FeedItem.victim`/`domain` + Task 2's seed fields. **Produces:** `ProfileResult` gains `claimedVictims: ClaimedVictim[]` and `activity` aggregates (sectors, countries, `timeline: {week:string,count:number}[]`, `victimCount`); `RansomIntel` gains `advisory_date?`/`last_reviewed?`/`note_image?`/`sources?`; `reportsFor` becomes dictionary-gated. Task 5 renders these.

- [ ] **Step 1: Types.** In `types.ts` add `victim?: string; domain?: string` to `FeedItem`; add `RansomIntel` fields `advisory_date?`, `last_reviewed?`, `note_image?`, `sources?: {id:string;url:string}[]`; add `export interface ClaimedVictim { id:string; victim:string; domain?:string; sector?:string; country?:string; date?:string; claimUrl:string }`.
- [ ] **Step 2: Failing fusion tests** — add to `__tests__/profiles.test.ts`:
```ts
it('builds an attributed claimed-victim list for a ransomware group', () => {
  const feed = [{ id:'a'.repeat(40), source:'ransomwarelive', category:'ransomware',
    title:'akira posted a new victim claim', summary:'Unverified claim…', url:'http://x.onion/a',
    victim:'Furnished Quarters', domain:'furnishedquarters.com',
    entities:{actors:['akira'],malware:[],vendors:[],cves:[]}, published_at:'2026-08-24T00:00:00Z' }]
  const p = profileFor('akira', { actors:[], malware:[], feed, relations:null, intel:[] })
  expect(p.claimedVictims[0]).toMatchObject({ victim:'Furnished Quarters', domain:'furnishedquarters.com', claimUrl:'http://x.onion/a' })
  expect(p.activity?.victimCount).toBe(1)
})
it('does not surface reportsFor for a common-word actor not in the dictionary', () => {
  // "play" as a bare RSS mention must not become a report unless dictionary-gated
  const feed = [{ id:'b'.repeat(40), source:'rss', category:'apt', title:'Google Play update', url:'', summary:'', entities:{actors:['Play'],malware:[],vendors:[],cves:[]}, published_at:'2026-08-24T00:00:00Z' }]
  const p = profileFor('play', { actors:[], malware:[], feed, relations:null, intel:[], trackedActors:new Set() })
  expect(p.reporting.length).toBe(0)
})
```
- [ ] **Step 3: Implement.** In `profiles.ts`: add `claimedVictims` (map ransomwarelive claims for the slug → `ClaimedVictim`, newest first), `activity` (sectors/countries sets + a weekly `timeline` bucketed from `published_at` + `victimCount`). Add a `trackedActors?: Set<string>` to `profileFor`'s data param and gate `reportsFor` so a report is kept only when the actor is in `trackedActors` OR the item is genuinely actor-attributed (dictionary match) — mirroring the pipeline's `tracked_actor_set` gate, killing the Play/Akira FP. Thread `advisory_date`/`last_reviewed`/`note_image`/`sources` through `intel`. Add `hasIntel`/`hasClaims` to `ProfileIndexEntry` (already has `hasIntel`). Keep all existing behavior; pure functions.
- [ ] **Step 4: Run** `cd web && npx vitest run profiles` — PASS; then full `npx vitest run` — PASS.
- [ ] **Step 5: Commit** `feat(profiles): claimed-victim list + activity aggregates + reportsFor dictionary gate`.

## Task 4: abuse.ch associated-malware surface

**Files:** Modify `web/src/components/views/profiles.ts` (+ its test). **Interfaces:** Produces `ProfileResult.associatedMalware: string[]` (CC0, from the malware entities co-occurring with the group in the feed / ATT&CK software), rendered as link chips.

- [ ] **Step 1: Failing test** — a group whose feed items / ATT&CK software name a malware family yields it in `associatedMalware`. - [ ] **Step 2: Implement** a pure selector over the existing `feed`/`software` data (no new fetch); dedupe. - [ ] **Step 3: Run vitest** — PASS. - [ ] **Step 4: Commit** `feat(profiles): surface associated malware (abuse.ch/ATT&CK, link-out)`.

## Task 5: Presentation design pass + logo proxy

**Files:** Create `functions/api/favicon.ts`; Modify `web/src/components/views/ActorProfile.tsx` + the directory component; possibly `web/public/_headers` + `web/index.html` (only if a proxy needs it — it should not). Test: a pure logo-src helper + `functions` unit if the harness supports it.

This is a **design task**, not transcription. Sequence:
- [ ] **Step 1: Design.** Invoke `ckm:ui-ux-pro-max` (with the reference libraries + the brand system as constraints) to design the rebuilt profile layout: identity header (name/aliases/first-seen/RaaS/status-as-facts + seeded badge), the kept **CISA "Initial access & detection"** panel, an **activity** panel (a claim-volume **timeline chart** — pick a deterministic chart from ui-ux-pro-max's set, no heavy new dep; sectors; countries; victim count), a **claimed-victims** list (logo + org + sector + country + date + **plain-text `.onion`** + "unverified claim, per <leak site>"), the ATT&CK fingerprint, related/reporting (link-outs), associated malware, and an **"as of <last_reviewed>"** provenance line. Produce the component structure + tokens; hold dark/Archivo/IBM-Plex-Mono/periwinkle.
- [ ] **Step 2: Logo proxy.** Create `functions/api/favicon.ts` (Cloudflare Pages Function, mirroring `functions/api/enrich`): `GET /api/favicon?d=<domain>` validates the domain, fetches `https://icons.duckduckgo.com/ip3/<domain>.ico` server-side, returns the image bytes same-origin with a long cache header; on any failure returns a 1x1 transparent PNG (so the client falls back to a monogram). This keeps the tight CSP (`img-src 'self'`) intact and never leaks the viewed victim domains to a third party. Client renders `<img src="/api/favicon?d=<domain>">` with an `onError` → monogram (org initials, brand-colored).
- [ ] **Step 3: Implement** the profile per Step 1's design, wiring Task 3's `claimedVictims`/`activity`/`reporting`/`intel`, honest-empty per section, `.onion` as plain non-navigable text, provenance line, seeded-group directory badge (render `hasIntel`).
- [ ] **Step 4: Build + lint** `cd web && npm run build && npm run lint` — PASS; `npx vitest run` — PASS.
- [ ] **Step 5: Commit** `feat(profile): design-pass rebuild + same-origin logo proxy + provenance`.

## Task 6: Provenance / staleness CI check

**Files:** Create `tests/test_intel_staleness.py`. **Interfaces:** none (a guard).
- [ ] **Step 1: Test** that every seed entry's `initial_access_cves` that appears in KEV is flagged if KEV marks it ransomware-associated but the seed lacks it (drift signal), and warns (not hard-fail) when `last_reviewed` is > 180 days before a fixed reference date passed in. Assert the CHECK FUNCTION's behavior on literals (not the live seed's content). - [ ] **Step 2: Implement** the pure check. - [ ] **Step 3: Run pytest** — PASS. - [ ] **Step 4: Commit** `feat(intel): staleness/drift guard for the curated seed`.

## Finishing

Full gates (`pytest`, `vitest`, `build`, `lint`, `extension build`), then **superpowers:finishing-a-development-branch**. After merge/deploy: the **three-lens review** — dispatch a **SOC Analyst** (triage value on a live alert), a **Data Analytics** (aggregations/timeline correct + honest), and a **UX Designer** (IA/formatting/polish/AI-slop) review of the live profile — then a **live dogfood** (re-seeded active group renders full; a claimed victim shows logo + attributed framing; `.onion` plain; provenance present).

---

## Self-Review

**Spec coverage:** §2 R3/sources → Task 1 (attributed facts) + Task 2 (CISA figures/provenance) + constraints; §3.1 collector → Task 1; §3.2 seed → Task 2; §3.3 abuse.ch → Task 4; §3.4 staleness → Task 6; §4 fusion → Task 3; §5 design pass + logos + `.onion` → Task 5; §6 coverage badge → Task 3 (`hasIntel`) + Task 5 (render); §8 review gates → Finishing. No gaps.

**Placeholder scan:** Mechanical tasks (1,2,3,4,6) carry real code/schema. Task 5 is a genuine design activity (invoke `ckm:ui-ux-pro-max`) + a concrete proxy spec — not a code placeholder. The seed re-do (Task 2) is verified curation from cited advisories, with the exact new fields specified.

**Type consistency:** `FeedItem.victim/domain` (Task 1 schema ↔ Task 3 type) match; `ClaimedVictim`/`activity`/`claimedVictims` names consistent Task 3 ↔ Task 5; `RansomIntel` provenance fields (Task 2 seed ↔ Task 3 type ↔ Task 5 render) match; `trackedActors` added to `profileFor` (Task 3) — Task 5 render + the route must pass it (fold the route wiring into Task 5's implement step).
