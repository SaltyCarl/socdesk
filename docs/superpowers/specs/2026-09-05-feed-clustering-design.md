# Feed Cross-Source Clustering + "What Changed" — Design

**Goal:** Move the Desk feed past aggregation. Today every row is 1:1 with one upstream item (`collectors/base.py:64` keys `id = sha1("{source}:{native_id}")`), so two OUTLETS covering the same CVE/actor are two rows. Cluster items that share a **primary entity** AND are **corroborated by ≥2 distinct outlets** into one **story** carrying (a) the corroborating outlets ("covered by BleepingComputer, THN, Unit 42") and (b) a computed delta ("EPSS 0.71→0.94 · now KEV-listed").

**Owner-approved direction (2026-09-05):** cluster key = primary entity; publish a **sibling `stories.json`** (no `feed.json` schema change); reuse the delta primitives.

> **Revised after adversarial vet (2026-09-05, against live `data/state/*.json`).** Four ship-breaking corrections folded in: (1) all 9 news outlets share `source="rss"` — corroboration/dedup MUST key on the `[Outlet]` title prefix (`FeedView.tsx:64 OUTLET_RE`), PORTED to Python; (2) a story requires **≥2 distinct OUTLETS**, not ≥2 members — this excludes the 46 single-outlet `ransomwarelive`-only "clusters" that are leak tallies already shown on Profiles (25 of 73 clusters qualify); (3) the CVE delta comes from **`cve_rows` (cves.json catalog)** — `cve_context` covers 0/20 live CVE stories; (4) stories build in **`run_pipeline.py` after `trends.json` (line ~201)**, not in `build_site_data` (no trends there). Plus: an **established-entity gate** on actor keys (kills the "play" = Google Play false positive, per `profiles.ts:905`); schema + `SCHEMA_FOR` MUST land with the payload (a missing `SCHEMA_FOR` entry is a `KeyError` that kills the whole run, `validate.py:36`).

**Non-goals (v1):** no `feed.json`/collector change; no per-actor claim-count delta (needs a history snapshot — v2); no NLP topic clustering (entity + outlet, deterministic).

---

## Global Constraints
- Free-tier; committed-dataset pattern (`stories.json` schema-gated; `gate()` falls back to prior on INVALID only); tests assert SHAPE on fixtures.
- **Honesty:** a story states only attributed facts — real member outlets and a delta from committed catalog data. No synthesized narrative. Representative title = a real member's outlet-stripped title.
- **Additive:** `feed.json` unchanged; a client with no story data renders the feed exactly as today.
- react-refresh, no inline styles, `noUnusedLocals`; vitest node env.

---

## §1 Cluster key + the corroboration threshold

Primary entity per item, deterministic (a CVE anchors more tightly than an actor mention); actor keys pass the established-entity gate:

```python
def primary_entity(item, established):  # -> (etype, evalue) | None
    e = item.get("entities") or {}
    if e.get("cves"):    return ("cve", e["cves"][0].upper())
    # established gate (port of profiles.ts `keep`): an actor anchors a story only
    # when it is a real tracked entity — kills "play" (Google Play) fusing news +
    # Play-ransomware claims. `established` = actors with an ATT&CK fingerprint OR
    # an intel seed OR >=1 leak-site claim (computed once from actors/intel/feed).
    if e.get("actors") and e["actors"][0].lower() in established:
        return ("actor", e["actors"][0].lower())
    if e.get("malware"): return ("malware", e["malware"][0].lower())
    return None  # nothing to anchor -> stays a 1:1 feed row, never a story
```

**A story = a cluster whose members span ≥2 DISTINCT OUTLETS.** Outlet is derived per member (§2), not the `source` field. This is the load-bearing rule: it keeps only genuinely cross-corroborated items (25 of 73 live clusters) and excludes single-outlet leak-tally clusters (which Profiles already aggregates). Members are the last 30 days (the feed window); cap at 12 members per story (a huge actor never becomes one giant row — the newest 12 by `published_at`).

---

## §2 `stories.json` — the sibling payload

Built in `run_pipeline.py` (§4) from the composed feed items + `cve_rows` + `trends`. Schema `schemas/stories.schema.json`, added to `SCHEMA_FOR` **in the same change** (a missing entry is a run-killing `KeyError`).

```jsonc
{ "generated_at", "schema_version": 1,
  "stories": [ {
    "key": "cve:CVE-2026-59310", "entity": "CVE-2026-59310", "entity_type": "cve",
    "title": "...",                       // newest member's title, [Outlet]-stripped
    "outlets": ["BleepingComputer", "The Hacker News", "Unit 42"],  // distinct, display-named
    "member_ids": ["<sha1>", ...], "member_count": 3,
    "published_at": "...", "severity": "high",
    "delta": {                            // present when catalog data exists (honest-absent otherwise)
      "kev": true, "kev_ransomware": false, "epss": 0.94,
      "epss_from": 0.71, "epss_to": 0.94 }  // from/to only when the CVE is a trends epss_mover
  } ] }
```

**Builder** (`pipeline/stories.py`):
- `story_outlet(item)` — PORT of `FeedView.tsx:64/93 sourceLabel`: `rss` → the `[Outlet]` prefix via `OUTLET_RE = r"^\s*\[([^\]]+)\]"`; `kev` → "CISA KEV"; `ransomwarelive` → "ransomware.live"; else the `source`. (TS can't be reused across the language boundary — this is a small Python port with a shared-shape test.)
- `established_actors(actors, intel, feed_items)` — lowercased set with an ATT&CK fingerprint OR intel seed OR ≥1 ransomwarelive claim (mirrors `profiles.ts` `keep`).
- `build_stories(feed_items, cve_rows, trends, actors, intel)`:
  1. group by `primary_entity`; per group compute distinct `outlets`; DROP groups with `<2` outlets;
  2. `title` = newest member title outlet-stripped (`OUTLET_RE` removed); `published_at`/`severity` = newest/max; `member_ids` newest-first, capped 12;
  3. **delta (CVE only):** join `cve_rows` by the entity CVE → `kev`, `kev_ransomware`, `epss`, `cvss`; then `trends.epss_movers` for the same CVE → `epss_from`/`epss_to`. Omit `delta` when the CVE isn't in the catalog (honest-absent). Actor/malware stories carry no `delta` in v1.
  4. sort by (has-delta desc, kev desc, member_count desc, published_at desc).

---

## §3 The client — a "Corroborated" strip in the briefing

`FeedView` is PROP-DRIVEN and renders a BRIEFING (masthead + one Lead + category Sections capped at 5), NOT a flat list. So:
- **Fetch in the route:** `FeedRoute.tsx` already `useStateData('feed')` — add `useStateData('stories')` and pass `stories` as a prop to `FeedView` (keeps FeedView pure + fixture-testable).
- **Render a "Corroborated stories" section** at the TOP of the briefing (above the Lead), only in the default briefing view (`filter==='all'`, no query) and only for stories with a delta OR ≥3 outlets (the highest-signal). Each story row: the outlet-stripped title + a "covered by N · A, B, C" line + delta chips — a `KevBadge` (`Badges.tsx`) when `delta.kev` and an EPSS from→to via `epssShift`/the `trendRows` primitive (NOT `EpssMeter`, which is single-value). Native `<details>` expands to the member items (each a normal row with its outlet + link) — the collapse is never lossy.
- **De-dup the briefing:** build a `Set(member_ids)`; exclude those ids from the Lead + Sections so a corroborated item shows once (as its story), not again as a member. If the Lead would have been a story member, the next-ranked non-member becomes the Lead.
- In list-mode (a lens filter or a search query), stories are NOT injected (the analyst asked for a filtered/ranked list) — v1 keeps stories to the default briefing. (Lens-aware stories are a v2 refinement.)
- **Additive/safe:** no `stories.json`, or `stories:[]` → the briefing renders exactly as today.

---

## §4 Build location (exact)
In `run_pipeline.py`, AFTER `payloads["trends.json"]` is set (~line 200) and BEFORE `gate()` (~line 234):
```python
payloads["stories.json"] = build_stories(
    payloads["feed.json"]["items"], cve_rows, payloads["trends.json"],
    actor_list, intel_groups)
```
`cve_rows` (unconditional, :128), the composed scored feed items, and `trends.json` are all in scope there; `actor_list`/`intel_groups` are the ATT&CK actors + the loaded intel seed (already read for `actors.json`/`ransomware_intel.json`). Stories inherit the gate + last-known-good + dual-write into `web/public/data/state/`.

---

## §5 Testing
- **Builder (pytest):** two rss items on one CVE from DIFFERENT `[Outlet]`s → one story, outlets=[both], delta from `cve_rows` (kev/epss); two items same CVE same outlet → NO story (<2 outlets); a `('actor','play')` group where `play`∉established → NO story (the false-positive gate); an established actor covered by 2 outlets → a story with no `delta`; member cap at 12; title is outlet-stripped.
- **`story_outlet` (pytest):** `[BleepingComputer] X` → "BleepingComputer"; a kev item → "CISA KEV"; a ransomwarelive item → "ransomware.live".
- **Schema (pytest):** `stories.json` fixture validates; `stories:[]` validates; `SCHEMA_FOR` wired (guard the KeyError).
- **Client (vitest node):** given feed + stories props, the Corroborated section renders the corroboration line + delta chips; member items are excluded from the Lead/Sections; a non-member renders normally; no stories prop → briefing unchanged.

## §6 Decomposition
- **Plan 1 — backend:** `pipeline/stories.py` (`story_outlet`, `established_actors`, `primary_entity`, `build_stories`) + `schemas/stories.schema.json` + `SCHEMA_FOR` + the `run_pipeline.py` wiring. Ships `stories.json`, headless + gate-validated.
- **Plan 2 — client:** `FeedRoute` fetch + the Corroborated briefing section + member de-dup + `<details>` expansion.

## §7 Deferred (v2)
- Per-actor/campaign claim-count delta ("3 new claims") — needs a per-entity history snapshot.
- Lens/search-aware story injection (v1 = default briefing only).
- Reports long-tail collapse + ISP-leaderboard right-sizing (OPEN-WORK §3 P3).
