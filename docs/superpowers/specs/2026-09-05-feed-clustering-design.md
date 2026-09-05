# Feed Cross-Source Clustering + "What Changed" — Design

**Goal:** Move the Desk feed past aggregation. Today every row is 1:1 with one upstream item (`collectors/base.py:64` keys `id = sha1("{source}:{native_id}")`), so two outlets covering the same CVE/actor/campaign are two rows. Cluster items that share a **primary entity** into one **story row** carrying (a) the corroborating sources ("covered by BleepingComputer, THN, Unit 42") and (b) a computed delta ("EPSS 0.71→0.94 · now KEV-listed").

**Owner-approved direction (2026-09-05):** cluster key = the item's primary entity; publish a **sibling `stories.json`** (NOT a breaking `feed.json` schema change — the 1:1 rows stay intact and the story layer is additive); reuse the existing `pipeline/history.py` / `trends.json` delta logic for the "what changed" line.

**Non-goals (v1):** no change to `feed.json`'s shape or the collector id-keying; no per-actor claim-history delta (v1 delta is CVE-only, from the trends data that already exists — actor/malware stories carry corroboration + recency, not a claim delta; that snapshot is v2); no ML/NLP topic clustering (entity-anchored only, deterministic).

---

## Global Constraints
- Free-tier; committed-dataset pattern (schema-gated `stories.json`, `gate()` falls back to prior on INVALID only); tests assert SHAPE on fixtures, never live content.
- **Honesty:** a story states only attributed facts — the member outlets (real `source`s) and a delta computed from committed data (trends/cve_context). No synthesized "story" narrative, no editorial. The representative title is a real member title, attributed.
- **Additive:** `feed.json` is unchanged; `stories.json` references member ids. A client with no story data renders the feed exactly as today.
- react-refresh, no inline styles, `noUnusedLocals`; vitest node env.

---

## §1 Cluster key — the primary entity

Each feed item's cluster key is its most salient entity, chosen deterministically (a CVE anchors more tightly than an actor mention):

```python
def primary_entity(item):  # -> (etype, evalue) | None
    e = item.get("entities") or {}
    if e.get("cves"):    return ("cve", e["cves"][0].upper())
    if e.get("actors"):  return ("actor", e["actors"][0].lower())
    if e.get("malware"): return ("malware", e["malware"][0].lower())
    return None  # nothing to anchor on -> stays a 1:1 feed row, never a story
```

A **story** is a cluster of **≥2 feed items** sharing a primary entity (one member is just a feed row, not a story). This directly satisfies "two outlets on one story render as a single row."

---

## §2 `stories.json` — the sibling payload

Built in `pipeline/publish.py` from the composed `feed.json` items + `trends.json` (for the delta) + `cve_context` (KEV). Schema `schemas/stories.schema.json`, added to `SCHEMA_FOR`, published every run (fresh — derived from the current feed, no keep-prior semantics needed beyond the usual gate).

```jsonc
{ "generated_at", "schema_version": 1,
  "stories": [ {
    "key": "cve:CVE-2024-3400",        // etype:evalue
    "entity": "CVE-2024-3400",
    "entity_type": "cve",               // cve | actor | malware
    "title": "...",                     // the newest member's title, [Outlet]-stripped
    "sources": ["BleepingComputer", "The Hacker News", "Unit 42"],  // distinct outlets, display-named
    "member_ids": ["<sha1>", ...],      // feed.json item ids this story collapses
    "member_count": 3,
    "published_at": "...",              // newest member
    "severity": "high",                 // highest member severity
    "delta": {                          // CVE stories only in v1; omitted otherwise
      "epss_from": 0.71, "epss_to": 0.94, "kev": true, "kev_ransomware": false }
  } ] }
```

**Builder** (`pipeline/stories.py::build_stories(feed_items, trends, cve_context)`):
1. Group `feed_items` by `primary_entity`; keep groups with `len ≥ 2`.
2. Per group: distinct `sources` → display names (reuse the `[Outlet]` title-prefix parse + a source→outlet map); `title` = newest member's title, outlet-prefix stripped; `published_at`/`severity` = newest/max.
3. **Delta (CVE stories):** look the entity CVE up in `trends.epss_movers` (→ `epss_from`/`epss_to`) and `cve_context[cve]` (→ `kev`/`kev_ransomware`). Omit the whole `delta` object when nothing is known (honest-absent).
4. Sort stories by (has-delta desc, member_count desc, published_at desc).

**Honesty on sources:** `sources` are the real member `source` fields mapped to human outlet names; never invented. If two members share a source, it appears once (distinct).

---

## §3 The client — collapse members into a story row

`web/src/components/.../FeedView` (the Desk feed): self-fetch `useStateData('stories')`. Build a `Set` of all `member_ids`. Render:
- one **story row** per story — title + a "covered by N · A, B, C" corroboration line + delta chips (an `EpssMeter` from→to + a `KevBadge` when `delta.kev`), reusing the existing `WhatChanged`/`trendRows` primitives;
- then the normal feed rows for every item whose id is **NOT** in a story (the 1:1 tail);
- stories sort above the singleton tail (they're the corroborated, higher-signal rows).

A story row expands (native `<details>`) to list its member items (each a normal row with its outlet + link), so the collapse is never lossy — the analyst can still reach every source.

**Additive/safe:** if `stories.json` is missing/empty, the feed renders exactly as today (every item a row).

---

## §4 Testing
- **Builder (pytest):** two items sharing a CVE → one story with both sources + member_ids; a single-member entity → NO story; a CVE story joins the trends delta (epss_from/to + kev); an actor story has no `delta`; sources are distinct + display-named.
- **Schema (pytest):** `stories.json` fixture validates; empty `stories:[]` validates; `SCHEMA_FOR` wired.
- **Publish (pytest):** `stories.json` in `build_site_data` (or run_pipeline), built from the composed feed + trends.
- **Client (vitest node):** given feed + stories fixtures, a story row renders the corroboration line + delta chips and the member items are NOT rendered as separate top-level rows; a feed item not in any story renders as a normal row; no stories → feed unchanged.

## §5 Decomposition
- **Plan 1 — backend:** `primary_entity` + `build_stories` + `schemas/stories.schema.json` + `SCHEMA_FOR` + publish wiring + the source→outlet display map. Ships `stories.json`, headless.
- **Plan 2 — client:** the story-row collapse in the feed (self-fetch stories, dedupe member ids, render corroboration + delta, `<details>` member expansion).

## §6 Deferred (v2)
- Per-actor / per-campaign claim-count delta ("3 new claims") — needs a per-entity history snapshot in `pipeline/history.py` (today it snapshots only epss/kev).
- A cluster key that merges an item carrying BOTH a CVE and an actor into the more newsworthy of the two (v1 is CVE-first deterministic).
- "Reports long tail" collapse + ISP-leaderboard right-sizing (OPEN-WORK §3 P3) — separate, smaller.
