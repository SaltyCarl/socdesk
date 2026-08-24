# Ransomware Triage Profile (CISA-sourced) — Design Spec

**Date:** 2026-08-24
**Status:** Approved design, pending implementation plan
**Feature:** Enrich SOCDesk ransomware group profiles with CISA-sourced, triage-grade
intelligence — the initial-access CVEs a group exploits, its #StopRansomware
advisory, key tooling, and in-hand attribution signals (ransom-note names,
encrypted extensions, RaaS flag).

This is **Approach A′** — the pivot of the original "mirror ransomware.live
`/v2/groups`" idea after a critical design review + a SOC-analyst assessment.
It is the first of two phases; the campaign-report / TI-parity page (Approach C)
renders on top of the same group→CVE data layer this builds, and is out of scope
here.

---

## 1. Goal

A tier-1/2 SOC analyst holding a ransomware alert (an EDR detection naming a
group, or a ransom note in hand) should be able to look the group up in SOCDesk
and get, in one view, the things that change what they do next:

- **Which door did they come through** — the known initial-access CVEs the group
  exploits, each clickable into SOCDesk's own CVE lookup (group → CVE →
  KEV/EPSS verdict).
- **The authoritative writeup** — a deep link to the group's CISA #StopRansomware
  advisory (citable to a customer).
- **In-hand attribution** — ransom-note filenames + encrypted-file extensions, so
  a note/extension on screen confirms or denies the group in seconds.
- **Hunting pivots** — the group's known tooling (Rclone, AnyDesk, AdFind, …)
  framed as things to hunt in customer telemetry.
- **Confidence calibration** — a RaaS/affiliate flag (TTPs vary per intrusion).

Orientation the profile already renders (aggregate leak-site sectors/countries,
claim volume, first-seen, aliases) stays; this adds the **triage** layer it lacks.

## 2. Background — why this shape (the pivot)

The original design mirrored ransomware.live's `/v2/groups` (descriptions, TTPs,
tools, leak-site FQDNs) into a committed dataset. Two independent reviews killed
that shape:

- **Compliance (blocker).** `collectors/__init__.py` and `COMPLIANCE.md` R3 record
  a *resolved* project decision: ransomware.live data is **link-out only, never
  mirrored** — R3 is "resolved" *because* of that decision. ransomware.live is
  "© all rights reserved," commercial use prohibited, non-commercial reuse needs
  the publisher's written permission; attribution does not grant the right to
  copy. Committing their prose/TTPs/leak-sites is a mirror and reverses R3. (It
  also freezes their editorial retractions — their `0apt` entry literally reads
  "WE HAVE DECIDED TO REMOVE ENTRIES FOR THIS GROUP.")
- **Utility.** A SOC-analyst assessment judged the mirrored `/groups` content
  *orientation, not triage* — opened once, screenshotted, then abandoned for
  Defender TI / CISA. The content that changes shift behavior (initial-access
  CVEs, the CISA advisory, note/extension signatures) does **not** come from
  ransomware.live `/groups`.

Both point the same way: the highest-value content is **CISA-sourced**, which is
**US-government public domain** — freely redistributable — and is exactly what the
analyst ranked first. This spec builds that instead.

## 3. Non-goals / explicitly dropped

- **No ransomware.live mirror.** No committed dataset of their descriptions,
  TTPs, tools, or leak-site FQDNs. ransomware.live stays **link-out only**: the
  existing feed-derived leak-site *activity* (already link-out to claim sources)
  plus a new "full profile at ransomware.live →" deep link.
- **No `reportsFor` category-widening.** The review showed it is both FP-prone
  (`data/entities/actors.json` contains the common words "Play" and "Akira", and
  `extract_entities` word-boundary-matches them) and ineffective (the long-tail
  groups aren't in the entity dictionary, so it yields reporting only for the
  ~13 high-FP dictionary groups). Left as-is.
- **No synthesized `active/inactive` status.** A leak-site liveness ping is not
  "the group is operating" (LockBit ran through the Cronos seizure); labeling it
  is SOCDesk manufacturing a verdict, which `profiles.ts` doctrine forbids.
- **No synthesized MO prose.** Discrete attributed facts + the advisory link, not
  a paraphrased summary SOCDesk would own.
- **Campaign-report page (Approach C)** is a separate later phase, gated on the
  CARL-KQL vet.

## 4. Compliance & sourcing

- Every seed field is a **discrete public fact** traceable to a cited CISA
  #StopRansomware advisory (a US-gov public-domain document, 17 U.S.C. §105).
  CVE IDs, tool names, note filenames, and extensions are facts, not copyrightable
  expression. The dataset is SOCDesk's own compilation of those facts, each
  attributed to its advisory.
- ransomware.live: **link-out only**, honoring COMPLIANCE.md R3. No content
  mirrored. Record a one-line note beside R3 confirming R3 is upheld (not
  reopened) by this feature.

## 5. Data — the curated seed dataset

A hand-maintained, committed file: **`data/ransomware_intel.json`** (alongside
`data/sources.json`, which follows the same read-and-publish pass-through — see
§6). SOCDesk's own curation; ~30-40 groups at launch (those with #StopRansomware
advisories + major active crews).

Per-group entry:

```json
{
  "slug": "akira",
  "name": "Akira",
  "aliases": ["Storm-1567"],
  "first_seen": "2023-03",
  "raas": true,
  "initial_access_cves": ["CVE-2023-20269", "CVE-2024-40766"],
  "advisory": { "id": "AA24-109A", "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-109a" },
  "tools": ["Rclone", "AnyDesk", "AdFind", "Advanced IP Scanner"],
  "ransom_note": ["akira_readme.txt"],
  "extensions": [".akira", ".powerranges"]
}
```

Field rules:
- `slug` — lowercased name, the address slug (matches the profile system's `#g=`).
- `initial_access_cves[]` — each must match `^CVE-\d{4}-\d{4,7}$`.
- `advisory.url` — must be on `cisa.gov` (schema-enforced host allowlist).
- `raas` boolean; `first_seen` a `YYYY` or `YYYY-MM` string.
- All arrays and strings **length-bounded** in the schema (the 8 MB-cap lesson),
  though ~40 groups is a few KB.

## 6. Pipeline — publish the curated seed (no collector)

The seed is curated, not fetched, so there is **no new collector**. It is
published via the same pass-through `data/sources.json` uses
(`run_pipeline.py`): read the curated file, wrap it in the standard envelope
(`generated_at`, `schema_version`), and add it to `payloads` so it flows through
`gate()` (schema-validate + last-known-good) and the triple dual-write, and is
served to the client.

- Register `"ransomware_intel.json": "ransomware_intel.schema.json"` in
  `pipeline/validate.py` `SCHEMA_FOR`.
- Add `schemas/ransomware_intel.schema.json` (bounded per §5).
- If the curated file is missing/unreadable, degrade to last-known-good (the gate
  already does this when the file is in `prior`); the committed seed guarantees a
  prior exists from run 1.

## 7. Fusion (`web/src/components/views/profiles.ts`)

Add the intel seed as a new snapshot, alongside the existing four
(ATT&CK fingerprint / leak-site activity / reporting / relations):

- **New type** `RansomIntel` mirroring the seed entry.
- **`profileFor`** gains `intel: RansomIntel | null` — the seed entry matched by
  `slug` OR any `alias` (lowercased). Null when the group isn't seeded (honest
  empty; the panel is simply absent).
- **`buildProfileIndex`** gains the seed as a directory source: a seeded group
  gets a directory entry even with no recent claims (coverage for the groups that
  matter). **Merge, don't duplicate** — a seeded slug that is also an ATT&CK actor
  (e.g. Akira) merges its intel onto the existing entry (same pattern as the
  `claimCount` merge), never a second row. Alias collisions resolve first-writer-
  wins against the existing catalogs.
- Pure functions, unit-tested in the node-env vitest (no I/O), same as the rest
  of `profiles.ts`.

## 8. Render (`web/src/components/views/ActorProfile.tsx`)

A new **"Initial access & detection"** `BoardPanel`, shown only when
`profile.intel` is present:

- **Initial-access CVEs** — each rendered as a link into SOCDesk's own CVE lookup
  at `/lookup#q=<CVE>` (the same deep link the omnibox/palette write; verified
  live), so the analyst pivots group → CVE → KEV/EPSS verdict inside the product.
  This is the north-star tie-in (it feeds the core lookup loop) and the reason to
  prefer our own CVE surface over an external link.
- **#StopRansomware advisory** — a labeled external link (`advisory.id` + host),
  `rel="noopener noreferrer"`.
- **Tools** — chips, framed as hunting pivots (a small "hunt for these in
  telemetry" caption).
- **Signatures** — ransom-note filename(s) + encrypted extension(s) in mono, for
  in-hand attribution.
- **RaaS flag** — a neutral chip ("RaaS — affiliate TTPs vary") when `raas`.
- Panel header/footer attributes the data to CISA + the advisory. Doctrine holds:
  attributed facts, no synthesized verdict, honest-absent when unseeded.

The existing panels are unchanged except: add a **"Full profile at
ransomware.live →"** link-out in the activity panel (link-out only, no mirrored
content). `.onion` handling is unchanged (already plain, non-clickable).

## 9. Coverage / directory

A group appears in the profile directory if it is **feed-active OR ATT&CK OR in
the curated seed**. Curated/active entries sort first. No 150-group empty-shell
flood — coverage is "the groups that matter," and a seeded-but-quiet group (a
notable crew with an advisory but no recent claims) now appears where it did not
before.

## 10. Testing

- **`profiles.test.ts`** — the new `intel` fusion: seeded slug resolves; alias
  match resolves; unseeded → null; the Akira actor+intel **merge** yields one
  entry with both fingerprint and intel.
- **Seed schema validation** — a test that `data/ransomware_intel.json` validates
  against its schema, every `initial_access_cves` entry matches the CVE pattern,
  and every `advisory.url` host is `cisa.gov`. (Validate the file's *shape/rules*,
  not a frozen row count — avoid the committed-dataset "is-empty" trap.)
- **Render** — build-gated via tsc+vite+eslint (node-env vitest can't render JSX);
  a small pure helper (e.g. the CVE→lookup href builder) is unit-tested.
- **Live dogfood post-deploy** — `ransomware_intel.json` publishes under cap; a
  seeded group renders the triage panel and its CVE links resolve to real CVE
  verdicts. (The discipline the KEV-due-date work earned.)

## 11. Global Constraints

- Free-tier / no paid APIs / no accounts. The seed is curated public-domain facts;
  no new external fetch at runtime.
- `github.com/SaltyCarl/*`: **no AI attribution** on any commit.
- Honesty doctrine (`shared/verdict/doctrine.ts`, `profiles.ts`): attributed facts
  only; every section degrades to a distinct honest empty; SOCDesk synthesizes no
  verdict.
- COMPLIANCE.md R3 upheld: ransomware.live link-out only.
- Committed-dataset test rule: assert schema/shape, never a live file's exact
  content.
- Deterministic, no ML.

## 12. Build sequence (for the implementation plan)

1. Schema + curated seed file (a small starter set, e.g. Akira, LockBit, Clop,
   BlackCat/ALPHV, Play, Royal, Medusa, BlackBasta, Rhysida, Qilin — groups with
   CISA advisories) + `validate.py` registration + publish pass-through.
2. `profiles.ts` fusion (types, `profileFor.intel`, `buildProfileIndex` merge) +
   unit tests.
3. `ActorProfile.tsx` triage panel + CVE-lookup link + ransomware.live link-out.
4. Wire `ransomware_intel.json` into the web data fetch (`useStateData`) + the
   profile route.
5. Deploy + live dogfood.

Each step is independently testable; step 1 gates 2-4 (they consume its shape).
