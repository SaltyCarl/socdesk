# Ransomware Triage Profile (CISA-sourced) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enrich SOCDesk ransomware group profiles with a curated, CISA-public-domain "Initial access & detection" block (initial-access CVEs, #StopRansomware advisory, tools, ransom-note/extension signatures, RaaS flag), whose CVEs pivot into SOCDesk's own lookup.

**Architecture:** A hand-curated seed file `data/ransomware_intel.json` is published through the pipeline the same way `data/sources.json` is (read → envelope → schema-gate → serve; no collector). The web profile-fusion layer (`profiles.ts`) gains it as a fifth snapshot, and `ActorProfile.tsx` renders a new attributed panel. ransomware.live stays link-out only (COMPLIANCE.md R3).

**Tech Stack:** Python 3.12 pipeline (`run_pipeline.py`, `pipeline/validate.py`), JSON Schema (Draft 2020-12), React 19 + TypeScript + Tailwind v4 (`web/`), node-env Vitest for pure logic, pytest for the pipeline.

**Spec:** `docs/superpowers/specs/2026-08-24-ransomware-triage-profile-design.md`

## Global Constraints

- **Compliance R3:** ransomware.live is LINK-OUT ONLY. Nothing from ransomware.live is committed/mirrored. Every seed field is a discrete public fact from a cited CISA (`cisa.gov`) advisory.
- **Honesty doctrine:** attributed facts only; no synthesized verdict/prose; every section degrades to a distinct honest-empty (an unseeded group simply has no panel).
- **No AI attribution** on any `github.com/SaltyCarl/*` commit (no Co-Authored-By, no Claude/Anthropic).
- **Schema-bound every string and array** in the new schema (the 8 MB-cap lesson). The `advisory.url` schema pattern enforces a `https://www.cisa.gov/` host allowlist.
- **Committed-dataset test rule:** assert schema/shape and field rules, never a live file's exact/empty content or row count.
- Free-tier, deterministic, no ML, no new runtime fetch (the seed is curated).
- Local pytest: `./.venv/Scripts/python.exe -m pytest`. Local vitest: `cd web && npx vitest run`.

---

## File Structure

- **Create** `schemas/ransomware_intel.schema.json` — bounded schema for the published intel payload.
- **Create** `data/ransomware_intel.json` — the curated seed (`{schema_version, groups[]}`; `generated_at` added at publish).
- **Modify** `pipeline/validate.py` — register the new file in `SCHEMA_FOR`.
- **Modify** `run_pipeline.py` — publish the seed via pass-through (derive its path from `sources_path`).
- **Modify** `tests/test_validate.py`, `tests/test_pipeline.py` — schema + publish tests.
- **Modify** `web/src/components/views/types.ts` — `RansomIntel` + `RansomIntelPayload` types.
- **Modify** `web/src/components/views/profiles.ts` — `intelFor`, `profileFor.intel`, `buildProfileIndex` intel merge; `ProfileResult.intel`, `ProfileIndexEntry.hasIntel`.
- **Create** `web/src/components/views/intelHref.ts` — pure `cveLookupHref(cve)` helper (+ test).
- **Modify** `web/src/components/views/profiles.test.ts` — fusion tests.
- **Modify** `web/src/components/views/ActorProfile.tsx` — the "Initial access & detection" panel + ransomware.live link-out.
- **Modify** `web/src/routes/ActorProfileRoute.tsx` — load `ransomware_intel`, thread it into fusion, include `intel` in `hasData`.

---

## Task 1: Curated seed dataset, schema, and pipeline publish

**Files:**
- Create: `schemas/ransomware_intel.schema.json`
- Create: `data/ransomware_intel.json`
- Modify: `pipeline/validate.py:8-20` (SCHEMA_FOR map)
- Modify: `run_pipeline.py:79-80` (after the sources.json pass-through)
- Test: `tests/test_validate.py`, `tests/test_pipeline.py:31-33`

**Interfaces:**
- Produces: a published `ransomware_intel.json` payload `{generated_at, schema_version, groups: RansomIntel[]}` where each group is `{slug, name, aliases[], first_seen?, raas?, initial_access_cves[], advisory:{id,url}, tools[], ransom_note[], extensions[]}`. Task 2 (web types) mirrors this shape.

- [ ] **Step 1: Create the bounded schema**

Create `schemas/ransomware_intel.schema.json`:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["generated_at", "schema_version", "groups"],
  "properties": {
    "generated_at": {"type": "string", "maxLength": 40},
    "schema_version": {"type": "integer"},
    "groups": {"type": "array", "maxItems": 500, "items": {
      "type": "object",
      "required": ["slug", "name"],
      "properties": {
        "slug": {"type": "string", "minLength": 2, "maxLength": 64, "pattern": "^[a-z0-9 ._-]+$"},
        "name": {"type": "string", "minLength": 1, "maxLength": 64},
        "aliases": {"type": "array", "maxItems": 16, "items": {"type": "string", "maxLength": 64}},
        "first_seen": {"type": "string", "maxLength": 10},
        "raas": {"type": "boolean"},
        "initial_access_cves": {"type": "array", "maxItems": 32,
          "items": {"type": "string", "pattern": "^CVE-\\d{4}-\\d{4,7}$"}},
        "advisory": {"type": "object", "required": ["id", "url"],
          "properties": {
            "id": {"type": "string", "maxLength": 32},
            "url": {"type": "string", "maxLength": 256, "pattern": "^https://www\\.cisa\\.gov/"}
          }},
        "tools": {"type": "array", "maxItems": 40, "items": {"type": "string", "maxLength": 64}},
        "ransom_note": {"type": "array", "maxItems": 16, "items": {"type": "string", "maxLength": 128}},
        "extensions": {"type": "array", "maxItems": 16, "items": {"type": "string", "maxLength": 32}}
      }
    }}
  }
}
```

- [ ] **Step 2: Create the curated seed with verified starter entries**

Create `data/ransomware_intel.json`. The three entries below are the concrete pattern (each field traceable to the cited CISA advisory):

```json
{
  "schema_version": 1,
  "groups": [
    {
      "slug": "akira", "name": "Akira", "aliases": ["Storm-1567"],
      "first_seen": "2023-03", "raas": true,
      "initial_access_cves": ["CVE-2023-20269", "CVE-2024-40766"],
      "advisory": {"id": "AA24-109A", "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-109a"},
      "tools": ["Rclone", "AnyDesk", "AdFind", "Advanced IP Scanner", "WinRAR", "Mimikatz"],
      "ransom_note": ["akira_readme.txt"], "extensions": [".akira", ".powerranges"]
    },
    {
      "slug": "clop", "name": "Cl0p", "aliases": ["TA505", "FIN11"],
      "first_seen": "2019-02", "raas": false,
      "initial_access_cves": ["CVE-2023-34362", "CVE-2023-27350", "CVE-2021-27101"],
      "advisory": {"id": "AA23-158A", "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a"},
      "tools": ["Cobalt Strike", "TrueBot", "FlawedAmmyy", "DEWMODE"],
      "ransom_note": ["README.txt", "Cl0pReadme.txt"], "extensions": [".clop", ".Cl0p"]
    },
    {
      "slug": "black basta", "name": "Black Basta", "aliases": [],
      "first_seen": "2022-04", "raas": true,
      "initial_access_cves": ["CVE-2024-1709"],
      "advisory": {"id": "AA24-131A", "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-131a"},
      "tools": ["Cobalt Strike", "Qakbot", "Mimikatz", "Rclone", "SoftPerfect Network Scanner"],
      "ransom_note": ["readme.txt"], "extensions": [".basta"]
    }
  ]
}
```

Then EXPAND to ~10 groups by adding entries for LockBit (`AA23-325A`), ALPHV/BlackCat (`AA23-353A`), Play (`AA23-352A`), Royal (`AA23-061A`), Rhysida (`AA23-319A`), Medusa (`AA25-071A`), and BianLian (`AA23-136A`). For EACH: open the cited CISA #StopRansomware advisory (`https://www.cisa.gov/news-events/cybersecurity-advisories`), and copy only fields the advisory states — CVEs, tools, note filenames, extensions. Omit a field the advisory does not state rather than guessing (honest-empty). `slug` = `name.toLowerCase()`.

- [ ] **Step 3: Register the schema**

In `pipeline/validate.py`, add to the `SCHEMA_FOR` dict (after the `sources.json` line):

```python
    "ransomware_intel.json": "ransomware_intel.schema.json",
```

- [ ] **Step 4: Write the failing schema-validation tests**

Add to `tests/test_validate.py`:

```python
def test_ransomware_intel_seed_validates():
    """The committed seed validates against its schema (shape/rules, not content)."""
    import json
    from pathlib import Path
    seed = json.loads(Path("data/ransomware_intel.json").read_text(encoding="utf-8"))
    payload = dict(seed, generated_at="2026-08-24T00:00:00Z")
    assert validate_payload("ransomware_intel.json", payload, "schemas") == []


def test_ransomware_intel_rejects_bad_cve_and_nonhost_advisory():
    bad = {"generated_at": "x", "schema_version": 1, "groups": [
        {"slug": "x", "name": "X", "initial_access_cves": ["not-a-cve"],
         "advisory": {"id": "A", "url": "https://evil.example/x"}}]}
    errs = validate_payload("ransomware_intel.json", bad, "schemas")
    assert errs != []
```

- [ ] **Step 5: Run the schema tests — expect FAIL then PASS**

Run: `./.venv/Scripts/python.exe -m pytest tests/test_validate.py -q`
Expected first: FAIL (`data/ransomware_intel.json` or the schema not found / not registered). After Steps 1-3 exist, expected: PASS.

- [ ] **Step 6: Add the publish pass-through**

In `run_pipeline.py`, immediately after the sources block (`payloads["sources.json"] = dict(sources, generated_at=iso(now))`), add:

```python
    # Curated ransomware-intel seed (CISA-sourced, public-domain facts) —
    # published like sources.json: read the committed file, envelope it, gate it.
    # No collector: it is curation, not a fetch. Path derived from sources_path so
    # tests that point sources_path at a fixture dir pick up a sibling seed too.
    intel_path = Path(sources_path).parent / "ransomware_intel.json"
    if intel_path.exists():
        payloads["ransomware_intel.json"] = dict(
            json.loads(intel_path.read_text(encoding="utf-8")), generated_at=iso(now))
```

- [ ] **Step 7: Extend the end-to-end publish assertion**

In `tests/test_pipeline.py::test_end_to_end_with_one_source_down`, extend the `published` assertion (line 32-33) to include the new file:

```python
    assert {"feed.json", "cves.json", "health.json", "sources.json",
            "actors.json", "malware.json", "ransomware_intel.json"} <= published
```

(The run uses the real `data/` dir via `sources_path="data/sources.json"`, so the committed seed publishes.)

- [ ] **Step 8: Run the pipeline + full pytest**

Run: `./.venv/Scripts/python.exe -m pytest tests/test_validate.py tests/test_pipeline.py -q`
Expected: PASS. Then `./.venv/Scripts/python.exe -m pytest tests/ -q` — PASS.

- [ ] **Step 9: Commit**

```bash
git add schemas/ransomware_intel.schema.json data/ransomware_intel.json pipeline/validate.py run_pipeline.py tests/test_validate.py tests/test_pipeline.py
git commit -m "feat(intel): curated CISA-sourced ransomware_intel seed + publish"
```

---

## Task 2: Profile fusion (`profiles.ts`)

**Files:**
- Modify: `web/src/components/views/types.ts` (add `RansomIntel`, `RansomIntelPayload`)
- Modify: `web/src/components/views/profiles.ts`
- Test: `web/src/components/views/profiles.test.ts`

**Interfaces:**
- Consumes: the `RansomIntel` shape from Task 1's payload.
- Produces: `intelFor(slug: string, intel: RansomIntel[]): RansomIntel | null`; `profileFor(slug, {actors, malware, feed, relations, intel})` now returns `ProfileResult` with an added `intel: RansomIntel | null`; `buildProfileIndex(actors, malware, feed, intel)` gains a 4th param; `ProfileIndexEntry` gains `hasIntel?: boolean`. Tasks 3-4 consume these.

- [ ] **Step 1: Add the types**

In `web/src/components/views/types.ts`, add:

```ts
export interface RansomIntel {
  slug: string
  name: string
  aliases?: string[]
  first_seen?: string
  raas?: boolean
  initial_access_cves?: string[]
  advisory?: { id: string; url: string }
  tools?: string[]
  ransom_note?: string[]
  extensions?: string[]
}

export interface RansomIntelPayload {
  generated_at?: string
  schema_version?: number
  groups?: RansomIntel[]
}
```

- [ ] **Step 2: Write the failing fusion tests**

Add to `web/src/components/views/profiles.test.ts` (import `buildProfileIndex`, `profileFor`, and add `type RansomIntel` to the type import from `./types`):

```ts
const INTEL: RansomIntel[] = [
  { slug: 'akira', name: 'Akira', aliases: ['Storm-1567'],
    initial_access_cves: ['CVE-2023-20269'],
    advisory: { id: 'AA24-109A', url: 'https://www.cisa.gov/x' },
    tools: ['Rclone'], ransom_note: ['akira_readme.txt'], extensions: ['.akira'], raas: true },
]

describe('intel fusion', () => {
  it('attaches the seed entry to a matching slug', () => {
    const p = profileFor('akira', { actors: [], malware: [], feed: [], relations: null, intel: INTEL })
    expect(p.intel?.advisory?.id).toBe('AA24-109A')
    expect(p.intel?.initial_access_cves).toEqual(['CVE-2023-20269'])
  })
  it('resolves the seed by alias', () => {
    const p = profileFor('storm-1567', { actors: [], malware: [], feed: [], relations: null, intel: INTEL })
    expect(p.intel?.name).toBe('Akira')
  })
  it('is null for an unseeded group', () => {
    const p = profileFor('nitrogen', { actors: [], malware: [], feed: [], relations: null, intel: INTEL })
    expect(p.intel).toBeNull()
  })
  it('lists a seeded-but-quiet group in the directory with hasIntel', () => {
    const idx = buildProfileIndex([], [], [], INTEL)
    const akira = idx.find((e) => e.slug === 'akira')
    expect(akira?.hasIntel).toBe(true)
  })
})
```

- [ ] **Step 3: Run — expect FAIL**

Run: `cd web && npx vitest run profiles`
Expected: FAIL (type errors — `intel` not a param / `p.intel` missing).

- [ ] **Step 4: Implement `intelFor` and thread it through**

In `web/src/components/views/profiles.ts`:

Add the import: `import type { FeedItem, Profile, RelationsPayload, RansomIntel } from './types'` (add `RansomIntel`).

Add the selector (near `findFingerprint`):

```ts
/** The curated CISA intel for a slug — matched by slug OR alias (lowercased).
 *  null when the group is not seeded (honest empty; the panel is absent). */
export function intelFor(slug: string, intel: RansomIntel[]): RansomIntel | null {
  return (
    intel.find(
      (g) =>
        g.slug.toLowerCase() === slug ||
        (g.aliases ?? []).some((a) => a?.toLowerCase() === slug),
    ) ?? null
  )
}
```

Add `intel` to `ProfileResult`:

```ts
export interface ProfileResult {
  slug: string
  name: string
  fingerprint: MitreFingerprint | null
  ransomware: RansomwareActivity | null
  reporting: Report[]
  related: RelatedRow[]
  intel: RansomIntel | null
}
```

In `profileFor`, add `intel` to the `data` param type and compute it (also update the early-return to include `intel: null`):

```ts
export function profileFor(
  slug: string,
  data: {
    actors: Profile[]
    malware: Profile[]
    feed: FeedItem[]
    relations: RelationsPayload | null
    intel: RansomIntel[]
  },
): ProfileResult {
  const s = slug.trim().toLowerCase()
  if (!s) {
    return { slug: '', name: '', fingerprint: null, ransomware: null, reporting: [], related: [], intel: null }
  }
  // ... existing fingerprint/ransomware/reporting/related computation ...
  const intel = intelFor(s, data.intel)
  return { slug: s, name, fingerprint, ransomware, reporting, related, intel }
}
```

- [ ] **Step 5: Add the directory merge to `buildProfileIndex`**

Add `hasIntel?: boolean` to `ProfileIndexEntry`. Add a 4th param `intel: RansomIntel[]` to `buildProfileIndex`, and after the ransomware-claims loop (before the reporting loop), merge the seed — onto an existing entry when present, else a new ransomware-kind row:

```ts
  for (const g of intel) {
    const slug = g.slug.toLowerCase()
    const existing = bySlug.get(slug)
    if (existing) existing.hasIntel = true
    else bySlug.set(slug, { slug, name: g.name, kind: 'ransomware', hasMitre: false, hasIntel: true })
  }
```

- [ ] **Step 6: Run the fusion tests + full vitest**

Run: `cd web && npx vitest run profiles` — PASS. Then `cd web && npx vitest run` — PASS (no regressions).

- [ ] **Step 7: Commit**

```bash
git add web/src/components/views/types.ts web/src/components/views/profiles.ts web/src/components/views/profiles.test.ts
git commit -m "feat(profiles): fuse curated ransomware intel by slug/alias"
```

---

## Task 3: The "Initial access & detection" panel (`ActorProfile.tsx`)

**Files:**
- Create: `web/src/components/views/intelHref.ts`
- Test: `web/src/components/views/intelHref.test.ts`
- Modify: `web/src/components/views/ActorProfile.tsx`

**Interfaces:**
- Consumes: `ProfileResult.intel` (Task 2), `navigate` from `../palette/commands`.
- Produces: a rendered panel; `cveLookupHref(cve: string): string`.

- [ ] **Step 1: Write the failing href-helper test**

Create `web/src/components/views/intelHref.test.ts`:

```ts
import { describe, it, expect } from 'vitest'
import { cveLookupHref } from './intelHref'

describe('cveLookupHref', () => {
  it('builds the in-app CVE lookup deep link', () => {
    expect(cveLookupHref('CVE-2023-20269')).toBe('/lookup#q=CVE-2023-20269')
  })
  it('encodes the query value', () => {
    expect(cveLookupHref('CVE-2023-4966')).toBe('/lookup#q=CVE-2023-4966')
  })
})
```

- [ ] **Step 2: Run — expect FAIL, then implement**

Run: `cd web && npx vitest run intelHref` → FAIL (module missing). Create `web/src/components/views/intelHref.ts`:

```ts
/** In-app CVE lookup deep link — the same `#q=` target the omnibox/palette write,
 *  so a group's initial-access CVE pivots into SOCDesk's own KEV/EPSS verdict. */
export function cveLookupHref(cve: string): string {
  return `/lookup#q=${encodeURIComponent(cve)}`
}
```

Run again: PASS.

- [ ] **Step 3: Add the panel to `ActorProfile.tsx`**

Add imports at the top of `web/src/components/views/ActorProfile.tsx`:

```ts
import { navigate } from '../palette/commands'
import { cveLookupHref } from './intelHref'
import type { RansomIntel } from './types'
```

Add the panel component (near the other panels, e.g. after `MitreFingerprintPanel`):

```tsx
/** In-app CVE link — plain <a> (⌘/middle-click opens a tab) with a left-click
 *  intercepted into SPA navigation, mirroring board-ui's DeskLink. */
function CveLink({ cve }: { cve: string }) {
  const href = cveLookupHref(cve)
  return (
    <a
      href={href}
      onClick={(e) => {
        if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || e.button !== 0) return
        e.preventDefault()
        navigate(href)
      }}
      className="rounded-sm border border-line bg-panel-soft px-1.5 py-0.5 font-mono text-micro text-accent underline-offset-2 transition-colors duration-150 ease-brand hover:border-line-bright hover:underline"
    >
      {cve}
    </a>
  )
}

/** CISA-sourced triage block: initial-access CVEs (pivot into our lookup), the
 *  #StopRansomware advisory, tools as hunting pivots, in-hand attribution
 *  signals, and a RaaS flag. Every fact attributed to CISA; nothing synthesised.
 *  Absent entirely when the group is unseeded. */
function IntelPanel({ intel }: { intel: RansomIntel }) {
  const cves = intel.initial_access_cves ?? []
  const tools = intel.tools ?? []
  const notes = intel.ransom_note ?? []
  const exts = intel.extensions ?? []
  return (
    <div className="flex flex-col gap-5">
      <p className="text-xs leading-relaxed text-muted">
        Initial access, tooling and detection signals below are drawn from the group's CISA
        #StopRansomware advisory — attributed facts, not a SOCDesk assessment.
      </p>

      {cves.length > 0 && (
        <div className="flex flex-col gap-2">
          <SectionLabel accent>Known initial-access CVEs</SectionLabel>
          <div className="flex flex-wrap gap-1.5">
            {cves.map((c) => (
              <CveLink key={c} cve={c} />
            ))}
          </div>
          <p className="text-micro text-faint">Check whether these are exposed on the affected customer.</p>
        </div>
      )}

      {intel.raas && (
        <MonoTag tone="accent">RaaS — affiliate TTPs vary per intrusion</MonoTag>
      )}

      {tools.length > 0 && (
        <div className="flex flex-col gap-2">
          <SectionLabel>Tooling — hunt for these in telemetry</SectionLabel>
          <div className="flex flex-wrap gap-1.5">
            {tools.map((t) => (
              <MonoTag key={t} tone="ghost">{t}</MonoTag>
            ))}
          </div>
        </div>
      )}

      {(notes.length > 0 || exts.length > 0) && (
        <div className="flex flex-col gap-2">
          <SectionLabel>In-hand signatures</SectionLabel>
          {notes.length > 0 && (
            <p className="font-mono text-micro text-muted">
              ransom note: <span className="text-paper">{notes.join(', ')}</span>
            </p>
          )}
          {exts.length > 0 && (
            <p className="font-mono text-micro text-muted">
              extension: <span className="text-paper">{exts.join(', ')}</span>
            </p>
          )}
        </div>
      )}

      {intel.advisory && (
        <ExternalLink href={intel.advisory.url}>
          CISA advisory {intel.advisory.id}
        </ExternalLink>
      )}
    </div>
  )
}
```

- [ ] **Step 4: Render the panel + the ransomware.live link-out**

In the `ActorProfile` component body, add the panel to the left column, after the Fingerprint `BoardPanel` and before "Recent activity":

```tsx
          {profile.intel && (
            <BoardPanel eyebrow="Initial access & detection" accent>
              <IntelPanel intel={profile.intel} />
            </BoardPanel>
          )}
```

In the "Recent activity" panel, when `ransomware` is present, add a link-out footer (after `RansomwareClaims`):

```tsx
              {ransomware && (
                <ExternalLink href={`https://www.ransomware.live/group/${encodeURIComponent(profile.slug)}`}>
                  Full profile at ransomware.live
                </ExternalLink>
              )}
```

- [ ] **Step 5: Build + lint (JSX gate)**

Run: `cd web && npm run build` — PASS (tsc + vite). Then `cd web && npm run lint` — PASS. Then `cd web && npx vitest run intelHref` — PASS.

- [ ] **Step 6: Commit**

```bash
git add web/src/components/views/intelHref.ts web/src/components/views/intelHref.test.ts web/src/components/views/ActorProfile.tsx
git commit -m "feat(profile): initial-access & detection panel with CVE pivot"
```

---

## Task 4: Wire the intel dataset into the profile route

**Files:**
- Modify: `web/src/routes/ActorProfileRoute.tsx`

**Interfaces:**
- Consumes: `RansomIntelPayload` (Task 2), `buildProfileIndex`/`profileFor` new signatures (Task 2).

- [ ] **Step 1: Load the intel payload**

In `web/src/routes/ActorProfileRoute.tsx`, add the type import (`RansomIntelPayload`) and a `useStateData` call beside the others (after `relations`):

```ts
  const intel = useStateData<RansomIntelPayload>('ransomware_intel')
```

- [ ] **Step 2: Thread it into the fusion memos**

Add a stable list memo beside the others:

```ts
  const intelList = useMemo(() => intel.data?.groups ?? [], [intel.data])
```

Update the `buildProfileIndex` call (add `intelList`) and its deps:

```ts
  const index = useMemo(
    () => buildProfileIndex(actorList, malwareList, feedItems, intelList),
    [actorList, malwareList, feedItems, intelList],
  )
```

Update the `profileFor` call (add `intel: intelList`) and its deps:

```ts
  const profile = useMemo(
    () =>
      slug
        ? profileFor(slug, {
            actors: actorList,
            malware: malwareList,
            feed: feedItems,
            relations: relations.data,
            intel: intelList,
          })
        : null,
    [slug, actorList, malwareList, feedItems, relations.data, intelList],
  )
```

- [ ] **Step 3: Include `intel` in `hasData`**

So a seeded-but-quiet group (no fingerprint/claims/reporting/relations) still renders:

```ts
  const hasData = Boolean(
    profile &&
      (profile.fingerprint ||
        profile.ransomware ||
        profile.reporting.length ||
        profile.related.length ||
        profile.intel),
  )
```

- [ ] **Step 4: Build + lint + full vitest**

Run: `cd web && npm run build` — PASS. `cd web && npm run lint` — PASS. `cd web && npx vitest run` — PASS.

- [ ] **Step 5: Commit**

```bash
git add web/src/routes/ActorProfileRoute.tsx
git commit -m "feat(profile): wire ransomware_intel into the profile route"
```

---

## Finishing

After Task 4, run the full gates once more (`./.venv/Scripts/python.exe -m pytest tests/ -q`; `cd web && npx vitest run`; `cd web && npm run build && npm run lint`; `cd extension && npm run build` — the shared card is unaffected but confirm parity). Then use **superpowers:finishing-a-development-branch**. After merge + push + deploy, **dogfood live** (the discipline this project earned): confirm `ransomware_intel.json` publishes under cap (`problems=[]`), open a seeded group's profile (e.g. `/actor#g=akira`), verify the "Initial access & detection" panel renders and a CVE link navigates to that CVE's lookup verdict.

---

## Self-Review

**Spec coverage:** §5 seed → Task 1 Steps 1-2; §6 publish pass-through → Task 1 Steps 3,6,7; §7 fusion (intelFor/profileFor/buildProfileIndex merge) → Task 2; §8 render (panel + CVE pivot + link-out) → Task 3; §9 coverage (hasIntel directory + hasData) → Task 2 Step 5 + Task 4 Step 3; §10 testing → each task's tests + Finishing dogfood; §3 dropped items (no widening/status/mirror) → nothing in the plan adds them; §4 compliance (cisa.gov host allowlist) → Task 1 schema pattern. No gaps.

**Placeholder scan:** All code steps carry real code. The seed's group-list expansion (Task 1 Step 2) is curation of verified public facts, with three concrete verified entries as the pattern and explicit per-field verification instructions — not a code placeholder.

**Type consistency:** `RansomIntel`/`RansomIntelPayload` (Task 2 Step 1) match the payload shape (Task 1) and are consumed unchanged in Tasks 3-4. `profileFor` gains `intel` in both the param object and the return (`ProfileResult.intel`), used as `profile.intel` in Tasks 3-4. `buildProfileIndex` gains the 4th `intel` param (Task 2 Step 5), passed as `intelList` (Task 4 Step 2). `cveLookupHref`/`CveLink`/`IntelPanel` names are consistent across Task 3. `useStateData<RansomIntelPayload>('ransomware_intel')` matches the published filename `ransomware_intel.json`.
