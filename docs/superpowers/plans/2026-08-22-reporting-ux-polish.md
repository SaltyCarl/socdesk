# IOC Reporting UX Polish Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring the shipped-but-under-discoverable IOC reporting write path up to SOCDesk's polish standard without disturbing the no-account lookup loop: a quiet-until-relevant contributor account control in the nav, a real Report button in the escalation-card action row, a modal `ReportDialog` with a full terminal state machine + OAuth draft preservation, a system-composed My-reports view, and a legibility pass — all composed from the shipped primitives.

**Architecture:** All new UI is React 19 in `web/` composing the shared primitives (`Button`/`buttonClasses`, `Panel`/`Card`, `MicroLabel`, `Chip`, `Divider`, `shared/lib/motion`, the `CommandPalette` `<dialog>` overlay pattern, the `SourceLedger` row). The reporting write path (GitHub OAuth + Turnstile + D1) is UNCHANGED — this is presentation + client state only, plus one one-line backend addition (`mine.js` echoes `login`). The read/lookup/analyzer path stays 100% no-account, and the account chrome fires **no** network probe until a browser has engaged reporting (`contributorSeen` gate).

**Tech Stack:** React 19 (`web/`), Tailwind v4 (`shared/tokens.css`), Motion.dev (WAAPI via `shared/lib/motion`), native `<dialog>`/`showModal()`, Cloudflare Pages Functions (JS) for `mine.js`, vitest (node env). No new dependencies.

**Spec:** `docs/superpowers/specs/2026-08-21-reporting-ux-polish-design.md`

## Global Constraints

- **Reserved-colour law:** success/confirmation is a UI event, NOT a verdict — the accent-stroked checkmark + `--paper` text (`CardActions.tsx` precedent), NEVER `text-verdict-green` (green already means "a source found nothing adverse"). Report **category** and **status** chips use `Chip variant="neutral"|"accent"` only; amber (`--gold`) appears ONLY on genuine policy outcomes (banned / capped). (spec §"Reserved-colour law", §C, §D)
- **Compose from existing primitives.** No hand-rolled `<div className="rounded-md border…">` — use `Button`/`buttonClasses`, `Panel`/`Card`, `MicroLabel`, `Chip`, `Divider`, `shared/lib/motion`, the `Notice` component, the `SourceLedger` row, and the `CommandPalette` `<dialog>` pattern. (spec §"Design law")
- **Narrow contributor identity — no read-loop features.** The account stays report + my-reports only. No watchlists, saved indicators, change-alerts, or enrich rate-limit tiers; no new read-path gating. (spec §"Non-goals")
- **Legibility.** Any text the user must actually READ (field labels, the indicator value, evidence/comment, meaning-bearing counters, error/success copy, menu/identity rows) uses `--muted` or `--paper`, NEVER `--faint`, and never `text-micro` faint for meaning. `--faint` is incidental adornment only. Do NOT retune the shared `--faint` token — fix the USAGE. (spec §"Legibility", §E)
- **NO AI attribution in any commit — SaltyCarl policy.** Every `git commit` in this plan is a plain conventional-commit message with NO `Co-Authored-By`, NO `Claude-Session`, NO Claude/Anthropic reference. Author identity **SaltyCarl**.

## Ground-truth corrections (verified against the repo — these OVERRIDE the spec text)

1. **Logout endpoint is `POST /api/auth/logout`** (`functions/api/auth/logout.js:2`), NOT `/api/auth/github/logout` as spec §A writes. Use the real path.
2. **Test harness is node-only pure logic.** `web/vitest.config.ts:27-29` sets `environment: 'node'` and `include: ['src/**/*.test.ts', '../shared/**/*.test.ts', '../lib/**/*.test.mjs']` — no jsdom, no `@testing-library/react` (confirmed absent from `web/package.json`), and `.test.tsx` is NOT collected. React components therefore CANNOT be render-tested here. This plan follows the shipped Phase 0+1 precedent (its React surfaces shipped with pure-logic vitest + build gate + a live dogfood pass): **every task extracts its decision logic into a pure, node-testable module and TDDs THAT**; the JSX wiring is gated by `tsc` (`npm --prefix web run build`) + the full green suite + the documented live dogfood pass. Tasks 3, 4, and 12 are pure JSX/doc plumbing with no extractable logic beyond a sibling task's module — their gate is the typecheck + full suite (called out explicitly, not a placeholder). Adding jsdom + a react-plugin vitest project is a deliberate, out-of-scope infra change — flag it to the owner, do not fold it in here.
3. **Part E supersedes Part C on the evidence/comment counters.** Spec §C says the counter goes "faint→amber near cap"; spec §E (owner constraint, later-dated) bans `--faint` for meaning-bearing text. The counter IS meaning-bearing, so it uses `text-muted` at rest and `text-verdict-amber` near the cap — never `text-faint`.

## Implementer notes (verify at the build gate)

- Several JSX snippets assume a primitive's prop API — `MicroLabel` with `as="label"`
  (Tasks 8), `Panel`/`Card` with `padding="sm"|"none"` (Tasks 6, 10), `Notice` with
  `eyebrow`/`title` + children (Task 10), `ViewHeader` with `eyebrow`/`title`/`intro`
  (Task 10). READ the actual component before wiring and match its real API; if a prop
  differs (e.g. `MicroLabel` has no `as`, wrap the label element yourself; `Notice`
  takes a `tone` not an `eyebrow`), adapt the JSX — the `tsc` build gate + full suite
  are the enforcement, and the pure tested modules are unaffected either way.
- Reserved-colour judgment call (spec-sanctioned): the char counter uses
  `text-verdict-amber` near the cap (Ground-truth #3 / spec §E). If the task reviewer
  reads a near-limit counter as too close to a verdict signal, a neutral warning
  treatment is an acceptable substitution — flag it, don't silently diverge.

## Verification gate (every task)

- The task's own new test file first (RED then GREEN): `cd web && npx vitest run <path>`.
- Then the FULL suite green (existing 434 must stay passing): `cd web && npx vitest run`.
- For any task that touches `.tsx`/`.ts` app code: `npm --prefix web run build` (tsc typecheck) clean.
- Commit only when all of the above pass.

---

## File Structure

**Create**
- `web/src/lib/useSession.ts` — RELOCATED hook (from `components/report/useSession.ts`) + pure `sessionStateFrom(status, body)` probe→state map. Shell-level chrome now, not report-only.
- `web/src/lib/useSession.test.ts` — pure `sessionStateFrom` mapping test.
- `web/src/lib/contributorSeen.ts` — `sd_contributor` localStorage bit (SSR-safe get/set).
- `web/src/lib/contributorSeen.test.ts` — get/set + storage-blocked test.
- `web/src/lib/accountChrome.ts` — pure `shouldProbeSession(seen)` + `accountView(seen, status)` (Part A truth table).
- `web/src/lib/accountChrome.test.ts` — truth-table + no-probe-when-unseen test.
- `web/src/lib/contrast.ts` — WCAG `contrastRatio` + the dark/light token hexes + readable-token set (Part E automatable half).
- `web/src/lib/contrast.test.ts` — readable ≥ AA on every surface; `--faint` < AA (usage-ban proof).
- `web/src/components/ui/AccountControl.tsx` — quiet-until-relevant nav control (Sign-in link ↔ `@handle` menu).
- `web/src/components/report/dialogView.ts` — pure `dialogView(status)` base-screen selector.
- `web/src/components/report/dialogView.test.ts` — selector test.
- `web/src/components/report/reportOutcome.ts` — pure `reportOutcome(status, body)` terminal-state map (the state machine core).
- `web/src/components/report/reportOutcome.test.ts` — exhaustive response→state test.
- `web/src/components/report/draft.ts` — sessionStorage draft `draftKey`/`save`/`load`/`clear` (SSR-safe).
- `web/src/components/report/draft.test.ts` — key format + round-trip + malformed/blocked tests.
- `web/src/components/report/reportChrome.ts` — exported success/policy class-string constants (reserved-colour, guard-testable).
- `web/src/components/report/reportChrome.test.ts` — reserved-colour guard (success carries no `verdict-*`).
- `web/src/components/report/ReportDialog.tsx` — the modal report form (replaces `ReportForm.tsx`).
- `web/src/routes/myReportsModel.ts` — pure `statusChipVariant(status)` (neutral/accent, never verdict).
- `web/src/routes/myReportsModel.test.ts` — status→variant test.
- `docs/DESIGN-TOKENS.md` — the `web/`-scoped token reference (side task).

**Modify**
- `shared/ui/buttonClasses.ts` — add the `tertiary` variant.
- `shared/ui/buttonClasses.test.ts` — NEW test file for the variant (lives beside the source; matched by `../shared/**/*.test.ts`).
- `shared/verdict-cards/EscalationCard.tsx` — optional `reportSlot?: ReactNode` in the header action row (after `CardActions`, behind a vertical `Divider`).
- `web/src/components/report/ReportButton.tsx` — real `Button variant="tertiary" size="sm"` + flag glyph; opens `ReportDialog`; marks `contributorSeen`; auto-reopens on a restored draft.
- `web/src/routes/Lookup.tsx` — pass `reportSlot` into `EscalationCard` (remove the `mt-2` below-card div).
- `web/src/components/ui/Topbar.tsx` — insert `<AccountControl/>` before `<ThemeToggle/>` in the right cluster.
- `web/src/components/ui/index.ts` — export `AccountControl`.
- `web/src/routes/MyReports.tsx` — redesign with `ViewHeader` + `Panel`/`SourceLedger` rows + status `Chip` + `Notice`.
- `functions/api/report/mine.js` — return `login` in the body.

**Delete**
- `web/src/components/report/useSession.ts` — moved to `web/src/lib/useSession.ts`.
- `web/src/components/report/ReportForm.tsx` — replaced by `ReportDialog.tsx` (in Task 8).

---

### Task 1: Shared session foundation — relocate `useSession`, extend `SessionState`, echo `login`

**Files:**
- Create: `web/src/lib/useSession.ts`, `web/src/lib/useSession.test.ts`
- Delete: `web/src/components/report/useSession.ts`
- Modify: `functions/api/report/mine.js:8`; `web/src/components/report/ReportForm.tsx:11` (import path only)

**Interfaces:**
- Produces: `type SessionState = { status: 'loading' | 'in' | 'out'; login?: string }`; `function sessionStateFrom(status: number, body: { login?: string } | null): SessionState`; `function useSession(): SessionState`.
- Consumes: `functions/api/report/mine.js` now responds `{ reports, login }` (200) — `requireSession` already decodes `p.login` (`functions/_lib/session.mjs:9`).

- [ ] **Step 1 — write the failing test** (`web/src/lib/useSession.test.ts`):

```ts
import { describe, expect, it } from 'vitest'
import { sessionStateFrom, type SessionState } from './useSession'

describe('sessionStateFrom — /api/report/mine probe → session state', () => {
  it('200 with a login is signed in, carrying the handle', () => {
    expect(sessionStateFrom(200, { login: 'octocat' })).toEqual<SessionState>({
      status: 'in',
      login: 'octocat',
    })
  })
  it('200 with no login is still signed in (login is optional)', () => {
    expect(sessionStateFrom(200, {})).toEqual<SessionState>({ status: 'in', login: undefined })
  })
  it('401 is signed out', () => {
    expect(sessionStateFrom(401, null)).toEqual<SessionState>({ status: 'out' })
  })
  it('a 5xx / unexpected status is signed out — never optimistically in', () => {
    expect(sessionStateFrom(503, null).status).toBe('out')
  })
})
```

- [ ] **Step 2 — run it, expect FAIL:** `cd web && npx vitest run src/lib/useSession.test.ts` → "Cannot find module './useSession'".

- [ ] **Step 3 — implement `web/src/lib/useSession.ts`:**

```ts
// useSession — Shell-level chrome (relocated from components/report). Probes
// GET /api/report/mine: 200 = signed in (echoing the GitHub login), anything
// else = signed out. Only guards the WRITE (report) path — the lookup/analyzer
// read path stays no-account.

import { useEffect, useState } from 'react'

export type SessionState = { status: 'loading' | 'in' | 'out'; login?: string }

/** Pure map of a probe (HTTP status + parsed body, or null on network/parse
 *  failure) to session state. Side-effect-free, so node-testable. */
export function sessionStateFrom(status: number, body: { login?: string } | null): SessionState {
  if (status === 200) return { status: 'in', login: body?.login }
  return { status: 'out' }
}

export function useSession(): SessionState {
  const [s, setS] = useState<SessionState>({ status: 'loading' })
  useEffect(() => {
    let live = true
    fetch('/api/report/mine', { credentials: 'same-origin' })
      .then(async (r) => {
        const body = await r.json().catch(() => null)
        if (live) setS(sessionStateFrom(r.status, body))
      })
      .catch(() => {
        if (live) setS({ status: 'out' })
      })
    return () => {
      live = false
    }
  }, [])
  return s
}
```

- [ ] **Step 4 — relocate + rewire:** delete `web/src/components/report/useSession.ts`; in `web/src/components/report/ReportForm.tsx` change `import { useSession } from './useSession'` (line 11) to `import { useSession } from '../../lib/useSession'`.

- [ ] **Step 5 — echo `login`** in `functions/api/report/mine.js` line 8, replacing the body:

```js
  return new Response(JSON.stringify({ reports, login: user.login }), { status: 200, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } })
```

- [ ] **Step 6 — run it, expect PASS:** `cd web && npx vitest run src/lib/useSession.test.ts`.
- [ ] **Step 7 — full suite + build:** `cd web && npx vitest run` (434 + 4 green) and `npm --prefix web run build` clean.
- [ ] **Step 8 — commit:**

```bash
git add web/src/lib/useSession.ts web/src/lib/useSession.test.ts web/src/components/report/ReportForm.tsx functions/api/report/mine.js
git rm web/src/components/report/useSession.ts
git commit -m "refactor(session): relocate useSession to lib, add login to SessionState + mine.js"
```

---

### Task 2: `tertiary` Button variant

**Files:**
- Modify: `shared/ui/buttonClasses.ts:13` (union), `:22-28` (`VARIANT` map), `:3-12` (doc comment)
- Test: `shared/ui/buttonClasses.test.ts` (new; matched by vitest include `../shared/**/*.test.ts`)

**Interfaces:**
- Produces: `type ButtonVariant = 'primary' | 'ghost' | 'tertiary' | 'danger'`; `buttonClasses('tertiary', 'sm')` → the borderless-until-hover, muted-ink skin at the `sm` box (`h-8 gap-1.5 px-3 text-xs`).
- Consumes: `cx` (`shared/lib/cx`), unchanged `BASE`/`SIZE` (`shared/ui/buttonClasses.ts:16-33`).

- [ ] **Step 1 — write the failing test** (`shared/ui/buttonClasses.test.ts`):

```ts
import { describe, expect, it } from 'vitest'
import { buttonClasses } from './buttonClasses'

describe('buttonClasses — tertiary variant (discoverable, not competing)', () => {
  it('is borderless-until-hover, muted ink, revealing paper on hover', () => {
    const c = buttonClasses('tertiary', 'sm')
    expect(c).toContain('border-transparent')
    expect(c).toContain('text-muted')
    expect(c).toContain('hover:border-line')
    expect(c).toContain('hover:bg-panel-soft')
    expect(c).toContain('hover:text-paper')
  })
  it('shares the sm box with its row-mates (h-8 / px-3 / text-xs)', () => {
    const c = buttonClasses('tertiary', 'sm')
    expect(c).toContain('h-8')
    expect(c).toContain('px-3')
    expect(c).toContain('text-xs')
  })
  it('carries NO verdict/severity colour (reserved-colour law)', () => {
    expect(buttonClasses('tertiary', 'sm')).not.toMatch(/verdict-|--red|--gold|--green/)
  })
})
```

- [ ] **Step 2 — run it, expect FAIL:** `cd web && npx vitest run ../shared/ui/buttonClasses.test.ts` → assertion fails (no `border-transparent` in the primary skin the default resolves to; and `'tertiary'` is not an accepted variant type).

- [ ] **Step 3 — implement** in `shared/ui/buttonClasses.ts`. Update the type on line 13:

```ts
export type ButtonVariant = 'primary' | 'ghost' | 'tertiary' | 'danger'
```

Add the entry to `VARIANT` (keeps a reserved 1px transparent border so hover reveals the hairline with no layout shift):

```ts
  tertiary:
    'border border-transparent bg-transparent text-muted hover:border-line hover:bg-panel-soft hover:text-paper',
```

Extend the doc block (lines 3-12) with one line:

```ts
 *   tertiary · borderless/muted → hover reveals — "discoverable but not
 *              competing" actions (e.g. Report in the card action row)
```

- [ ] **Step 4 — run it, expect PASS:** `cd web && npx vitest run ../shared/ui/buttonClasses.test.ts`.
- [ ] **Step 5 — full suite + build:** `cd web && npx vitest run` green; `npm --prefix web run build` clean.
- [ ] **Step 6 — commit:**

```bash
git add shared/ui/buttonClasses.ts shared/ui/buttonClasses.test.ts
git commit -m "feat(button): add tertiary variant for discoverable-not-competing actions"
```

---

### Task 3: `EscalationCard` gains optional `reportSlot`

**Files:**
- Modify: `shared/verdict-cards/EscalationCard.tsx:21` (import `Divider`), `:61-76` (props), `:94-100` (header action row)

**Interfaces:**
- Produces: `EscalationCard` accepts `reportSlot?: ReactNode`, rendered in the header row after `CardActions`, separated by a vertical `Divider`. Omitted by every other consumer (extension/cockpit/inline) → unchanged render.
- Consumes: `Divider` (`shared/ui`), `CardActions` (already imported at `EscalationCard.tsx:20`).

**Note (harness):** pure JSX plumbing — no extractable logic. Gate is `tsc` + full suite green + the live dogfood pass (per the harness note above). No isolated unit test is added; the slot's presence is exercised by Task 4's Lookup wiring and confirmed visually in the dogfood pass.

- [ ] **Step 1 — add the import** to `shared/verdict-cards/EscalationCard.tsx` line 21 (extend the existing `../ui` import to include `Divider`):

```ts
import { Chip, Divider, MicroLabel, type ChipVariant } from '../ui'
```

- [ ] **Step 2 — add the prop** to the component signature (after `onCompare`, around line 75), and its JSDoc:

```ts
  onCompare,
  /** Web-only reporting affordance (a ReportButton). Rendered in the header
   *  action row after CardActions, behind a vertical Divider. Only Lookup.tsx
   *  passes it; every other consumer omits it and renders unchanged. */
  reportSlot,
}: {
  data: VerdictData
  theme?: CanvasTheme
  baseUrl?: string
  onCompare?: (c: CompareResult | null) => void
  reportSlot?: ReactNode
}) {
```

Add the `ReactNode` type import to the React import at line 13:

```ts
import { useState, type ReactNode } from 'react'
```

- [ ] **Step 3 — render the slot** in the header action row (lines 97-99), replacing the `<div className="ml-auto">` wrapper. Use an `items-stretch` row so the vertical `Divider`'s `h-full` resolves to the button height (no arbitrary height, no `!important`):

```tsx
          <div className="ml-auto flex items-stretch gap-2">
            <CardActions data={data} theme={theme} compare={compare} />
            {reportSlot && (
              <>
                <Divider orientation="vertical" className="self-stretch" />
                <div className="flex items-center">{reportSlot}</div>
              </>
            )}
          </div>
```

- [ ] **Step 4 — gate:** `cd web && npx vitest run` (still 434 + prior new tests, green — the shared card is imported by existing verdict tests) and `npm --prefix web run build` clean.
- [ ] **Step 5 — commit:**

```bash
git add shared/verdict-cards/EscalationCard.tsx
git commit -m "feat(escalation-card): optional reportSlot in the header action row"
```

---

### Task 4: `ReportButton` → real tertiary Button, mounted via Lookup's `reportSlot`

**Files:**
- Modify: `web/src/components/report/ReportButton.tsx` (full rewrite), `web/src/routes/Lookup.tsx:76-82` (pass `reportSlot`, remove `mt-2` div), `web/src/routes/Lookup.tsx:35` (import path unchanged)

**Interfaces:**
- Produces: `ReportButton` renders `Button variant="tertiary" size="sm"` with a flag glyph, label "Report", `aria-label="Report this indicator"`; still opens the (existing, unchanged) `ReportForm` inline. `ReportForm` is swapped to `ReportDialog` in Task 8.
- Consumes: `Button` (`../ui`), `ReportForm` (`./ReportForm`), `IndicatorType` (`@socdesk/shared/indicators`).

**Note (harness):** pure JSX plumbing — no extractable logic. Gate is `tsc` + full suite green + dogfood. (`contributorSeen` on click is wired in Task 5; the `ReportDialog` swap + draft auto-open in Tasks 8-9.)

- [ ] **Step 1 — rewrite** `web/src/components/report/ReportButton.tsx`:

```tsx
// ReportButton — the real "report this indicator" affordance. Mounted in the
// EscalationCard header action row (via Lookup's reportSlot), at a quieter
// weight than the Copy-text ghost so hierarchy reads Copy card > Copy text >
// Report. Opens the report form, which itself gates on GitHub sign-in; the
// lookup/analyzer read path is unaffected.

import { useState } from 'react'
import type { IndicatorType } from '@socdesk/shared/indicators'
import { Button } from '../ui'
import { ReportForm } from './ReportForm'

function FlagGlyph() {
  return (
    <svg viewBox="0 0 24 24" fill="none" className="size-4 shrink-0" aria-hidden="true">
      <path
        d="M5 21V4m0 0h11l-2 4 2 4H5"
        stroke="currentColor"
        strokeWidth="1.7"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  )
}

export function ReportButton({ iocType, iocValue }: { iocType: IndicatorType; iocValue: string }) {
  const [open, setOpen] = useState(false)
  return (
    <>
      <Button
        variant="tertiary"
        size="sm"
        aria-label="Report this indicator"
        onClick={() => setOpen(true)}
      >
        <FlagGlyph />
        Report
      </Button>
      {open && <ReportForm iocType={iocType} iocValue={iocValue} onClose={() => setOpen(false)} />}
    </>
  )
}
```

- [ ] **Step 2 — wire the slot** in `web/src/routes/Lookup.tsx`. In `CardTriptych` (lines 71-89) replace the escalation-card block so the button rides the card's `reportSlot` and the `mt-2` below-card div is gone:

```tsx
        <div>
          <Label>Client register — escalation card</Label>
          <EscalationCard
            data={data}
            theme={theme}
            reportSlot={
              reportable ? <ReportButton iocType={data.type} iocValue={data.indicator} /> : undefined
            }
          />
        </div>
```

- [ ] **Step 3 — gate:** `cd web && npx vitest run` green; `npm --prefix web run build` clean.
- [ ] **Step 4 — commit:**

```bash
git add web/src/components/report/ReportButton.tsx web/src/routes/Lookup.tsx
git commit -m "feat(report): real tertiary Report button in the card action row"
```

---

### Task 5: `contributorSeen` util + set-sites

**Files:**
- Create: `web/src/lib/contributorSeen.ts`, `web/src/lib/contributorSeen.test.ts`
- Modify: `web/src/components/report/ReportButton.tsx` (mark on click), `web/src/lib/useSession.ts` (mark on `status:'in'`), `web/src/routes/MyReports.tsx` (mark on mount)

**Interfaces:**
- Produces: `function isContributorSeen(): boolean`; `function markContributorSeen(): void`. `localStorage` key `sd_contributor` (presence = truthy); SSR-safe (every touch wrapped, mirroring `shared/lib/theme.ts:18-26`).

- [ ] **Step 1 — write the failing test** (`web/src/lib/contributorSeen.test.ts`):

```ts
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { isContributorSeen, markContributorSeen } from './contributorSeen'

function fakeStorage(): Storage {
  const m = new Map<string, string>()
  return {
    getItem: (k: string) => (m.has(k) ? (m.get(k) as string) : null),
    setItem: (k: string, v: string) => void m.set(k, v),
    removeItem: (k: string) => void m.delete(k),
    clear: () => m.clear(),
    key: () => null,
    length: 0,
  } as unknown as Storage
}

describe('contributorSeen — sd_contributor localStorage bit', () => {
  beforeEach(() => vi.stubGlobal('localStorage', fakeStorage()))
  afterEach(() => vi.unstubAllGlobals())

  it('is false before anything is written', () => {
    expect(isContributorSeen()).toBe(false)
  })
  it('is true once marked', () => {
    markContributorSeen()
    expect(isContributorSeen()).toBe(true)
  })
  it('never throws when storage is blocked (private mode / SSR)', () => {
    vi.stubGlobal('localStorage', {
      getItem: () => {
        throw new Error('blocked')
      },
      setItem: () => {
        throw new Error('blocked')
      },
    } as unknown as Storage)
    expect(() => markContributorSeen()).not.toThrow()
    expect(isContributorSeen()).toBe(false)
  })
})
```

- [ ] **Step 2 — run it, expect FAIL:** `cd web && npx vitest run src/lib/contributorSeen.test.ts` → "Cannot find module './contributorSeen'".

- [ ] **Step 3 — implement `web/src/lib/contributorSeen.ts`:**

```ts
// contributorSeen — a one-bit hint that this browser has engaged the reporting
// write path at least once. The quiet account chrome (AccountControl) and its
// session probe are gated on it, so a browser that only ever looks up pays
// NOTHING (no DOM, no /api/report/mine call). SSR-safe: every storage touch is
// wrapped (private mode / no DOM throws), mirroring shared/lib/theme.ts.

const KEY = 'sd_contributor'

export function isContributorSeen(): boolean {
  try {
    return localStorage.getItem(KEY) === '1'
  } catch {
    return false
  }
}

export function markContributorSeen(): void {
  try {
    localStorage.setItem(KEY, '1')
  } catch {
    /* storage blocked — the chrome simply stays quiet this session */
  }
}
```

- [ ] **Step 4 — wire the three set-sites:**
  - `web/src/components/report/ReportButton.tsx`: `import { markContributorSeen } from '../../lib/contributorSeen'` and change the Button `onClick` to `onClick={() => { markContributorSeen(); setOpen(true) }}`.
  - `web/src/lib/useSession.ts`: `import { markContributorSeen } from './contributorSeen'`; in the `.then` success branch, mark when resolving in:
    ```ts
        if (live) {
          const next = sessionStateFrom(r.status, body)
          if (next.status === 'in') markContributorSeen()
          setS(next)
        }
    ```
  - `web/src/routes/MyReports.tsx`: `import { markContributorSeen } from '../lib/contributorSeen'`; add `useEffect(() => { markContributorSeen() }, [])` (a returning contributor who deep-links `/reports` keeps the quiet chrome).

- [ ] **Step 5 — run it, expect PASS:** `cd web && npx vitest run src/lib/contributorSeen.test.ts`.
- [ ] **Step 6 — full suite + build:** `cd web && npx vitest run` green; `npm --prefix web run build` clean.
- [ ] **Step 7 — commit:**

```bash
git add web/src/lib/contributorSeen.ts web/src/lib/contributorSeen.test.ts web/src/components/report/ReportButton.tsx web/src/lib/useSession.ts web/src/routes/MyReports.tsx
git commit -m "feat(report): contributorSeen bit + the three set-sites"
```

---

### Task 6: `AccountControl` nav control (Part A) + Topbar insertion

**Files:**
- Create: `web/src/lib/accountChrome.ts`, `web/src/lib/accountChrome.test.ts`, `web/src/components/ui/AccountControl.tsx`
- Modify: `web/src/components/ui/index.ts` (export), `web/src/components/ui/Topbar.tsx:75-78` (insert before `<ThemeToggle/>`)

**Interfaces:**
- Produces: `function shouldProbeSession(seen: boolean): boolean`; `type AccountView = 'none' | 'signin' | 'chip'`; `function accountView(seen: boolean, status: SessionState['status']): AccountView`; component `<AccountControl/>`.
- Consumes: `useSession` (`../../lib/useSession`), `isContributorSeen` (`../../lib/contributorSeen`), `navigate` (`../palette/commands`), `Card`/`Divider`/`MicroLabel` (`../ui`), `shared/lib/motion` (`animate`, `DUR`, `EASE`, `prefersReducedMotion`).
- Backend: menu "Sign out" → `POST /api/auth/logout` (`functions/api/auth/logout.js` — the REAL path; spec §A's `/api/auth/github/logout` is wrong). Sign-in link → `GET /api/auth/github/start?return=<pathname+hash>` (same construction as `functions/api/auth/github/start.js`).

- [ ] **Step 1 — write the failing test** (`web/src/lib/accountChrome.test.ts`):

```ts
import { describe, expect, it } from 'vitest'
import { accountView, shouldProbeSession } from './accountChrome'

describe('shouldProbeSession — network restraint (no probe when unseen)', () => {
  it('fires no probe for a browser that never engaged reporting', () => {
    expect(shouldProbeSession(false)).toBe(false)
  })
  it('probes for a returning contributor', () => {
    expect(shouldProbeSession(true)).toBe(true)
  })
})

describe('accountView — Part A truth table', () => {
  it('unseen renders nothing, at any status', () => {
    expect(accountView(false, 'loading')).toBe('none')
    expect(accountView(false, 'in')).toBe('none')
    expect(accountView(false, 'out')).toBe('none')
  })
  it('seen + loading renders nothing (brief, no loading chrome)', () => {
    expect(accountView(true, 'loading')).toBe('none')
  })
  it('seen + out renders the quiet Sign-in link', () => {
    expect(accountView(true, 'out')).toBe('signin')
  })
  it('seen + in renders the account chip', () => {
    expect(accountView(true, 'in')).toBe('chip')
  })
})
```

- [ ] **Step 2 — run it, expect FAIL:** `cd web && npx vitest run src/lib/accountChrome.test.ts` → "Cannot find module './accountChrome'".

- [ ] **Step 3 — implement `web/src/lib/accountChrome.ts`:**

```ts
// accountChrome — the Part A decision logic, kept pure (node-testable) and out
// of the component so the "quiet-until-relevant" doctrine is enforced at the
// data layer, not just visually.

import type { SessionState } from './useSession'

/** Gate the /api/report/mine probe: an unseen browser fires NOTHING. */
export function shouldProbeSession(seen: boolean): boolean {
  return seen
}

export type AccountView = 'none' | 'signin' | 'chip'

/** What the topbar renders, from the two gate signals. */
export function accountView(seen: boolean, status: SessionState['status']): AccountView {
  if (!seen) return 'none'
  if (status === 'in') return 'chip'
  if (status === 'out') return 'signin'
  return 'none' // loading → nothing (brief; no loading chrome)
}
```

- [ ] **Step 4 — run it, expect PASS:** `cd web && npx vitest run src/lib/accountChrome.test.ts`.

- [ ] **Step 5 — implement the component `web/src/components/ui/AccountControl.tsx`.** The outer shell reads `contributorSeen` on mount (SSR-safe via `useState(false)` + `useEffect`, mirroring `ThemeToggle`); it renders nothing — and mounts no probe — until seen, then delegates to an inner `AccountMenu` that calls `useSession` (so the probe fires only for contributors). Reuse `MobileNav`'s dismiss contract (Escape / outside-pointerdown / return-focus) WITHOUT a portal (the menu anchors `absolute` to a `relative` wrapper — no fixed-position stacking trap):

```tsx
import { useEffect, useId, useRef, useState } from 'react'
import { animate } from 'motion'
import { cx } from '@socdesk/shared/lib/cx'
import { DUR, EASE, prefersReducedMotion } from '@socdesk/shared/lib/motion'
import { Card, Divider, MicroLabel } from '../ui'
import { navigate } from '../palette/commands'
import { useSession } from '../../lib/useSession'
import { isContributorSeen } from '../../lib/contributorSeen'
import { accountView } from '../../lib/accountChrome'

/**
 * AccountControl — the quiet-until-relevant contributor entry (Part A). Invisible
 * to the 99% who only look up: an unseen browser renders no DOM and fires no
 * session probe. A returning contributor sees a "Sign in" link (signed out) or
 * an @handle chip + menu (signed in). Signing in / out never touches the read
 * loop. contributorSeen outlives sign-out, so the quiet link returns.
 */
export function AccountControl() {
  const [seen, setSeen] = useState(false)
  useEffect(() => setSeen(isContributorSeen()), [])
  if (!seen) return null // no DOM, and (crucially) AccountMenu's probe never mounts
  return <AccountMenu />
}

const signInHref = () =>
  `/api/auth/github/start?return=${encodeURIComponent(location.pathname + location.hash)}`

function AccountMenu() {
  const session = useSession()
  const view = accountView(true, session.status)
  const [open, setOpen] = useState(false)
  const menuId = useId()
  const wrapRef = useRef<HTMLDivElement>(null)
  const panelRef = useRef<HTMLDivElement>(null)
  const triggerRef = useRef<HTMLButtonElement>(null)

  // Dismiss on Escape / outside pointer; move focus to the first item on open;
  // return focus to the trigger on close. Same contract as MobileNav.
  useEffect(() => {
    if (!open) return
    const raf = requestAnimationFrame(() =>
      panelRef.current?.querySelector<HTMLElement>('[role="menuitem"]')?.focus(),
    )
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault()
        setOpen(false)
        triggerRef.current?.focus()
      }
    }
    const onPointer = (e: PointerEvent) => {
      if (wrapRef.current?.contains(e.target as Node)) return
      setOpen(false)
    }
    document.addEventListener('keydown', onKey)
    document.addEventListener('pointerdown', onPointer)
    return () => {
      cancelAnimationFrame(raf)
      document.removeEventListener('keydown', onKey)
      document.removeEventListener('pointerdown', onPointer)
    }
  }, [open])

  // Panel enter (WAAPI, reduced-motion-safe) — same sanctioned lib/motion path.
  useEffect(() => {
    const panel = panelRef.current
    if (!open || !panel || prefersReducedMotion()) return
    animate(
      panel,
      { opacity: [0, 1], transform: ['translateY(-6px)', 'translateY(0px)'] },
      { duration: DUR.base, ease: EASE.brand },
    )
  }, [open])

  const signOut = async () => {
    try {
      await fetch('/api/auth/logout', { method: 'POST', credentials: 'same-origin' })
    } catch {
      /* best-effort; the cookie clears server-side */
    }
    setOpen(false)
    // Optimistic — stay on page; contributorSeen persists so "Sign in" returns.
    location.reload()
  }

  if (view === 'none') return null

  if (view === 'signin') {
    return (
      <a
        href={signInHref()}
        className="font-mono text-micro font-semibold uppercase tracking-label text-muted outline-offset-2 transition-colors duration-150 ease-brand hover:text-paper focus-visible:outline-2 focus-visible:outline-accent"
      >
        Sign in
      </a>
    )
  }

  const handle = session.login ? `@${session.login}` : 'Account'
  return (
    <div ref={wrapRef} className="relative">
      <button
        ref={triggerRef}
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={menuId}
        aria-label={`Account menu, signed in as ${session.login ?? 'contributor'}`}
        className={cx(
          'inline-flex h-8 items-center gap-1.5 rounded-md border border-line bg-panel px-2.5 font-mono text-micro font-semibold text-muted',
          'outline-offset-2 transition-colors duration-150 ease-brand hover:border-line-bright hover:text-paper focus-visible:outline-2 focus-visible:outline-accent',
        )}
      >
        <span className="text-accent">{handle}</span>
        <Chevron open={open} />
      </button>

      {open && (
        <div ref={panelRef} className="absolute right-0 top-full z-40 mt-1.5 w-56">
          <Card padding="sm">
            <div id={menuId} role="menu" aria-label="Account" className="flex flex-col gap-1">
              <div className="flex flex-col gap-0.5 px-1 pb-1">
                <MicroLabel tone="faint">Signed in with GitHub</MicroLabel>
                <span className="font-mono text-xs font-semibold text-paper">{handle}</span>
              </div>
              <Divider />
              <a
                href="/reports"
                role="menuitem"
                onClick={(e) => {
                  if (e.button === 0 && !e.metaKey && !e.ctrlKey && !e.shiftKey && !e.altKey) {
                    e.preventDefault()
                    navigate('/reports')
                    setOpen(false)
                  }
                }}
                className="rounded-md px-2 py-1.5 font-sans text-xs text-muted outline-offset-[-2px] transition-colors duration-150 ease-brand hover:bg-panel-soft hover:text-paper focus-visible:outline-2 focus-visible:outline-accent"
              >
                My reports
              </a>
              <button
                type="button"
                role="menuitem"
                onClick={signOut}
                className="rounded-md px-2 py-1.5 text-left font-sans text-xs text-muted outline-offset-[-2px] transition-colors duration-150 ease-brand hover:bg-panel-soft hover:text-paper focus-visible:outline-2 focus-visible:outline-accent"
              >
                Sign out
              </button>
            </div>
          </Card>
        </div>
      )}
    </div>
  )
}

function Chevron({ open }: { open: boolean }) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      className={cx('size-3.5 shrink-0 transition-transform duration-150 ease-brand', open && 'rotate-180')}
      aria-hidden="true"
    >
      <path d="M6 9l6 6 6-6" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}
```

Note: `Card` needs `Card` in the `../ui` re-export — it already is (`web/src/components/ui/index.ts:5-15` re-exports `Card`). `Chevron` uses `cx` from `@socdesk/shared/lib/cx`.

- [ ] **Step 6 — export + insert.** In `web/src/components/ui/index.ts`, add after the `Topbar` export:

```ts
export { AccountControl } from './AccountControl'
```

In `web/src/components/ui/Topbar.tsx`, import it (`import { AccountControl } from './AccountControl'`) and insert it in the right cluster (lines 75-78) before `<ThemeToggle/>`:

```tsx
        <div className="ml-auto flex items-center gap-3">
          {right}
          <AccountControl />
          <ThemeToggle />
        </div>
```

- [ ] **Step 7 — full suite + build:** `cd web && npx vitest run` (accountChrome test green) and `npm --prefix web run build` clean.
- [ ] **Step 8 — commit:**

```bash
git add web/src/lib/accountChrome.ts web/src/lib/accountChrome.test.ts web/src/components/ui/AccountControl.tsx web/src/components/ui/index.ts web/src/components/ui/Topbar.tsx
git commit -m "feat(nav): quiet-until-relevant AccountControl with contributor menu"
```

---

### Task 7: `ReportDialog` shell — `<dialog>`/`showModal()` + session gate

**Files:**
- Create: `web/src/components/report/dialogView.ts`, `web/src/components/report/dialogView.test.ts`, `web/src/components/report/ReportDialog.tsx` (shell only; fields land in Task 8)

**Interfaces:**
- Produces: `type DialogView = 'loading' | 'gate' | 'fill'`; `function dialogView(status: SessionState['status']): DialogView`; component `<ReportDialog iocType iocValue open onClose/>` (native `<dialog>` on the `CommandPalette` pattern, width `w-[min(28rem,calc(100%-2rem))]`).
- Consumes: `useSession` (`../../lib/useSession`), `dialogView`, `Button`/`MicroLabel` (`../ui`), `shared/lib/motion`.

- [ ] **Step 1 — write the failing test** (`web/src/components/report/dialogView.test.ts`):

```ts
import { describe, expect, it } from 'vitest'
import { dialogView } from './dialogView'

describe('dialogView — base screen from session status', () => {
  it('loading → the brief loading tick', () => {
    expect(dialogView('loading')).toBe('loading')
  })
  it('out → the sign-in gate', () => {
    expect(dialogView('out')).toBe('gate')
  })
  it('in → the fill form', () => {
    expect(dialogView('in')).toBe('fill')
  })
})
```

- [ ] **Step 2 — run it, expect FAIL:** `cd web && npx vitest run src/components/report/dialogView.test.ts` → "Cannot find module './dialogView'".

- [ ] **Step 3 — implement `web/src/components/report/dialogView.ts`:**

```ts
import type { SessionState } from '../../lib/useSession'

/** The base (pre-submit) screen, from session status alone. Terminal post-submit
 *  screens are driven by reportOutcome (Task 8), not this. */
export type DialogView = 'loading' | 'gate' | 'fill'

export function dialogView(status: SessionState['status']): DialogView {
  switch (status) {
    case 'loading':
      return 'loading'
    case 'out':
      return 'gate'
    case 'in':
      return 'fill'
  }
}
```

- [ ] **Step 4 — run it, expect PASS:** `cd web && npx vitest run src/components/report/dialogView.test.ts`.

- [ ] **Step 5 — implement the shell `web/src/components/report/ReportDialog.tsx`** (opens/closes on the CommandPalette pattern; renders the gate/loading, plus a placeholder `fill` body that Task 8 fills). Sign-in CTA in the gate = `Button variant="primary"`:

```tsx
// ReportDialog — the modal report form, rebuilt on the one overlay pattern the
// app already has: a native <dialog> + showModal() + WAAPI motion via
// shared/lib/motion, Escape/backdrop close, native focus trap. Signed-out
// analysts see a non-accusatory sign-in gate; signed-in analysts get the form
// (Task 8). The lookup/analyzer read path is untouched.

import { useEffect, useRef } from 'react'
import { animate } from 'motion'
import { DUR, EASE, prefersReducedMotion } from '@socdesk/shared/lib/motion'
import type { IndicatorType } from '@socdesk/shared/indicators'
import { Button, MicroLabel } from '../ui'
import { useSession } from '../../lib/useSession'
import { dialogView } from './dialogView'

export interface ReportDialogProps {
  iocType: IndicatorType
  iocValue: string
  open: boolean
  onClose: () => void
}

export function ReportDialog({ iocType, iocValue, open, onClose }: ReportDialogProps) {
  const session = useSession()
  const dialogRef = useRef<HTMLDialogElement>(null)
  const panelRef = useRef<HTMLDivElement>(null)
  const view = dialogView(session.status)

  useEffect(() => {
    const dlg = dialogRef.current
    const panel = panelRef.current
    if (!dlg) return
    if (open) {
      if (!dlg.open) {
        try {
          dlg.showModal()
        } catch {
          /* already open (StrictMode double-invoke) */
        }
      }
      if (panel && !prefersReducedMotion()) {
        animate(
          panel,
          { opacity: [0, 1], transform: ['translateY(-8px) scale(0.985)', 'translateY(0px) scale(1)'] },
          { duration: DUR.base, ease: EASE.brand },
        )
      }
    } else if (dlg.open) {
      dlg.close()
    }
  }, [open])

  const signInHref = `/api/auth/github/start?return=${encodeURIComponent(
    location.pathname + location.hash,
  )}`

  return (
    <dialog
      ref={dialogRef}
      aria-label={`Report ${iocValue}`}
      onCancel={(e) => {
        e.preventDefault()
        onClose()
      }}
      onClick={(e) => {
        if (e.target === dialogRef.current) onClose()
      }}
      className="mx-auto mt-[14vh] w-[min(28rem,calc(100%-2rem))] max-w-full bg-transparent p-0 text-paper outline-none backdrop:bg-ink/75 backdrop:backdrop-blur-[3px] max-sm:mt-[8vh]"
    >
      <div
        ref={panelRef}
        className="flex w-full flex-col gap-3 rounded-lg border border-line bg-raised p-5 shadow-e3"
      >
        <div className="flex items-center justify-between gap-4">
          <MicroLabel tone="accent">Report indicator</MicroLabel>
          <span className="break-all font-mono text-micro text-muted">{iocValue}</span>
        </div>

        {view === 'loading' && <p className="text-xs text-muted">Checking your session…</p>}

        {view === 'gate' && (
          <div className="flex flex-col gap-3">
            <p className="text-xs leading-relaxed text-muted">
              Reporting needs a quick GitHub sign-in (so reports are attributable). Look-ups never do.
            </p>
            <div className="flex items-center gap-2">
              <Button variant="primary" size="sm" onClick={() => (location.href = signInHref)}>
                Sign in with GitHub
              </Button>
              <Button variant="ghost" size="sm" onClick={onClose}>
                Cancel
              </Button>
            </div>
          </div>
        )}

        {view === 'fill' && (
          <p className="text-xs text-muted" data-testid="report-fill-placeholder">
            {iocType} form — added in Task 8.
          </p>
        )}
      </div>
    </dialog>
  )
}
```

- [ ] **Step 6 — full suite + build:** `cd web && npx vitest run` green; `npm --prefix web run build` clean. (`ReportDialog` is not yet mounted anywhere — Task 8 swaps `ReportButton` onto it.)
- [ ] **Step 7 — commit:**

```bash
git add web/src/components/report/dialogView.ts web/src/components/report/dialogView.test.ts web/src/components/report/ReportDialog.tsx
git commit -m "feat(report): ReportDialog shell on the native dialog pattern"
```

---

### Task 8: `ReportDialog` fields + submit — full terminal state machine

**Files:**
- Create: `web/src/components/report/reportOutcome.ts`, `web/src/components/report/reportOutcome.test.ts`, `web/src/components/report/reportChrome.ts`
- Modify: `web/src/components/report/ReportDialog.tsx` (fill form + submit + terminal states), `web/src/components/report/ReportButton.tsx` (open `ReportDialog` instead of `ReportForm`)
- Delete: `web/src/components/report/ReportForm.tsx`

**Interfaces:**
- Produces: `type ReportOutcome = { kind: 'queued' } | { kind: 'deduped' } | { kind: 'expired' } | { kind: 'turnstile' } | { kind: 'invalid'; field?: string } | { kind: 'banned' } | { kind: 'capped' } | { kind: 'error' }`; `function reportOutcome(status: number, body: { deduped?: boolean; error?: string } | null): ReportOutcome`; `reportChrome` constants `SUCCESS_ICON_CLASS` / `SUCCESS_TEXT_CLASS`.
- Consumes: server contract from `functions/api/report.js` (200 `{deduped?}`, 401, 400 `{error}`, 403, 429), `validateReport` category vocab (`lib/reporting/validate.mjs:4-7` — `CATEGORIES`), `Button`/`MicroLabel`/`Panel` (`../ui`), `reportOutcome`, `reportChrome`, `dialogView`.

- [ ] **Step 1 — write the failing test** (`web/src/components/report/reportOutcome.test.ts`):

```ts
import { describe, expect, it } from 'vitest'
import { reportOutcome } from './reportOutcome'

describe('reportOutcome — /api/report response → terminal state', () => {
  it('200 fresh insert → queued', () => {
    expect(reportOutcome(200, { id: 'x', status: 'queued' } as never)).toEqual({ kind: 'queued' })
  })
  it('200 deduped:true → deduped', () => {
    expect(reportOutcome(200, { deduped: true })).toEqual({ kind: 'deduped' })
  })
  it('401 → expired (re-gate; draft preserved)', () => {
    expect(reportOutcome(401, { error: 'auth' })).toEqual({ kind: 'expired' })
  })
  it('400 turnstile → turnstile (reset the widget)', () => {
    expect(reportOutcome(400, { error: 'turnstile' })).toEqual({ kind: 'turnstile' })
  })
  it('400 validation → invalid, carrying the field key', () => {
    expect(reportOutcome(400, { error: 'evidence' })).toEqual({ kind: 'invalid', field: 'evidence' })
    expect(reportOutcome(400, { error: 'ioc_value' })).toEqual({ kind: 'invalid', field: 'ioc_value' })
  })
  it('403 → banned (terminal, flat)', () => {
    expect(reportOutcome(403, { error: 'banned' })).toEqual({ kind: 'banned' })
  })
  it('429 → capped (terminal-today)', () => {
    expect(reportOutcome(429, { error: 'rate' })).toEqual({ kind: 'capped' })
  })
  it('network/parse failure (null body, status 0) → error (retryable)', () => {
    expect(reportOutcome(0, null)).toEqual({ kind: 'error' })
  })
  it('an unexpected 5xx → error (retryable, draft intact)', () => {
    expect(reportOutcome(500, null)).toEqual({ kind: 'error' })
  })
})
```

- [ ] **Step 2 — run it, expect FAIL:** `cd web && npx vitest run src/components/report/reportOutcome.test.ts` → "Cannot find module './reportOutcome'".

- [ ] **Step 3 — implement `web/src/components/report/reportOutcome.ts`:**

```ts
// reportOutcome — the pure heart of the ReportDialog state machine. Maps the
// /api/report response (HTTP status + parsed JSON body, or null on a
// network/parse failure) to a terminal dialog state. Mirrors the server
// contract in functions/api/report.js exactly:
//   200 {deduped:true} → deduped ; 200 → queued
//   401 → expired ; 403 → banned ; 429 → capped
//   400 {error:'turnstile'} → turnstile ; 400 {error:<field>} → invalid(field)
//   anything else / null → error (retryable, draft intact)

export type ReportOutcome =
  | { kind: 'queued' }
  | { kind: 'deduped' }
  | { kind: 'expired' }
  | { kind: 'turnstile' }
  | { kind: 'invalid'; field?: string }
  | { kind: 'banned' }
  | { kind: 'capped' }
  | { kind: 'error' }

export function reportOutcome(
  status: number,
  body: { deduped?: boolean; error?: string } | null,
): ReportOutcome {
  if (status === 200) return body?.deduped ? { kind: 'deduped' } : { kind: 'queued' }
  if (status === 401) return { kind: 'expired' }
  if (status === 403) return { kind: 'banned' }
  if (status === 429) return { kind: 'capped' }
  if (status === 400) {
    if (body?.error === 'turnstile') return { kind: 'turnstile' }
    return { kind: 'invalid', field: body?.error }
  }
  return { kind: 'error' }
}
```

- [ ] **Step 4 — run it, expect PASS:** `cd web && npx vitest run src/components/report/reportOutcome.test.ts`.

- [ ] **Step 5 — implement `web/src/components/report/reportChrome.ts`** (exported class strings so the reserved-colour guard in Task 11 can assert them — success is accent + paper, NEVER verdict-green):

```ts
// reportChrome — reserved-colour class strings for the report confirmation.
// A report CONFIRMATION is UI chrome, not a verdict: success is the accent-
// stroked checkmark + paper text, NEVER text-verdict-green (green already means
// "a source found nothing adverse"; reusing it would let a user misread "queued"
// as "this IOC is clean"). Exported so the reserved-colour guard test can assert
// no verdict hue leaks in.

export const SUCCESS_ICON_CLASS = 'size-4 shrink-0 stroke-[var(--accent)]'
export const SUCCESS_TEXT_CLASS = 'text-paper'
```

- [ ] **Step 6 — build the fill form + submit + terminal states** into `web/src/components/report/ReportDialog.tsx`. Replace the `fill` placeholder with the real form and add a `terminal` state driven by `reportOutcome`. Category defaults to a disabled `""` placeholder (drop the silent `'scanner'`); evidence is `required` with a `n / 2000` counter (`text-muted`, `text-verdict-amber` near cap — never `text-faint`, per Ground-truth correction #3); comment optional with `n / 1000`; Turnstile in a labeled fixed-height slot (`appearance:'interaction-only'`, `size:'compact'`); shared Buttons; a `role="status" aria-live="polite"` region for outcomes; success = accent ✓ (`reportChrome`), amber ONLY for banned/capped. Full component:

```tsx
import { useEffect, useRef, useState } from 'react'
import { animate } from 'motion'
import { DUR, EASE, prefersReducedMotion } from '@socdesk/shared/lib/motion'
import type { IndicatorType } from '@socdesk/shared/indicators'
import { Button, MicroLabel } from '../ui'
import { useSession } from '../../lib/useSession'
import { dialogView } from './dialogView'
import { reportOutcome, type ReportOutcome } from './reportOutcome'
import { SUCCESS_ICON_CLASS, SUCCESS_TEXT_CLASS } from './reportChrome'

const CATEGORIES = [
  'brute-force', 'ssh', 'port-scan', 'web-app-attack', 'phishing',
  'malware-c2', 'scanner', 'spam', 'exploited-host', 'other',
]
const EVIDENCE_MAX = 2000
const COMMENT_MAX = 1000

export interface ReportDialogProps {
  iocType: IndicatorType
  iocValue: string
  open: boolean
  onClose: () => void
}

function CheckGlyph() {
  return (
    <svg viewBox="0 0 16 16" fill="none" className={SUCCESS_ICON_CLASS} strokeWidth={2}
      strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M3.5 8.5 L6.5 11.5 L12.5 4.5" />
    </svg>
  )
}

function counterClass(n: number, max: number): string {
  return n > max * 0.9 ? 'text-verdict-amber' : 'text-muted'
}

export function ReportDialog({ iocType, iocValue, open, onClose }: ReportDialogProps) {
  const session = useSession()
  const dialogRef = useRef<HTMLDialogElement>(null)
  const panelRef = useRef<HTMLDivElement>(null)
  const widgetRef = useRef<HTMLDivElement>(null)
  const tokenRef = useRef<string>('')
  const widgetIdRef = useRef<string>('')

  const [category, setCategory] = useState('')
  const [evidence, setEvidence] = useState('')
  const [comment, setComment] = useState('')
  const [touchedEvidence, setTouchedEvidence] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [outcome, setOutcome] = useState<ReportOutcome | null>(null)

  // A POST-time 401 (`expired`) must FORCE the sign-in gate: the mount-time
  // session probe still reads 'in', so dialogView() alone would leave us on
  // 'fill' with no matching render branch (an empty dialog). Expired overrides.
  const view = outcome?.kind === 'expired' ? 'gate' : dialogView(session.status)

  // Native dialog open/close + panel motion (CommandPalette pattern).
  useEffect(() => {
    const dlg = dialogRef.current
    const panel = panelRef.current
    if (!dlg) return
    if (open) {
      if (!dlg.open) {
        try { dlg.showModal() } catch { /* already open */ }
      }
      if (panel && !prefersReducedMotion()) {
        animate(panel,
          { opacity: [0, 1], transform: ['translateY(-8px) scale(0.985)', 'translateY(0px) scale(1)'] },
          { duration: DUR.base, ease: EASE.brand })
      }
    } else if (dlg.open) {
      dlg.close()
    }
  }, [open])

  // Turnstile — load + render once signed in and on the fill screen.
  useEffect(() => {
    if (!open || view !== 'fill' || !widgetRef.current) return
    if (!document.querySelector('script[src^="https://challenges.cloudflare.com/turnstile"]')) {
      const s = document.createElement('script')
      s.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js'
      s.async = true
      document.head.appendChild(s)
    }
    const id = setInterval(() => {
      // @ts-expect-error injected global
      if (window.turnstile && widgetRef.current && !widgetRef.current.dataset.rendered) {
        widgetRef.current.dataset.rendered = '1'
        // @ts-expect-error injected global
        widgetIdRef.current = window.turnstile.render(widgetRef.current, {
          sitekey: import.meta.env.VITE_TURNSTILE_SITEKEY,
          appearance: 'interaction-only',
          size: 'compact',
          callback: (t: string) => { tokenRef.current = t },
        })
        clearInterval(id)
      }
    }, 200)
    return () => clearInterval(id)
  }, [open, view])

  const resetTurnstile = () => {
    // @ts-expect-error injected global
    if (window.turnstile && widgetIdRef.current) window.turnstile.reset(widgetIdRef.current)
    tokenRef.current = ''
  }

  const submit = async () => {
    setTouchedEvidence(true)
    if (!evidence.trim() || !category) return // no request; inline messages handle it
    setSubmitting(true)
    setOutcome(null)
    let status = 0
    let body: { deduped?: boolean; error?: string } | null = null
    try {
      const r = await fetch('/api/report', {
        method: 'POST', credentials: 'same-origin',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          ioc_type: iocType, ioc_value: iocValue, category, evidence, comment,
          turnstileToken: tokenRef.current,
        }),
      })
      status = r.status
      body = await r.json().catch(() => null)
    } catch {
      status = 0
    }
    const next = reportOutcome(status, body)
    setSubmitting(false)
    setOutcome(next)
    if (next.kind === 'turnstile' || next.kind === 'error') resetTurnstile()
  }

  const signInHref = `/api/auth/github/start?return=${encodeURIComponent(location.pathname + location.hash)}`
  const evidenceEmpty = touchedEvidence && !evidence.trim()

  return (
    <dialog
      ref={dialogRef}
      aria-label={`Report ${iocValue}`}
      onCancel={(e) => { e.preventDefault(); onClose() }}
      onClick={(e) => { if (e.target === dialogRef.current) onClose() }}
      className="mx-auto mt-[14vh] w-[min(28rem,calc(100%-2rem))] max-w-full bg-transparent p-0 text-paper outline-none backdrop:bg-ink/75 backdrop:backdrop-blur-[3px] max-sm:mt-[8vh]"
    >
      <div ref={panelRef} className="flex w-full flex-col gap-3 rounded-lg border border-line bg-raised p-5 shadow-e3">
        <div className="flex items-center justify-between gap-4">
          <MicroLabel tone="accent">Report indicator</MicroLabel>
          <span className="break-all font-mono text-micro text-muted">{iocValue}</span>
        </div>

        {view === 'loading' && <p className="text-xs text-muted">Checking your session…</p>}

        {view === 'gate' && (
          <div className="flex flex-col gap-3">
            <p className="text-xs leading-relaxed text-muted">
              {outcome?.kind === 'expired'
                ? 'Your session expired. Sign in again — your draft is kept.'
                : 'Reporting needs a quick GitHub sign-in (so reports are attributable). Look-ups never do.'}
            </p>
            <div className="flex items-center gap-2">
              <Button variant="primary" size="sm" onClick={() => (location.href = signInHref)}>
                Sign in with GitHub
              </Button>
              <Button variant="ghost" size="sm" onClick={onClose}>Cancel</Button>
            </div>
          </div>
        )}

        {view === 'fill' && outcome?.kind === 'queued' && (
          <div className="flex flex-col gap-3" role="status" aria-live="polite">
            <p className={`inline-flex items-center gap-2 text-sm font-medium ${SUCCESS_TEXT_CLASS}`}>
              <CheckGlyph /> Queued for review — thanks.
            </p>
            <div className="flex items-center gap-2">
              <Button variant="primary" size="sm" onClick={() => { location.href = '/reports' }}>
                View my reports
              </Button>
              <Button variant="ghost" size="sm" onClick={onClose}>Done</Button>
            </div>
          </div>
        )}

        {view === 'fill' && outcome?.kind === 'deduped' && (
          <div className="flex flex-col gap-3" role="status" aria-live="polite">
            <p className={`inline-flex items-center gap-2 text-sm font-medium ${SUCCESS_TEXT_CLASS}`}>
              <CheckGlyph /> Already reported — you have an open report for this indicator.
            </p>
            <div className="flex items-center gap-2">
              <Button variant="primary" size="sm" onClick={() => { location.href = '/reports' }}>
                View my reports
              </Button>
              <Button variant="ghost" size="sm" onClick={onClose}>Done</Button>
            </div>
          </div>
        )}

        {view === 'fill' && outcome?.kind === 'banned' && (
          <p role="status" aria-live="polite"
             className="rounded-md border border-[var(--edge-gold)] px-3 py-2 text-xs text-verdict-amber">
            This account cannot submit reports.
          </p>
        )}

        {view === 'fill' && outcome?.kind === 'capped' && (
          <p role="status" aria-live="polite"
             className="rounded-md border border-[var(--edge-gold)] px-3 py-2 text-xs text-verdict-amber">
            Daily limit reached (25/day). Try again tomorrow.
          </p>
        )}

        {view === 'fill' && (!outcome || ['turnstile', 'invalid', 'error'].includes(outcome.kind)) && (
          <div className="flex flex-col gap-3">
            <div className="flex flex-col gap-1">
              <MicroLabel tone="muted" as="label">Category</MicroLabel>
              <select
                value={category}
                onChange={(e) => setCategory(e.target.value)}
                aria-label="Report category"
                className="rounded-md border border-line bg-field px-2 py-1.5 font-sans text-xs text-paper outline-offset-2 focus-visible:outline-2 focus-visible:outline-accent"
              >
                <option value="" disabled>Select a category</option>
                {CATEGORIES.map((c) => (<option key={c} value={c}>{c}</option>))}
              </select>
            </div>

            <div className="flex flex-col gap-1">
              <div className="flex items-baseline justify-between">
                <MicroLabel tone="muted" as="label">Evidence</MicroLabel>
                <span className={`font-mono text-micro ${counterClass(evidence.length, EVIDENCE_MAX)}`}>
                  {evidence.length} / {EVIDENCE_MAX}
                </span>
              </div>
              <textarea
                value={evidence}
                onChange={(e) => setEvidence(e.target.value.slice(0, EVIDENCE_MAX))}
                onBlur={() => setTouchedEvidence(true)}
                required
                rows={3}
                aria-label="Evidence — what you observed"
                placeholder="What you observed — don't paste sensitive/internal data"
                className="rounded-md border border-line bg-field px-2 py-1.5 font-mono text-xs text-paper outline-offset-2 placeholder:text-faint focus-visible:outline-2 focus-visible:outline-accent"
              />
              {evidenceEmpty && <p className="text-micro text-muted">Evidence is required.</p>}
            </div>

            <div className="flex flex-col gap-1">
              <div className="flex items-baseline justify-between">
                <MicroLabel tone="muted" as="label">Comment (optional)</MicroLabel>
                <span className={`font-mono text-micro ${counterClass(comment.length, COMMENT_MAX)}`}>
                  {comment.length} / {COMMENT_MAX}
                </span>
              </div>
              <input
                value={comment}
                onChange={(e) => setComment(e.target.value.slice(0, COMMENT_MAX))}
                aria-label="Optional comment"
                placeholder="Anything else worth noting"
                className="rounded-md border border-line bg-field px-2 py-1.5 font-sans text-xs text-paper outline-offset-2 placeholder:text-faint focus-visible:outline-2 focus-visible:outline-accent"
              />
            </div>

            <div className="flex flex-col gap-1">
              <MicroLabel tone="muted">Verification</MicroLabel>
              <div ref={widgetRef} className="min-h-[65px]" />
            </div>

            {outcome?.kind === 'turnstile' && (
              <p role="status" aria-live="polite" className="text-xs text-muted">
                Verification failed — please complete the challenge and resubmit.
              </p>
            )}
            {outcome?.kind === 'invalid' && (
              <p role="status" aria-live="polite" className="text-xs text-muted">
                {outcome.field === 'evidence'
                  ? 'Evidence is required.'
                  : 'That report was rejected — check the indicator and try again.'}
              </p>
            )}
            {outcome?.kind === 'error' && (
              <p role="status" aria-live="polite" className="text-xs text-muted">
                Something went wrong — your draft is kept. Try again.
              </p>
            )}

            <div className="flex items-center gap-2">
              <Button variant="primary" size="sm" disabled={submitting} onClick={submit}>
                {submitting ? 'Submitting…' : 'Submit report'}
              </Button>
              <Button variant="ghost" size="sm" onClick={onClose}>Cancel</Button>
            </div>
          </div>
        )}
      </div>
    </dialog>
  )
}
```

- [ ] **Step 7 — swap `ReportButton` onto `ReportDialog`** and delete `ReportForm`. In `web/src/components/report/ReportButton.tsx` change the import `import { ReportForm } from './ReportForm'` → `import { ReportDialog } from './ReportDialog'`, and the render `{open && <ReportForm .../>}` → `{open && <ReportDialog iocType={iocType} iocValue={iocValue} open={open} onClose={() => setOpen(false)} />}`.

- [ ] **Step 8 — run it, expect PASS:** `cd web && npx vitest run src/components/report/reportOutcome.test.ts`.
- [ ] **Step 9 — full suite + build:** `cd web && npx vitest run` green; `npm --prefix web run build` clean.
- [ ] **Step 10 — commit:**

```bash
git add web/src/components/report/reportOutcome.ts web/src/components/report/reportOutcome.test.ts web/src/components/report/reportChrome.ts web/src/components/report/ReportDialog.tsx web/src/components/report/ReportButton.tsx
git rm web/src/components/report/ReportForm.tsx
git commit -m "feat(report): ReportDialog fields + full terminal state machine"
```

---

### Task 9: OAuth draft preservation

**Files:**
- Create: `web/src/components/report/draft.ts`, `web/src/components/report/draft.test.ts`
- Modify: `web/src/components/report/ReportDialog.tsx` (stash before sign-in), `web/src/components/report/ReportButton.tsx` (auto-reopen + restore on mount)

**Interfaces:**
- Produces: `interface ReportDraft { category: string; evidence: string; comment: string; pendingOpen: boolean }`; `draftKey(iocType, iocValue): string`; `saveDraft(iocType, iocValue, draft): void`; `loadDraft(iocType, iocValue): ReportDraft | null`; `clearDraft(iocType, iocValue): void`. `sessionStorage` keyed `sd-report-draft:<type>:<value>`; SSR-safe.

- [ ] **Step 1 — write the failing test** (`web/src/components/report/draft.test.ts`):

```ts
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { clearDraft, draftKey, loadDraft, saveDraft } from './draft'

function fakeStorage(): Storage {
  const m = new Map<string, string>()
  return {
    getItem: (k: string) => (m.has(k) ? (m.get(k) as string) : null),
    setItem: (k: string, v: string) => void m.set(k, v),
    removeItem: (k: string) => void m.delete(k),
    clear: () => m.clear(),
    key: () => null,
    length: 0,
  } as unknown as Storage
}

describe('report draft — sessionStorage keyed to the resolved indicator', () => {
  beforeEach(() => vi.stubGlobal('sessionStorage', fakeStorage()))
  afterEach(() => vi.unstubAllGlobals())

  it('namespaces the key to type + value', () => {
    expect(draftKey('ipv4', '45.9.148.20')).toBe('sd-report-draft:ipv4:45.9.148.20')
  })
  it('round-trips a draft', () => {
    saveDraft('ipv4', '45.9.148.20', { category: 'scanner', evidence: 'hit', comment: 'x', pendingOpen: true })
    expect(loadDraft('ipv4', '45.9.148.20')).toEqual({
      category: 'scanner', evidence: 'hit', comment: 'x', pendingOpen: true,
    })
  })
  it('returns null for a missing draft', () => {
    expect(loadDraft('domain', 'evil.com')).toBeNull()
  })
  it('only restores onto the SAME indicator', () => {
    saveDraft('ipv4', '1.1.1.1', { category: 'ssh', evidence: 'e', comment: '', pendingOpen: true })
    expect(loadDraft('ipv4', '2.2.2.2')).toBeNull()
  })
  it('tolerates malformed JSON (returns null, no throw)', () => {
    sessionStorage.setItem(draftKey('ipv4', '1.1.1.1'), '{not json')
    expect(loadDraft('ipv4', '1.1.1.1')).toBeNull()
  })
  it('clearDraft removes it', () => {
    saveDraft('ipv4', '1.1.1.1', { category: 'ssh', evidence: 'e', comment: '', pendingOpen: true })
    clearDraft('ipv4', '1.1.1.1')
    expect(loadDraft('ipv4', '1.1.1.1')).toBeNull()
  })
  it('never throws when storage is blocked', () => {
    vi.stubGlobal('sessionStorage', {
      getItem: () => { throw new Error('blocked') },
      setItem: () => { throw new Error('blocked') },
      removeItem: () => { throw new Error('blocked') },
    } as unknown as Storage)
    expect(() => saveDraft('ipv4', '1.1.1.1', { category: '', evidence: '', comment: '', pendingOpen: true })).not.toThrow()
    expect(loadDraft('ipv4', '1.1.1.1')).toBeNull()
  })
})
```

- [ ] **Step 2 — run it, expect FAIL:** `cd web && npx vitest run src/components/report/draft.test.ts` → "Cannot find module './draft'".

- [ ] **Step 3 — implement `web/src/components/report/draft.ts`:**

```ts
// draft — preserve a typed report across the GitHub OAuth round trip. Before
// navigating to GitHub, the dialog stashes the draft (with pendingOpen:true) in
// sessionStorage keyed to the exact resolved indicator; on return, ReportButton
// auto-opens the dialog and restores it, then clears the flag. SSR-safe.

export interface ReportDraft {
  category: string
  evidence: string
  comment: string
  pendingOpen: boolean
}

export function draftKey(iocType: string, iocValue: string): string {
  return `sd-report-draft:${iocType}:${iocValue}`
}

export function saveDraft(iocType: string, iocValue: string, draft: ReportDraft): void {
  try {
    sessionStorage.setItem(draftKey(iocType, iocValue), JSON.stringify(draft))
  } catch {
    /* storage blocked — the round trip just won't restore; non-fatal */
  }
}

export function loadDraft(iocType: string, iocValue: string): ReportDraft | null {
  try {
    const raw = sessionStorage.getItem(draftKey(iocType, iocValue))
    if (!raw) return null
    const p = JSON.parse(raw) as Partial<ReportDraft>
    return {
      category: typeof p.category === 'string' ? p.category : '',
      evidence: typeof p.evidence === 'string' ? p.evidence : '',
      comment: typeof p.comment === 'string' ? p.comment : '',
      pendingOpen: p.pendingOpen === true,
    }
  } catch {
    return null
  }
}

export function clearDraft(iocType: string, iocValue: string): void {
  try {
    sessionStorage.removeItem(draftKey(iocType, iocValue))
  } catch {
    /* no-op */
  }
}
```

- [ ] **Step 4 — run it, expect PASS:** `cd web && npx vitest run src/components/report/draft.test.ts`.

- [ ] **Step 5 — wire the stash** in `web/src/components/report/ReportDialog.tsx`. Add `initialDraft?: ReportDraft` to `ReportDialogProps`; seed `category`/`evidence`/`comment` state from it (`useState(() => initialDraft?.category ?? '')`, etc.). Before the sign-in navigation (both the gate CTA and the `expired` re-gate), stash first:

```tsx
import { saveDraft, type ReportDraft } from './draft'
// ...
const goSignIn = () => {
  saveDraft(iocType, iocValue, { category, evidence, comment, pendingOpen: true })
  location.href = signInHref
}
```

Point both gate `Sign in with GitHub` buttons' `onClick` at `goSignIn`.

- [ ] **Step 6 — wire auto-reopen + restore** in `web/src/components/report/ReportButton.tsx`: on mount, load a pending draft for the current indicator; if `pendingOpen`, open the dialog with it and clear the flag:

```tsx
import { useEffect, useState } from 'react'
import { clearDraft, loadDraft, type ReportDraft } from './draft'
// ...
const [open, setOpen] = useState(false)
const [restored, setRestored] = useState<ReportDraft | null>(null)
useEffect(() => {
  const d = loadDraft(iocType, iocValue)
  if (d?.pendingOpen) {
    setRestored(d)
    setOpen(true)
    clearDraft(iocType, iocValue)
  }
}, [iocType, iocValue])
// ...
{open && (
  <ReportDialog
    iocType={iocType}
    iocValue={iocValue}
    open={open}
    initialDraft={restored ?? undefined}
    onClose={() => setOpen(false)}
  />
)}
```

- [ ] **Step 7 — full suite + build:** `cd web && npx vitest run` green; `npm --prefix web run build` clean.
- [ ] **Step 8 — commit:**

```bash
git add web/src/components/report/draft.ts web/src/components/report/draft.test.ts web/src/components/report/ReportDialog.tsx web/src/components/report/ReportButton.tsx
git commit -m "feat(report): preserve the typed draft across the OAuth round trip"
```

---

### Task 10: `MyReports` redesign (Part D)

**Files:**
- Create: `web/src/routes/myReportsModel.ts`, `web/src/routes/myReportsModel.test.ts`
- Modify: `web/src/routes/MyReports.tsx` (full redesign)

**Interfaces:**
- Produces: `function statusChipVariant(status: string): 'neutral' | 'accent'`; redesigned `MyReports` route.
- Consumes: `ViewHeader` (`../components/views/ViewFrame`), `Panel`/`Chip` (`../components/ui`), `Notice` (`../components/lookup/LookupStates`), the `SourceLedger` row pattern (`shared/verdict-cards/ui.tsx:190-223` — bordered `ul`, `even:bg-panel-soft/40` zebra, fixed-width left cell). Data shape from `functions/api/report/mine.js` → `{ reports, login }`, rows `{ id, ioc_type, ioc_value, category, status, created_at }` (`lib/reporting/db.mjs:37-43`).

- [ ] **Step 1 — write the failing test** (`web/src/routes/myReportsModel.test.ts`):

```ts
import { describe, expect, it } from 'vitest'
import { statusChipVariant } from './myReportsModel'

describe('statusChipVariant — status → neutral/accent, never a verdict hue', () => {
  it('queued and other in-flight states are neutral', () => {
    expect(statusChipVariant('queued')).toBe('neutral')
    expect(statusChipVariant('reviewing')).toBe('neutral')
    expect(statusChipVariant('rejected')).toBe('neutral')
  })
  it('an actioned/terminal state rides the accent', () => {
    expect(statusChipVariant('published')).toBe('accent')
    expect(statusChipVariant('accepted')).toBe('accent')
    expect(statusChipVariant('actioned')).toBe('accent')
  })
  it('is case-insensitive', () => {
    expect(statusChipVariant('PUBLISHED')).toBe('accent')
  })
  it('an unknown status defaults to neutral', () => {
    expect(statusChipVariant('whatever')).toBe('neutral')
  })
})
```

- [ ] **Step 2 — run it, expect FAIL:** `cd web && npx vitest run src/routes/myReportsModel.test.ts` → "Cannot find module './myReportsModel'".

- [ ] **Step 3 — implement `web/src/routes/myReportsModel.ts`:**

```ts
// myReportsModel — pure view logic for the My-reports route (kept out of the
// component so it exports no non-component values — react-refresh discipline,
// and so it is node-testable).

/** A report's moderation status → a NEUTRAL/ACCENT chip variant, NEVER a verdict
 *  hue (a report's lifecycle is not a severity read). In-flight stays neutral;
 *  an actioned/terminal state rides the product accent. */
export function statusChipVariant(status: string): 'neutral' | 'accent' {
  const s = status.toLowerCase()
  if (s === 'published' || s === 'accepted' || s === 'actioned') return 'accent'
  return 'neutral'
}
```

- [ ] **Step 4 — run it, expect PASS:** `cd web && npx vitest run src/routes/myReportsModel.test.ts`.

- [ ] **Step 5 — redesign `web/src/routes/MyReports.tsx`** with the system primitives (ViewHeader + Panel + SourceLedger-style zebra rows + status `Chip` + `Notice` for the three text states). Keep `markContributorSeen()` on mount (added in Task 5). Full component:

```tsx
// MyReports — the author's own report-status view (routable-but-hidden; reached
// from the account menu + the post-submit link). Reads GET /api/report/mine;
// React escapes all text — no HTML rendering of report fields.

import { useEffect, useState } from 'react'
import { Chip, MicroLabel, Panel } from '../components/ui'
import { ViewHeader } from '../components/views/ViewFrame'
import { Notice } from '../components/lookup/LookupStates'
import { markContributorSeen } from '../lib/contributorSeen'
import { statusChipVariant } from './myReportsModel'

type Row = {
  id: string
  ioc_type: string
  ioc_value: string
  category: string
  status: string
  created_at: string
}

export function MyReports() {
  const [rows, setRows] = useState<Row[] | null>(null)
  const [auth, setAuth] = useState(true)
  const [error, setError] = useState(false)

  useEffect(() => {
    markContributorSeen()
    fetch('/api/report/mine', { credentials: 'same-origin' })
      .then(async (r) => {
        if (r.status === 401) return setAuth(false)
        if (!r.ok) return setError(true)
        const b = await r.json()
        setRows(b.reports ?? [])
      })
      .catch(() => setError(true))
  }, [])

  return (
    <div className="flex flex-col gap-8">
      <ViewHeader
        eyebrow="My reports"
        title="Your submitted indicators"
        intro="Every indicator you've reported and where it sits in review. Visible only to you."
      />

      {!auth ? (
        <Notice eyebrow="Sign in" title="Sign in to see your reports">
          Reporting is attributable, so this view needs a GitHub sign-in.{' '}
          <a href="/api/auth/github/start?return=/reports" className="text-accent underline">
            Sign in with GitHub
          </a>
          .
        </Notice>
      ) : error ? (
        <Notice eyebrow="Error" title="Couldn't load your reports">
          Something went wrong reaching the report store — try again.
        </Notice>
      ) : !rows ? (
        <p className="text-xs text-muted">Loading your reports…</p>
      ) : rows.length === 0 ? (
        <Notice eyebrow="Empty" title="No reports yet">
          When you report an indicator from a lookup card, it will appear here as “queued”.
        </Notice>
      ) : (
        <Panel padding="none">
          <ul className="overflow-hidden rounded-lg">
            {rows.map((r) => (
              <li
                key={r.id}
                className="flex items-start gap-3 border-b border-line px-4 py-3 last:border-0 even:bg-panel-soft/40"
              >
                <span className="flex w-[132px] shrink-0 flex-col items-start gap-1.5">
                  <Chip variant={statusChipVariant(r.status)}>{r.status}</Chip>
                  <span className="font-mono text-micro text-muted">{r.created_at.slice(0, 10)}</span>
                </span>
                <span className="flex min-w-0 flex-1 flex-col gap-0.5">
                  <span className="break-all font-mono text-xs font-semibold text-paper">{r.ioc_value}</span>
                  <MicroLabel tone="muted">{r.category}</MicroLabel>
                </span>
              </li>
            ))}
          </ul>
        </Panel>
      )}
    </div>
  )
}
```

- [ ] **Step 6 — full suite + build:** `cd web && npx vitest run` green; `npm --prefix web run build` clean.
- [ ] **Step 7 — commit:**

```bash
git add web/src/routes/myReportsModel.ts web/src/routes/myReportsModel.test.ts web/src/routes/MyReports.tsx
git commit -m "feat(reports): redesign My reports with ViewHeader + ledger rows + Notice"
```

---

### Task 11: Legibility / eye-test pass (Part E)

**Files:**
- Create: `web/src/lib/contrast.ts`, `web/src/lib/contrast.test.ts`, `web/src/components/report/reportChrome.test.ts`
- Modify: any report/MyReports usage that puts `--faint` on meaning-bearing text (audit + swap to `--muted`)

**Interfaces:**
- Produces: `function contrastRatio(a: string, b: string): number`; `DARK_TOKENS` / `LIGHT_TOKENS` hex maps (mirrored from `shared/tokens.css:106-130` and `:87-100`); `SURFACES`, `READABLE_TEXT`, `AA_NORMAL`.
- Consumes (guard): `SUCCESS_ICON_CLASS` / `SUCCESS_TEXT_CLASS` (`./reportChrome`).

**Measured ratios (dark, computed against the real hexes):** `muted` on `panel` = 6.70 (AA pass), on `panelSoft` = 5.74, on `raised` = 6.25, on `field` = 7.58; `faint` on `panel` = 3.61 (AA **fail**), on `panelSoft` = 3.10; `paper` ≥ 12 everywhere; `accent` on `panelSoft` = 4.83 (AA pass, its worst case). Light theme is stricter still: `faint` on `panel` = 2.88. So `muted`/`paper`/`accent` clear AA on every surface in both themes; `faint` clears none.

- [ ] **Step 1 — write the failing contrast test** (`web/src/lib/contrast.test.ts`):

```ts
import { describe, expect, it } from 'vitest'
import {
  AA_NORMAL, contrastRatio, DARK_TOKENS, LIGHT_TOKENS, READABLE_TEXT, SURFACES,
} from './contrast'

describe('contrastRatio — WCAG 2.x', () => {
  it('white on black is 21:1', () => {
    expect(contrastRatio('#FFFFFF', '#000000')).toBeCloseTo(21, 0)
  })
})

describe('legibility — readable text clears AA on every surface (both themes)', () => {
  for (const [name, T] of [['dark', DARK_TOKENS], ['light', LIGHT_TOKENS]] as const) {
    for (const surface of SURFACES) {
      for (const token of READABLE_TEXT) {
        it(`${name}: ${token} on ${surface} ≥ ${AA_NORMAL}`, () => {
          expect(contrastRatio(T[token], T[surface])).toBeGreaterThanOrEqual(AA_NORMAL)
        })
      }
    }
  }
})

describe('legibility — --faint is BELOW AA (why readable text must not use it)', () => {
  it('dark: faint on panel is below 4.5', () => {
    expect(contrastRatio(DARK_TOKENS.faint, DARK_TOKENS.panel)).toBeLessThan(AA_NORMAL)
  })
  it('light: faint on panel is below 4.5', () => {
    expect(contrastRatio(LIGHT_TOKENS.faint, LIGHT_TOKENS.panel)).toBeLessThan(AA_NORMAL)
  })
})
```

- [ ] **Step 2 — run it, expect FAIL:** `cd web && npx vitest run src/lib/contrast.test.ts` → "Cannot find module './contrast'".

- [ ] **Step 3 — implement `web/src/lib/contrast.ts`:**

```ts
// contrast — the automatable half of the Part E eye-test. WCAG 2.x relative-
// luminance + contrast-ratio, plus the dark/light token hexes (mirrored from
// shared/tokens.css) and which text tokens are "readable" (meaning-bearing).
// The visual eye-test (rendering each surface/state) is the documented live
// dogfood pass. Do NOT retune the shared --faint token — fix the USAGE.

function channel(c: number): number {
  const s = c / 255
  return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4)
}
function luminance(hex: string): number {
  const n = hex.replace('#', '')
  const r = parseInt(n.slice(0, 2), 16)
  const g = parseInt(n.slice(2, 4), 16)
  const b = parseInt(n.slice(4, 6), 16)
  return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b)
}
export function contrastRatio(a: string, b: string): number {
  const la = luminance(a)
  const lb = luminance(b)
  const hi = Math.max(la, lb)
  const lo = Math.min(la, lb)
  return (hi + 0.05) / (lo + 0.05)
}

// Mirrored from shared/tokens.css (dark: lines 106-130; light: 87-100).
export const DARK_TOKENS = {
  ink: '#0E121A', panel: '#161C27', panelSoft: '#212936', raised: '#1B2230', field: '#0A0E15',
  paper: '#E9EDF4', muted: '#98A3B4', faint: '#697486', accent: '#7C8AFF',
} as const
export const LIGHT_TOKENS = {
  ink: '#EDF1F6', panel: '#F8FAFC', panelSoft: '#E8EDF3', raised: '#FFFFFF', field: '#FFFFFF',
  paper: '#131A24', muted: '#55606F', faint: '#8996A6', accent: '#4A4FD0',
} as const

export const SURFACES = ['ink', 'panel', 'panelSoft', 'raised', 'field'] as const
export const READABLE_TEXT = ['muted', 'paper', 'accent'] as const
export const AA_NORMAL = 4.5
```

- [ ] **Step 4 — run it, expect PASS:** `cd web && npx vitest run src/lib/contrast.test.ts`.

- [ ] **Step 5 — write the reserved-colour guard test** (`web/src/components/report/reportChrome.test.ts`):

```ts
import { describe, expect, it } from 'vitest'
import { SUCCESS_ICON_CLASS, SUCCESS_TEXT_CLASS } from './reportChrome'

describe('report success chrome is accent, never a verdict hue', () => {
  it('carries no verdict-* class (green = "a source found nothing adverse")', () => {
    expect(SUCCESS_ICON_CLASS).not.toMatch(/verdict/)
    expect(SUCCESS_TEXT_CLASS).not.toMatch(/verdict/)
  })
  it('success is the accent-stroked check + paper text', () => {
    expect(SUCCESS_ICON_CLASS).toContain('stroke-[var(--accent)]')
    expect(SUCCESS_TEXT_CLASS).toContain('text-paper')
  })
})
```

- [ ] **Step 6 — run it, expect PASS:** `cd web && npx vitest run src/components/report/reportChrome.test.ts` (green — `reportChrome.ts` already satisfies it from Task 8; this test locks the contract).

- [ ] **Step 7 — audit + fix usages.** Grep the reporting surfaces for `text-faint` / `tone="faint"` on meaning-bearing text and swap to `--muted`:
  - `ReportDialog.tsx` — the counters already use `text-muted`/`text-verdict-amber` (Ground-truth correction #3); confirm no meaning-bearing `text-faint` remains. The evidence/comment `placeholder:text-faint` is acceptable (placeholder = incidental adornment, not read content).
  - `MyReports.tsx` — dates + category use `text-muted` (done in Task 10); confirm no `text-faint`.
  - `AccountControl.tsx` — the identity `MicroLabel tone="faint"` "Signed in with GitHub" is a decorative caption above the `@handle` (which is `text-paper`); it is non-essential adornment, so it is allowed. The Sign-in link and menu items use `text-muted` (done in Task 6). No change required; note the audit outcome in the commit body.
  - Run `cd web && npx vitest run src/lib/contrast.test.ts` again to confirm nothing regressed.

- [ ] **Step 8 — full suite + build:** `cd web && npx vitest run` green; `npm --prefix web run build` clean.
- [ ] **Step 9 — commit:**

```bash
git add web/src/lib/contrast.ts web/src/lib/contrast.test.ts web/src/components/report/reportChrome.test.ts
git commit -m "test(a11y): contrast helper + reserved-colour guard for the reporting UI"
```

---

### Task 12: `docs/DESIGN-TOKENS.md` — the web/-scoped token reference

**Files:**
- Create: `docs/DESIGN-TOKENS.md`

**Interfaces:** none (documentation). Source of truth is `shared/tokens.css` (imported by `web/src/index.css:2`).

**Note (harness):** documentation-only — no code, no new test. Gate is the full suite staying green (unchanged) — this is the honest verification for a doc task.

- [ ] **Step 1 — write `docs/DESIGN-TOKENS.md`** with these sections (a short, non-duplicative reference so the vocabulary isn't reverse-engineered from primitives each time):
  - **Source of truth:** `shared/tokens.css` (dark: lines 106-130; light: 87-100), imported by `web/src/index.css`. This doc is a map, not a second source — never fork the hexes.
  - **Room neutrals:** `--ink` / `--panel` / `--panel-soft` / `--raised` / `--field` (surfaces, back-to-front); `--line` / `--line-bright` / `--line-strong` (hairlines); `--paper` / `--muted` / `--faint` (text, brightest-to-quietest). Tailwind utilities: `bg-panel`, `text-muted`, `border-line`, etc.
  - **Product accent:** `--accent` / `--accent-dim` / `--ink-on-accent` (periwinkle — tabs, primary buttons, links, focus rings, active state, the signed-in indicator, UI confirmations). NEVER a verdict.
  - **Verdict / severity (meaning only):** `--red` / `--gold`(amber) / `--green` → `text-verdict-red` / `-amber` / `-green`. Tints/edges: `--tint-*` / `--edge-*`. Reserved-colour law: verdict hues carry a source's read on an indicator (or an owner-approved analyzer signal tier) — never decoration, never a UI confirmation.
  - **Type scale:** `text-micro` (11px, floor) → `text-display` (64px), with the mono micro-label voice (`MicroLabel`, `tracking-label` 0.14em, uppercase). Fonts: `font-sans`/`font-display` = Archivo, `font-mono` = IBM Plex Mono.
  - **Radii:** `rounded-sm` (4) / `-md` (8) / `-lg` (12). **Motion:** `--duration-fast|base|slow|draw`, `--ease-brand|-io|-spring`, mirrored in `shared/lib/motion.ts` (`DUR`/`EASE`); WAAPI-only for CSP.
  - **Legibility rule (Part E):** readable text uses `--muted` or `--paper`; `--faint` is incidental adornment only. Measured (dark, on `--panel`): `--muted` = 6.70:1 (AA pass), `--faint` = 3.61:1 (AA fail); light is stricter. Enforced by `web/src/lib/contrast.test.ts`.
  - **Primitives index:** `Button`/`buttonClasses` (primary/ghost/tertiary/danger), `Panel`/`Card`, `MicroLabel`, `Chip` (neutral/accent + verdict families), `Divider`, `Notice`, `SourceLedger`, the `<dialog>` overlay pattern — cite each file path.

- [ ] **Step 2 — gate:** `cd web && npx vitest run` still green (unchanged count).
- [ ] **Step 3 — commit:**

```bash
git add docs/DESIGN-TOKENS.md
git commit -m "docs: add web-scoped design-tokens reference"
```

---

## Live dogfood pass (documented, not automated — per spec §Testing "Live-only")

After Task 12, on the deployed site (Turnstile + OAuth need the live origin, per Phase 0+1 precedent):
1. Anonymous: confirm the topbar shows NO account chrome and the Network tab shows NO `/api/report/mine` call.
2. Click Report on a resolved lookup card → the tertiary button sits in the card action row; the modal opens; signed-out shows the gate.
3. Sign in → OAuth round trip returns you to the card with the dialog auto-reopened and the draft restored.
4. Submit with empty evidence (inline required), then valid → accent ✓ success (NOT green); re-submit same indicator → deduped copy.
5. Confirm the account chip `@handle` menu → My reports + Sign out (Sign out returns the quiet "Sign in" link, not zero chrome).
6. Eye-test each surface/state in both themes — nothing reads illegibly faint.
