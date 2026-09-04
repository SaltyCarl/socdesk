# Hunt Playbooks — Plan 2: Client Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Make Hunt Playbooks visible: below the enrichment EscalationCard, render a `HuntPlaybookPanel` — scenario chips filtered to the IOC type, the selected playbook's ordered steps with the IOC injected into each step's KQL, copy-buttoned. Consumes the `playbooks.json` Plan 1 already ships.

**Architecture:** A pure templating/filter module (`playbooks.ts`) + a shared KQL-block affordance extracted from the hunt-pack (`HuntKql.tsx`) + a leaf panel (`HuntPlaybookPanel.tsx`) that self-fetches `useStateData('playbooks')` and is rendered by `ResultRegion` when the enriched indicator is huntable and has matching playbooks.

**Tech Stack:** React 19 + Tailwind v4; vitest (node env, `renderToStaticMarkup`).

**Spec:** `docs/superpowers/specs/2026-09-03-hunt-playbooks-design.md`

## Global Constraints
- **IOC↔param namespaces differ:** `data.type` is `IndicatorType` (`ipv4`/`ipv6`/…, never `'ip'`); a step's `param` is a family (`ip`/`upn`/…). Map with `PARAM_FOR_TYPE` (`ipv4→ip`, `ipv6→ip`). A step injects ONLY when `PARAM_FOR_TYPE[iocType] === step.param`; otherwise its `{{param}}` stays VISIBLE (a follow-on placeholder — never fabricate the discovered account).
- **Safe substitution:** escape the IOC as a KQL string literal (`\`→`\\`, `"`→`\"`, strip control chars) before insertion into `"…"`.
- **v1 = local selection state, no URL persistence, no full-width route.** KQL blocks scroll in `overflow-x-auto`. Deep-link (`alert=`) is v2.
- **Reuse, don't fork:** extract the hunt-pack's `<details>View KQL</details>` + `CopyKqlButton` + `copyPlain` into a shared module; both the Adversaries hunt-pack and the playbook step use it (no drift).
- **Honesty:** panel doctrine line ("parameterized starting points, syntax-validated against the Kusto emulator — not a detection guarantee; verify your schema"); playbook-level technique chips → the Adversaries hunt-pack; provenance `SOCDesk · MIT · tested <date>`.
- No inline styles (`react/forbid-dom-props`); react-refresh (pure fns in `.ts`, component files export only components); vitest env node; `noUnusedLocals`.

---

### Task 1: Types + `playbooksForType` + `injectIoc` (pure)

**Files:**
- Modify: `web/src/components/views/types.ts` (add `PlaybookStep`, `Playbook`, `PlaybooksPayload`)
- Create: `web/src/components/views/playbooks.ts`
- Test: `web/src/components/views/__tests__/playbooks.test.ts`

**Interfaces — Produces:**
```ts
// types.ts
export interface PlaybookStep { id: string; title: string; kind: 'pivot' | 'scenario'
  param: string; dialect: string; tables?: string[]; kql: string }
export interface Playbook { id: string; title: string; alert_sources?: string[]
  ioc_types: string[]; techniques: string[]; tested?: string
  source: { kind: string; url: string; license: string; author?: string }; steps: PlaybookStep[] }
export interface PlaybooksPayload { generated_at: string; schema_version: number; playbooks: Playbook[] }
// playbooks.ts
export const PARAM_FOR_TYPE: Record<string, string>
export function playbooksForType(playbooks: Playbook[], iocType: string): Playbook[]
export function injectIoc(kql: string, stepParam: string, iocType: string, iocValue: string): string
```

- [ ] **Step 1: Write the failing test**

```ts
// playbooks.test.ts
import { describe, expect, it } from 'vitest'
import { injectIoc, playbooksForType, PARAM_FOR_TYPE } from '../playbooks'
import type { Playbook } from '../types'

const pb = (id: string, ioc_types: string[]): Playbook => ({
  id, title: id, ioc_types, techniques: [], source: { kind: 'socdesk', url: 'x', license: 'MIT' }, steps: [],
})

describe('playbooksForType', () => {
  it('keeps playbooks whose ioc_types include the enriched type', () => {
    const all = [pb('a', ['ipv4', 'ipv6']), pb('b', ['domain'])]
    expect(playbooksForType(all, 'ipv4').map((p) => p.id)).toEqual(['a'])
    expect(playbooksForType(all, 'domain').map((p) => p.id)).toEqual(['b'])
    expect(playbooksForType(all, 'sha256')).toEqual([])
  })
})

describe('injectIoc', () => {
  it('substitutes when the param family matches the IOC type (ipv4 -> ip)', () => {
    expect(injectIoc('where IPAddress == "{{ip}}"', 'ip', 'ipv4', '203.0.113.7'))
      .toBe('where IPAddress == "203.0.113.7"')
  })
  it('leaves a non-matching (follow-on) placeholder visible', () => {
    expect(injectIoc('where UserPrincipalName == "{{upn}}"', 'upn', 'ipv4', '203.0.113.7'))
      .toBe('where UserPrincipalName == "{{upn}}"')
  })
  it('escapes quotes/backslashes so the IOC cannot break the string literal', () => {
    expect(injectIoc('== "{{domain}}"', 'domain', 'domain', 'a"\\b'))
      .toBe('== "a\\"\\\\b"')
  })
  it('PARAM_FOR_TYPE maps both IP families to ip', () => {
    expect(PARAM_FOR_TYPE.ipv4).toBe('ip')
    expect(PARAM_FOR_TYPE.ipv6).toBe('ip')
  })
})
```

- [ ] **Step 2: Run to verify fail** — `npx vitest run src/components/views/__tests__/playbooks.test.ts` → FAIL (module missing).

- [ ] **Step 3: Add the types** — in `types.ts`, append the three interfaces above.

- [ ] **Step 4: Implement `playbooks.ts`**

```ts
import type { Playbook } from './types'

/** IndicatorType (ipv4/ipv6/domain/...) → step param FAMILY (ip/domain/...).
 *  Both IP families collapse to `ip`; `email` has no v1 param (identity playbooks
 *  are IP-triggered in v1). */
export const PARAM_FOR_TYPE: Record<string, string> = {
  ipv4: 'ip', ipv6: 'ip', domain: 'domain', url: 'url', md5: 'md5', sha1: 'sha1', sha256: 'sha256',
}

/** Playbooks offered for an enriched IOC type — those whose ioc_types include it. */
export function playbooksForType(playbooks: Playbook[], iocType: string): Playbook[] {
  return playbooks.filter((p) => p.ioc_types.includes(iocType))
}

/** Escape a value for safe insertion inside a KQL double-quoted string literal. */
function escapeKqlString(v: string): string {
  // eslint-disable-next-line no-control-regex
  return v.replace(/[\x00-\x1f]/g, '').replace(/\/g, '\\').replace(/"/g, '\\"')
}

/** Substitute `{{stepParam}}` with the escaped IOC ONLY when the IOC's type maps
 *  to this step's param family; otherwise leave the placeholder visible (a
 *  follow-on entity the analyst fills — never fabricated). */
export function injectIoc(kql: string, stepParam: string, iocType: string, iocValue: string): string {
  if (PARAM_FOR_TYPE[iocType] !== stepParam) return kql
  return kql.split(`{{${stepParam}}}`).join(escapeKqlString(iocValue))
}
```

- [ ] **Step 5: Run to verify pass** — `npx vitest run src/components/views/__tests__/playbooks.test.ts` → all pass.

- [ ] **Step 6: Commit** — `git add web/src/components/views/types.ts web/src/components/views/playbooks.ts web/src/components/views/__tests__/playbooks.test.ts && git commit -m "feat(playbooks): types + playbooksForType + injectIoc (client)"`

---

### Task 2: Extract the shared KQL affordance

**Files:**
- Create: `web/src/components/views/HuntKql.tsx` (`copyPlain`, `CopyKqlButton`, `KqlBlock`)
- Modify: `web/src/components/views/ActorProfile.tsx` (remove local `copyPlain`/`CopyKqlButton`; `HuntRowView` uses `KqlBlock`; import from `./HuntKql`)
- Test: existing `web/src/components/views/__tests__/ActorProfile.test.tsx` stays green (no behavior change).

**Interfaces — Produces:**
```ts
copyPlain (module-local, used only by CopyKqlButton)
export function CopyKqlButton(props: { kql: string }): JSX.Element
export function KqlBlock(props: { kql: string; label?: string }): JSX.Element  // the <details>View KQL</details> + <pre> + CopyKqlButton
```

- [ ] **Step 1: Create `HuntKql.tsx`** — lift `copyPlain` (ActorProfile.tsx:782-790) and `CopyKqlButton` (:792-809) verbatim, and add `KqlBlock` factoring the `<details>` from `HuntRowView` (:842-854):

```tsx
import { useState } from 'react'

async function copyPlain(text: string): Promise<boolean> {
  try {
    if (!navigator.clipboard?.writeText) return false
    await navigator.clipboard.writeText(text)
    return true
  } catch {
    return false
  }
}

export function CopyKqlButton({ kql }: { kql: string }) {
  const [state, setState] = useState<'idle' | 'copied' | 'blocked'>('idle')
  const label = state === 'copied' ? 'Copied' : state === 'blocked' ? 'Clipboard blocked' : 'Copy KQL'
  return (
    <button
      type="button"
      onClick={() => {
        void copyPlain(kql).then((ok) => {
          setState(ok ? 'copied' : 'blocked')
          setTimeout(() => setState('idle'), 2000)
        })
      }}
      className="inline-flex items-center rounded-md border border-line bg-panel px-2.5 py-1 font-mono text-micro font-semibold text-muted transition-colors duration-150 ease-brand hover:border-line-bright hover:text-paper focus-visible:outline-2 focus-visible:outline-accent"
    >
      {label}
    </button>
  )
}

/** The shared "▶ View KQL" disclosure + scrollable code block + copy button —
 *  used by the Adversaries hunt-pack row AND the enrichment playbook step. */
export function KqlBlock({ kql, label = 'View KQL' }: { kql: string; label?: string }) {
  return (
    <details>
      <summary className="cursor-pointer select-none font-mono text-micro font-semibold uppercase tracking-label text-accent">
        {label}
      </summary>
      <pre className="mt-2 overflow-x-auto whitespace-pre rounded-md border border-line bg-panel p-3 font-mono text-micro text-paper">
        {kql}
      </pre>
      <div className="mt-2">
        <CopyKqlButton kql={kql} />
      </div>
    </details>
  )
}
```

- [ ] **Step 2: Refactor `ActorProfile.tsx`** — delete the local `copyPlain` + `CopyKqlButton` defs; in `HuntRowView`, replace the inline `<details>…</details>` (:842-854) with `<KqlBlock kql={r.kql} />`; add `import { KqlBlock } from './HuntKql'` (and drop any now-unused `useState` import ONLY if nothing else in the file uses it — verify with a grep; ActorProfile uses `useState` elsewhere, so keep it).

- [ ] **Step 3: Run to verify no regression** — `npx vitest run src/components/views/__tests__/ActorProfile.test.tsx` → green (the hunt-pack still renders "View KQL" + the KQL text); `npx tsc -b` clean; `npm run lint` clean (no unused `copyPlain`/`CopyKqlButton`).

- [ ] **Step 4: Commit** — `git add web/src/components/views/HuntKql.tsx web/src/components/views/ActorProfile.tsx && git commit -m "refactor(hunt): extract shared KqlBlock/CopyKqlButton affordance"`

---

### Task 3: `HuntPlaybookPanel`

**Files:**
- Create: `web/src/components/views/HuntPlaybookPanel.tsx`
- Test: `web/src/components/views/__tests__/HuntPlaybookPanel.test.tsx`

**Interfaces:**
- Consumes: `playbooksForType`, `injectIoc` (Task 1), `KqlBlock` (Task 2), `TechniqueChip`, `ExternalLink`, `MonoLabel`, `useStateData`.
- Produces: `HuntPlaybookPanel({ iocType, iocValue }: { iocType: string; iocValue: string }): JSX.Element | null`.

Behaviour: self-fetch `useStateData<PlaybooksPayload>('playbooks')`; `matches = playbooksForType(data?.playbooks ?? [], iocType)`; return `null` when `matches.length === 0` (loading or no playbook for this type → render nothing). Otherwise: honesty line; a chip row (`matches.map` → a button per playbook that `setSelectedId`); the selected playbook (default `matches[0]`) rendered as its ordered steps — each `<KqlBlock kql={injectIoc(step.kql, step.param, iocType, iocValue)} label={step.title} />`, and when the step's `{{param}}` survives (a follow-on), a one-line "replace the placeholder with an account from the pivot above" note; playbook-level `TechniqueChip`s; provenance + `ExternalLink` to `source.url`.

- [ ] **Step 1: Write the failing test**

```tsx
// HuntPlaybookPanel.test.tsx
import { describe, expect, it, vi } from 'vitest'
import { renderToStaticMarkup } from 'react-dom/server'

vi.mock('../useStateData', () => ({
  useStateData: () => ({ status: 'ready', data: { generated_at: 'x', schema_version: 1, playbooks: [
    { id: 'unfamiliar-signin-properties', title: 'Unfamiliar sign-in properties',
      ioc_types: ['ipv4', 'ipv6'], techniques: ['T1078.004'], tested: '2026-09-04',
      source: { kind: 'socdesk', url: 'https://x/y.yaml', license: 'MIT', author: 'SOCDesk' },
      steps: [
        { id: 'signins-from-ip', title: 'Every sign-in from this IP', kind: 'pivot', param: 'ip',
          dialect: 'log_analytics', tables: ['SigninLogs'], kql: 'SigninLogs | where IPAddress == "{{ip}}"' },
        { id: 'novelty', title: 'Novelty for an account', kind: 'scenario', param: 'upn',
          dialect: 'log_analytics', tables: ['SigninLogs'], kql: 'where UserPrincipalName == "{{upn}}"' }] },
    { id: 'password-spray', title: 'Password spray', ioc_types: ['ipv4'], techniques: ['T1110.003'],
      source: { kind: 'socdesk', url: 'https://x/z.yaml', license: 'MIT' }, steps: [] }] } }),
}))
import { HuntPlaybookPanel } from '../HuntPlaybookPanel'

describe('HuntPlaybookPanel', () => {
  it('renders a chip per matching playbook and the default playbook steps with the IP injected', () => {
    const html = renderToStaticMarkup(<HuntPlaybookPanel iocType="ipv4" iocValue="203.0.113.7" />)
    expect(html).toContain('Unfamiliar sign-in properties')
    expect(html).toContain('Password spray')                 // chip
    expect(html).toContain('203.0.113.7')                    // {{ip}} injected in the default playbook
    expect(html).not.toContain('{{ip}}')
    expect(html).toContain('{{upn}}')                        // follow-on placeholder stays visible
    expect(html).toContain('starting point')                 // honesty line
  })

  it('renders nothing for a type with no matching playbook', () => {
    const html = renderToStaticMarkup(<HuntPlaybookPanel iocType="sha256" iocValue="abc" />)
    expect(html).toBe('')
  })
})
```

- [ ] **Step 2: Run to verify fail** — FAIL (module missing).

- [ ] **Step 3: Implement `HuntPlaybookPanel.tsx`** — self-contained; uses `useStateData`, `playbooksForType`, `injectIoc`, `KqlBlock`, `TechniqueChip`, `ExternalLink`, brand-token chips (mirror the ProfileDirectory kind-chip style). Renders `null` when no matches. Default selection = `matches[0]`; a `<button>` per playbook sets the selection (local `useState`). Each step: `injectIoc(step.kql, step.param, iocType, iocValue)` → `KqlBlock`; if the result still contains `{{`, render the follow-on note. Provenance from `selected.source`. (Full component authored in this step — mirror `HuntPackPanel`'s honesty line + `DIALECT_CAVEAT[log_analytics]` copy.)

- [ ] **Step 4: Run to verify pass** — both tests pass.

- [ ] **Step 5: Commit** — `git add web/src/components/views/HuntPlaybookPanel.tsx web/src/components/views/__tests__/HuntPlaybookPanel.test.tsx && git commit -m "feat(playbooks): HuntPlaybookPanel"`

---

### Task 4: Wire into the enrichment surface

**Files:**
- Modify: `web/src/components/cockpit/ResultRegion.tsx` (render the panel below the EscalationCard when huntable)
- Test: extend the panel/ResultRegion coverage as feasible in node env.

**Interfaces:**
- Consumes: `HuntPlaybookPanel` (Task 3), `isEnrichable` (already imported in ResultRegion).

- [ ] **Step 1: Render the panel** — in `ResultRegion.tsx`, in the `cockpit.kind === 'indicator'` + `state.kind === 'ok'` branch, inside the existing `<div className="flex w-full max-w-md flex-col gap-3">`, AFTER the `<EscalationCard … />`, add (the panel self-gates to null when the type has no playbooks):

```tsx
        {isEnrichable(state.data.type) && (
          <HuntPlaybookPanel iocType={state.data.type} iocValue={state.data.indicator} />
        )}
```

Add `import { HuntPlaybookPanel } from '../views/HuntPlaybookPanel'`.

- [ ] **Step 2: Verify** — `npx tsc -b` clean; `npm run lint` clean; `npx vitest run` (full) green; `npm run build` succeeds.

- [ ] **Step 3: Commit** — `git add web/src/components/cockpit/ResultRegion.tsx && git commit -m "feat(playbooks): render HuntPlaybookPanel under the enrichment card"`

---

### Task 5: The four remaining v1 playbooks (data)

**Files:**
- Create: `data/hunt/playbooks/socdesk-impossible-travel.yaml`, `-mfa-fatigue-method-added.yaml`, `-malicious-inbox-rule.yaml`, `-risky-oauth-consent.yaml`
- Test: `tests/test_playbooks.py::test_committed_playbooks_load_and_validate` (bump the count) + local Kustainer.

Each: IP-pivot step 1 (SigninLogs, `param: ip`) + a `{{upn}}`-scoped scenario step on its table (SigninLogs / AuditLogs / OfficeActivity — all have committed DDL), adapting the matching authored rule (`socdesk-mfa-method-added-after-risky-signin`, `-inbox-rule-forward-or-hide`, `-oauth-consent-risk-tiering`). Every step's sample-substituted KQL MUST pass the Kustainer lane (`KUSTO_URL=http://localhost:8091 python tools/validate_hunt_kql.py --from-allowlist`) before commit — a scenario whose table lacks a column is trimmed until fixed.

- [ ] **Step 1: Author the four YAMLs** (SigninLogs pivot + scenario step, following the Task-5 exemplars of Plan 1). **Step 2:** update the count assertion in `tests/test_playbooks.py` to `>= 6`. **Step 3:** `python -m pytest tests/test_playbooks.py -q` green. **Step 4:** boot Kustainer + run the lane; all `*::*` steps PASS. **Step 5:** commit.

---

## Self-Review
- **Spec coverage:** §2 templating → Task 1; §3 panel + reuse → Tasks 2/3/4; §5 scenarios → Task 5 (+ Plan 1's 2). Deep-link/full-width/AH stay v2 (spec §9). No client gap.
- **Placeholder scan:** every code step carries real code; Task 3 Step 3 and Task 5 Step 1 author full components/YAMLs during implementation from the shown interfaces + the Plan-1 exemplars (not "similar to").
- **Type consistency:** `Playbook`/`PlaybookStep`/`PlaybooksPayload` (Task 1) used by the panel (Task 3) + wiring (Task 4); `injectIoc(kql, stepParam, iocType, iocValue)` signature identical across Task 1 and Task 3; `KqlBlock({kql,label})` from Task 2 used in Task 3.
