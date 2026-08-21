# IOC Reporting — UX Polish Design Spec

**Status:** proposed (2026-08-21) · **Depends on:** IOC Reporting Phase 0+1 (shipped + live)
**Informed by:** a 3-specialist UX Team review (nav/account-entry, report affordance/form, visual/design-system cohesion).

## Goal

Bring the shipped-but-under-discoverable IOC reporting write path up to SOCDesk's
polish standard, without disturbing the no-account lookup loop. Three surfaces:
a discoverable **contributor sign-in / account** entry, a real **Report affordance**
on the resolved lookup card, and a polished **report form + My-reports** view.

## Non-goals (locked out)

- **No broader user account.** The account stays a **narrow contributor identity**
  (report + my-reports, and later reputation / corroboration-vote / contributor-profile).
  It never touches the read/lookup loop. Watchlists, saved indicators, change-alerts,
  and enrich rate-limit tiers are a deliberate future doctrine-change (see BACKLOG.md),
  not this work.
- No new read-path account gating. Lookup / enrich / analyzer stay 100% no-account.
- No reputation/corroboration/profile UI yet (the account menu's list shape leaves room
  for them without restructuring).

## Design law (correction — read first)

`design-system.md` ("Chart Room") is **historical**: it governs the retired `site/`
app only. The binding law for `web/` is `CLAUDE.md` + `shared/tokens.css` + the shipped
primitives. **All work composes from existing primitives** — `Button`/`buttonClasses`,
`Panel`/`Card`, `MicroLabel`, `Chip`, `Divider`, `shared/lib/motion`, and the
`CommandPalette` `<dialog>` overlay pattern — never hand-rolled `<div className="rounded-md border…">`.

**Reserved-colour law (binding):**
- Periwinkle `--accent` = product chrome (tabs, primary buttons, links, focus rings,
  active state, the signed-in indicator). Never a verdict/severity read.
- `--red` / `--gold`(amber) / `--green` = verdict-severity meaning ONLY (a source's read
  on an indicator, or the analyzer's owner-approved signal tiers).
- **UI confirmations are not verdicts.** "Report submitted / queued" uses the accent-stroked
  checkmark + paper text (the `CardActions.tsx` precedent) — **never `text-verdict-green`**
  (green already means "a source found nothing adverse"; reusing it risks a user reading
  "queued" as "this IOC is clean").
- Report **category** and **status** chips use `Chip variant="neutral"|"accent"` only —
  never the verdict variants.

**Side task (fold in):** there is no consolidated `web/` design-tokens doc — the vocabulary
is reverse-engineered from primitives each time. Write a short `web/`-scoped tokens reference
(`docs/DESIGN-TOKENS.md` or similar) as part of this work so it isn't re-derived next time.

---

## Part A — Account control (nav): quiet-until-relevant

A new topbar control that stays invisible to the 99% who only look up, and appears for
contributors — gated by **two** signals so the anonymous path pays nothing:

- `contributorSeen` — `localStorage` key `sd_contributor` (presence = truthy), read once
  on mount (mirror `ThemeToggle`'s SSR-safe mount-read). Set at three write sites:
  `ReportButton` click, `useSession` resolving `status:'in'`, and `MyReports` mount.
- `session.status` — from `useSession`.

**The probe is gated behind `contributorSeen`:** a browser that has never engaged reporting
fires **no** session probe and renders **no** DOM. Restraint enforced at the network layer,
not just visually.

| `contributorSeen` | `session.status` | Topbar renders |
|---|---|---|
| false | any | nothing (no DOM, no probe) |
| true | loading | nothing (brief; no loading chrome) |
| true | out | quiet **"Sign in"** text link |
| true | in | **AccountChip** (`@handle` + menu) |

`contributorSeen` intentionally outlives sign-out (a returning contributor keeps the quiet
"Sign in" link, not amnesia to zero chrome).

**Components / changes:**
- New `web/src/components/ui/AccountControl.tsx`, exported from `components/ui/index.ts`.
- **Relocate** `useSession` from `components/report/useSession.ts` → `web/src/lib/useSession.ts`
  (it's now Shell-level chrome, not a report-only dependency); update the one import in
  `ReportForm`. Non-functional move.
- **Extend `SessionState`** to `{ status: 'loading'|'in'|'out'; login?: string }`.
  Backend: `functions/api/report/mine.js` returns `login` in its body (one line; `requireSession`
  already decodes `p.login`). No new endpoint, reuses the same probe.
- Menu panel = `Card padding="sm"` (`bg-raised`, e-elevation, `rounded-lg`), anchored
  `absolute` to a `relative` trigger wrapper — **no portal** (unlike `MobileNav`, no
  fixed-position stacking trap here). Reuse `MobileNav`'s dismiss contract (Escape /
  outside-pointerdown / return-focus). SPA nav via the exported `navigate()` from
  `palette/commands.ts` (don't fork a third copy).
- **Wire logout:** `POST /api/auth/github/logout` exists but nothing calls it today — the
  menu's "Sign out" does. On success: close, re-probe (or optimistic `status:'out'`), stay
  on page; `contributorSeen` persists so the quiet "Sign in" link returns.
- `/reports` **stays `nav:false`** (never a primary tab). Reachable via the menu's "My reports"
  and the post-submit link.
- Topbar insertion: `{right} <AccountControl/> <ThemeToggle/>` (`Topbar.tsx`).

**Menu contents:** non-interactive identity row (`MicroLabel tone="faint"` "Signed in with
GitHub" + `@handle` mono) → `Divider` → "My reports" (`<a role="menuitem">` → `/reports`) →
"Sign out" (`<button role="menuitem">`).

**Sign-in link / OAuth:** `href="/api/auth/github/start?return=<pathname+hash>"` (same
`return=` construction `ReportForm` uses), so callback returns the user where they were.
Three OAuth entry points total (topbar link, report dialog gate, `/reports` gate) — all hit
the one existing endpoint with the identical `return=` contract; no new OAuth code.

**Accessibility:** trigger `aria-haspopup="menu" aria-expanded aria-controls aria-label="Account
menu, signed in as <login>"`; panel `role="menu"`; real `<a>`/`<button>` `role="menuitem"`;
Escape closes + returns focus; focus moves to first item on open; motion via `shared/lib/motion`
with reduced-motion honored; standard `focus-visible:outline-accent` ring.

**States sketch:**
```
Anonymous (99%):   [SOCDESK] Overview Lookup Analyzer Desk Profiles  [Lookup… ⌘K] [☀]
Returning, out:    …                                                 [Lookup… ⌘K] Sign in [☀]
Signed in:         …                                                 [Lookup… ⌘K] [@handle ▾] [☀]
   menu ▾ → "SIGNED IN WITH GITHUB / @handle" · My reports · Sign out
```

---

## Part B — Report affordance: a real button in the card action row

Root cause of "no button": today it's 11px faint text mounted **below** the card in page
whitespace (`Lookup.tsx` `mt-2` div after the card container closes), not a control.

- Add optional `reportSlot?: ReactNode` to the shared `EscalationCard`, rendered in the
  existing header action row after `CardActions`, separated by a vertical `Divider`.
  **Only `Lookup.tsx` passes it** (as it already conditionally passes `reportable`); the
  extension/cockpit/inline consumers omit it and render unchanged — preserves the intentional
  web-only reporting boundary.
- `ReportButton` becomes a real `Button` at `size="sm"` (`h-8`, matching row-mates) at a
  **quieter weight than ghost**, so hierarchy reads Copy card (primary) > Copy text (ghost)
  > **Report**. Flag glyph (`size-4`, 24-viewbox stroke family), label "Report",
  `aria-label="Report this indicator"`.
- **Decision — button weight:** add a new `tertiary` variant to `buttonClasses.ts`
  (`border-transparent bg-transparent text-muted hover:border-line hover:bg-panel-soft
  hover:text-paper`, same `h-8 gap-1.5 px-3 text-xs` as `sm`) — a small, reusable
  design-system addition for "discoverable but not competing" actions. **Reversible
  alternative:** reuse the existing `ghost` variant and accept Report reading at equal
  weight to Copy text. (Chosen: `tertiary`.)

```
│▍ ESCALATION DRAFT   SOCDESK · TRIAGE   [Copy card][Copy text] │ [⚑ Report] │
```

Row already `flex-wrap` — on narrow viewports Report wraps to its own line, no overlap.

**Follow-up (out of scope, one line):** `ResultRegion.tsx` (cockpit) renders the same card
with no report slot; once `reportSlot` exists it can be wired there too. Not in this spec.

---

## Part C — Report form → `ReportDialog`

Rebuild `ReportForm` as a modal `ReportDialog` on the **one** overlay pattern the app already
has: `CommandPalette`'s native `<dialog>` + `showModal()` + WAAPI motion via `shared/lib/motion`,
Escape/backdrop-click close, native focus trap. Width `w-[min(28rem,calc(100%-2rem))]`.
No new drawer mechanism.

**State machine:**
```
closed → open
  ├─ session loading → loading (brief "…")
  ├─ session out     → gate (sign-in prompt; draft-restored note if returning)
  │     → [sign in] → OAuth round trip → return → auto-reopen at fill, draft restored
  └─ session in      → fill
        → submit, evidence empty     → fill + inline "Evidence is required" (no request)
        → submit, turnstile pending  → submit disabled + hint
        → submit                     → submitting (fields locked, "Submitting…")
              → 200 queued            → success-queued (accent ✓, "View my reports"/"Done")
              → 200 deduped:true      → success-deduped ("Already reported…")
              → 401                   → gate (session expired), draft preserved
              → 400 turnstile         → fill + error banner, widget reset
              → 400 validation        → fill + banner (field-mapped where user-fixable)
              → 403 banned            → banned (terminal, flat, no retry)
              → 429                   → capped ("Daily limit reached (25/day)", terminal-today)
              → network/other         → fill + retryable banner, draft intact
```

**Key interaction fix — the OAuth round trip:** today signing in from the form loses the
dialog *and* the typed draft. Fix: before navigating to GitHub, stash
`{category, evidence, comment, pendingOpen:true}` in `sessionStorage` keyed
`sd-report-draft:<iocType>:<iocValue>`. On mount, if a pending draft matches the current
resolved indicator, auto-open the dialog with the draft restored, then clear the flag.

**Form specifics:**
- **Category:** default to a disabled `"Select a category"` placeholder — drop the current
  silent `'scanner'` default (a silent-miscategorization risk).
- **Evidence:** `required`, `MicroLabel` counter `n / 2000` (mono, right-aligned, faint→amber
  near cap); inline "Evidence is required" once touched-and-empty (not just a mute disabled
  submit). Keep `font-mono` (technical/evidence content).
- **Comment (optional):** `font-sans`, counter `n / 1000`.
- **Turnstile:** labeled `MicroLabel "Verification"` slot with a fixed-height loading
  placeholder while the widget loads; render `appearance:'interaction-only'`, `size:'compact'`
  to fit the 28rem dialog.
- **Buttons:** shared `Button` — `variant="ghost" size="sm"` Cancel, `variant="primary"
  size="sm"` Submit. Sign-in CTA in the gate state = `Button variant="primary"` (not the
  current hand-rolled mono-micro anchor).
- **Surfaces:** the form chrome uses `Panel` (not a re-invented `rounded-md border bg-panel`
  div). Error/empty states route through the shared `Notice` component.
- **Reserved-colour:** success = accent ✓ + paper (NOT green); errors split — amber only for
  genuine policy outcomes (banned/capped, `Notice tone="amber"`), muted for plain validation.

**Accessibility:** `<dialog>` gives focus trap + Escape free; every field gets an explicit
`<label>`/`aria-label` (current markup has none — placeholder-only); success/error copy in a
`role="status" aria-live="polite"` region (the copy-toast pattern).

---

## Part D — My reports view

Currently bare `<p>`/`<ul>` one click from the polished card — the largest "bolted-on" gap.
Redesign with the system:
- `ViewHeader` (`ViewFrame.tsx`) eyebrow `"My reports"` (`tick`) + title, matching every other route.
- Rows: `Panel`-wrapped list reusing the `SourceLedger` row pattern (`shared/verdict-cards/ui.tsx`)
  — bordered, `even:bg-panel-soft/40` zebra, fixed-width left cell — not a flat `flex gap-2` of raw text.
- Status → `Chip variant="neutral"` (or `accent` for a terminal/actioned state), never bare span,
  never a verdict variant.
- The three text states (signed-out / error / empty) → shared `Notice` component, consistent with
  every other honest empty/error state in the app.

---

## Shared / cross-cutting changes (summary)

1. `shared/verdict-cards/EscalationCard.tsx` — optional `reportSlot?: ReactNode` in the header row.
2. `shared/ui/buttonClasses.ts` — new `tertiary` variant.
3. `web/src/lib/useSession.ts` — relocated from `components/report/`; `SessionState` gains `login?`.
4. `functions/api/report/mine.js` — return `login` in the response body (one line).
5. Reserved-colour fixes in the report components (success ≠ green; errors split by meaning).
6. `docs/DESIGN-TOKENS.md` (new) — the `web/`-scoped tokens reference (side task).

## Testing

- **Unit (Vitest, must stay green + add):** `contributorSeen` gating logic (no probe when unseen);
  `SessionState` shape; validation→state mapping (401/400/403/429/dedup); draft save/restore keying;
  a reserved-colour guard test asserting the success node carries no `verdict-*` class. Existing 434
  stay green.
- **Component states:** render each dialog terminal state from a mocked fetch; assert copy + that
  banned/capped are terminal (no enabled submit).
- **Live-only (documented, not automated):** the OAuth round trip and Turnstile render require the
  live site — covered by a manual dogfood pass, per Phase 0+1 precedent.

## Risks

- A returning contributor now fires a session probe per route load (gated behind `contributorSeen`;
  never touches the enrich/read data path). Low, flagged.
- Small layout shift during the `loading` tick — accept, visual-QA it (topbar is sticky).
- Turnstile fit inside 28rem — mitigated by `compact`/`interaction-only`.

## Build approach

Short spec (this) → `writing-plans` → subagent-driven-development, same flow that landed
Phase 0+1 cleanly.
