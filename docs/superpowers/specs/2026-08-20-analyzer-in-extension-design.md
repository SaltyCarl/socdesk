# Analyzer in the Extension — Design Spec

**Date:** 2026-08-20 · **Status:** design, pre-implementation · **Scope target:** `shared/` + `extension/` + `web/` (import rewiring only)

## 0. Summary

Bring the PowerShell/cmd **analyzer** to the browser extension so an analyst can
analyze a script **without leaving the alert console**. The driving workflow:

> A Defender alert fires → the Attack Story shows a `powershell -enc …` /
> cmd command line → the analyst **highlights** it → right-clicks **"Check in
> SOCDesk"** → a **side panel** opens with the full analysis (decode ladder,
> technique-signal tally, kill-chain "what it did" bullets, extracted IOCs with
> click-to-enrich) docked beside the console.

The analyzer is web-only today by accident of file placement, not by nature: the
engine (`shared/analyzer/`) is already a shared, framework-free, 100%
client-side, `eval`-free string→data transform. This is a **component lift +
extension wiring**, not a rewrite.

## 1. Locked decisions (owner, 2026-08-20)

- **Surface: MV3 side panel** (`chrome.sidePanel`) — full window-height, docked;
  the analyzer output is tall and stays open beside the Defender tab. The
  existing toolbar **popup keeps indicator lookup**; script analysis opens the
  side panel.
- **Trigger: auto-route, one gesture.** One "Check in SOCDesk" context item (and
  a paste box in the panel). `classifyCockpitInput` (already in
  `shared/intent.ts`) decides: `command` → analyzer, `indicator` → lookup. This
  is the same guard that keeps a script from ever reaching `/api/enrich`.

## 2. Doctrine / invariants (unchanged, load-bearing)

- **The analyzed script is NEVER sent to `/api/enrich`.** It is analyzed locally
  in the extension; the text never leaves the browser. Only a **clicked IOC**
  enriches (through the extension's existing `fetchEnrich` path). This is the
  data boundary; `classifyCockpitInput` (`command`-wins-ties) is its guard.
- **The analyzer never executes input** — no `eval` / `new Function` / dynamic
  dispatch. Pure string→data. (Also required for MV3, which forbids remote code.)
- **Honest empties, no fabricated verdict** — the analyzer's existing
  completeness/opaque-tier honesty travels as-is.
- **No AI attribution** anywhere (repo rule).
- Deterministic; shared analyzer tests stay green; `tsc -b` clean for `web/`,
  `shared/`, and `extension/`.

## 3. Architecture

### 3.1 Lift the analyzer UI into `shared/`

Move the render components from `web/src/components/analyzer/` to a new
`shared/analyzer-ui/` so both `web/` and `extension/` consume them, exactly as
`shared/verdict-cards/EscalationCard` is shared today.

Straight move (import only `@socdesk/shared/*` — no web-local deps):
- `AnalyzerResult.tsx`, `DecodeLadder.tsx`, `TechniqueTally.tsx`,
  `ActionBullets.tsx`, `IocTable.tsx`, `usePsAnalysis.ts`.

`web/` keeps thin re-export shims (or updated imports) so the `/analyzer` route
and cockpit render the moved components unchanged.

### 3.2 Decouple `InlineLookup` (the one entangled piece)

`InlineLookup` today uses the web's heavyweight `useLookup`, which pulls in
`views/`, `hero/heroLayers`, `routes/lookupModel` (globe layers the inline card
does not use). Rework it to a **lean, injectable enrich path**:

- `InlineLookup` takes its lookup via a prop/hook that returns
  `{ kind, data?, reason? }` from `fetchEnrich(type, raw)` → `EscalationCard`.
  No globe, no route model.
- `web/` passes an adapter backed by its existing `useLookup` (so the standalone
  `/lookup` globe behaviour is untouched where it matters); the analyzer's inline
  expansion uses the lean shared path on both surfaces.
- `useEffectiveTheme` → `shared/lib/theme` (already shared). `LookupStates` moves
  to shared, re-pointed at `shared/ui` + `shared/lib/cx`.

Net: `shared/analyzer-ui/` has **no** dependency on `web/src`.

### 3.3 Extension: side panel + routing

- **manifest.json**: add `"sidePanel"` permission and a `side_panel` entry
  (`default_path`); keep the existing `action` popup.
- **background.ts**: on the "Check in SOCDesk" context click (or toolbar), read
  the selection, `classifyCockpitInput` it, stash `{ mode: 'analyze'|'lookup',
  q }` in `chrome.storage.session`, and `chrome.sidePanel.open()` for `analyze`
  (open the popup for `lookup`, as today). A selection that is a command routes
  to `analyze`.
- **New `src/panel/Panel.tsx`** (+ `panel.html` entry in the extension Vite
  build): reads the pending handoff, and:
  - `analyze` → renders `<AnalyzerResult>` from `shared/analyzer-ui`, feeding the
    script through the shared `analyze()`; IOC rows use the lean inline lookup
    against the configured origin.
  - `lookup` → same `EscalationCard` flow as the popup (shared).
  - a paste box so the analyst can paste directly into the panel.
- The panel reuses the popup's honest state machine (idle / invalid / loading /
  ok / unavailable) and the origin-from-Options resolution.

### 3.4 web/ — import rewiring only

`web/` swaps its `components/analyzer/*` imports to `@socdesk/shared/analyzer-ui`
and provides the `useLookup` adapter for its own `/lookup` route. No behaviour
change on the web `/analyzer` route or cockpit.

## 4. Non-goals (v1)

- **Not** porting the cockpit, overview, CTI feed, or globe to the extension —
  analyzer + indicator lookup only.
- **No** new analyzer capability (no new technique families / deobfusc breadth
  here — that is the separate analyzer roadmap). This is a *surface* port.
- **No** Chrome Web Store publish in this work — that stays an owner action; this
  ships the built `extension/dist` ready to load unpacked.

## 5. Testing

- Shared analyzer engine + `analyzer-ui` split: existing `shared/analyzer`
  vitest suite stays green; add a test that `classifyCockpitInput` routes the
  Defender-style samples (`powershell -enc`, cmd `for /f` finger, mshta) to
  `command` and IPs/domains to `indicator` (guarding the data boundary).
- `InlineLookup` decoupling: a test that the lean lookup hook only ever passes
  the single IOC (never the script) to the enrich call.
- Builds: `npm --prefix web run build`, `cd web && npx vitest run ../shared src`,
  and `npm --prefix extension run build` all clean.
- Manual: load `extension/dist` unpacked, select a script on any page →
  side panel analyzes it; select an IP → popup looks it up.

## 6. Risks

- **Side-panel API availability** — `chrome.sidePanel` is Chrome 114+. Acceptable
  (the extension already targets modern Chrome). Firefox has no sidePanel; the
  manifest gates it, and Firefox falls back to the popup-scroll for analyze
  (documented, not blocking v1 which is Chrome-first).
- **`InlineLookup` refactor** touching the web `/lookup` route — mitigated by the
  adapter keeping web behaviour, and the existing src tests.
- **Panel height / scroll** — the panel is full-height; long decode ladders
  scroll within their existing `overflow` containers.
