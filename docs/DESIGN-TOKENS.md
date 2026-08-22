# Design Tokens — `web/` reference

Quick-reference map of the token vocabulary used by `web/` (and the browser
extension). **Source of truth is `shared/tokens.css`** — dark + light hex
blocks, imported by `web/src/index.css` (`@import "../../shared/tokens.css"`
after `@import "tailwindcss"`). This doc names things; it never forks a hex.

> `design-system.md` (repo root, "Chart Room") is **historical** — it
> governs only the retired `site/` app, which still carries the old warm
> espresso palette. This doc describes the current cool-slate `web/` system.

## Room neutrals

Surfaces, back-to-front: `--ink` / `--panel` / `--panel-soft` / `--raised` /
`--field`. Hairlines: `--line` / `--line-bright` / `--line-strong`. Text,
brightest-to-quietest: `--paper` / `--muted` / `--faint`.

Tailwind utilities (via `@theme inline` in `shared/tokens.css`): `bg-panel`,
`bg-raised`, `border-line`, `border-line-bright`, `text-paper`, `text-muted`,
`text-faint`, etc.

## Product accent

`--accent` / `--accent-dim` / `--ink-on-accent` — periwinkle. Tabs, primary
buttons, links, focus rings, active state, the signed-in indicator, UI
confirmations. **Never a verdict.**

## Verdict / severity (meaning only)

`--red` / `--gold` (amber) / `--green` → Tailwind `text-verdict-red` /
`text-verdict-amber` / `text-verdict-green`. Tints + hairline edges:
`--tint-accent`/`--edge-accent`, `--tint-red`/`--edge-red`,
`--tint-gold`/`--edge-gold`, `--tint-green`/`--edge-green` (a wash + a
hairline, never a fill).

**Reserved-colour law:** verdict hues carry a source's read on an indicator
(or an owner-approved analyzer signal tier — see `Chip`'s
`signal-near-dispositive` / `signal-strong` variants below). Never
decoration, never a UI confirmation.

## Type scale

`text-micro` (11px, the floor) → `text-xs` → `text-base` → `text-md` →
`text-lg` → `text-xl` → `text-2xl` → `text-display` (64px). Mono
micro-label voice: `MicroLabel` component, `tracking-label` (0.14em),
uppercase, `text-micro`.

Fonts: `font-sans` / `font-display` = Archivo (self-hosted,
`web/public/fonts/`), `font-mono` = IBM Plex Mono.

## Radii

`rounded-sm` (4px) / `rounded-md` (8px) / `rounded-lg` (12px).

## Motion

Real member names from `shared/lib/motion.ts` (mirrors the CSS
`--duration-*` / `--ease-*` custom properties by hand — kept in sync
manually, since JS can't read build-time `@theme` values):

- `DUR.fast` (0.15s), `DUR.base` (0.24s), `DUR.slow` (0.6s), `DUR.draw` (1.1s)
- `EASE.brand` (expo-out, most enters), `EASE.brandInOut` (in-out, moves/reorders)
- `SPRING.press` / `SPRING.gentle` / `SPRING.snappy` — Motion.dev spring configs for input-driven micro-interactions

Helpers: `enter`, `exit`, `enterStagger`, `usePressScale`, `useEnterOnMount`,
`prefersReducedMotion`. Every helper honours reduced motion. All animation
runs through Motion.dev's `animate()`/`hover()`/`press()` (WAAPI +
CSSOM), never injected `<style>` or inline `style=""` — required for the
strict `style-src 'self'` CSP.

## Legibility rule (Part E)

Readable text uses `--muted` or `--paper` only. `--faint` is incidental
adornment (dividers, disabled hints) — never body copy. Measured (dark, on
`--panel`): `--muted` = 6.70:1 (AA pass), `--faint` = 3.61:1 (AA fail);
light theme is stricter still. Enforced by `web/src/lib/contrast.test.ts`.

## Primitives index

All from `shared/ui/` (barrel: `shared/ui/index.ts`) unless noted:

| Primitive | File | Notes |
|---|---|---|
| `Button` / `buttonClasses` | `shared/ui/Button.tsx`, `shared/ui/buttonClasses.ts` | variants: `primary` / `ghost` / `tertiary` / `danger` |
| `Panel`, `Card`, `CardHeader`, `CardBody` | `shared/ui/Card.tsx` | `Panel` = flat recessive surface; `Card` = raised + `shadow-e1`, used sparingly |
| `Chip` | `shared/ui/Chip.tsx` | `neutral`/`accent`/`technique` (product, periwinkle) · `signal-near-dispositive`/`signal-strong` (analyzer risk tier) · `catalog`/`behavioral`/`reputation`/`list` (source-class) · `malicious`/`suspicious`/`grayware`/`benign`/`unknown` (verdict-severity) |
| `MicroLabel` | `shared/ui/MicroLabel.tsx` | tones: `muted` (default) / `accent` / `faint`; `tick` adds a periwinkle kicker rule |
| `Divider` | `shared/ui/Divider.tsx` | `orientation="horizontal"\|"vertical"`, `strong` |
| `SourceLedger` | `shared/verdict-cards/ui.tsx` | per-source verdict ledger row list |
| `Notice` | `web/src/components/lookup/LookupStates.tsx` | web-local (not in the shared barrel); honest non-ok lookup states — `tone="muted"\|"amber"` |
| `<dialog>` overlay pattern | `web/src/components/palette/CommandPalette.tsx`, `web/src/components/report/ReportDialog.tsx` | native `<dialog>` + `showModal()` (top-layer, real focus trap, native backdrop) + WAAPI panel choreography |
