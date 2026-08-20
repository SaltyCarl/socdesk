# SOCDesk — Repo Map

A file/directory → responsibility index for fast orientation. The goal: know **where a thing lives** before you go looking, so you read the one file you're changing, not five to find it.

**Live app: `web/`** (Vite + React 19 + Tailwind v4 + Motion). **`shared/`** is a framework-free library (`@socdesk/shared/*`) consumed by `web/` + the extension. The Python pipeline (`collectors/` / `pipeline/`) still runs and feeds `web/`. **`site/`** is the superseded legacy app — history only, not deployed.

For *how it works* (data flow, the analyzer pipeline, the cockpit), read [ARCHITECTURE.md](ARCHITECTURE.md). This doc is just the where.

## Top-level tree

```
web/                  live app — Vite + React; web/dist is the deploy artifact
  src/App.tsx         router: a ROUTES table (path/label/size/el/nav) matched on location.pathname; nav:false hides a route from the topbar (e.g. /gallery, /privacy) but keeps it directly reachable
  src/routes/         one file per route (route map below)
  src/components/      cockpit/ analyzer/ hero/ palette/ lookup/ views/ overview/ ui/ shell/ (map below)
  public/sw.js        a deliberate tombstone SW (clears caches + unregisters; NOT an offline cache — that was site/sw.js)
  public/data/state/  the pipeline's dual-write target that web/ fetches at runtime
shared/               framework-free lib (@socdesk/shared/*) — map below
lib/enrich.mjs        source fan-out behind the /api/enrich Pages Function
functions/            Cloudflare Pages Functions (/api/enrich)
extension/            MV3 browser extension; consumes shared/ for detection + the escalation card
design/               brand book, mockups, visual reference (historical — governs the legacy site/ direction)
collectors/           one module per source: exposes SOURCE and collect(fetch, now)
pipeline/             join, score, relate, snapshot, validate, publish
schemas/              JSON Schema per published payload — the data contract
run_pipeline.py       wires collectors → pipeline → data/state/ + web/public/data/state/
data/state/           COMMITTED last-known-good payloads + daily history snapshots
data/entities/        actor / malware / vendor dictionaries used for extraction
site/                 LEGACY superseded static site (history only; not deployed)
site-tests/  tests/   Playwright (site/) + pytest (pipeline), fixture-backed
```

## `web/src/routes/` (registered in `App.tsx`'s ROUTES)

- `Overview.tsx` (`/`) — the polymorphic cockpit: three.js globe + omnibox that classifies input → escalation card OR PowerShell analyzer inline.
- `Lookup.tsx` (`/lookup`) — standalone escalation-card view; reads/writes `#q=` deep links; redirects command-shaped values to `/analyzer`.
- `PowerShellAnalyzer.tsx` (`/analyzer`) — bare textarea over `usePsAnalysis`; renders the shared `AnalyzerResult`.
- `DataDeskRoute.tsx` (`/desk`) — tabbed shell composing feed / vulns / actors / health / sources / toolbelt; each tab is a `*Route.tsx` → `components/views/*View.tsx`.
- `FeedRoute` / `VulnsRoute` / `ActorsRoute` / `HealthRoute` / `SourcesRoute` / `ToolbeltRoute` — the `/desk` tabs (Toolbelt is a deliberate stub — only Base64 decode is live, linking to `/analyzer`).
- `ActorProfileRoute.tsx` (`/actor`) — a single ATT&CK actor/malware profile + directory, resolvable by name/alias.
- `Gallery.tsx` (`/gallery`, `nav:false`) — the design-system craft-review surface (internal; hidden from the top-nav, reachable by direct URL).
- `Privacy.tsx` (`/privacy`, `nav:false`) — the disclosure page.
- `lookupModel.ts` — pure helpers: `readLookupQuery` (decode `#q=`), `cveToVerdict` (CVE catalog row → `VerdictData`).

## `web/src/components/`

- **`cockpit/`** — `useCockpitInput` (composes `useLookup` + `usePsAnalysis`; `resolveKind` monotonic toward command), `ResultRegion` (dispatch by `cockpit.kind`), `CockpitOmnibox` (input ↔ auto-growing textarea morph), `ModeChip` (correctable kind chip).
- **`analyzer/`** — `AnalyzerResult` (the shared, stateless result composition), `TechniqueTally` (technique chips + the one gated red/amber characterization callout), `DecodeLadder`, `IocTable` ("Look up →" pivot), `usePsAnalysis` (React wrapper over `shared/analyzer`'s `analyze()`).
- **`hero/`** — `useGlobe3` / `GlobeStage3` (three.js globe + `suspend`/`resume` yield), `heroLayers` / `useHeroPins` / `pins` (real-data pin model), `enrichFly` (omnibox → globe-landing seam), `TipCard`.
- **`palette/`** — `CommandPalette`, `commands.ts` (`submitLookup` — the shared route-to-`/lookup`-or-`/analyzer` entry every non-cockpit surface uses), `classify` (delegates to `detectType`), `fuzzy`, `recents`.
- **`lookup/`** — `useLookup` (the one indicator→resolution hook shared by `/lookup` + the cockpit), `LookupStates`, `useEffectiveTheme`.
- **`views/`** — one `*View.tsx` per `/desk` tab + `useStateData` (snapshot fetcher) + async-gate/skeleton primitives + `profiles`/`relations` ATT&CK lookups.
- **`overview/`** — the Overview "situational board" (`OverviewStats`, `RansomwareActivity`, `NamedActorActivity`, `PatchPriority`, `FreshnessStrip`, `Sparkline`) via `aggregations.ts`.
- **`ui/`, `shell/`** — web-only chrome: `Topbar`, `ThemeToggle`; `Shell` (frame), `Omnibox`, `MobileNav`, `PageContainer`.

## `shared/` (`@socdesk/shared/*`)

- **`analyzer/`** — the PowerShell/multi-interpreter analysis pipeline; entry `analyze()` in `report.ts`. Stages: `preprocess` (interpreter detect + body/flag extraction) → `lex` (PS) / `cmdlex` (cmd caret deobfusc) → `fold` (Base64/gzip decode) → `resolve` (deobfuscation) → `extract` (IOCs) → `techniques` + `lolbins` (signatures) → `report`. `wsh.ts` = WSH numeric-char-code decode + honesty signals. `types.ts` / `index.ts` = types + barrel.
- **`intent.ts`** — `classifyCockpitInput`: the data-boundary gate every submit path calls **before** `detectType`, so a pasted command never reaches `/api/enrich`.
- **`indicators.ts`** — `detectType` / `refang` / `isEnrichable`: the one indicator classifier shared by extension, web, and the analyzer's IOC extraction.
- **`verdict/`** — the doctrine/data layer: `types` (`VerdictData`), `client` (front half of `/api/enrich`, never throws), `map` (response → `VerdictData`), `doctrine` (verdict wording/banding + `composeEscalation`).
- **`verdict-cards/`** — the rendered card UI: `EscalationCard`, `heroes` (per-type hero), `CompareIp` (impossible-travel), `CardActions`, `copy` (PNG via `drawVerdict` + plain text).
- **`card/`** — the canvas/geo layer: `model` (view-model), `geo` (landmask), `palette` (canvas hex mirror of `tokens.css`), `travel` (great-circle math), `drawVerdict` (the Copy-card PNG).
- **`ui/`, `lib/`** — framework-agnostic primitives (`Button`/`Card`/`Chip`/`MicroLabel`/`Divider`, `SdMonogram`) + `cx` / `motion` / `theme`.
- **`tokens.css`** — the design-token source of truth (mirrored as literal hexes in `card/palette.ts` for canvas).

> Keep this current as part of any structural change (new route, new component dir, moved module). A stale map is worse than none.
