// heroes.tsx — one skeleton, a type-appropriate hero (design spec §3.3).
//
//   IP      → geo/ASN dot-matrix map + pin (context, never a verdict)
//   Domain  → registration-age tell + resolved geo
//   URL     → the scanned page the client would have seen (urlscan slot)
//   Hash    → malware IDENTITY (family, catalog, file facts, first→last)
//   CVE     → exploitation-status banner (KEV / CVSS / EPSS), authoritative
//
// The IP map is drawn as SVG from the SAME geo model + landmask (geo.ts) the
// copy-card canvas uses, so the pin lands identically. Reserved-colour law
// holds: the geo hero is periwinkle (product), NEVER a verdict tone; red/amber
// appear only where they carry verdict meaning. No inline styles (CSP).

import { useRef, type ReactNode } from 'react'
import type { VerdictData } from '../verdict'
import { cx } from '../lib/cx'
import { Chip, MicroLabel } from '../ui'
import { WORLD, coordLabel, geoModel, greatCircleArc, project, type FlagDef, type GeoModel } from '../card/geo'
import { cveModel, domainModel, hashModel, urlModel } from '../card/model'
import type { CompareResult } from './CompareIp'

/* ---------- shared scaffolding ------------------------------------------- */

/** The tinted-accent panel every hero shares (the periwinkle product surface). */
function HeroPanel({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex flex-col gap-2.5 rounded-md border border-[var(--edge-accent)] bg-[var(--tint-accent)] p-3">
      <MicroLabel tone="muted">{label}</MicroLabel>
      {children}
    </div>
  )
}

function FactCell({ k, v, mono = true }: { k: string; v: string; mono?: boolean }) {
  return (
    <div className="min-w-0 rounded-sm border border-line bg-field px-2 py-1.5">
      <span className="block font-mono text-[8px] font-bold uppercase tracking-label text-faint">{k}</span>
      <span className={cx('block break-words font-semibold text-paper', mono ? 'font-mono text-micro' : 'text-xs')}>
        {v}
      </span>
    </div>
  )
}

/* ---------- IP — geolocation map ----------------------------------------- */

function FlagSvg({ flag }: { flag: FlagDef }) {
  const n = flag.bands.length
  return (
    <svg viewBox="0 0 30 20" preserveAspectRatio="none" className="size-full">
      {flag.bands.map((c, i) =>
        flag.dir === 'v' ? (
          <rect key={i} x={(30 / n) * i} y={0} width={30 / n + 0.5} height={20} fill={c} />
        ) : (
          <rect key={i} x={0} y={(20 / n) * i} width={30} height={20 / n + 0.5} fill={c} />
        ),
      )}
    </svg>
  )
}

function FlagChip({ geo }: { geo: GeoModel }) {
  return (
    <span
      className="inline-flex h-5 w-[30px] shrink-0 overflow-hidden rounded-sm border border-line-strong"
      role="img"
      aria-label={`Flag of ${geo.countryName}`}
    >
      {geo.flag ? (
        <FlagSvg flag={geo.flag} />
      ) : (
        <span className="grid size-full place-items-center bg-panel-soft font-mono text-micro text-muted">
          {geo.countryCode || '??'}
        </span>
      )}
    </span>
  )
}

/** The IP geolocation map. With a `compare` present it also draws the honest
 *  great-circle route to the second sign-in's location + a secondary (hollow)
 *  pin there. The route is `--paper` (high-contrast over the periwinkle map);
 *  pins are `--accent`, never a verdict tone. The primary pin stays dominant. */
function WorldMap({ geo, compare }: { geo: GeoModel; compare?: CompareResult | null }) {
  const cols = WORLD[0].length
  const rows = WORLD.length
  const { fx, fy } = project(geo.lat, geo.lon)
  const px = fx * cols
  const py = fy * rows
  const hlC = Math.round(px - 0.5)
  const hlR = Math.round(py - 0.5)
  const headY = py - 3.9

  const cells: Array<{ x: number; y: number; hot: boolean }> = []
  for (let r = 0; r < rows; r++) {
    const line = WORLD[r]
    for (let c = 0; c < line.length; c++) {
      if (line[c] !== '#') continue
      cells.push({ x: c, y: r, hot: Math.abs(c - hlC) <= 1 && Math.abs(r - hlR) <= 1 })
    }
  }
  const pin = `M ${px.toFixed(2)} ${py.toFixed(2)} L ${(px - 1.6).toFixed(2)} ${(py - 2.8).toFixed(2)} A 1.9 1.9 0 1 1 ${(px + 1.6).toFixed(2)} ${(py - 2.8).toFixed(2)} Z`

  // Second sign-in overlay (projected with the SAME equirectangular `project`).
  const p2 = compare ? project(compare.second.lat, compare.second.lon) : null
  const px2 = p2 ? p2.fx * cols : 0
  const py2 = p2 ? p2.fy * rows : 0
  const arcSegs = compare ? greatCircleArc(geo.lat, geo.lon, compare.second.lat, compare.second.lon) : []

  return (
    <svg
      viewBox={`0 0 ${cols} ${rows}`}
      preserveAspectRatio="xMidYMid meet"
      className="w-full rounded-sm border border-[var(--edge-accent)] bg-[var(--tint-accent)]"
      role="img"
      aria-label={
        compare
          ? `World map with location pins on ${geo.countryName} and ${compare.second.countryName}, joined by a route line`
          : `World map with a location pin on ${geo.countryName}`
      }
    >
      <g className="stroke-[var(--edge-accent)] opacity-40" strokeWidth={0.12}>
        {[16, 32, 48, 64].map((x) => (
          <line key={x} x1={x} y1={0} x2={x} y2={rows} />
        ))}
        <line x1={0} y1={rows / 2} x2={cols} y2={rows / 2} />
      </g>
      <g className="fill-[var(--accent)] opacity-40" shapeRendering="crispEdges">
        {cells
          .filter((c) => !c.hot)
          .map((c) => (
            <rect key={`${c.x}-${c.y}`} x={c.x + 0.14} y={c.y + 0.14} width={0.72} height={0.72} />
          ))}
      </g>
      <g className="fill-[var(--accent)]" shapeRendering="crispEdges">
        {cells
          .filter((c) => c.hot)
          .map((c) => (
            <rect key={`${c.x}-${c.y}`} x={c.x + 0.14} y={c.y + 0.14} width={0.72} height={0.72} />
          ))}
      </g>
      {compare && (
        <>
          {/* the route — solid --paper, drawn BEHIND the pins; each segment
              reveals origin→destination via the sd-arc-draw keyframe (pathLength
              normalises length so one dash spans the whole segment). */}
          <g
            className="fill-none stroke-[var(--paper)] opacity-90"
            strokeWidth={0.28}
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            {arcSegs.map((seg, i) => (
              <polyline
                key={i}
                className="sd-arc-draw"
                pathLength={1}
                points={seg.map((p) => `${(p.fx * cols).toFixed(2)},${(p.fy * rows).toFixed(2)}`).join(' ')}
              />
            ))}
          </g>
          {/* secondary sign-in — a hollow marker so the primary pin stays dominant */}
          <g>
            <circle cx={px2} cy={py2} r={1.7} strokeWidth={0.35} className="fill-none stroke-[var(--accent)] opacity-90" />
            <circle cx={px2} cy={py2} r={0.65} className="fill-[var(--accent)]" />
          </g>
        </>
      )}
      <g>
        <ellipse cx={px} cy={py} rx={2.1} ry={0.7} className="fill-[var(--accent)] opacity-30" />
        <circle cx={px} cy={headY} r={3.3} strokeWidth={0.4} className="fill-none stroke-[var(--accent)] opacity-50" />
        <path d={pin} className="fill-[var(--accent)]" />
        <circle cx={px} cy={headY} r={0.85} className="fill-[var(--panel)]" />
      </g>
    </svg>
  )
}

export function IpHero({ data, compare }: { data: VerdictData; compare?: CompareResult | null }) {
  const geo = geoModel(data.context, data.sources)
  if (!geo) return null
  const sub = [geo.city, geo.asn, geo.org].filter(Boolean).join(' · ')
  return (
    <HeroPanel label="Geolocation — context, not a verdict">
      <WorldMap geo={geo} compare={compare} />
      <div className="flex flex-wrap items-center gap-3">
        <FlagChip geo={geo} />
        <div className="min-w-0">
          <div className="font-display text-lg font-extrabold leading-none tracking-tight text-paper">
            {geo.countryName}
          </div>
          {sub && <div className="mt-1 font-mono text-xs text-muted">{sub}</div>}
        </div>
        <div className="ml-auto text-right font-mono text-micro leading-tight text-faint">
          {coordLabel(geo)}
          <br />
          via ipinfo
        </div>
      </div>
    </HeroPanel>
  )
}

/* ---------- Domain — registration-age tell ------------------------------- */

function ageLevel(ageDays: number): number {
  if (!Number.isFinite(ageDays)) return 0
  if (ageDays <= 30) return 1
  if (ageDays <= 90) return 2
  if (ageDays <= 365) return 3
  if (ageDays <= 1095) return 4
  return 5
}

export function DomainHero({ data }: { data: VerdictData }) {
  const dm = domainModel(data)
  const um = urlModel(data)
  const level = ageLevel(dm.ageDays)
  const resolvedGeo = dm.resolved
    ? [dm.resolved.countryName, dm.resolved.city].filter(Boolean).join(' · ')
    : '—'
  const hosting = dm.resolved
    ? [dm.resolved.asn, dm.resolved.org].filter(Boolean).join(' · ') || '—'
    : '—'
  return (
    <div className="flex flex-col gap-2.5">
      <HeroPanel label="Registration age — the newly-registered tell">
        <div className="flex flex-wrap items-baseline gap-2">
          <span
            className={cx(
              'font-display text-lg font-extrabold tracking-tight',
              dm.newlyRegistered ? 'text-verdict-amber' : 'text-paper',
            )}
          >
            {dm.ageLabel}
          </span>
          {dm.newlyRegistered && <Chip variant="suspicious">newly registered</Chip>}
        </div>
        {dm.ageNote && <span className="font-mono text-micro text-faint">{dm.ageNote}</span>}
        <div className="flex items-center gap-2">
          <span className="flex gap-1" aria-hidden="true">
            {[1, 2, 3, 4, 5].map((i) => (
              <span
                key={i}
                className={cx(
                  'h-2.5 w-4 rounded-sm',
                  i <= level ? (dm.newlyRegistered ? 'bg-verdict-amber' : 'bg-accent') : 'bg-line',
                )}
              />
            ))}
          </span>
          <span className="font-mono text-micro text-faint">younger → older</span>
        </div>
        <div className="grid grid-cols-2 gap-2">
          <FactCell k="Registered" v={dm.registered} />
          <FactCell k="Registrar" v={dm.registrar} mono={false} />
          <FactCell k="Resolves to" v={resolvedGeo} mono={false} />
          <FactCell k="Hosting" v={hosting} />
        </div>
        {dm.resolvedIp && (
          <a
            href={`/#q=${encodeURIComponent(dm.resolvedIp)}`}
            className="inline-flex w-fit items-center gap-1 font-mono text-micro text-accent underline underline-offset-2 outline-offset-2 hover:no-underline focus-visible:outline-2 focus-visible:outline-accent"
          >
            Hosting IP {dm.resolvedIp} — check reputation <span aria-hidden="true">→</span>
          </a>
        )}
      </HeroPanel>
      {/* a domain's latest urlscan scan is a useful "what does this render as"
          preview — show the scanned-page panel when one exists (item: bare
          domains should get the screenshot too). */}
      {um.screenshot && <ScannedPagePanel data={data} />}
    </div>
  )
}

/* ---------- URL — the scanned page --------------------------------------- */

function ScreenshotGlyph() {
  return (
    <svg viewBox="0 0 24 24" fill="none" className="size-7 stroke-[var(--faint)]" strokeWidth={1.4} strokeLinecap="round" strokeLinejoin="round">
      <rect x="2.5" y="4" width="19" height="13" rx="1.5" />
      <line x1="9" y1="20" x2="15" y2="20" />
      <line x1="12" y1="17" x2="12" y2="20" />
    </svg>
  )
}

function urlVerdictVariant(v: VerdictData['sources'][number]['verdict']) {
  if (v === 'malicious') return 'malicious' as const
  if (v === 'suspicious') return 'suspicious' as const
  return 'unknown' as const
}

/** Browserling opens the (possibly hostile) URL inside a disposable REMOTE
 *  browser — the analyst's own machine never fetches it, and nothing is submitted
 *  to a public scanner (unlike a urlscan submission, which SOCDesk deliberately
 *  never does — see lib/enrich.mjs). The version-less win10/chrome path resolves
 *  to the current free-tier browser, so it won't rot on Chrome bumps. Verified
 *  live 2026-08-18; if Browserling change their scheme this one line is the fix
 *  (BACKLOG P1.3). The target URL is appended RAW — Browserling parses everything
 *  after /chrome/ as the URL, so it must not be percent-encoded. */
function browserlingUrl(indicator: string): string {
  // A bare domain gets an https:// scheme so Browserling parses it as a URL.
  const url = /^https?:\/\//i.test(indicator) ? indicator : `https://${indicator}`
  return `https://www.browserling.com/browse/win10/chrome/${url}`
}

/** The urlscan "scanned page" panel: the screenshot (click to enlarge in a
 *  native <dialog> lightbox — Esc / click-outside to close), the scan verdict
 *  chip, optional URL-only facts, and the Browserling safe-view pivot. Shared by
 *  the URL hero and the domain hero — a domain's latest urlscan scan is just as
 *  useful a preview — and both keep existing-scans-only honesty (no scan → the
 *  empty state + Browserling). */
function ScannedPagePanel({ data, showFacts = false }: { data: VerdictData; showFacts?: boolean }) {
  const um = urlModel(data)
  const dialogRef = useRef<HTMLDialogElement>(null)
  return (
    <HeroPanel label="Scanned page — what the client would have seen">
      <div className="relative overflow-hidden rounded-sm border border-line bg-field">
        {um.screenshot ? (
          <button
            type="button"
            onClick={() => dialogRef.current?.showModal()}
            aria-label="Enlarge the scanned-page screenshot"
            className="group block w-full cursor-zoom-in outline-offset-2 focus-visible:outline-2 focus-visible:outline-accent"
          >
            <img src={um.screenshot} alt={`Rendered page for ${um.finalUrl}`} className="block w-full" />
            <span className="pointer-events-none absolute inset-x-0 bottom-0 flex items-center justify-center gap-1 bg-ink/70 py-1 font-mono text-micro font-semibold uppercase tracking-label text-paper opacity-0 transition-opacity duration-150 group-hover:opacity-100">
              <span aria-hidden="true">⤢</span> click to enlarge
            </span>
          </button>
        ) : (
          <div className="flex aspect-[16/10] items-center justify-center bg-panel-soft">
            <span className="flex flex-col items-center gap-1.5 text-center">
              <ScreenshotGlyph />
              <span className="font-mono text-micro leading-tight text-faint">
                no urlscan screenshot on record
                <br />
                view it live in Browserling ↓
              </span>
            </span>
          </div>
        )}
        <span className="absolute left-2 top-2">
          <Chip variant={urlVerdictVariant(um.verdict)}>{um.scanner}</Chip>
        </span>
      </div>
      {showFacts && (
        <div className="grid gap-2">
          <FactCell k="Final URL" v={um.finalUrl} />
          {um.pageTitle && <FactCell k="Page title" v={um.pageTitle} mono={false} />}
        </div>
      )}
      <div className="flex flex-col gap-1 border-t border-line pt-2.5">
        <a
          href={browserlingUrl(data.indicator)}
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex w-fit items-center gap-1.5 font-mono text-xs font-semibold text-accent underline-offset-2 outline-offset-2 hover:underline focus-visible:outline-2 focus-visible:outline-accent"
        >
          Open live in Browserling — safe remote sandbox
          <span aria-hidden="true">↗</span>
        </a>
        <p className="font-mono text-micro leading-tight text-faint">
          Loads the page in a disposable remote browser — your machine never touches it, and nothing is submitted to a public scanner.
        </p>
      </div>
      {um.screenshot && (
        <dialog
          ref={dialogRef}
          onClick={(e) => {
            if (e.target === dialogRef.current) dialogRef.current?.close()
          }}
          className="m-auto w-fit max-w-[92vw] rounded-lg border border-line-bright bg-ink p-0 backdrop:bg-black/70"
        >
          <div className="flex flex-col">
            <div className="flex items-center justify-between gap-3 border-b border-line px-3 py-2">
              <span className="truncate font-mono text-micro text-muted">{um.finalUrl}</span>
              <button
                type="button"
                onClick={() => dialogRef.current?.close()}
                className="shrink-0 rounded-sm border border-line bg-panel px-2 py-0.5 font-mono text-micro font-semibold uppercase tracking-label text-muted hover:border-line-bright hover:text-paper focus-visible:outline-2 focus-visible:outline-accent"
              >
                Close ✕
              </button>
            </div>
            <img
              src={um.screenshot}
              alt={`Rendered page for ${um.finalUrl}`}
              className="block max-h-[80vh] w-auto max-w-full"
            />
          </div>
        </dialog>
      )}
    </HeroPanel>
  )
}

export function UrlHero({ data }: { data: VerdictData }) {
  return <ScannedPagePanel data={data} showFacts />
}

/* ---------- Hash — malware identity (hash-v2 reference) ------------------- */

function C2Glyph() {
  return (
    <svg viewBox="0 0 24 24" fill="none" className="size-6 stroke-[var(--accent)]" strokeWidth={1.6} strokeLinecap="round">
      <line x1="12" y1="12" x2="5.5" y2="6" />
      <line x1="12" y1="12" x2="18.5" y2="7" />
      <line x1="12" y1="12" x2="12" y2="19.5" />
      <circle cx="12" cy="12" r="2.8" className="fill-[var(--accent)] stroke-none" />
      <circle cx="5.5" cy="6" r="2" />
      <circle cx="18.5" cy="7" r="2" />
      <circle cx="12" cy="19.5" r="2" />
    </svg>
  )
}

export function HashHero({ data }: { data: VerdictData }) {
  const hm = hashModel(data)
  return (
    <HeroPanel label="Malware identity">
      <div className="flex items-center gap-3">
        <span className="grid size-11 shrink-0 place-items-center rounded-md border border-[var(--edge-accent)] bg-[var(--tint-accent)]">
          <C2Glyph />
        </span>
        <div className="flex min-w-0 flex-col gap-1">
          <span className="font-display text-lg font-extrabold leading-none tracking-tight text-paper">
            {hm.family}
          </span>
          <span className="flex flex-wrap items-center gap-1.5">
            <Chip variant={hm.grayware ? 'grayware' : 'malicious'}>{hm.classification}</Chip>
            {hm.catalogName && <Chip variant="catalog">{hm.catalogName}</Chip>}
          </span>
        </div>
      </div>

      {hm.aliases.length > 0 && (
        <p className="flex flex-wrap items-baseline gap-1.5">
          <span className="font-mono text-micro font-bold uppercase tracking-label text-faint">seen as</span>
          {hm.aliases.map((a) => (
            <code
              key={a}
              className="rounded-sm border border-line bg-field px-1.5 py-0.5 font-mono text-micro text-paper"
            >
              {a}
            </code>
          ))}
        </p>
      )}

      <div className="grid grid-cols-4 gap-2">
        <FactCell k="Type" v={hm.fileType} />
        <FactCell k="Size" v={hm.size} />
        <FactCell k="Signed" v={hm.signed} />
        <FactCell k="Detect" v={hm.detect} />
      </div>

      <div className="flex flex-col gap-1.5">
        <MicroLabel tone="faint">Observed in the wild</MicroLabel>
        <div className="relative h-4 overflow-hidden rounded-sm border border-line bg-field">
          <div className="absolute inset-y-0 inset-x-[3%] rounded-sm bg-accent/20" />
          <div className="absolute inset-0 grid place-items-center font-mono text-micro font-semibold text-muted">
            {hm.durationLabel}
          </div>
        </div>
        <div className="flex justify-between font-mono text-micro text-faint">
          <span>First seen {hm.firstSeen}</span>
          <span>Last seen {hm.lastSeen}</span>
        </div>
      </div>

      {hm.prevalenceLevel > 0 && (
        <div className="flex items-center gap-2">
          <span className="flex gap-0.5" aria-hidden="true">
            {[1, 2, 3, 4, 5].map((i) => (
              <span
                key={i}
                className={cx('h-3 w-1 rounded-[1px]', i <= hm.prevalenceLevel ? 'bg-accent' : 'bg-line')}
              />
            ))}
          </span>
          <span className="font-mono text-micro text-muted">
            <b className="font-semibold text-paper">{hm.prevalenceLabel}</b>
          </span>
        </div>
      )}
    </HeroPanel>
  )
}

/* ---------- CVE — exploitation-status banner ----------------------------- */

export function CveHero({ data }: { data: VerdictData }) {
  const cm = cveModel(data)
  const vp = [cm.vendor, cm.product].filter(Boolean).join(' · ')
  return (
    <HeroPanel label="Exploitation status — authoritative">
      <div className="flex flex-wrap items-center gap-2">
        {cm.kev ? (
          <Chip variant="malicious">Known exploited · CISA KEV</Chip>
        ) : (
          <Chip variant="unknown">Not in KEV catalog</Chip>
        )}
        {vp && <span className="font-mono text-xs text-muted">{vp}</span>}
      </div>
      <div className="grid grid-cols-3 gap-2">
        <FactCell k="CVSS" v={cm.cvssSeverity !== '—' ? `${cm.cvss} · ${cm.cvssSeverity}` : cm.cvss} />
        <FactCell k="EPSS · via FIRST.org" v={Number.isFinite(cm.epssPct) ? `${cm.epssPct}%` : cm.epss} />
        <FactCell k="Action due" v={cm.due || '—'} />
      </div>
      <p className="font-mono text-micro text-muted">Sources: CISA KEV · NVD · FIRST.org (EPSS)</p>
    </HeroPanel>
  )
}

/* ---------- the dispatcher ----------------------------------------------- */

/** Render the type-appropriate hero for a card. Null when a type carries no
 *  hero (or the data can't support one — e.g. an IP with no geo). */
export function Hero({ data, compare }: { data: VerdictData; compare?: CompareResult | null }) {
  switch (data.type) {
    case 'ipv4':
    case 'ipv6':
      return <IpHero data={data} compare={compare} />
    case 'domain':
      return <DomainHero data={data} />
    case 'url':
      return <UrlHero data={data} />
    case 'md5':
    case 'sha1':
    case 'sha256':
      return <HashHero data={data} />
    case 'cve':
      return <CveHero data={data} />
    default:
      return null
  }
}
