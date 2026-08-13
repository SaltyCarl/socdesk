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

import type { ReactNode } from 'react'
import type { VerdictData } from '../../lib/verdict'
import { cx } from '../../lib/cx'
import { Chip, MicroLabel } from '../ui'
import { WORLD, coordLabel, geoModel, project, type FlagDef, type GeoModel } from './geo'
import { cveModel, domainModel, hashModel, urlModel } from './model'

/* ---------- shared scaffolding ------------------------------------------- */

/** The tinted-accent panel every hero shares (the periwinkle product surface). */
function HeroPanel({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex flex-col gap-2.5 rounded-md border border-[var(--edge-accent)] bg-[var(--tint-accent)] p-3">
      <MicroLabel tone="faint">{label}</MicroLabel>
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

function WorldMap({ geo }: { geo: GeoModel }) {
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

  return (
    <svg
      viewBox={`0 0 ${cols} ${rows}`}
      preserveAspectRatio="xMidYMid meet"
      className="w-full rounded-sm border border-[var(--edge-accent)] bg-[var(--tint-accent)]"
      role="img"
      aria-label={`World map with a location pin on ${geo.countryName}`}
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
      <g>
        <ellipse cx={px} cy={py} rx={2.1} ry={0.7} className="fill-[var(--accent)] opacity-30" />
        <circle cx={px} cy={headY} r={3.3} strokeWidth={0.4} className="fill-none stroke-[var(--accent)] opacity-50" />
        <path d={pin} className="fill-[var(--accent)]" />
        <circle cx={px} cy={headY} r={0.85} className="fill-[var(--panel)]" />
      </g>
    </svg>
  )
}

export function IpHero({ data }: { data: VerdictData }) {
  const geo = geoModel(data.context, data.sources)
  if (!geo) return null
  const sub = [geo.city, geo.asn, geo.org].filter(Boolean).join(' · ')
  return (
    <HeroPanel label="Geolocation — context, not a verdict">
      <WorldMap geo={geo} />
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
  const level = ageLevel(dm.ageDays)
  const resolvedGeo = dm.resolved
    ? [dm.resolved.countryName, dm.resolved.city].filter(Boolean).join(' · ')
    : '—'
  const hosting = dm.resolved
    ? [dm.resolved.asn, dm.resolved.org].filter(Boolean).join(' · ') || '—'
    : '—'
  return (
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
    </HeroPanel>
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

export function UrlHero({ data }: { data: VerdictData }) {
  const um = urlModel(data)
  return (
    <HeroPanel label="Scanned page — what the client would have seen">
      <div className="relative overflow-hidden rounded-sm border border-line bg-field">
        {um.screenshot ? (
          <img src={um.screenshot} alt={`Rendered page for ${um.finalUrl}`} className="block w-full" />
        ) : (
          <div className="flex aspect-[16/10] items-center justify-center bg-panel-soft">
            <span className="flex flex-col items-center gap-1.5 text-center">
              <ScreenshotGlyph />
              <span className="font-mono text-micro leading-tight text-faint">
                urlscan screenshot slot
                <br />
                captured at scan time
              </span>
            </span>
          </div>
        )}
        <span className="absolute left-2 top-2">
          <Chip variant={urlVerdictVariant(um.verdict)}>{um.scanner}</Chip>
        </span>
      </div>
      <div className="grid gap-2">
        <FactCell k="Final URL" v={um.finalUrl} />
        {um.pageTitle && <FactCell k="Page title" v={um.pageTitle} mono={false} />}
      </div>
    </HeroPanel>
  )
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
        <FactCell k="EPSS" v={Number.isFinite(cm.epssPct) ? `${cm.epssPct}%` : cm.epss} />
        <FactCell k="Action due" v={cm.due || '—'} />
      </div>
    </HeroPanel>
  )
}

/* ---------- the dispatcher ----------------------------------------------- */

/** Render the type-appropriate hero for a card. Null when a type carries no
 *  hero (or the data can't support one — e.g. an IP with no geo). */
export function Hero({ data }: { data: VerdictData }) {
  switch (data.type) {
    case 'ipv4':
      return <IpHero data={data} />
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
