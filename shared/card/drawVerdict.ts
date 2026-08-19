// drawVerdict.ts — the escalation "Copy card": one indicator's attributed
// reputation, drawn to a PNG an analyst drops straight into a client email.
//
// WHY A CANVAS (not html2canvas / SVG-to-image): the mark must be DETERMINISTIC
// and self-contained — same VerdictData in, byte-identical pixels out, on the
// site and (later) the extension, under `default-src 'none'`. Everything ships
// inside the bundle: the palette (palette.ts), the world landmask (geo.ts), and
// all wording comes from the verdict-lib doctrine. Nothing is fetched at capture
// time, so the indicator + its coordinates never leave the browser.
//
// CRAFT CONSTRAINTS (design spec §2 anti-slop): FLAT fills only — no gradients,
// no drop shadows, no emoji. Text is vector (embedded brand faces); the flag is
// drawn as colour bands, never an emoji glyph (which falls back to letters on
// canvas). Call after `document.fonts.ready` so the faces are resolved.
//
// HONESTY (docs/VERDICT-LANGUAGE §4, binding): the tally leads as a COUNT; every
// source is attributed with its finding as fact; a dual-use qualifier sits under
// the tally; geo is labelled context, never a verdict, and never in the tally;
// the verify caveat is baked in; and there is NO branding and NO recommendation
// on the artifact — it rides inside the analyst's own email.

import type { Band, VerdictData, VerdictSource } from '../verdict'
import { CAVEAT, assessmentLine, classTag, dualUseNote, hashHeadline, isStale, predicate } from '../verdict'
import { detectTheme, MONO, SANS, mix, THEMES, type CanvasTheme, type Palette } from './palette'
import { WORLD, coordLabel, geoModel, greatCircleArc, project, type GeoModel } from './geo'
import type { CompareResult } from '../verdict-cards/CompareIp'
import {
  cveLead,
  cveModel,
  gaugeCaption,
  domainAgeLevel,
  domainModel,
  gaugeSegments,
  hashModel,
  isBannerLed,
  type CveModel,
  type DomainModel,
  type HashModel,
} from './model'

const W = 440 // CSS px — comfortable inline in an email body
const PAD = 18
const SCALE = 2 // drawn at 2x so it stays crisp when scaled / printed
const RADIUS = 12

const TYPE_LABEL: Record<string, string> = {
  ipv4: 'IPv4',
  domain: 'DOMAIN',
  url: 'URL',
  md5: 'MD5',
  sha1: 'SHA-1',
  sha256: 'SHA-256',
  cve: 'CVE',
  email: 'EMAIL',
}

const stampUTC = (x: string | number | Date): string => {
  const d = x ? new Date(x) : new Date()
  const iso = Number.isNaN(d.getTime()) ? new Date().toISOString() : d.toISOString()
  return iso.replace('T', ' ').slice(0, 16) + ' UTC'
}

function bandInk(T: Palette, band: Band): string {
  if (band === 'red') return T.vRed
  if (band === 'amber' || band === 'grayware') return T.vAmber
  if (band === 'green') return T.vGreen
  return T.textFaint
}

/* ---------- the card content model (pure) -------------------------------- */

type Hero =
  | { kind: 'geo'; geo: GeoModel; note: string; compare?: CompareResult | null }
  | { kind: 'domain'; dm: DomainModel }
  | { kind: 'identity'; hash: HashModel }
  | { kind: 'cve'; cve: CveModel }
  | { kind: 'facts'; label: string; rows: Array<[string, string]> }
  | { kind: 'none' }

interface CardModel {
  typeLabel: string
  indicator: string
  bannerLed: boolean
  headline: string
  band: Band
  segments: ReturnType<typeof gaugeSegments>
  caption: { left: string; right: string }
  dualUse: string | null
  hero: Hero
  sources: Array<{
    name: string
    verdict: VerdictSource['verdict']
    finding: string
    /** Resolved source-class tag ("catalog/identity"…); '' when unclassified. */
    classLabel: string
    /** The "as of <date>" recency string; '' when the source carries no date. */
    recency: string
    /** True only when stale AND not a catalog/KEV membership (item 5). */
    stale: boolean
  }>
  caveat: string
  generated: string
  queried: string
}

function heroFor(data: VerdictData, now: Date, compare?: CompareResult | null): Hero {
  if (data.type === 'cve') return { kind: 'cve', cve: cveModel(data) }
  if (data.identityLed) return { kind: 'identity', hash: hashModel(data) }
  // Domain leads with the registration-age tell (spec §3.3), NOT the geo map —
  // the newly-registered date is the signal; resolved geo is a secondary line.
  // (Mirrors the web DomainHero so the two registers agree for one indicator.)
  if (data.type === 'domain') return { kind: 'domain', dm: domainModel(data, now) }
  if (data.type === 'ipv4') {
    const geo = geoModel(data.context, data.sources)
    if (geo) return { kind: 'geo', geo, note: dualUseNote(data.sources) ?? '', compare }
  }
  if (data.type === 'url') {
    const scan = data.sources.find((s) => s.name === 'urlscan') ?? data.sources[0]
    const rows: Array<[string, string]> = (scan?.facts ?? [])
      .filter(([k]) => /url|title|verdict|scanned/i.test(k))
      .slice(0, 4)
      .map(([k, v]) => [k, v])
    return { kind: 'facts', label: 'Scanned page', rows }
  }
  // domain with no geo, or anything else → a labelled fact strip from the lead.
  const lead = data.sources[0]
  const rows: Array<[string, string]> = (lead?.facts ?? []).slice(0, 4).map(([k, v]) => [k, v])
  return rows.length ? { kind: 'facts', label: 'Key facts', rows } : { kind: 'none' }
}

function cardModel(data: VerdictData, now: Date, compare?: CompareResult | null): CardModel {
  const bannerLed = isBannerLed(data)
  const headline = data.identityLed
    ? hashHeadline(data)
    : data.type === 'cve'
      ? cveLead(data)
      : assessmentLine(data.sources)

  return {
    typeLabel: TYPE_LABEL[data.type] ?? String(data.type).toUpperCase(),
    indicator: data.indicator,
    bannerLed,
    headline,
    band: data.band,
    segments: gaugeSegments(data),
    caption: gaugeCaption(data),
    dualUse: dualUseNote(data.sources),
    hero: heroFor(data, now, compare),
    sources: data.sources.map((s) => ({
      name: s.name,
      verdict: s.verdict,
      // verb-led predicate (the row already prints the name in bold beside it),
      // so the class verb appears exactly once — source-subject-first.
      finding: predicate(s),
      // Source-class tag + recency travel to the PNG so the copy card carries the
      // same class + "as of <date>" the client card now shows. Unclassified draws
      // no chip; a catalog/KEV membership never shows "stale" (item 3 / item 5).
      classLabel: s.class === 'unclassified' ? '' : classTag(s),
      recency: s.recency ? `as of ${s.recency}` : '',
      stale: isStale(s.recency, now) && s.class !== 'catalog' && !s.kev,
    })),
    caveat: CAVEAT,
    generated: stampUTC(now),
    queried: stampUTC(data.checkedAt || now),
  }
}

/* ---------- text helpers ------------------------------------------------- */

let measureCtx: CanvasRenderingContext2D | null = null
function measurer(): CanvasRenderingContext2D {
  if (!measureCtx) {
    const c = document.createElement('canvas').getContext('2d')
    if (!c) throw new Error('2D canvas context unavailable')
    measureCtx = c
  }
  return measureCtx
}

/** Greedy wrap; hard character breaks for unbroken strings (a 64-char hash or a
 *  long URL has no spaces to wrap on). */
function wrap(ctx: CanvasRenderingContext2D, text: string, font: string, maxWidth: number): string[] {
  ctx.font = font
  const out: string[] = []
  for (const paragraph of String(text).split('\n')) {
    let line = ''
    for (const word of paragraph.split(/\s+/)) {
      const next = line ? `${line} ${word}` : word
      if (ctx.measureText(next).width <= maxWidth) {
        line = next
        continue
      }
      if (line) out.push(line)
      if (ctx.measureText(word).width <= maxWidth) {
        line = word
        continue
      }
      let chunk = ''
      for (const ch of word) {
        if (ctx.measureText(chunk + ch).width > maxWidth) {
          out.push(chunk)
          chunk = ch
        } else chunk += ch
      }
      line = chunk
    }
    out.push(line)
  }
  return out
}

function roundRect(ctx: CanvasRenderingContext2D, x: number, y: number, w: number, h: number, r: number): void {
  const rr = Math.min(r, w / 2, h / 2)
  ctx.beginPath()
  ctx.moveTo(x + rr, y)
  ctx.arcTo(x + w, y, x + w, y + h, rr)
  ctx.arcTo(x + w, y + h, x, y + h, rr)
  ctx.arcTo(x, y + h, x, y, rr)
  ctx.arcTo(x, y, x + w, y, rr)
  ctx.closePath()
}

const SEG_FILL: Partial<Record<VerdictSource['verdict'], (T: Palette) => string>> = {
  malicious: (T) => T.vRed,
  suspicious: (T) => T.vAmber,
  benign: (T) => T.vGreen,
}

/* ============================================================ *
 * Painter. One measure pass (draw=false) sizes each block, one
 * draw pass (draw=true) renders it, down the same code path, so
 * measured and drawn heights can never drift.
 * ============================================================ */

function paint(ctx: CanvasRenderingContext2D, m: CardModel, T: Palette, draw: boolean): number {
  const inner = W - PAD * 2
  const mc = measurer()
  const width = (s: string, font: string): number => {
    mc.font = font
    return mc.measureText(s).width
  }
  const text = (
    s: string,
    font: string,
    color: string,
    x: number,
    y: number,
    align: CanvasTextAlign = 'left',
  ): void => {
    if (!draw) return
    ctx.font = font
    ctx.fillStyle = color
    ctx.textAlign = align
    ctx.fillText(s, x, y)
    ctx.textAlign = 'left'
  }

  let y = PAD + 3 // below the flat accent bar

  /* header — kind + "Generated" timestamp. NO wordmark, NO mark (§4). */
  text('INDICATOR REPUTATION', `700 9px ${SANS}`, T.textFaint, PAD, y + 8)
  text(`Generated ${m.generated}`, `400 8.5px ${MONO}`, T.textFaint, W - PAD, y + 8, 'right')
  y += 22

  /* indicator + type badge */
  const indFont = `600 16px ${MONO}`
  const indLines = wrap(mc, m.indicator, indFont, inner - 60)
  indLines.forEach((line, i) => {
    text(line, indFont, T.text, PAD, y + 14)
    if (i === 0) {
      const badge = m.typeLabel
      const bf = `600 9.5px ${MONO}`
      const bw = width(badge, bf) + 12
      if (draw) {
        ctx.strokeStyle = T.border2
        ctx.lineWidth = 1
        roundRect(ctx, W - PAD - bw, y + 2, bw, 15, 4)
        ctx.stroke()
      }
      text(badge, bf, T.textDim, W - PAD - bw / 2, y + 12.5, 'center')
    }
    y += 21
  })
  y += 4

  if (m.bannerLed) {
    /* identity / exploitation banner LEADS — no cross-source tally. */
    y = paintLead(ctx, m, T, draw, y, inner)
    y = paintHero(ctx, m, T, draw, y, inner)
  } else {
    /* tally LEADS as a count */
    text('COVERAGE TALLY — ACROSS PUBLIC SOURCES', `700 9px ${SANS}`, T.textFaint, PAD, y + 8)
    y += 16
    y = paintTally(ctx, m, T, draw, y, inner, width)
    y = paintGauge(ctx, m, T, draw, y, inner)
    y = paintHero(ctx, m, T, draw, y, inner)
  }

  /* attributed source rows */
  y = paintSources(ctx, m, T, draw, y, inner)

  return y + PAD
}

function paintLead(ctx: CanvasRenderingContext2D, m: CardModel, T: Palette, draw: boolean, y: number, inner: number): number {
  const mc = measurer()
  const font = `600 13.5px ${SANS}`
  for (const line of wrap(mc, m.headline, font, inner)) {
    if (draw) {
      ctx.font = font
      ctx.fillStyle = T.text
      ctx.textAlign = 'left'
      ctx.fillText(line, PAD, y + 12)
    }
    y += 19
  }
  return y + 6
}

function paintTally(
  ctx: CanvasRenderingContext2D,
  m: CardModel,
  T: Palette,
  draw: boolean,
  y: number,
  inner: number,
  width: (s: string, font: string) => number,
): number {
  const toneInk = bandInk(T, m.band)
  const hlFont = `700 15px ${SANS}`
  const numFont = `900 15px ${SANS}`
  const numMatch = m.headline.match(/^(\d+)(.*)$/s)
  let hx = PAD
  if (numMatch && draw) {
    ctx.font = numFont
    ctx.fillStyle = toneInk
    ctx.textAlign = 'left'
    ctx.fillText(numMatch[1], PAD, y + 14)
  }
  if (numMatch) hx = PAD + width(numMatch[1], numFont)

  const restText = numMatch ? numMatch[2] : m.headline
  const avail0 = inner - (hx - PAD)
  const lines: string[] = []
  let line = ''
  for (const w of restText.trim().split(/\s+/)) {
    const cand = line ? line + ' ' + w : w
    const limit = lines.length === 0 ? avail0 : inner
    if (width(cand, hlFont) <= limit) line = cand
    else {
      if (line) lines.push(line)
      line = w
    }
  }
  if (line) lines.push(line)
  lines.forEach((ln, i) => {
    if (draw) {
      ctx.font = hlFont
      ctx.fillStyle = T.text
      ctx.textAlign = 'left'
      ctx.fillText((i === 0 ? ' ' : '') + ln, i === 0 ? hx : PAD, y + 14)
    }
    y += 19
  })
  if (!lines.length) y += 19
  return y + 4
}

function paintGauge(ctx: CanvasRenderingContext2D, m: CardModel, T: Palette, draw: boolean, y: number, inner: number): number {
  const segN = Math.max(m.segments.length, 1)
  const segGap = 3
  const segH = 9
  const segW = (inner - segGap * (segN - 1)) / segN
  if (draw) {
    m.segments.forEach((v, i) => {
      const sx = PAD + i * (segW + segGap)
      roundRect(ctx, sx, y, segW, segH, 3)
      const fill = SEG_FILL[v]
      if (fill) {
        ctx.fillStyle = fill(T)
        ctx.fill()
      } else {
        ctx.strokeStyle = v === 'benign' ? T.vGreen : T.border3
        ctx.lineWidth = 1
        ctx.stroke()
      }
    })
    if (!m.segments.length) {
      roundRect(ctx, PAD, y, inner, segH, 3)
      ctx.fillStyle = T.panel2
      ctx.fill()
    }
  }
  y += segH + 6
  const cap = `400 8.5px ${MONO}`
  if (draw) {
    ctx.font = cap
    ctx.fillStyle = T.textFaint
    ctx.textAlign = 'left'
    ctx.fillText(m.caption.left, PAD, y + 6)
    ctx.textAlign = 'right'
    ctx.fillText(m.caption.right, W - PAD, y + 6)
    ctx.textAlign = 'left'
  }
  return y + 16
}

/* ---------- per-type heroes --------------------------------------------- */

function paintHero(ctx: CanvasRenderingContext2D, m: CardModel, T: Palette, draw: boolean, y: number, inner: number): number {
  switch (m.hero.kind) {
    case 'geo':
      return paintGeo(ctx, m.hero.geo, T, draw, y, inner, m.hero.compare)
    case 'domain':
      return paintDomain(ctx, m.hero.dm, T, draw, y, inner)
    case 'identity':
      return paintIdentity(ctx, m.hero.hash, T, draw, y, inner)
    case 'cve':
      return paintCve(ctx, m.hero.cve, T, draw, y, inner)
    case 'facts':
      return paintFacts(ctx, m.hero.label, m.hero.rows, T, draw, y, inner)
    default:
      return y
  }
}

/** The tinted accent panel every hero shares — measured, then filled behind. */
function heroPanel(ctx: CanvasRenderingContext2D, T: Palette, draw: boolean, y: number, inner: number, h: number): void {
  if (!draw) return
  ctx.fillStyle = mix(T.accent, T.panel, 0.07)
  ctx.strokeStyle = mix(T.accent, T.border2, 0.26)
  ctx.lineWidth = 1
  roundRect(ctx, PAD, y, inner, h, 10)
  ctx.fill()
  ctx.stroke()
}

/** "City, CC" when we have it, else the country name — the compact place label
 *  for the geographic-separation fact (mirrors CompareIp's on-screen label). */
const geoLabel = (g: GeoModel): string =>
  [g.city, g.countryCode].filter(Boolean).join(', ') || g.countryName

/** The one-line geographic-separation fact bundled onto the copy-card when a
 *  compare is active: distance · from → to · (when a time gap was given) the
 *  implied speed + band. A clean fact, muted — no caveat (the analyst owns the
 *  nuance in the email body). */
function geoSepLine(g: GeoModel, c: CompareResult): string {
  const a = c.assessment
  const vel = a.mph != null && a.mphLabel ? ` · ${a.mphLabel} (${a.band})` : ''
  return `GEOGRAPHIC SEPARATION: ${a.milesLabel} · ${geoLabel(g)} → ${geoLabel(c.second)}${vel}`
}

function paintGeo(ctx: CanvasRenderingContext2D, g: GeoModel, T: Palette, draw: boolean, y: number, inner: number, compare?: CompareResult | null): number {
  const ipad = 12
  const contentW = inner - ipad * 2
  const mapH = contentW * (WORLD.length / WORLD[0].length)

  // Geographic-separation fact — present ONLY when a compare is bundled. Its
  // wrapped line count is computed identically in the measure + draw passes, so
  // the block height never drifts; with no compare, sepBlock is 0 and the whole
  // hero is byte-identical to the single-IP card (drawVerdict.test determinism).
  const mc = measurer()
  const sepFont = `400 8.5px ${MONO}`
  const sepGap = 7
  const sepLH = 12
  const sepLines = compare ? wrap(mc, geoSepLine(g, compare), sepFont, contentW) : []
  const sepBlock = compare ? sepGap + sepLines.length * sepLH : 0
  const geoH = ipad + 12 + 8 + mapH + 12 + 30 + sepBlock + ipad

  heroPanel(ctx, T, draw, y, inner, geoH)

  let gy = y + ipad
  if (draw) {
    ctx.font = `700 9px ${SANS}`
    ctx.fillStyle = T.textFaint
    ctx.textAlign = 'left'
    ctx.fillText('GEOLOCATION — CONTEXT, NOT A VERDICT', PAD + ipad, gy + 8)
  }
  gy += 12 + 8

  paintWorld(ctx, T, draw, PAD + ipad, gy, contentW, mapH, g, compare)
  gy += mapH + 12

  const cx = PAD + ipad
  const flagW = 30
  const flagH = 20
  paintFlag(ctx, T, draw, cx, gy + 2, flagW, flagH, g)

  const nameX = cx + flagW + 11
  if (draw) {
    ctx.textAlign = 'left'
    ctx.font = `800 24px ${SANS}`
    ctx.fillStyle = T.text
    ctx.fillText(g.countryName, nameX, gy + 20)
    const sub = [g.city, g.asn, g.org].filter(Boolean).join(' · ')
    if (sub) {
      ctx.font = `400 10.5px ${MONO}`
      ctx.fillStyle = T.textDim
      ctx.fillText(sub, nameX, gy + 33)
    }
    ctx.textAlign = 'right'
    ctx.font = `400 8.5px ${MONO}`
    ctx.fillStyle = T.textFaint
    ctx.fillText(coordLabel(g), W - PAD - ipad, gy + 12)
    ctx.fillText('via ipinfo', W - PAD - ipad, gy + 24)
    ctx.textAlign = 'left'
  }

  // the geographic-separation fact, below the country row (muted, no caveat)
  if (compare && draw) {
    ctx.font = sepFont
    ctx.fillStyle = T.textDim
    ctx.textAlign = 'left'
    sepLines.forEach((ln, i) => ctx.fillText(ln, PAD + ipad, gy + 30 + sepGap + 9 + i * sepLH))
  }

  return y + geoH + 12
}

function paintWorld(ctx: CanvasRenderingContext2D, T: Palette, draw: boolean, x: number, y: number, w: number, h: number, g: GeoModel, compare?: CompareResult | null): void {
  if (!draw) return
  const cols = WORLD[0].length
  const rows = WORLD.length
  const cell = w / cols
  const mapBg = mix(T.accent, T.panel2, 0.08)
  const mapLand = mix(T.accent, T.border2, 0.42)
  const mapHot = T.accent

  ctx.strokeStyle = mix(T.accent, T.panel, 0.18)
  ctx.lineWidth = 1
  roundRect(ctx, x, y, w, h, 7)
  ctx.fillStyle = mapBg
  ctx.fill()
  ctx.stroke()
  ctx.save()
  roundRect(ctx, x, y, w, h, 7)
  ctx.clip()

  ctx.strokeStyle = mix(T.accent, mapBg, 0.14)
  ctx.lineWidth = 1
  for (const gx of [16, 32, 48, 64]) {
    ctx.beginPath()
    ctx.moveTo(x + gx * cell, y)
    ctx.lineTo(x + gx * cell, y + h)
    ctx.stroke()
  }
  ctx.beginPath()
  ctx.moveTo(x, y + h / 2)
  ctx.lineTo(x + w, y + h / 2)
  ctx.stroke()

  const { fx, fy } = project(g.lat, g.lon)
  const hlC = Math.round(fx * cols - 0.5)
  const hlR = Math.round(fy * rows - 0.5)

  for (let r = 0; r < rows; r++) {
    const line = WORLD[r]
    for (let c = 0; c < line.length; c++) {
      if (line[c] !== '#') continue
      const hot = Math.abs(c - hlC) <= 1 && Math.abs(r - hlR) <= 1
      ctx.fillStyle = hot ? mapHot : mapLand
      ctx.fillRect(x + (c + 0.12) * cell, y + (r + 0.12) * cell, cell * 0.76, cell * 0.76)
    }
  }

  // Second sign-in overlay: the honest great-circle route + a secondary hollow
  // pin, drawn UNDER the primary pin so it never competes with it. The route is
  // --paper (high-contrast ink, visible over the periwinkle map in both themes);
  // the pin stays --accent — never a verdict hue. Matches the SVG WorldMap
  // treatment. Wrapped in save/restore so the dash/alpha/width
  // state can't leak into the primary pin below.
  if (compare) {
    ctx.save()
    ctx.strokeStyle = T.text
    ctx.globalAlpha = 0.9
    ctx.lineWidth = Math.max(1, 0.28 * cell)
    ctx.lineJoin = 'round'
    ctx.lineCap = 'round'
    ctx.setLineDash([2 * cell, 1.4 * cell])
    for (const seg of greatCircleArc(g.lat, g.lon, compare.second.lat, compare.second.lon)) {
      ctx.beginPath()
      seg.forEach((p, i) => {
        const ax = x + p.fx * w
        const ay = y + p.fy * h
        if (i === 0) ctx.moveTo(ax, ay)
        else ctx.lineTo(ax, ay)
      })
      ctx.stroke()
    }
    ctx.setLineDash([])

    const p2 = project(compare.second.lat, compare.second.lon)
    const px2 = x + p2.fx * w
    const py2 = y + p2.fy * h
    ctx.globalAlpha = 0.9
    ctx.lineWidth = Math.max(0.8, 0.35 * cell)
    ctx.beginPath()
    ctx.arc(px2, py2, 1.7 * cell, 0, Math.PI * 2)
    ctx.stroke()
    ctx.globalAlpha = 1
    ctx.fillStyle = mapHot
    ctx.beginPath()
    ctx.arc(px2, py2, 0.7 * cell, 0, Math.PI * 2)
    ctx.fill()
    ctx.restore()
  }

  const px = x + fx * w
  const tipY = y + fy * h
  const headY = tipY - 3.9 * cell
  ctx.fillStyle = mapHot
  ctx.globalAlpha = 0.28
  ctx.beginPath()
  ctx.ellipse(px, tipY, 2.1 * cell, 0.7 * cell, 0, 0, Math.PI * 2)
  ctx.fill()
  ctx.globalAlpha = 0.5
  ctx.strokeStyle = mapHot
  ctx.lineWidth = Math.max(0.8, 0.4 * cell)
  ctx.beginPath()
  ctx.arc(px, headY, 3.3 * cell, 0, Math.PI * 2)
  ctx.stroke()
  ctx.globalAlpha = 1
  ctx.fillStyle = mapHot
  ctx.beginPath()
  ctx.moveTo(px, tipY)
  ctx.lineTo(px - 1.6 * cell, tipY - 1.1 * cell)
  ctx.arc(px, headY, 1.9 * cell, Math.PI * 0.75, Math.PI * 0.25, false)
  ctx.closePath()
  ctx.fill()
  ctx.fillStyle = T.panel
  ctx.beginPath()
  ctx.arc(px, headY, 0.9 * cell, 0, Math.PI * 2)
  ctx.fill()

  ctx.restore()
}

function paintFlag(ctx: CanvasRenderingContext2D, T: Palette, draw: boolean, x: number, y: number, w: number, h: number, g: GeoModel): void {
  if (!draw) return
  ctx.save()
  roundRect(ctx, x, y, w, h, 3)
  ctx.clip()
  if (g.flag) {
    const bands = g.flag.bands
    const n = bands.length
    if (g.flag.dir === 'v') {
      const bw = w / n
      bands.forEach((c, i) => {
        ctx.fillStyle = c
        ctx.fillRect(x + i * bw, y, bw + 0.5, h)
      })
    } else {
      const bh = h / n
      bands.forEach((c, i) => {
        ctx.fillStyle = c
        ctx.fillRect(x, y + i * bh, w, bh + 0.5)
      })
    }
  } else {
    ctx.fillStyle = mix(T.accent, T.panel2, 0.2)
    ctx.fillRect(x, y, w, h)
    ctx.fillStyle = T.textDim
    ctx.font = `700 9px ${MONO}`
    ctx.textAlign = 'center'
    ctx.textBaseline = 'middle'
    ctx.fillText(g.countryCode || '??', x + w / 2, y + h / 2 + 0.5)
    ctx.textAlign = 'left'
    ctx.textBaseline = 'alphabetic'
  }
  ctx.restore()
  ctx.strokeStyle = T.border3
  ctx.lineWidth = 1
  roundRect(ctx, x + 0.5, y + 0.5, w - 1, h - 1, 3)
  ctx.stroke()
}

/** Domain registration-age hero — mirrors the web DomainHero (spec §3.3): the
 *  age + newly-registered state lead; registered date / registrar / resolved geo
 *  are the supporting facts. Geo is demoted to a secondary line (never a hero,
 *  never a verdict tone). */
function paintDomain(ctx: CanvasRenderingContext2D, dm: DomainModel, T: Palette, draw: boolean, y: number, inner: number): number {
  const ipad = 12
  const factH = 34
  const h = ipad + 12 + 8 + 26 + 16 + 10 + (factH * 2 + 8) + ipad
  heroPanel(ctx, T, draw, y, inner, h)

  const ageInk = dm.newlyRegistered ? T.vAmber : T.text
  let gy = y + ipad
  if (draw) {
    ctx.textAlign = 'left'
    ctx.font = `700 9px ${SANS}`
    ctx.fillStyle = T.textFaint
    ctx.fillText('REGISTRATION AGE — THE NEWLY-REGISTERED TELL', PAD + ipad, gy + 8)
  }
  gy += 12 + 8

  if (draw) {
    ctx.font = `800 20px ${SANS}`
    ctx.fillStyle = ageInk
    ctx.textAlign = 'left'
    ctx.fillText(dm.ageLabel, PAD + ipad, gy + 16)
    if (dm.newlyRegistered) {
      const chip = 'NEWLY REGISTERED'
      ctx.font = `700 8px ${MONO}`
      const cw = ctx.measureText(chip).width + 14
      const cx = W - PAD - ipad - cw
      ctx.fillStyle = mix(T.vAmber, T.panel, 0.16)
      roundRect(ctx, cx, gy + 2, cw, 16, 4)
      ctx.fill()
      ctx.fillStyle = T.vAmber
      ctx.textAlign = 'center'
      ctx.fillText(chip, cx + cw / 2, gy + 13)
      ctx.textAlign = 'left'
    }
  }
  gy += 26

  // discrete maturity meter — younger → older (amber when newly registered)
  if (draw) {
    const barW = 16
    const barH = 10
    const gap = 4
    const level = domainAgeLevel(dm.ageDays)
    for (let i = 0; i < 5; i++) {
      const bx = PAD + ipad + i * (barW + gap)
      const on = i < level
      ctx.fillStyle = on ? (dm.newlyRegistered ? T.vAmber : T.accent) : mix(T.border2, T.panel, 0.6)
      roundRect(ctx, bx, gy, barW, barH, 3)
      ctx.fill()
    }
    ctx.font = `400 8.5px ${MONO}`
    ctx.fillStyle = T.textFaint
    ctx.textAlign = 'right'
    ctx.fillText('younger → older', W - PAD - ipad, gy + 8)
    ctx.textAlign = 'left'
  }
  gy += 16 + 10

  // supporting facts (2×2): registered · registrar · resolves-to · hosting
  const resolved = dm.resolved
    ? [dm.resolved.countryName, dm.resolved.city].filter(Boolean).join(' · ') || '—'
    : '—'
  const hosting = dm.resolved
    ? [dm.resolved.asn, dm.resolved.org].filter(Boolean).join(' · ') || '—'
    : '—'
  const facts: Array<[string, string]> = [
    ['REGISTERED', dm.registered],
    ['REGISTRAR', dm.registrar],
    ['RESOLVES TO', resolved],
    ['HOSTING', hosting],
  ]
  const gap2 = 8
  const fw = (inner - ipad * 2 - gap2) / 2
  const mc = measurer()
  if (draw) {
    facts.forEach(([k, v], i) => {
      const col = i % 2
      const row = Math.floor(i / 2)
      const fx = PAD + ipad + col * (fw + gap2)
      const fyy = gy + row * (factH + 8)
      ctx.fillStyle = T.field
      ctx.strokeStyle = mix(T.accent, T.border, 0.18)
      ctx.lineWidth = 1
      roundRect(ctx, fx, fyy, fw, factH, 4)
      ctx.fill()
      ctx.stroke()
      ctx.font = `700 7.5px ${MONO}`
      ctx.fillStyle = T.textFaint
      ctx.textAlign = 'left'
      ctx.fillText(k, fx + 8, fyy + 12)
      ctx.font = `600 10.5px ${MONO}`
      ctx.fillStyle = T.text
      const vv = wrap(mc, v, `600 10.5px ${MONO}`, fw - 16)[0] ?? v
      ctx.fillText(vv, fx + 8, fyy + 26)
    })
  }
  gy += factH * 2 + 8

  return y + h + 12
}

function paintIdentity(ctx: CanvasRenderingContext2D, hash: HashModel, T: Palette, draw: boolean, y: number, inner: number): number {
  const ipad = 12
  const sevInk = hash.grayware ? T.vAmber : T.vRed
  const factH = 34
  const h = ipad + 12 + 8 + 30 + (hash.aliases.length ? 16 : 0) + 10 + factH + 14 + 16 + ipad
  heroPanel(ctx, T, draw, y, inner, h)

  let gy = y + ipad
  if (draw) {
    ctx.textAlign = 'left'
    ctx.font = `700 9px ${SANS}`
    ctx.fillStyle = T.textFaint
    ctx.fillText('MALWARE IDENTITY', PAD + ipad, gy + 8)
  }
  gy += 12 + 8

  if (draw) {
    ctx.font = `800 22px ${SANS}`
    ctx.fillStyle = T.text
    ctx.fillText(hash.family, PAD + ipad, gy + 18)
    // classification chip
    ctx.font = `700 9px ${MONO}`
    const cw = ctx.measureText(hash.classification.toUpperCase()).width + 14
    const cx = W - PAD - ipad - cw
    ctx.fillStyle = mix(sevInk, T.panel, 0.16)
    roundRect(ctx, cx, gy + 4, cw, 16, 4)
    ctx.fill()
    ctx.fillStyle = sevInk
    ctx.textAlign = 'center'
    ctx.fillText(hash.classification.toUpperCase(), cx + cw / 2, gy + 15)
    ctx.textAlign = 'left'
  }
  gy += 30

  if (hash.aliases.length) {
    if (draw) {
      ctx.font = `400 9.5px ${MONO}`
      ctx.fillStyle = T.textDim
      ctx.fillText('seen as ' + hash.aliases.join(' · '), PAD + ipad, gy + 8)
    }
    gy += 16
  }
  gy += 10

  // 4-column fact chips
  const facts: Array<[string, string]> = [
    ['TYPE', hash.fileType],
    ['SIZE', hash.size],
    ['SIGNED', hash.signed],
    ['DETECT', hash.detect],
  ]
  const gap = 8
  const fw = (inner - ipad * 2 - gap * 3) / 4
  if (draw) {
    facts.forEach(([k, v], i) => {
      const fx = PAD + ipad + i * (fw + gap)
      ctx.fillStyle = T.field
      ctx.strokeStyle = mix(T.accent, T.border, 0.18)
      ctx.lineWidth = 1
      roundRect(ctx, fx, gy, fw, factH, 4)
      ctx.fill()
      ctx.stroke()
      ctx.font = `700 7.5px ${MONO}`
      ctx.fillStyle = T.textFaint
      ctx.textAlign = 'left'
      ctx.fillText(k, fx + 8, gy + 12)
      ctx.font = `600 11px ${MONO}`
      ctx.fillStyle = T.text
      ctx.fillText(v, fx + 8, gy + 26)
    })
  }
  gy += factH + 14

  // first → last observed line
  if (draw) {
    ctx.font = `400 9px ${MONO}`
    ctx.fillStyle = T.textDim
    ctx.textAlign = 'left'
    ctx.fillText(`First ${hash.firstSeen}  ·  ${hash.durationLabel}`, PAD + ipad, gy + 8)
    ctx.textAlign = 'right'
    ctx.fillStyle = T.textFaint
    ctx.fillText(`${hash.prevalenceLabel}`, W - PAD - ipad, gy + 8)
    ctx.textAlign = 'left'
  }
  gy += 16

  return y + h + 12
}

function paintCve(ctx: CanvasRenderingContext2D, cve: CveModel, T: Palette, draw: boolean, y: number, inner: number): number {
  const ipad = 12
  const sevInk = cve.kev ? T.vRed : cve.cvssSeverity === 'High' || cve.cvssSeverity === 'Critical' ? T.vAmber : T.textDim
  const h = ipad + 12 + 8 + 26 + 14 + 34 + ipad
  heroPanel(ctx, T, draw, y, inner, h)

  let gy = y + ipad
  if (draw) {
    ctx.textAlign = 'left'
    ctx.font = `700 9px ${SANS}`
    ctx.fillStyle = T.textFaint
    ctx.fillText('EXPLOITATION STATUS', PAD + ipad, gy + 8)
  }
  gy += 12 + 8

  if (draw) {
    ctx.font = `800 16px ${SANS}`
    ctx.fillStyle = sevInk
    ctx.fillText(cve.kev ? 'Known exploited (CISA KEV)' : 'Not in KEV catalog', PAD + ipad, gy + 14)
  }
  gy += 26

  const vp = [cve.vendor, cve.product].filter(Boolean).join(' · ')
  if (draw && vp) {
    ctx.font = `400 10px ${MONO}`
    ctx.fillStyle = T.textDim
    ctx.fillText(vp, PAD + ipad, gy + 8)
  }
  gy += 14

  const chips: Array<[string, string]> = [
    ['CVSS', `${cve.cvss}  ${cve.cvssSeverity}`],
    ['EPSS', Number.isFinite(cve.epssPct) ? `${cve.epssPct}%` : cve.epss],
    ['ACTION DUE', cve.due || '—'],
  ]
  const gap = 8
  const cw = (inner - ipad * 2 - gap * 2) / 3
  if (draw) {
    chips.forEach(([k, v], i) => {
      const cx = PAD + ipad + i * (cw + gap)
      ctx.fillStyle = T.field
      ctx.strokeStyle = mix(T.accent, T.border, 0.18)
      ctx.lineWidth = 1
      roundRect(ctx, cx, gy, cw, 30, 4)
      ctx.fill()
      ctx.stroke()
      ctx.font = `700 7.5px ${MONO}`
      ctx.fillStyle = T.textFaint
      ctx.textAlign = 'left'
      ctx.fillText(k, cx + 8, gy + 11)
      ctx.font = `600 10.5px ${MONO}`
      ctx.fillStyle = T.text
      ctx.fillText(v, cx + 8, gy + 24)
    })
  }
  gy += 34

  return y + h + 12
}

function paintFacts(ctx: CanvasRenderingContext2D, label: string, rows: Array<[string, string]>, T: Palette, draw: boolean, y: number, inner: number): number {
  if (!rows.length) return y
  const ipad = 12
  const rowH = 18
  const h = ipad + 12 + 8 + rows.length * rowH + ipad - 4
  heroPanel(ctx, T, draw, y, inner, h)

  let gy = y + ipad
  if (draw) {
    ctx.textAlign = 'left'
    ctx.font = `700 9px ${SANS}`
    ctx.fillStyle = T.textFaint
    ctx.fillText(label.toUpperCase(), PAD + ipad, gy + 8)
  }
  gy += 12 + 8

  const mc = measurer()
  for (const [k, v] of rows) {
    if (draw) {
      ctx.font = `600 10px ${SANS}`
      ctx.fillStyle = T.textDim
      ctx.textAlign = 'left'
      ctx.fillText(k, PAD + ipad, gy + 9)
      ctx.font = `400 10px ${MONO}`
      ctx.fillStyle = T.text
      ctx.textAlign = 'right'
      const maxV = inner - ipad * 2 - 120
      const vv = wrap(mc, v, `400 10px ${MONO}`, maxV)[0] ?? v
      ctx.fillText(vv, W - PAD - ipad, gy + 9)
      ctx.textAlign = 'left'
    }
    gy += rowH
  }
  return y + h + 12
}

/* ---------- attributed source rows -------------------------------------- */

function paintSources(ctx: CanvasRenderingContext2D, m: CardModel, T: Palette, draw: boolean, y: number, inner: number): number {
  const mc = measurer()
  const rowPadX = 10
  const rowPadY = 7
  const nameW = 96
  const dotGap = 8
  const dotR = 3.5
  const nameStart = PAD + rowPadX + dotGap + dotR * 2 + 6
  const findX = nameStart + nameW + 8
  const findW = W - PAD - rowPadX - findX
  const rightEdge = W - PAD - rowPadX
  const findFont = `400 9.5px ${MONO}`
  const chipFont = `700 7px ${MONO}`
  const metaFont = `400 8px ${MONO}`
  const metaH = 15 // gap + one 12px meta line (class chip + recency)

  const rows = m.sources.length
    ? m.sources
    : [
        {
          name: '—',
          verdict: 'unknown' as const,
          finding: 'No consulted source returned a finding.',
          classLabel: '',
          recency: '',
          stale: false,
        },
      ]
  // Measure once (identical in the measure + draw passes → heights never drift):
  // finding line count + whether the row carries a class/recency meta line.
  const rowInfo = rows.map((s) => ({
    findingLines: Math.min(2, wrap(mc, s.finding, findFont, findW).length || 1),
    hasMeta: Boolean(s.classLabel) || Boolean(s.recency),
  }))
  const rowHeights = rowInfo.map(
    ({ findingLines, hasMeta }) => Math.max(20, rowPadY * 2 + findingLines * 13 + (hasMeta ? metaH : 0)),
  )
  const listH = rowHeights.reduce((a, b) => a + b, 0)

  if (draw) {
    ctx.strokeStyle = T.border
    ctx.lineWidth = 1
    roundRect(ctx, PAD, y, inner, listH, 8)
    ctx.stroke()
    ctx.save()
    roundRect(ctx, PAD, y, inner, listH, 8)
    ctx.clip()
  }

  let ry = y
  rows.forEach((s, i) => {
    const rh = rowHeights[i]
    const { findingLines, hasMeta } = rowInfo[i]
    if (draw) {
      if (i % 2 === 1) {
        ctx.fillStyle = mix(T.panel2, T.panel, 0.45)
        ctx.fillRect(PAD, ry, inner, rh)
      }
      if (i > 0) {
        ctx.fillStyle = T.border
        ctx.fillRect(PAD, ry, inner, 1)
      }
      const topY = ry + rowPadY
      const baseY = topY + 9 // first-line baseline

      // per-source verdict dot, aligned to the first line
      const dotCol = SEG_FILL[s.verdict]?.(T) ?? T.textFaint
      ctx.fillStyle = dotCol
      ctx.beginPath()
      ctx.arc(PAD + rowPadX + dotR, topY + 6, dotR, 0, Math.PI * 2)
      ctx.fill()

      // source name (left column)
      ctx.font = `600 11px ${SANS}`
      ctx.fillStyle = T.text
      ctx.textAlign = 'left'
      ctx.fillText(s.name, nameStart, baseY)

      // finding (right column, up to 2 lines)
      const lines = wrap(mc, s.finding, findFont, findW).slice(0, 2)
      ctx.font = findFont
      ctx.fillStyle = T.textDim
      lines.forEach((ln, li) => {
        let out = ln
        if (li === 1 && wrap(mc, s.finding, findFont, findW).length > 2) out = ln.replace(/.$/, '…')
        ctx.fillText(out, findX, baseY + li * 13)
      })

      // meta line: class micro-chip under the name (periwinkle — source-class,
      // never a verdict hue), recency right-aligned. Suppress each when absent.
      if (hasMeta) {
        const metaY = topY + findingLines * 13 + 3
        const metaBase = metaY + 8.5
        if (s.classLabel) {
          const label = s.classLabel.toUpperCase()
          ctx.font = chipFont
          const cw = ctx.measureText(label).width + 10
          ctx.fillStyle = mix(T.accent, T.panel, 0.16)
          roundRect(ctx, nameStart, metaY, cw, 12, 3)
          ctx.fill()
          ctx.fillStyle = T.accent
          ctx.textAlign = 'left'
          ctx.fillText(label, nameStart + 5, metaBase)
        }
        if (s.recency) {
          ctx.font = metaFont
          ctx.textAlign = 'right'
          if (s.stale) {
            const staleTxt = ' · stale'
            const sw = ctx.measureText(staleTxt).width
            ctx.fillStyle = T.vAmber
            ctx.fillText(staleTxt, rightEdge, metaBase)
            ctx.fillStyle = T.textFaint
            ctx.fillText(s.recency, rightEdge - sw, metaBase)
          } else {
            ctx.fillStyle = T.textFaint
            ctx.fillText(s.recency, rightEdge, metaBase)
          }
          ctx.textAlign = 'left'
        }
      }
    }
    ry += rh
  })
  if (draw) ctx.restore()

  return y + listH + 10
}

/* ---------- public API --------------------------------------------------- */

export interface DrawOptions {
  theme?: CanvasTheme
  now?: Date
  /** A bundled inline Compare-IP result — draws the arc + second pin on the map
   *  and the geographic-separation fact line. Absent = the single-IP card. */
  compare?: CompareResult | null
}

/**
 * Render the card to a canvas sized to its content, in the given (or detected)
 * theme. Call after `document.fonts.ready` so the brand faces are resolved —
 * canvas silently substitutes a fallback face otherwise.
 */
export function renderVerdictCanvas(data: VerdictData, opts: DrawOptions = {}): HTMLCanvasElement {
  const theme = opts.theme ?? detectTheme()
  const T = THEMES[theme] ?? THEMES.dark
  const now = opts.now ?? new Date()
  const m = cardModel(data, now, opts.compare)

  const height = paint(measurer(), m, T, false)

  const canvas = document.createElement('canvas')
  canvas.width = W * SCALE
  canvas.height = Math.ceil(height) * SCALE
  const ctx = canvas.getContext('2d')
  if (!ctx) throw new Error('2D canvas context unavailable')
  ctx.scale(SCALE, SCALE)
  ctx.textBaseline = 'alphabetic'

  // card background + hairline border, clipped to the rounded shape
  roundRect(ctx, 0.5, 0.5, W - 1, height - 1, RADIUS)
  ctx.fillStyle = T.panel
  ctx.fill()
  ctx.save()
  roundRect(ctx, 0.5, 0.5, W - 1, height - 1, RADIUS)
  ctx.clip()

  // FLAT accent bar (no gradient — anti-slop, deterministic)
  ctx.fillStyle = T.accent
  ctx.fillRect(0, 0, W, 3)

  paint(ctx, m, T, true)
  ctx.restore()

  ctx.strokeStyle = T.border2
  ctx.lineWidth = 1
  roundRect(ctx, 0.5, 0.5, W - 1, height - 1, RADIUS)
  ctx.stroke()

  return canvas
}
