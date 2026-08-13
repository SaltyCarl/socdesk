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

import type { Band, VerdictData, VerdictSource } from '../../lib/verdict'
import { CAVEAT, assessmentLine, dualUseNote, hashHeadline, isStale, predicate } from '../../lib/verdict'
import { detectTheme, MONO, SANS, mix, THEMES, type CanvasTheme, type Palette } from './palette'
import { WORLD, coordLabel, geoModel, project, type GeoModel } from './geo'
import {
  cveLead,
  cveModel,
  gaugeCaption,
  gaugeSegments,
  hashModel,
  isBannerLed,
  type CveModel,
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
  | { kind: 'geo'; geo: GeoModel; note: string }
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
  sources: Array<{ name: string; verdict: VerdictSource['verdict']; finding: string; stale: boolean }>
  caveat: string
  generated: string
  queried: string
}

function heroFor(data: VerdictData): Hero {
  if (data.type === 'cve') return { kind: 'cve', cve: cveModel(data) }
  if (data.identityLed) return { kind: 'identity', hash: hashModel(data) }
  if (data.type === 'ipv4' || data.type === 'domain') {
    const geo = geoModel(data.context, data.sources)
    if (geo) return { kind: 'geo', geo, note: dualUseNote(data.sources) ?? '' }
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

function cardModel(data: VerdictData, now: Date): CardModel {
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
    hero: heroFor(data),
    sources: data.sources.map((s) => ({
      name: s.name,
      verdict: s.verdict,
      // verb-led predicate (the row already prints the name in bold beside it),
      // so the class verb appears exactly once — source-subject-first.
      finding: predicate(s),
      stale: isStale(s.recency, now),
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
    text('CONSENSUS TALLY — ACROSS PUBLIC SOURCES', `700 9px ${SANS}`, T.textFaint, PAD, y + 8)
    y += 16
    y = paintTally(ctx, m, T, draw, y, inner, width)
    y = paintGauge(ctx, m, T, draw, y, inner)
    if (m.dualUse) y = paintNote(ctx, 'NOTE', m.dualUse, T, draw, y, inner, T.accent)
    y = paintHero(ctx, m, T, draw, y, inner)
  }

  /* attributed source rows */
  y = paintSources(ctx, m, T, draw, y, inner)

  /* verify caveat (§4) — baked in so it cannot be lost on forward */
  y = paintNote(ctx, '', m.caveat, T, draw, y, inner, T.border3)

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

function paintNote(
  ctx: CanvasRenderingContext2D,
  label: string,
  body: string,
  T: Palette,
  draw: boolean,
  y: number,
  inner: number,
  barColor: string,
): number {
  const mc = measurer()
  const barTop = y - 2
  let ny = y
  if (label) {
    if (draw) {
      ctx.font = `700 8.5px ${SANS}`
      ctx.fillStyle = T.textDim
      ctx.textAlign = 'left'
      ctx.fillText(label, PAD + 10, ny + 8)
    }
    ny += 12
  }
  for (const line of wrap(mc, body, `400 10px ${SANS}`, inner - 12)) {
    if (draw) {
      ctx.font = `400 10px ${SANS}`
      ctx.fillStyle = T.textDim
      ctx.textAlign = 'left'
      ctx.fillText(line, PAD + 10, ny + 9)
    }
    ny += 14
  }
  if (draw) {
    ctx.fillStyle = barColor
    ctx.fillRect(PAD, barTop, 2, ny - barTop)
  }
  return ny + 8
}

/* ---------- per-type heroes --------------------------------------------- */

function paintHero(ctx: CanvasRenderingContext2D, m: CardModel, T: Palette, draw: boolean, y: number, inner: number): number {
  switch (m.hero.kind) {
    case 'geo':
      return paintGeo(ctx, m.hero.geo, T, draw, y, inner)
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

function paintGeo(ctx: CanvasRenderingContext2D, g: GeoModel, T: Palette, draw: boolean, y: number, inner: number): number {
  const ipad = 12
  const contentW = inner - ipad * 2
  const mapH = contentW * (WORLD.length / WORLD[0].length)
  const geoH = ipad + 12 + 8 + mapH + 12 + 30 + ipad

  heroPanel(ctx, T, draw, y, inner, geoH)

  let gy = y + ipad
  if (draw) {
    ctx.font = `700 9px ${SANS}`
    ctx.fillStyle = T.textFaint
    ctx.textAlign = 'left'
    ctx.fillText('GEOLOCATION — CONTEXT, NOT A VERDICT', PAD + ipad, gy + 8)
  }
  gy += 12 + 8

  paintWorld(ctx, T, draw, PAD + ipad, gy, contentW, mapH, g)
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

  return y + geoH + 12
}

function paintWorld(ctx: CanvasRenderingContext2D, T: Palette, draw: boolean, x: number, y: number, w: number, h: number, g: GeoModel): void {
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
  const findX = PAD + rowPadX + dotGap + dotR * 2 + 6 + nameW + 8
  const findW = W - PAD - rowPadX - findX
  const findFont = `400 9.5px ${MONO}`

  const rows = m.sources.length
    ? m.sources
    : [{ name: '—', verdict: 'unknown' as const, finding: 'No consulted source returned a finding.', stale: false }]
  const rowHeights = rows.map((s) => {
    const lines = Math.min(2, wrap(mc, s.finding, findFont, findW).length || 1)
    return Math.max(20, rowPadY * 2 + lines * 13)
  })
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
    if (draw) {
      if (i % 2 === 1) {
        ctx.fillStyle = mix(T.panel2, T.panel, 0.45)
        ctx.fillRect(PAD, ry, inner, rh)
      }
      if (i > 0) {
        ctx.fillStyle = T.border
        ctx.fillRect(PAD, ry, inner, 1)
      }
      const dotCol = SEG_FILL[s.verdict]?.(T) ?? T.textFaint
      ctx.fillStyle = dotCol
      ctx.beginPath()
      ctx.arc(PAD + rowPadX + dotR, ry + rh / 2, dotR, 0, Math.PI * 2)
      ctx.fill()

      ctx.font = `600 11px ${SANS}`
      ctx.fillStyle = T.text
      ctx.textAlign = 'left'
      ctx.fillText(s.name, PAD + rowPadX + dotGap + dotR * 2 + 6, ry + rh / 2 + 4)

      const lines = wrap(mc, s.finding, findFont, findW).slice(0, 2)
      ctx.font = findFont
      ctx.fillStyle = T.textDim
      const startY = ry + rh / 2 - (lines.length - 1) * 6.5 + 4
      lines.forEach((ln, li) => {
        let out = ln
        if (li === 1 && wrap(mc, s.finding, findFont, findW).length > 2) out = ln.replace(/.$/, '…')
        ctx.fillText(out, findX, startY + li * 13)
      })
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
  const m = cardModel(data, now)

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
