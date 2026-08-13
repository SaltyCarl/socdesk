// model.ts — per-entity-type hero view-models, derived from the shared
// VerdictData. Pure functions: VerdictData in, plain view data out (strings /
// numbers / booleans — NO Tailwind classes, NO React). The tally / band / lead
// fact themselves come straight from the verdict-lib doctrine; this file only
// pulls the type-specific fields the heroes render (family, registration age,
// KEV/CVSS, …) out of the attributed source facts.

import type { FactRow, SourceVerdict, VerdictData } from '../verdict'
import { isAdverse, phraseFinding } from '../verdict'
import { geoModel, type GeoModel } from './geo'

/** Case-insensitive fact lookup for a source's [label, value] rows. */
export function factMap(facts?: FactRow[]): Map<string, string> {
  return new Map((facts ?? []).map(([k, v]) => [String(k).toLowerCase(), String(v)]))
}

function pick(m: Map<string, string>, ...keys: string[]): string {
  for (const k of keys) {
    const v = m.get(k.toLowerCase())
    if (v) return v
  }
  return ''
}

/* ---------- gauge (client + analyst share the segment ordering) ---------- */

const RANK: Record<SourceVerdict, number> = { malicious: 0, suspicious: 1, benign: 2, unknown: 3 }

/** One gauge segment per consulted source, severity-ordered for a clean read. */
export function gaugeSegments(data: VerdictData): SourceVerdict[] {
  return [...data.sources].sort((a, b) => RANK[a.verdict] - RANK[b.verdict]).map((s) => s.verdict)
}

export interface VerdictCounts {
  malicious: number
  suspicious: number
  benign: number
  unknown: number
  notFlagged: number
}

export function verdictCounts(data: VerdictData): VerdictCounts {
  const by = (v: SourceVerdict) => data.sources.filter((s) => s.verdict === v).length
  const malicious = by('malicious')
  const suspicious = by('suspicious')
  return {
    malicious,
    suspicious,
    benign: by('benign'),
    unknown: by('unknown'),
    notFlagged: Math.max(0, data.consulted - malicious - suspicious),
  }
}

/** The gauge caption halves ("4 malicious · 1 suspicious" / "1 not flagged"). */
export function gaugeCaption(data: VerdictData): { left: string; right: string } {
  const c = verdictCounts(data)
  const left: string[] = []
  if (c.malicious) left.push(`${c.malicious} malicious`)
  if (c.suspicious) left.push(`${c.suspicious} suspicious`)
  if (!left.length) left.push('none flagged')
  return { left: left.join(' · '), right: `${c.notFlagged} not flagged` }
}

/* ---------- hash — malware identity (spec §3.4) --------------------------- */

export interface HashModel {
  family: string
  grayware: boolean
  /** The classification word for the hero severity chip. */
  classification: string
  aliases: string[]
  fileType: string
  size: string
  signed: string
  detect: string
  firstSeen: string
  lastSeen: string
  durationLabel: string
  prevalenceLabel: string
  /** 0–5, for the discrete prevalence bars. */
  prevalenceLevel: number
  delivery: string
  catalogName: string
}

function monthsBetween(a: string, b: string): number {
  const t0 = Date.parse(a)
  const t1 = Date.parse(b)
  if (!Number.isFinite(t0) || !Number.isFinite(t1)) return 0
  return Math.max(0, Math.round((t1 - t0) / (30 * 864e5)))
}

function prevalenceBand(submissions: string): { label: string; level: number } {
  const n = parseInt(submissions.replace(/[^\d]/g, ''), 10)
  if (!Number.isFinite(n) || n <= 0) return { label: 'Prevalence unknown', level: 0 }
  if (n >= 2000) return { label: 'Widely circulated', level: 5 }
  if (n >= 500) return { label: 'Common', level: 4 }
  if (n >= 50) return { label: 'Seen in multiple environments', level: 3 }
  if (n >= 5) return { label: 'Seen occasionally', level: 2 }
  return { label: 'Rarely seen', level: 1 }
}

export function hashModel(data: VerdictData): HashModel {
  const catalog = data.sources.find((s) => s.class === 'catalog' && s.verdict !== 'unknown')
  const src = catalog ?? data.sources.find(isAdverse) ?? data.sources[0]
  const fm = factMap(src?.facts)
  const vt = data.sources.find((s) => s.name === 'VirusTotal')
  const vfm = factMap(vt?.facts)

  const grayware = data.band === 'grayware' || Boolean(src?.pua)
  const firstSeen = pick(fm, 'first seen', 'first')
  const lastSeen = pick(fm, 'last seen', 'last')
  const months = monthsBetween(firstSeen, lastSeen)
  const prev = prevalenceBand(pick(fm, 'submissions', 'prevalence'))

  return {
    family: pick(fm, 'family') || 'Unclassified sample',
    grayware,
    classification: grayware
      ? 'Grayware · PUA'
      : pick(fm, 'classification', 'threat type') || 'Command & control',
    aliases: pick(fm, 'seen as', 'aliases')
      .split(/[,·]/)
      .map((s) => s.trim())
      .filter(Boolean),
    fileType: pick(fm, 'file type', 'type') || '—',
    size: pick(fm, 'size') || '—',
    signed: pick(fm, 'signed') || '—',
    detect: pick(vfm, 'detections', 'detect') || pick(fm, 'detections', 'detect') || '—',
    firstSeen: firstSeen || '—',
    lastSeen: lastSeen || '—',
    durationLabel: months >= 1 ? `~${months} months circulating` : 'Recently observed',
    prevalenceLabel: prev.label,
    prevalenceLevel: prev.level,
    delivery: pick(fm, 'delivery', 'delivery method'),
    catalogName: src?.name ?? '',
  }
}

/* ---------- domain — registration-age tell (spec §3.3) -------------------- */

export interface DomainModel {
  registered: string
  ageDays: number
  ageLabel: string
  /** The tell: a domain registered inside the last month. */
  newlyRegistered: boolean
  registrar: string
  resolved: GeoModel | null
}

function daysSince(iso: string, now: Date): number {
  const t = Date.parse(iso)
  if (!Number.isFinite(t)) return NaN
  return Math.max(0, Math.round((now.getTime() - t) / 864e5))
}

/** Domain-age maturity bucket (0–5) for the discrete meter. Shared thresholds
 *  so the web DomainHero and the copy-card canvas read the same tell. */
export function domainAgeLevel(ageDays: number): number {
  if (!Number.isFinite(ageDays)) return 0
  if (ageDays <= 30) return 1
  if (ageDays <= 90) return 2
  if (ageDays <= 365) return 3
  if (ageDays <= 1095) return 4
  return 5
}

/** `now` is injected so the canvas can render byte-deterministically for a fixed
 *  render clock; the web hero calls it with the default (live) clock. When the
 *  WHOIS row carries an explicit age, no clock is read at all. */
export function domainModel(data: VerdictData, now: Date = new Date()): DomainModel {
  const whois = data.context.find((c) => /whois|registr/i.test(c.name)) ?? data.context[0]
  const fm = factMap(whois?.facts)
  const registered = pick(fm, 'registered', 'created', 'registration date')
  const explicitAge = parseInt(pick(fm, 'age', 'age (days)').replace(/[^\d]/g, ''), 10)
  const ageDays = Number.isFinite(explicitAge) && explicitAge > 0 ? explicitAge : daysSince(registered, now)
  const ageLabel = !Number.isFinite(ageDays)
    ? 'Registration age unknown'
    : ageDays < 45
      ? `${ageDays} days old`
      : ageDays < 730
        ? `~${Math.round(ageDays / 30)} months old`
        : `~${Math.round(ageDays / 365)} years old`

  return {
    registered: registered || '—',
    ageDays: Number.isFinite(ageDays) ? ageDays : NaN,
    ageLabel,
    newlyRegistered: Number.isFinite(ageDays) && ageDays <= 30,
    registrar: pick(fm, 'registrar') || '—',
    resolved: geoModel(data.context, data.sources),
  }
}

/* ---------- url — the page the client would have seen (spec §3.3) --------- */

export interface UrlModel {
  screenshot: string
  finalUrl: string
  pageTitle: string
  verdict: SourceVerdict
  scanner: string
}

export function urlModel(data: VerdictData): UrlModel {
  const scan =
    data.sources.find((s) => s.name === 'urlscan') ??
    data.sources.find((s) => s.screenshot) ??
    data.sources.find(isAdverse) ??
    data.sources[0]
  const fm = factMap(scan?.facts)
  return {
    screenshot: scan?.screenshot ?? '',
    finalUrl: pick(fm, 'final url', 'effective url', 'landing url') || data.indicator,
    pageTitle: pick(fm, 'page title', 'title'),
    verdict: scan?.verdict ?? 'unknown',
    scanner: scan?.name ?? 'urlscan',
  }
}

/* ---------- cve — exploitation status, authoritative (spec §5) ------------ */

export interface CveModel {
  kev: boolean
  cvss: string
  cvssSeverity: string
  epss: string
  epssPct: number
  vendor: string
  product: string
  added: string
  due: string
}

export function cveModel(data: VerdictData): CveModel {
  const kevSrc = data.sources.find((s) => s.kev) ?? null
  const merged = factMap(data.sources.flatMap((s) => s.facts ?? []))
  const cvss = pick(merged, 'cvss', 'cvss score')
  const cvssNum = parseFloat(cvss)
  const epss = pick(merged, 'epss', 'epss score')
  const epssNum = parseFloat(epss)

  return {
    kev: Boolean(kevSrc),
    cvss: cvss || '—',
    cvssSeverity:
      pick(merged, 'severity') ||
      (!Number.isFinite(cvssNum)
        ? '—'
        : cvssNum >= 9
          ? 'Critical'
          : cvssNum >= 7
            ? 'High'
            : cvssNum >= 4
              ? 'Medium'
              : 'Low'),
    epss: epss || '—',
    epssPct: Number.isFinite(epssNum) ? Math.round(epssNum * 100) : NaN,
    vendor: pick(merged, 'vendor'),
    product: pick(merged, 'product'),
    added: pick(merged, 'added', 'date added'),
    due: pick(merged, 'action due', 'due', 'remediation due'),
  }
}

/** The CVE lead sentence — source-subject-first, KEV wins (spec §5). Shared by
 *  the on-screen banner and the copy-card canvas so wording can't drift. */
export function cveLead(data: VerdictData): string {
  const kev = data.sources.find((s) => s.kev)
  if (kev) return `${phraseFinding(kev)}.`
  const c = cveModel(data)
  return c.cvss !== '—'
    ? `Not in the KEV catalog — no confirmed in-the-wild exploitation on record. CVSS ${c.cvss} (${c.cvssSeverity}).`
    : 'No exploitation data on record — absence of data is not evidence of safety.'
}

/** A card leads with its hero (no cross-source tally) for identity indicators
 *  (hashes) and for CVEs — both are single-source authority, not a vote. */
export function isBannerLed(data: VerdictData): boolean {
  return data.identityLed || data.type === 'cve'
}
