// doctrine.ts — the verdict language, as deterministic pure functions.
//
// This is the single source of SOCDesk's wording + banding. SOCDesk emits no
// verdict word of its own for a live indicator; it counts what independent
// public sources reported and attributes each finding
// (docs/VERDICT-LANGUAGE.md + design spec §3.1 "VERDICT-LANGUAGE v2").
//
// EVERY function here is pure: same inputs → same output, no side effects, no
// clock reads except through an injected `now`. That is what lets the console,
// the extension, the escalation text, and the canvas PNG all render byte-for-
// byte the same assessment.

import type {
  Band,
  ContextRow,
  IndicatorType,
  SourceClass,
  Tone,
  VerdictData,
  VerdictSource,
} from './types';
import {
  CAVEAT,
  CLASS_BY_SOURCE,
  CLASS_PRECEDENCE,
  CLASS_TAG,
  GRAYWARE_LABEL,
  IDENTITY_TYPES,
  KEV_PRECEDENCE,
  STALE_DAYS,
  THIN_COVERAGE,
  VERB_BY_CLASS,
} from './types';

/* ---------- classification helpers --------------------------------------- */

/** The source-class for a source name (spec §3.1). Unknown → `score`. */
export function sourceClassFor(name: string): SourceClass {
  return CLASS_BY_SOURCE[name] ?? 'score';
}

/** True when a source's finding is adverse (its verdict flags the indicator). */
export function isAdverse(s: Pick<VerdictSource, 'verdict'>): boolean {
  return s.verdict === 'malicious' || s.verdict === 'suspicious';
}

const PUA_RE =
  /\b(pua|pup|potentially[\s-]?unwanted|gray?ware|grey?ware|adware|riskware|unwanted|not-?a-?virus)\b/i;

/** Detect a PUA / grayware finding from free text (headline, facts, tags).
 *  "flagged" ≠ "malware" (spec §3.1) — this drives the distinct grayware band. */
export function detectPua(text: string): boolean {
  return PUA_RE.test(String(text ?? ''));
}

/** Identity types are IDENTITY, not a cross-source vote (hash carve-out). */
export function isIdentityType(type: IndicatorType): boolean {
  return IDENTITY_TYPES.has(type);
}

/* ---------- the confidence ladder (spec §3.1) ---------------------------- */

/** Authority rank for a source — lower = higher authority. Published,
 *  deterministic: KEV > hash-catalog > behavioral > reputation-score > list. */
export function sourceRank(s: Pick<VerdictSource, 'class' | 'kev'>): number {
  return s.kev ? KEV_PRECEDENCE : CLASS_PRECEDENCE[s.class];
}

/** The lead fact (spec §3.1): the highest-authority attributed source that has
 *  something to say — an adverse source if any, otherwise a benign one — with
 *  source-subject-first phrasing. Null only when every source is a no-record.
 *  Stable: ties keep input order. */
export function leadFact(
  sources: VerdictSource[],
): { source: VerdictSource; phrasing: string } | null {
  const byRank = (a: VerdictSource, b: VerdictSource) => sourceRank(a) - sourceRank(b);
  const adverse = sources.filter(isAdverse).sort(byRank);
  const lead = adverse[0] ?? sources.filter((s) => s.verdict === 'benign').sort(byRank)[0];
  if (!lead) return null;
  return { source: lead, phrasing: phraseFinding(lead) };
}

/* ---------- source-subject-first phrasing (spec §3.1) -------------------- */

/** Lowercase the first letter only when it is a plain Capitalised word — never
 *  an acronym (RIOT, IP), an identifier (AS3209), or a number. */
function softLower(s: string): string {
  return /^[A-Z][a-z]/.test(s) ? s.charAt(0).toLowerCase() + s.slice(1) : s;
}

/** Phrase a source's finding with the SOURCE as the sentence subject:
 *  "MalwareBazaar catalogs known sample — family Cobalt Strike" — never
 *  "Confirmed sample — MalwareBazaar" (spec §3.1 grammatical rule). */
export function phraseFinding(s: VerdictSource): string {
  const verb = s.kev ? 'confirms' : VERB_BY_CLASS[s.class];
  const finding = String(s.finding ?? '').trim();
  return finding ? `${s.name} ${verb} ${softLower(finding)}` : `${s.name} — no finding reported`;
}

/** The human class tag for the ledger, e.g. "catalog/identity". */
export function classTag(s: Pick<VerdictSource, 'class' | 'kev'>): string {
  return s.kev ? 'KEV/authoritative' : CLASS_TAG[s.class];
}

/* ---------- the tally (contract §1–§2) + the doctrine band (spec §3.1) --- */

/** The ratio tally, matching the server `consensus()` exactly. Tone rides the
 *  ratio alone (no hidden weighting): grey M=0, green N=0, red N≥M/2, else amber. */
export function consensus(sources: VerdictSource[]): {
  consulted: number;
  flagged: number;
  tone: Tone;
} {
  const consulted = sources.length;
  const flagged = sources.filter(isAdverse).length;
  const tone: Tone =
    consulted === 0 ? 'grey' : flagged === 0 ? 'green' : flagged * 2 >= consulted ? 'red' : 'amber';
  return { consulted, flagged, tone };
}

/** The doctrine band (spec §3.1) — colour DECOUPLED from the raw N/M ratio.
 *
 *  An authoritative (catalog/KEV) adverse source, or a source asserting its own
 *  `malicious` verdict, drives RED regardless of how thin the ratio is — so a
 *  1-of-6 catalog/KEV hit is never diluted to green (or amber) by the majority
 *  of quiet sources. Score/list "suspicious"-only findings fall back to the
 *  ratio (majority red, minority amber). PUA-only adverse findings are their
 *  own grayware band: flagged, but not confirmed malware. */
export function deriveBand(sources: VerdictSource[]): Band {
  const m = sources.length;
  if (m === 0) return 'grey';

  const adverse = sources.filter(isAdverse);
  const n = adverse.length;
  if (n === 0) return 'green';

  // Every adverse finding is merely PUA/grayware → its own band, visually
  // separate from red. "flagged" ≠ "malware".
  if (adverse.every((s) => s.pua === true)) return 'grayware';

  // Catalog / KEV membership = confirmed identity → red at any ratio.
  if (adverse.some((s) => s.kev === true || s.class === 'catalog')) return 'red';
  // A source asserting its OWN malicious verdict is respected → red.
  if (adverse.some((s) => s.verdict === 'malicious')) return 'red';
  // Otherwise only score/list "suspicious": the ratio decides.
  if (n * 2 >= m) return 'red';
  return 'amber';
}

/** Map the doctrine band to the shipped CSS ink class (design law: grey =
 *  unknown and is never green; grayware shares amber's orange ink). */
export function toneClass(band: Band): 'red' | 'orange' | 'green' | 'muted' {
  switch (band) {
    case 'red':
      return 'red';
    case 'amber':
    case 'grayware':
      return 'orange';
    case 'green':
      return 'green';
    default:
      return 'muted';
  }
}

/** The grayware label — exported so surfaces don't hard-code the wording. */
export function graywareLabel(): string {
  return GRAYWARE_LABEL;
}

/* ---------- recency / staleness (spec §3.1) ------------------------------ */

const ISO_DATE = /^\d{4}-\d{2}-\d{2}/;

/** True when a source's data is older than the stale window. Non-dates
 *  ("never", "—") are not stale — absence of a date is not staleness. */
export function isStale(recency: string | null | undefined, now: Date = new Date()): boolean {
  if (!recency || !ISO_DATE.test(recency)) return false;
  const t = Date.parse(recency);
  if (!Number.isFinite(t)) return false;
  return now.getTime() - t > STALE_DAYS * 864e5;
}

/* ---------- tally-as-coverage headline (spec §3.1) ----------------------- */

/** The on-screen gauge headline. Read as COVERAGE, never a threat score: a
 *  low/quiet tally reads "thin coverage; sources have no record — absence of
 *  data is not evidence of safety," and NEVER "probably fine." */
export function coverageHeadline(sources: VerdictSource[]): string {
  const { consulted: m, flagged: n } = consensus(sources);
  if (m === 0)
    return 'No reputation data available from consulted sources — absence of data is not evidence of safety.';
  if (n === 0) {
    const noRecord = sources.filter((s) => s.verdict === 'unknown').length;
    const base = `0 of ${m} consulted sources flagged this — no adverse findings. Not a clearance.`;
    if (noRecord > 0 || m < THIN_COVERAGE)
      return (
        `${base} Thin coverage — ${noRecord} of ${m} have no record on file; ` +
        'absence of data is not evidence of safety.'
      );
    return base;
  }
  return `${n} of ${m} consulted sources flagged this as adverse.`;
}

/** The escalation ASSESSMENT line (§4). Worded "public reputation sources"
 *  (this travels into a ticket), distinct from the on-screen gauge headline. */
export function assessmentLine(sources: VerdictSource[]): string {
  const { consulted: m, flagged: n } = consensus(sources);
  if (m === 0)
    return 'No reputation data available from consulted sources — not evidence of safety.';
  return `${n} of ${m} public reputation sources flagged this as adverse.`;
}

/* ---------- hash carve-out (spec §3.1) ----------------------------------- */

/** The identity-led headline for a hash: lead with the catalog fact, show the
 *  VirusTotal ratio as a SUB-fact — do NOT wrap a cross-source tally around a
 *  hash (a hash is identity, not a vote). */
export function hashHeadline(data: Pick<VerdictData, 'sources'>): string {
  const catalog = data.sources.find((s) => s.class === 'catalog' && s.verdict !== 'unknown');
  const vt = data.sources.find((s) => s.name === 'VirusTotal' && s.verdict !== 'unknown');
  if (catalog) {
    const sub = vt ? `  ${phraseFinding(vt)}.` : '';
    return `${phraseFinding(catalog)}.${sub}`;
  }
  if (vt) return `${phraseFinding(vt)}.`;
  return 'No catalog or engine has this sample on record — absence of data is not evidence of safety.';
}

/* ---------- dual-use / mitigating context (spec §4) ---------------------- */

/** A dual-use / mitigating qualifier (Tor exit, RIOT known-good) surfaced
 *  DIRECTLY beneath the tally, so "N of M flagged" is never misread as N
 *  independent confirmations. Null when none applies. */
export function dualUseNote(sources: VerdictSource[]): string | null {
  const factHas = (label: RegExp, value: RegExp) =>
    sources.some((s) => (s.facts ?? []).some(([k, v]) => label.test(k) && value.test(v)));
  if (factHas(/tor exit/i, /^yes$/i))
    return 'a source tags this a Tor exit node — elevated abuse reporting can reflect dual-use traffic, not one operator.';
  if (factHas(/riot|known-good/i, /^yes$/i))
    return 'GreyNoise tags this a known-good business service (RIOT) — likely dual-use infrastructure.';
  return null;
}

/* ---------- the plain-text escalation composer (spec §4) ----------------- */

/** Defang an indicator for a ticket: evil.com → evil[.]com, http → hxxp. */
export function defang(s: string): string {
  return String(s ?? '')
    .replace(/\./g, '[.]')
    .replace(/^http/i, 'hxxp');
}

function stampUTC(x: string | number | Date): string {
  const d = x ? new Date(x) : new Date();
  const iso = Number.isNaN(d.getTime()) ? new Date().toISOString() : d.toISOString();
  return iso.replace('T', ' ').slice(0, 16) + ' UTC';
}

function ledgerLine(s: VerdictSource, now: Date): string {
  const rec = s.recency
    ? ` (as of ${s.recency}${isStale(s.recency, now) ? ', stale' : ''})`
    : '';
  return `  • ${phraseFinding(s)} [${classTag(s)}]${rec}`;
}

function contextLine(c: ContextRow): string {
  return `  • ${c.name} — ${c.finding}`;
}

/** The §4 escalation block as an ordered array of lines. Rendered to text (the
 *  copy-out) from this SAME array, so what the analyst reads and what they paste
 *  can never drift. No recommendation, no branding — the artifact travels
 *  embedded in the analyst's own email, which supplies identity and next steps. */
export function escalationLines(data: VerdictData, now: Date = new Date()): string[] {
  const type = String(data.type ?? '').toUpperCase();
  const lines = [`INDICATOR: ${defang(data.indicator)}  (${type})`];

  if (data.identityLed) {
    lines.push(`ASSESSMENT: ${hashHeadline(data)}`);
  } else {
    lines.push(`ASSESSMENT: ${assessmentLine(data.sources)}`);
    const lead = leadFact(data.sources);
    if (lead && data.band !== 'green' && data.band !== 'grey')
      lines.push(`  Strongest signal: ${lead.phrasing}.`);
    if (data.band === 'grayware') lines.push(`  Note: ${GRAYWARE_LABEL}.`);
    const note = dualUseNote(data.sources);
    if (note) lines.push(`  Note: ${note}`);
  }

  lines.push(
    '',
    'EVIDENCE (third-party reputation data — attributed, not independently verified):',
  );
  if (data.sources.length) for (const s of data.sources) lines.push(ledgerLine(s, now));
  else lines.push('  • No consulted source returned a finding.');

  if (data.context.length || data.errors.length) {
    lines.push('', 'CONTEXT (not a verdict):');
    for (const c of data.context) lines.push(contextLine(c));
    if (data.errors.length)
      lines.push(
        `  • Not consulted: ${data.errors.map((e) => `${e.source} (${e.reason})`).join(', ')}`,
      );
  }

  lines.push(
    '',
    `CAVEAT: ${CAVEAT}`,
    `— Generated ${stampUTC(now)}. Sources queried ${stampUTC(data.checkedAt || now)}.`,
  );
  return lines;
}

/** The copy-to-clipboard / download escalation text (§4). The plain-text block
 *  always travels alongside the image (deliverability, copyability, a11y). */
export function composeEscalation(data: VerdictData, now: Date = new Date()): string {
  return escalationLines(data, now).join('\n');
}
