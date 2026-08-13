// map.ts — map an /api/enrich response into the shared VerdictData.
//
// The server (lib/enrich.mjs) fans one indicator across every source and returns
// per-source rows with their own verdict, headline, facts, and verify link. It
// does NOT tag source-class, pick a recency, flag PUA, or compute the doctrine
// band — those are SOCDesk's own contribution, applied deterministically here so
// the analyst console, the extension, and the canvas PNG all read identically.
//
// Pure: response in, VerdictData out. No I/O (the fetch lives in client.ts).

import type {
  ContextRow,
  FactRow,
  IndicatorType,
  NotConsulted,
  SourceVerdict,
  VerdictData,
  VerdictSource,
} from './types';
import { consensus, deriveBand, detectPua, isIdentityType, sourceClassFor } from './doctrine';

/** The raw per-source row as the server emits it. */
export interface RawSource {
  name: string;
  verdict?: string;
  kind?: string;
  headline?: string;
  facts?: FactRow[];
  url?: string;
  screenshot?: string;
  tags?: string[];
}

/** The raw /api/enrich response body. */
export interface EnrichResponse {
  indicator: string;
  type: string;
  checked_at?: string;
  sources: RawSource[];
  errors?: NotConsulted[];
  partial?: boolean;
}

const VERDICTS: ReadonlySet<string> = new Set(['malicious', 'suspicious', 'benign', 'unknown']);

function normalizeVerdict(v: unknown): SourceVerdict {
  const s = String(v ?? 'unknown');
  return (VERDICTS.has(s) ? s : 'unknown') as SourceVerdict;
}

const RECENCY_KEY = /last|seen|scanned|reported|analys|first/i;
const ISO_DATE = /^\d{4}-\d{2}-\d{2}/;

/** Best-effort recency: the most useful date-like fact the source returned.
 *  "never" / "—" carry no date and yield null (absence, not staleness). */
function pickRecency(row: RawSource): string | null {
  const dated = (row.facts ?? []).filter(([k, v]) => RECENCY_KEY.test(k) && ISO_DATE.test(v));
  // Prefer a "last …" date over a "first …" one when both exist.
  const last = dated.find(([k]) => /last|seen|scanned|reported|analys/i.test(k));
  return (last ?? dated[0])?.[1] ?? null;
}

/** PUA/grayware across the row's free text — headline, all fact values, tags. */
function rowIsPua(row: RawSource): boolean {
  const hay = [
    row.headline ?? '',
    ...(row.facts ?? []).map(([, v]) => v),
    ...(row.tags ?? []),
  ].join(' ');
  return detectPua(hay);
}

function mapSource(row: RawSource): VerdictSource {
  return {
    name: row.name,
    verdict: normalizeVerdict(row.verdict),
    class: sourceClassFor(row.name),
    finding: row.headline ?? '',
    recency: pickRecency(row),
    url: row.url ?? '',
    facts: row.facts,
    pua: rowIsPua(row),
    screenshot: row.screenshot,
  };
}

function mapContext(row: RawSource): ContextRow {
  return {
    name: row.name,
    finding: row.headline ?? '',
    facts: row.facts,
    url: row.url ?? '',
  };
}

/** Map a validated /api/enrich body into the shared VerdictData. The tally,
 *  band, and identity flag are all recomputed here so the doctrine layer is the
 *  single source of truth (the server's own tally is ignored on purpose). */
export function mapResponse(body: EnrichResponse): VerdictData {
  const rows = Array.isArray(body.sources) ? body.sources : [];
  const type = String(body.type ?? '') as IndicatorType;

  const sources = rows.filter((r) => r.kind !== 'context').map(mapSource);
  const context = rows.filter((r) => r.kind === 'context').map(mapContext);
  const errors = Array.isArray(body.errors) ? body.errors : [];

  const { consulted, flagged, tone } = consensus(sources);

  return {
    indicator: String(body.indicator ?? ''),
    type,
    consulted,
    flagged,
    tone,
    band: deriveBand(sources),
    sources,
    context,
    errors,
    partial: body.partial ?? errors.length > 0,
    checkedAt: String(body.checked_at ?? ''),
    identityLed: isIdentityType(type),
  };
}
