// index.ts — public surface of the verdict library.
//
// One shared VerdictData object + the doctrine functions that derive its wording
// and band + the enrichment client that produces it. Pure logic, no UI: every
// surface (console, extension, escalation card, canvas PNG) imports from here.

export type {
  Band,
  ContextRow,
  FactRow,
  IndicatorType,
  NotConsulted,
  SourceClass,
  SourceVerdict,
  Tone,
  VerdictData,
  VerdictSource,
} from './types';
export {
  CAVEAT,
  CLASS_BY_SOURCE,
  CLASS_PRECEDENCE,
  CLASS_TAG,
  ENRICHABLE_TYPES,
  GRAYWARE_LABEL,
  IDENTITY_TYPES,
  KEV_PRECEDENCE,
  STALE_DAYS,
  THIN_COVERAGE,
  VERB_BY_CLASS,
} from './types';

export {
  assessmentLine,
  classTag,
  composeEscalation,
  consensus,
  coverageHeadline,
  defang,
  deriveBand,
  detectPua,
  dualUseNote,
  escalationLines,
  graywareLabel,
  hashHeadline,
  isAdverse,
  isIdentityType,
  isStale,
  leadFact,
  phraseFinding,
  predicate,
  sourceClassFor,
  sourceRank,
  toneClass,
} from './doctrine';

export type { EnrichResponse, RawSource } from './map';
export { mapResponse } from './map';

export type { EnrichOutcome, FetchEnrichOptions, FetchLike } from './client';
export { fetchEnrich, FETCH_TIMEOUT_MS, isEnrichable } from './client';
