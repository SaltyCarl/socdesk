// types.ts — the shared verdict data model + doctrine constants.
//
// One typed `VerdictData` object drives every surface: the analyst console, the
// browser-extension popup, the client escalation card, and the future canvas
// PNG. SOCDesk emits NO verdict word of its own for a live indicator
// (docs/VERDICT-LANGUAGE.md) — it counts what independent public sources
// reported and attributes each finding. These types encode that contract plus
// the v2 doctrine refinements from the design spec §3.1.
//
// Pure declarations + frozen lookup tables. No behaviour, no I/O.

/** The indicator families SOCDesk recognises. */
export type IndicatorType =
  | 'ipv4'
  | 'ipv6'
  | 'domain'
  | 'url'
  | 'md5'
  | 'sha1'
  | 'sha256'
  | 'cve'
  | 'email';

/** Each source yields its OWN per-source verdict; SOCDesk never overrides it.
 *  "flagged" (adverse) = the verdict is `malicious` OR `suspicious`. */
export type SourceVerdict = 'malicious' | 'suspicious' | 'benign' | 'unknown';

/** Source-class tags (spec §3.1). Facts ABOUT the source — litmus-safe, they
 *  expose correlation without SOCDesk weighting one source over another:
 *   - catalog       a system of record that catalogs known samples/entities
 *   - behavioral    a verdict from observed activity (scanning, page render)
 *   - score         a computed reputation number / engine ratio
 *   - list          membership on a list (blocklist, RIOT known-good, Tor)
 *   - unclassified  an UNMAPPED source — never impersonates a scored source:
 *                   no class chip, a neutral verb, lowest authority, and it
 *                   never forces a severity band. The honest fallback. */
export type SourceClass = 'catalog' | 'authoritative' | 'behavioral' | 'score' | 'list' | 'unclassified';

/** The doctrine band (spec §3.1). Superset of the contract tone: adds the
 *  distinct `grayware` state so "flagged" is never conflated with "malware". */
export type Band = 'red' | 'amber' | 'grayware' | 'green' | 'grey';

/** The ratio tone from the contract (docs/VERDICT-LANGUAGE.md §2). Kept for the
 *  gauge fill and back-compat; the doctrine `band` is what surfaces label by. */
export type Tone = 'red' | 'amber' | 'green' | 'grey';

/** An attributed [label, value] row, rendered verbatim — the source speaking. */
export type FactRow = readonly [label: string, value: string];

/** A consulted, class-tagged reputation source. */
export interface VerdictSource {
  /** Source name, e.g. "MalwareBazaar". Always the sentence subject (spec §3.1). */
  name: string;
  /** The source's own per-source verdict. */
  verdict: SourceVerdict;
  /** Source-class tag (spec §3.1). */
  class: SourceClass;
  /** The source's one-line finding, stated as fact (server `headline`). */
  finding: string;
  /** ISO date (or human token) of the source's data; null when none is known. */
  recency: string | null;
  /** Where the recipient verifies it, at source. Always present when known. */
  url: string;
  /** The source's attributed [label, value] rows, retained for the card. */
  facts?: FactRow[];
  /** PUA/grayware flag — the finding is "flagged" but not confirmed malware. */
  pua?: boolean;
  /** The source OBSERVED the indicator (returned real data) but assigned no
   *  malicious/benign verdict — e.g. GreyNoise seeing a known opportunistic
   *  scanner. Distinguishes "seen, no verdict" from a genuine "no record"
   *  coverage gap, so an observation never inflates the thin-coverage read. */
  observed?: boolean;
  /** KEV / authoritative-catalog membership — top of the confidence ladder. */
  kev?: boolean;
  /** A same-origin screenshot preview (urlscan), when present. */
  screenshot?: string;
}

/** A context row (e.g. ipinfo geo/ASN). Carries no adverse/benign signal and is
 *  NEVER in the tally — shown separately, labelled "context — not a verdict". */
export interface ContextRow {
  name: string;
  finding: string;
  facts?: FactRow[];
  url: string;
}

/** A source that was applicable but not consulted (no key, or it errored).
 *  Named, never hidden — silence about an unconsulted source lies by omission. */
export interface NotConsulted {
  source: string;
  reason: string;
}

/** The one shared object all surfaces + the canvas PNG consume. */
export interface VerdictData {
  indicator: string;
  type: IndicatorType;
  /** M — scored (non-context) sources that returned a response. */
  consulted: number;
  /** N — of those, the ones whose verdict is malicious or suspicious. */
  flagged: number;
  /** The contract ratio tone (gauge fill / back-compat). */
  tone: Tone;
  /** The doctrine band (spec §3.1) — what surfaces color + label by. */
  band: Band;
  /** Scored, class-tagged sources (the tally + the attributed ledger). */
  sources: VerdictSource[];
  /** Context rows — never in the tally. */
  context: ContextRow[];
  /** Applicable-but-not-consulted sources. */
  errors: NotConsulted[];
  /** True when one or more sources were unavailable. */
  partial: boolean;
  /** ISO timestamp the sources were queried. */
  checkedAt: string;
  /** Hash carve-out (spec §3.1): identity, not a vote — do NOT render a tally. */
  identityLed: boolean;
}

/* ---------- doctrine constants ------------------------------------------- */

/** The client-safe caveat (docs/VERDICT-LANGUAGE.md §4). Travels on every
 *  copy-out; it is what keeps the artifact honest in front of a client. */
export const CAVEAT =
  'Reflects third-party reputation gathered at the time shown; it may be ' +
  'incomplete or out of date and has not been independently confirmed.';

/** Grayware band label (spec §3.1) — "flagged" is not "malware". */
export const GRAYWARE_LABEL = 'grayware — flagged, not confirmed malware';

/** Source-class by source name. The server does not emit a class; it is a fact
 *  about the source, assigned here. Every source SOCDesk consults is mapped, so
 *  nothing hits the honest `unclassified` fallback (doctrine.sourceClassFor) in
 *  practice — an unmapped source there would be a genuinely new feed. */
export const CLASS_BY_SOURCE: Readonly<Record<string, SourceClass>> = {
  MalwareBazaar: 'catalog',
  ThreatFox: 'catalog',
  'CISA KEV': 'catalog',
  NVD: 'authoritative',
  GreyNoise: 'behavioral',
  urlscan: 'behavioral',
  'Hybrid Analysis': 'behavioral',
  AbuseIPDB: 'score',
  VirusTotal: 'score',
  Spamhaus: 'list',
};

/** The confidence ladder (spec §3.1), published + deterministic. Lower rank =
 *  higher authority: KEV > hash-catalog > behavioral-observed > reputation-score
 *  > list-membership. `kev` on a source jumps it to the top. */
export const CLASS_PRECEDENCE: Readonly<Record<SourceClass, number>> = {
  catalog: 1,
  authoritative: 1,
  behavioral: 2,
  score: 3,
  list: 4,
  unclassified: 5,
};
export const KEV_PRECEDENCE = 0;

/** Verb per class for source-subject-first phrasing (spec §3.1). The source is
 *  always the subject: "MalwareBazaar catalogs…", never "…— MalwareBazaar". */
export const VERB_BY_CLASS: Readonly<Record<SourceClass, string>> = {
  catalog: 'catalogs',
  authoritative: 'reports',
  behavioral: 'classifies',
  score: 'reports',
  list: 'lists',
  unclassified: 'reports',
};

/** Human class tag for the escalation ledger. */
export const CLASS_TAG: Readonly<Record<SourceClass, string>> = {
  catalog: 'catalog/identity',
  authoritative: 'authoritative',
  behavioral: 'behavioral/observed',
  score: 'reputation-score',
  list: 'list-membership',
  unclassified: 'unclassified',
};

/** Indicator types that are IDENTITY, not a cross-source vote (hash carve-out,
 *  spec §3.1). CVE is authoritative single-source (§5) and also excluded from
 *  the tally, but CVEs are not enriched through this client. */
export const IDENTITY_TYPES: ReadonlySet<IndicatorType> = new Set<IndicatorType>([
  'md5',
  'sha1',
  'sha256',
]);

/** Reputation types this client enriches via /api/enrich. */
export const ENRICHABLE_TYPES: ReadonlySet<IndicatorType> = new Set<IndicatorType>([
  'ipv4',
  'ipv6',
  'domain',
  'url',
  'md5',
  'sha1',
  'sha256',
]);

/** Coverage below this many consulted sources reads as "thin coverage". */
export const THIN_COVERAGE = 3;

/** A source's data older than this many days is flagged stale (spec §3.1). */
export const STALE_DAYS = 90;
