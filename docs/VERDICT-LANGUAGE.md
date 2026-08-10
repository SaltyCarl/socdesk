# SOCDesk — Verdict-Language Taxonomy & Escalation-Writing Spec

Governing policy for how SOCDesk phrases verdicts and escalations. Applies
uniformly to the **browser-extension popup**, the **website enrichment card**,
and the copy-paste **escalation card**. Authored 2026-08-10 (SOC-analyst /
communications review).

## 0. Governing principle

SOCDesk is a triage aid whose output is used to *escalate for verification* and
may reach a client. It must never state as its own fact anything it cannot
independently stand behind.

1. **SOCDesk owns exactly one assessment: the overall verdict** — a *graded
   analyst judgment*, phrased defensibly, never a flat declaration.
2. **Everything else is someone else's observation** — per-source findings are
   attributed and stated as what the source *reports/observes/classifies*.
   SOCDesk never launders a vendor's opinion into its own assertion.
3. **Defensible ≠ mushy** — a genuine high-confidence threat still reads urgent.
   Urgency comes from the confidence grade, color, and recommended action, not
   from a stronger, unearned verb.

**"Suspicious" is the strongest word SOCDesk uses about a live indicator.** It
never says "malicious," "safe," "clean," or "confirmed malicious" in its own
voice. Confidence grading, not a bigger word, carries the weight.

## 1. Verdict taxonomy

Badge = fixed **finding word** + **confidence pill**. The eye reads one token;
the pill and assessment line carry the nuance.

| Tier | Badge | Color | On-screen assessment line |
|---|---|---|---|
| 1 | **SUSPICIOUS · HIGH** | Red | High-confidence suspicious — multiple independent sources report adverse signal. Recommend verifying and escalating. |
| 2 | **SUSPICIOUS · MODERATE** | Amber | Suspicious — one or more sources report adverse signal; picture is mixed. Recommend verifying before action. |
| 3 | **INCONCLUSIVE** | Yellow-grey | Weak or conflicting signal — not enough to call. Recommend manual review / additional enrichment. |
| 4 | **NO ADVERSE FINDINGS** | Green-neutral | No consulted source reported adverse signal. This is **not** a clearance — absence of findings, not proof of safety. |
| 5 | **NO DATA** | Grey | No reputation data available from consulted sources. Not evidence of safety; enrich further or verify manually. |

Popup abbreviations (space-constrained): Tier 4 → `NO FLAGS`, Tier 5 →
`UNKNOWN`; full line on tap/hover. Finding word + pill never change across
surfaces.

**Confidence rubric** (what the overall-verdict computation grades against):
- **HIGH** — ≥2 independent credible adverse sources AND ≥1 *strong* signal
  (AbuseIPDB high confidence w/ meaningful volume, GreyNoise `malicious`, or a
  MalwareBazaar known-sample hit) AND no strong contradicting benign signal.
- **MODERATE** — a single credible adverse source, several weak signals, or an
  adverse signal partly offset by mitigating context.
- **LOW / INCONCLUSIVE** — marginal/aging signal, low counts, borderline ratios,
  or adverse signal that is plausibly benign dual-use.
- A GreyNoise **RIOT / known-good / benign** classification caps confidence and
  is surfaced explicitly ("but GreyNoise classifies this as common business
  infrastructure — verify before blocking").

## 2. Assert-vs-hedge rule

**Authoritative catalog membership** (verifiable fact about a system of record)
MAY be stated directly, *always attributed*:

| Source | Wording pattern |
|---|---|
| CISA KEV | "**CISA confirms** CVE-… is exploited in the wild (KEV, added YYYY-MM-DD)." |
| MalwareBazaar | "**MalwareBazaar catalogs** this hash as a known malware sample (family: …, first seen …)." |

Licensed verbs for authorities: confirms, catalogs, lists, records, tracks.

**Reputation scoring / detection ratios** MUST hedge — keep the raw number as
the fact, keep the verdict inside the source's attribution:

| Source | Wording pattern | Never |
|---|---|---|
| AbuseIPDB | "AbuseIPDB **reports** 98% abuse confidence across 1,204 reports." | "This IP is malicious." |
| VirusTotal | "**14 of 94** VirusTotal engines **flag** this sample." | "This file is malware." |
| GreyNoise | "GreyNoise **classifies** this IP as malicious (opportunistic scanning)." | "This IP is a scanner." |
| urlscan | "urlscan's existing scan **rated** this URL malicious (8/10)." | "This URL is malicious." |

Hedge verbs: reports, observes, classifies, flags, rates, scores, associates.
Pattern: `<Source> <hedge verb> <raw finding as fact>`.

## 3. Per-source line language

Each line attributes, states the raw finding as fact, and does not promote it to
a SOCDesk verdict. **ipinfo is context, never a verdict** (never colors the
badge). Benign/RIOT findings are surfaced with equal prominence and cap
confidence — never buried.

- `AbuseIPDB — reports 98% abuse confidence, 1,204 reports (last report Nd ago).`
- `VirusTotal — 14 / 94 engines flag this sample.`  (ratio matters; 14/94 ≠ 14/2)
- `GreyNoise — classifies as malicious; observed scanning; tagged Tor exit.`
- `ipinfo (context) — AS3209 (Vodafone), Germany. Geo/ASN only, not a verdict.`
- `MalwareBazaar — catalogs this hash as known; family: Cobalt Strike; 3 samples.`
- `urlscan — existing scan (YYYY-MM-DD) rated malicious, 8/10.` or `not consulted.`

## 4. Escalation-card template

Reads as an analyst's assessment with evidence, sources, and a recommended
action — never an assertion of fact.

```
INDICATOR: <value>  (<type>)
ASSESSMENT: <finding word> — <confidence> confidence.
  <1–2 sentence defensible synthesis in SOCDesk's own voice: what the weight
  of evidence is consistent with, framed as pending verification.>

EVIDENCE (third-party reputation data — attributed, not independently verified):
  • <Source> — <raw finding as fact, with counts/ratios/dates>
  • ...

CONTEXT (not a verdict):
  • ipinfo — <ASN / geo>
  • <mitigating/dual-use note, e.g. Tor exit, RIOT known-good>

RECOMMENDED ACTION: <Verify / Escalate / Monitor> — <specific next step>.

SOURCES & CAVEAT: <list w/ query time>. Reputation data can be stale or wrong
  and has not been independently verified; verify before any blocking or
  client-facing action.
— Generated by SOCDesk <timestamp / tz>
```

**Worked example — `185.220.101.42`:** ASSESSMENT reads "SUSPICIOUS — HIGH
confidence. The weight of third-party evidence is consistent with hostile /
abuse-associated infrastructure: four independent sources report adverse
signal… Note this is also a tagged Tor exit node, which attracts elevated abuse
reporting and can reflect dual-use traffic — confirm relevance before acting."
Never "this IP is malicious." It would survive a client reading it and still
reads urgent. (Full example in the source review.)

## 5. CVE language

KEV = observed fact (assert, CISA-attributed). EPSS/CVSS = model/score (hedge).

| Current | Rendered wording | Basis |
|---|---|---|
| ACTIVELY EXPLOITED | `EXPLOITED IN THE WILD — CISA-confirmed (KEV, added YYYY-MM-DD)` | Fact, attributed. |
| LIKELY EXPLOITED | `HIGH EXPLOITATION PROBABILITY — EPSS 0.94 (94th pct)` | EPSS is a prediction — drop "exploited". |
| CRITICAL SEVERITY | `CVSS 9.8 (Critical)` | Published score. |
| TRACKED | `TRACKED — no confirmed exploitation on file` | Neutral; not a safety claim. |

Never let an EPSS-high CVE render as confirmed in-the-wild exploitation.

## 6. Do / Don't

**Don't:** "malicious/safe/clean/benign" as SOCDesk's own flat verdict ·
"confirmed malicious/definitely/guaranteed/100%/known bad" · "this X **is**
[malware/C2/an attacker]" · "blocked/quarantined" (implies an action not taken)
· "no threat/you're good" (reads as clearance) · promoting a source's verdict
into SOCDesk's voice.

**Do:** "high-confidence suspicious" · "multiple independent sources report /
flag…" · "consistent with / associated with / reported / observed / classified
as…" · "CISA confirms… / MalwareBazaar catalogs…" (attributed) · "no adverse
findings — **not a clearance**" · "pending verification / based on third-party
reputation data / may be stale / not independently verified" · "recommend
verifying / escalating / monitoring."

**Litmus test for any string SOCDesk emits:** *Could a client read this and hold
us to it as a statement of fact?* If yes and it isn't authoritative-catalog-
attributed, hedge it and name the source.

## Implementation surface

- `lib/enrich.mjs` — per-source `headline`/verdict wording; the `overall()` grade.
- `site/js/enrich-client.js`, `site/js/verdict.js`, `site/js/evidence.js` — badge
  words, confidence pill, assessment line, escalation-card text.
- `extension/popup.js` — the same taxonomy (WORD/TONE maps) + the escalation card.
- Keep all three surfaces in lockstep — the finding word + pill are identical
  everywhere.
