# SOCDesk — Verdict Language: the Consensus Tally

Governing policy for how SOCDesk presents an indicator assessment. Applies
uniformly to the **browser-extension popup**, the **website enrichment card**,
and the copy-paste **escalation card**. Authored 2026-08-10; revised to the
consensus-tally model (owner decision).

> **Revised 2026-08-18 — DE-WORDIFY.** The escalation card and its copy-out are
> now a **clean, factual artifact** the analyst annotates in the escalation
> email. The client-safe **CAVEAT** sentence and the prose **"Note:"** lines
> (dual-use, grayware) are **no longer rendered** on the card, the PNG, or the
> copy-text. Honesty is carried by **structure** — attribution + source-class
> tags + the coverage tally + honest empties + geo-as-context — **not by
> disclaimer prose.** The mitigating signals became **chips.** The analyst owns
> the nuance in the email. Everything else in this doc — the consensus tally, the
> per-source attribution model, no synthesized score, coverage-not-verdict —
> **still holds unchanged.** Only §4 (the escalation card) and the caveat
> guidance in §6 change; see the marked revisions below.

## 0. Governing principle

SOCDesk is a triage aid whose output is used to *escalate for verification* and
may reach a client. **SOCDesk does not pronounce a verdict — it counts what
independent public sources reported.** A tally is a fact; a verdict is an
opinion SOCDesk cannot stand behind. This is the VirusTotal model ("14 of 94
engines flagged this") applied *across services* — and the cross-service
consensus is SOCDesk's own contribution, because no single service provides it.

**SOCDesk never says "malicious," "suspicious," "safe," or "clean" in its own
voice** about a live indicator. It says how many sources flagged it, and shows
each source's attributed finding.

## 1. The consensus tally (the headline)

For the multi-source reputation types — **IPv4, domain, URL, MD5/SHA-1/SHA-256**
— the primary output is a ratio:

> **`N of M` public sources flagged `<indicator>` as adverse.**

Rendered as a VT-style gauge/number (`5 / 6`), colored, with the per-source
breakdown beneath. **No verdict word.**

**"Flagged as adverse"** for a source = that source's own verdict is
`malicious` OR `suspicious`. (Each source already yields a per-source verdict;
"flagged" is simply an adverse one.)

**The denominator `M` = consulted sources** — those that returned a response and
are neither context nor unconsulted:
- **ipinfo is context, never in the tally** (geo/ASN is not an adverse/benign
  signal). Shown separately, labeled "context — not a verdict."
- **No-key / not-consulted sources are excluded from `M`** and shown separately
  ("urlscan — not consulted"). Honest about coverage: "5 of 6 consulted."
- A source that returned **benign** (e.g. AbuseIPDB 0%) or **no data on record**
  IS consulted → counts in `M`, not in `N`. (Like VT engines that didn't
  detect.)

`N` = consulted sources whose verdict is malicious or suspicious.

## 2. Tone / color (from the ratio, not an opinion)

| Condition | Color | Headline text |
|---|---|---|
| `N = 0` | Green-neutral | "**0 of M** consulted sources flagged this — no adverse findings. **Not a clearance.**" |
| `0 < N < M/2` | Amber | "**N of M** consulted sources flagged this as adverse." |
| `N ≥ M/2` (majority) | Red | "**N of M** consulted sources flagged this as adverse." |
| `M = 0` (nothing consulted returned) | Grey | "No reputation data available from consulted sources. Not evidence of safety." |

The color reflects the ratio; it is not a hidden weighting. The gauge fill = `N
/ M`. An authoritative-catalog hit (MalwareBazaar known-sample) is a `malicious`
verdict, so it naturally raises `N` — no special-casing needed, but see §3 for
how it's phrased in the breakdown.

## 3. Per-source line language (the breakdown)

Each line **attributes**, states the **raw finding as fact**, and never promotes
a source's finding into SOCDesk's own verdict.

- `AbuseIPDB — reports 98% abuse confidence, 1,204 reports (last report Nd ago).`
- `VirusTotal — 14 / 94 engines flag this sample.`  (ratio matters; 14/94 ≠ 14/2)
- `GreyNoise — classifies as malicious; observed scanning; tagged Tor exit.`
- `ipinfo (context) — AS3209 (Vodafone), Germany. Not a verdict.`
- `MalwareBazaar — catalogs this hash as a known sample; family: Cobalt Strike.`
- `urlscan — existing scan (YYYY-MM-DD) rated malicious, 8/10.` / `not consulted.`

**Assert vs hedge:** authoritative catalog membership may be stated directly
*with attribution* (`CISA confirms…`, `MalwareBazaar catalogs…` — verbs:
confirms, catalogs, lists, records, tracks). Reputation scores/ratios must hedge
— keep the raw number as the fact, keep any verdict inside the source's
attribution (`reports`, `flags`, `classifies`, `rates`, `scores`). A
benign/RIOT/known-good finding is surfaced with equal prominence and never
buried (`GreyNoise — classifies as benign (RIOT: common business service)`).

## 4. Escalation card (ratio-led) — ⚠️ DE-WORDIFIED 2026-08-18

A **clean, factual artifact.** It reads as a tally + attributed evidence, never
an assertion, and it carries **no disclaimer prose.** The honesty lives in the
**structure** — every claim is named, class-tagged, and dated; the coverage
tally is a count, never a synthesized score; empties are stated plainly; geo is
labelled context; mitigating signals are **chips.** The analyst adds the nuance,
the recommendation, and any caveat in their own words in the escalation email
the card travels inside.

```
INDICATOR: <value>  (<type>)
ASSESSMENT: <N> of <M> public reputation sources flagged this as adverse.
  <optional one-line factual, attributed synthesis, e.g. "Strongest signal:
  MalwareBazaar catalogs 3 known samples (Cobalt Strike).">

EVIDENCE — each source named, class-tagged, and dated:
  • <Source>  [<class>]  — <raw finding as fact, with counts/ratios> · as of <DATE>
  • ...
  (class ∈ catalog/identity · authoritative · behavioral/observed ·
   reputation-score · list-membership · unclassified)

SIGNALS: <chip>  <chip>            (e.g. Tor exit · dual-use · hosting/datacenter)

CONTEXT (not a verdict):
  • Geolocation — <city, country · ASN (org)>
  • Registration — Registered <DATE> · <registrar>            (RDAP, context)
  • Not consulted: <sources w/o data or key>                  (honest coverage)

— Generated <timestamp / tz>. Sources queried <time>.
```

**Removed in the de-wordify (do not reintroduce):** the trailing **CAVEAT**
sentence ("Reflects third-party reputation … not independently confirmed") and
the inline prose **"Note:"** lines (dual-use, grayware). Both were disclaimer
prose; the same honesty is now carried structurally by the class tags, the "as
of DATE" recency, the honest "not consulted" line, and the SIGNALS chips. This
applies identically to the card on screen, the **"Copy card"** PNG, and the
**"Copy text"** block.

**No recommendation in the copy-out card.** What to *do* about an indicator
(escalate / block / monitor) is the analyst's judgment and belongs in *their*
words in the ticket — SOCDesk must not put a recommended action into an artifact
that travels into a ticket under the analyst's name. The copy-out block reports
the tally, attributed evidence, and context only — no recommendation and, since
the de-wordify, no caveat sentence. Optional "things to check" guidance MAY
appear elsewhere *on the page* (for the analyst's eyes, never inside the copy-out
block). The copy buttons are labelled by their **target** — **`Copy card`** (the
PNG) and **`Copy text`** — never by a verdict or an action.

**The copied artifact carries no SOCDesk branding.** The name and mark appear
only on-screen; both copy-outs — the plain-text block and the image "Copy card" —
carry a neutral timestamp provenance only (`— Generated <timestamp>. Sources
queried <time>.`). The artifact always travels embedded in the analyst's own MSSP
email, which supplies producer identity, case context, and next steps. (If it were
ever forwarded standalone it would be unattributed — acceptable only because it is
never sent bare.) **Source names are retained** — attribution is the model: each
source is named with a verify link. Resolve any commercial-ToS / redistribution
constraints per source (see the source-license review); prefer name-plus-link over
reproducing large amounts of a source's proprietary data. **Dual-use / mitigating
signals** (e.g. a Tor exit node) render as **chips**, not prose, kept prominent so
"N of M flagged" is never misread as N independent confirmations. **Geolocation
stays prominent** in the image artifact (still labelled *context — not a verdict*);
case-specific interpretation is the analyst's, added in the email. Client-facing
wording glosses analyst jargon (spell out the ASN's org; expand IOC / C2). The
plain-text block always travels alongside the image (deliverability, copyability,
accessibility).

**Worked example — `185.220.101.42`:**
`ASSESSMENT: 5 of 6 public reputation sources flagged 185.220.101.42 as adverse.
Strongest signal: MalwareBazaar catalogs 3 known samples (Cobalt Strike).` with a
**`Tor exit`** chip under the tally and the geo/ASN as labelled context. No
SOCDesk-voice verdict, no prescribed action, and no caveat sentence — a count +
attributed, class-tagged, dated evidence + the dual-use chip. Reads urgent,
survives a client reading it, and leaves the decision — and the nuance — to the
analyst in the email.

## 5. CVE language (unchanged — authoritative, not a tally)

CVEs are a single authoritative system of record, not a multi-source vote — the
consensus model does not apply. Keep:

| State | Rendered | Basis |
|---|---|---|
| KEV-listed | `EXPLOITED IN THE WILD — CISA-confirmed (KEV, added YYYY-MM-DD)` | Fact, attributed. |
| High EPSS | `HIGH EXPLOITATION PROBABILITY — EPSS 0.94 (94th pct)` | Prediction — never "exploited". |
| High CVSS | `CVSS 9.8 (Critical)` | Published score. |
| Neither | `TRACKED — no confirmed exploitation on file` | Neutral; not a safety claim. |

## 6. Do / Don't

**Don't:** any SOCDesk-voice verdict word ("malicious/suspicious/safe/clean") ·
"confirmed/definitely/guaranteed/known bad" · "this X **is** [malware/C2]" ·
"blocked/quarantined" · "no threat/you're good" · promoting a source's verdict
into SOCDesk's voice.

**Do:** lead with the tally ("N of M sources flagged…") · attribute every source
finding · "CISA confirms… / MalwareBazaar catalogs…" (authorities) · "no adverse
findings — **not a clearance**" · convey "third-party / may be stale / not
independently verified" **structurally** — via the source-class tags and the "as
of DATE" recency, **not** a caveat sentence on the card (de-wordify, §4) · leave
"recommend verifying / escalating / monitoring" to the analyst's own words in the
escalation email, never inside the copy-out artifact.

**Litmus test:** *Could a client hold us to this as a statement of fact?* The
tally always survives it (it's a count); anything else must be attributed.

## 7. Implementation surface & data contract

**`lib/enrich.mjs`** — replace `overall()` with `consensus(rows)` returning the
tally. The `/api/enrich` response gains:
```
{ ...,
  consulted: <M int>,      // non-context sources that returned a response
  flagged:   <N int>,      // consulted sources with verdict malicious|suspicious
  tone: "red"|"amber"|"green"|"grey",   // from §2
  sources: [...], errors: [...], partial }
```
Keep per-source `verdict` (drives "flagged"); drop the top-level single-word
`verdict` (replaced by the tally). Context rows (`kind:"context"`) and `errors`
are excluded from `consulted`/`flagged`.

**Web app + extension** (`shared/verdict-cards/` — `EscalationCard`, `heroes`,
`CompareIp`, `copy`; `shared/card/` — `drawVerdict`, `travel`) — render the
`N / M` headline (§2), the attributed, class-tagged breakdown (§3), and the
de-wordified escalation card (§4). The `web/` React app and the `extension/`
popup import the **same** shared components, so the card is byte-identical across
both. (The legacy `site/js` renderer is superseded.)

All surfaces render from the same contract; the `N / M` headline is identical
everywhere.
