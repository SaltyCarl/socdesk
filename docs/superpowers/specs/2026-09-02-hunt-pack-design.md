# Hunt Pack — framework-tied KQL hunting layer for Adversaries profiles

**Date:** 2026-09-02 · **Status:** REVISED per adversarial spec review (2 blockers +
6 importants folded, all findings externally verified) — awaiting owner review
**Origin:** Adversaries critique Tier-3 §9 ("the panel Defender TA charges for") +
owner direction 2026-09-02: existing-rule efficacy gauged against the public
framework corpus; deficiencies made up by hand-authoring **and testing** —
a rebuild tied to frameworks/best practices, not a port of the legacy library.

## 0. Goal

Every Adversaries profile gets a **Hunt pack** panel: kill-chain-ordered,
copyable KQL hunting queries keyed to the entity's ATT&CK techniques — each
row carrying provenance (source, author, license, rule id, dialect,
last-modified) and the honest framing that it is a starting query to validate
against the customer's schema, never a detection guarantee.

## 1. Load-bearing boundaries

1. **Clean-room public corpus.** The legacy private KQL library (CARL) is a
   *benchmark input only* — used privately to gauge coverage. Published rules
   are (a) framework-sourced with license + attribution, or (b) freshly
   hand-authored for SOCDesk against public schemas — informed by the gap
   analysis, never copied. H3 rationales cite public references only
   (review rule — the one soft leak channel).
2. **Deterministic, never generated.** No LLM-authored queries. Framework
   rules arrive verbatim (Sentinel repo) or via deterministic toolchain
   conversion (SigmaHQ → pySigma kusto backend). A rule failing conversion or
   validation is DROPPED with a pipeline health warning — never hand-patched.
3. **Licensing gate (verified against license texts).**
   - Azure/Azure-Sentinel: **MIT** — hosted with attribution.
   - SigmaHQ: **DRL 1.1** — conversion + hosting of output IS permitted, but
     requires **(1) author attribution, (2) link to the rule, (3) DRL notice/
     link**. The rule model carries `source.author`; the stamp renders it
     ("SigmaHQ · frack113 · DRL 1.1"); the panel links the DRL text once.
   - Elastic detection-rules: link-out only — a POLICY choice (ELv2 would
     technically permit more; we keep the stricter posture).
   - pysigma-backend-kusto is LGPL-3.0 — fine as a pipeline-only dep;
     converted output is not LGPL-encumbered.
4. **⚠ TWO KQL DIALECTS, first-class.** Advanced-hunting (Defender XDR:
   Device* tables, `Timestamp`) and Log Analytics (Sentinel workspaces:
   `TimeGenerated`; different column sets) are NOT interchangeable — a
   `Timestamp` query errors in a Sentinel LA workspace. Every rule carries
   `dialect: "advanced_hunting" | "log_analytics"`; the panel renders it and
   the swap caveat ("Defender advanced hunting; in a Sentinel workspace
   replace Timestamp → TimeGenerated and re-validate"). H2's converter runs
   the **microsoft_xdr pipeline** (production-grade; the Sentinel-ASIM and
   azure-monitor pipelines are beta/alpha — not used in v1), so H2 output is
   advanced_hunting dialect by construction. Kustainer DDL is maintained
   PER DIALECT.
5. **Accuracy-first QA (two-tier — the repo's cron-never-red doctrine):**
   - **Hard gate in ci.yml**: a job conditional on `data/hunt/**` /
     hunt-collector changes boots Kustainer (verified: image
     `mcr.microsoft.com/azuredataexplorer/kustainer-linux:latest`,
     `ACCEPT_EULA=Y`, ~4GB, port 8080, no HEALTHCHECK → explicit readiness
     poll; automated testing is the documented permitted use), creates the
     per-dialect table schemas, runs every hosted rule, fails the PR on any
     error. Gates H3 authored rules and allowlist additions.
   - **Collect-time**: conversion/validation failures drop the rule into
     `pipeline_warnings` (health.json) — the twice-hourly cron never goes red
     on an upstream problem (run_pipeline doctrine).
6. **Kustainer catalog = curation criterion.** The emulator lacks
   advanced-hunting-only functions (FileProfile(), DeviceFromIP(), ASIM
   parsers). The maintained table/function catalog is an explicit ALLOWLIST
   criterion: curation only admits rules whose tables are in the catalog and
   that avoid emulator-absent functions. A rule rejected for catalog reasons
   is a curation decision, never a silent validation drop.
7. KQL only in v1 (owner decision); Sigma originals linked for provenance.
8. Free-tier; committed-dataset model; reserved colors untouched.

## 2. Phases

### H0 — Efficacy gauge (private analysis; gates H3's scope)
Inventory the legacy library (measured: 6,431 lines; identity/cloud-heavy —
SigninLogs 126 · OfficeActivity 66 · AuditLogs 60 vs DeviceProcessEvents 13 ·
Registry 3) against the technique set that matters here (tracked actors'
fingerprints + seed tooling; endpoint-heavy). Per technique: Sentinel-repo
coverage? SigmaHQ coverage? legacy-only ideas worth FRESH authoring?
Corpus density is verified real (Sentinel `relevantTechniques` hits: T1486=49,
T1490=14, T1059.001=16, T1078=538; Sigma tags: t1059.001=238, t1486=17).
**Output:** full gap report stays PRIVATE (kql-sentinel-lab repo); only a
sanitized framework-coverage matrix (technique → sentinel/sigma/none —
derivable entirely from public sources) is committed here. Owner reviews
before H3 authoring begins.

### H1 — Sentinel-repo collector (curated, SHA-pinned allowlist)
`data/hunt/sentinel_allowlist.json`: entries `{path, sha, id, techniques[],
dialect}` — fetched as `raw.githubusercontent.com/Azure/Azure-Sentinel/
<sha>/<path>` (immutable, reproducible, audit-friendly; collector warns on
drift). Curation targets `Solutions/**/Hunting Queries/` (the modern YAML
corpus — 3,368 files with relevantTechniques; the top-level tree is
mixed-vintage legacy). Parser: full-YAML document load (`query:` key —
NOT front-matter), tolerant of `.yaml`/`.yml`, spaces in names
(URL-encoded), missing `relevantTechniques`, non-ATT&CK `tactics` values —
**the allowlist's `techniques[]` is the authoritative key**, verified at
curation time. PyYAML pinned explicitly. Cache-days gated.

### H2 — Sigma conversion lane
`data/hunt/sigma_allowlist.json` (ids/paths/SHAs into SigmaHQ). Deps:
`pysigma==1.0.*`-compatible + `pysigma-backend-kusto==1.0.*` (Python 3.12 OK).
Convert via microsoft_xdr pipeline at collect time → advanced_hunting
dialect; failures drop + warn. Fills techniques H1 lacks. `source.author`
extracted from the Sigma rule (DRL clause 1).

### H3 — Hand-authored lane (gap-driven)
`data/hunt/authored/*.yaml`: SOCDesk-original rules — KQL + metadata
(technique ids, tables, dialect, rationale w/ public citations, author,
`tested` date). Written ONLY for gaps the H0 report identifies; must pass
the ci.yml Kustainer gate before merge.

### H4 — The panel
Committed `hunt_packs.json` (§3). Rows grouped by tactic (reusing the shipped
technique_tactics order), each: title · copyable KQL block · technique chips ·
dialect tag · provenance stamp ("Microsoft Sentinel community · MIT ·
modified 2026-06" / "SigmaHQ · <author> · DRL 1.1" / "SOCDesk · tested
2026-09-02") · source link. **Caps (verified worst case: Kimsuky 130
techniques):** ≤3 rules per technique (priority: socdesk > sentinel > sigma,
then modified recency, deterministic), ~50 rows per panel with a collapsed
remainder; techniques with no hosted rule get the link-out floor row (ATT&CK
#detections + SigmaHQ search). **Join rule:** parent-technique normalization —
exact sub-technique matches rank above family-level matches (fingerprints
carry 321 sub-ids; Sentinel keys parent-heavy, Sigma sub-heavy). Panel copy:
"Community/authored hunting queries — validate table names and thresholds
against the customer's schema before running."

## 3. Data model

`hunt_packs.json` = {generated_at, schema_version, rules: [{
  id, title, kql (max 16KB — real rules run 5KB+), techniques[] (T-ids),
  tables[], dialect ("advanced_hunting"|"log_analytics" — OUR enum, safe),
  source: {kind: "sentinel"|"sigma"|"socdesk" (OUR enum), url, license,
           author?, rule_id?, modified?}, tested? (socdesk-kind only)}]}
rules maxItems bounded; keep-prior + non-empty-guard publish (threat_ips
pattern); SCHEMA_FOR entry + hunt_packs.schema.json + the standard dual-write.
Entity → rules join is CLIENT-side by technique id (with the §H4 parent
fallback) — no per-entity duplication.

## 4. QA gates
Per-phase adversarially-vetted plans (standing process) · ci.yml Kustainer
job (conditional, readiness-polled) as the hard gate · collect-time
drop-to-warnings · 3-lens review on H4 · live dogfood (Akira + a MITRE-only
actor + a malware page).

## 5. Rollout
H0 (gauge → owner reviews) → H1 (+H4 ships with Sentinel-only coverage) →
H2 → H3 (ongoing gap fills). The panel is useful after H1; later phases
deepen coverage.
