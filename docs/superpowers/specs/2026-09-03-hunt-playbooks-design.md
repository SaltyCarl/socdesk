# Hunt Playbooks — KQL at the Enrichment Stage — Design

**Goal:** Close the enrichment dead-end. Today an analyst enriches an IOC in SOCDesk and gets a *verdict* (the EscalationCard) but nothing to **do in their own SIEM**. Hunt Playbooks turn the verdict into action: the analyst picks the alert that triggered their lookup and gets an ordered, IOC-parameterized, syntax-validated KQL playbook to run in Microsoft Sentinel — the general IP pivot first, then scenario-specific hunts.

**Motivating flow (verbatim from the owner):** alert for *unfamiliar sign-in properties* → analyst plugs the suspicious IP into SOCDesk → enriches → **picks "Unfamiliar sign-in properties"** → gets a playbook: (1) every sign-in from this IP, (2) the trust-reduced novelty hunt for the accounts it touched, (3) new MFA methods / inbox rules for those accounts.

> **Revised after adversarial vet (2026-09-03).** Load-bearing corrections folded in: **v1 is `log_analytics` (Sentinel) ONLY** — the advanced_hunting sign-in table (`AADSignInEventsBeta`) has NO DDL in `data/hunt/kusto_ddl/advanced_hunting/` (only Device* tables), so an AH form cannot pass the Kustainer gate the spec relies on; AH is v2 (gated on sourcing that DDL). `injectIoc` maps the real `IndicatorType` (`ipv4`/`ipv6`, never `'ip'`) to the `ip` param family. The IP pivot is `SigninLogs`-specific and surfaces the ACCOUNTS; scenario steps on `OfficeActivity`/`AuditLogs` chain via the `{{upn}}` follow-on, not IP. `playbooks.json` publishes FRESH every run (no keep-prior — authored-local, like the authored rules). Single-dialect v1 means NO dialect toggle (matches the existing `DIALECT_CAVEAT` pattern). Deep-link (`alert=`) + a full-width lookup route are v2 (neither exists today). Decomposed into 2 plans.

**Non-goals (v1):** no execution against the analyst's environment (copy-paste only); no synthesized verdict on results; **advanced_hunting (Defender) dialect deferred to v2** (needs sign-in DDL sourced first); **no endpoint/network scenario families** (hash/domain playbooks are v2 — the data model already carries `ioc_types`, so it's new YAML, not new architecture); **no `alert=` deep-link and no full-width route** (v1 selection is local component state, panel scrolls in-column); no automatic entity-chaining that fabricates a discovered account (§2). v1 is **identity-first, IP-centric, Sentinel-only.**

---

## Global Constraints
- **Free-tier / no new runtime deps.** Client-side templating; the catalog is committed JSON. No new external calls at enrichment (the IOC is the analyst's own input; nothing about their environment leaves the browser).
- **Honesty doctrine** (`shared/verdict/doctrine.ts`): the playbook is *"parameterized starting points, syntax-validated against the Kusto emulator — not a detection guarantee. Verify table names and your own schema before running."* No verdict on results; absence renders nothing; a discovered account is never fabricated (§2).
- **Clean-room provenance.** Playbooks are hand-authored from PUBLIC frameworks (Sentinel community / SigmaHQ / Microsoft docs / MITRE) — never employer IP, never ported from CARL. Attributed (SOCDesk · MIT), keyed to ATT&CK, Kustainer-validated in CI — identical bar to the hunt-pack.
- **One KQL dialect in v1: `log_analytics`** (`TimeGenerated`, `SigninLogs`/`OfficeActivity`/`AuditLogs`/`IdentityInfo`). Every v1 step is Sentinel KQL. The panel keeps the hunt-pack's existing `DIALECT_CAVEAT` line ("written for a Sentinel workspace; in Defender advanced hunting swap `TimeGenerated`→`Timestamp` and re-validate") rather than a toggle. AH-native forms + a toggle are v2.
- **No inline styles** (`react/forbid-dom-props`); brand system held; **react-refresh** (pure templating/util in `.ts`, component files export only components); **committed-dataset tests assert shape**, never live-file content; **`noUnusedLocals`** (an unused local is a build error).

---

## Architecture

```
data/hunt/playbooks/*.yaml   (hand-authored, one alert scenario each, log_analytics)
        │  load_playbooks()  (sibling of pipeline/hunt.py::load_authored_rules)
        ▼
pipeline/publish.py → playbooks.json   (schema-gated; published FRESH every run, no keep-prior)
        │  committed to data/state/
        ▼
web:  ResultRegion → EscalationCard (today)   [the ONLY enrichment surface; /lookup is retired]
        + HuntPlaybookPanel  ← NEW
             • scenarios filtered to the enriched IOC type (ipv4/ipv6 in v1)
             • zero-click default: the general SigninLogs IP pivot renders immediately
             • pick a scenario → its ordered steps, each templated with the IOC
             • rendered via the hunt-pack's extracted step renderer (copy KQL + provenance)
```

The catalog is data; the client is a pure renderer + a safe string-templater. The CI Kustainer lane proves every step's KQL (sample-substituted) before it ships.

---

## §1 Data model — the alert→playbook catalog

One YAML file per alert scenario in `data/hunt/playbooks/`, e.g. `socdesk-unfamiliar-signin-properties.yaml`:

```yaml
id: unfamiliar-signin-properties
title: Unfamiliar sign-in properties
alert_sources: [Entra ID Protection]     # display provenance only
ioc_types: [ipv4, ipv6]                   # which ENRICHED IndicatorType values offer this scenario
techniques: [T1078.004, T1621]            # ATT&CK ties (playbook-level) → chips + hunt-pack cross-link
tested: "2026-09-03"
rationale: >                              # human-only; STRIPPED from the published payload
  Public-framework citation + why this ordering. Never shipped to the client.
steps:
  - id: signins-from-ip
    title: Every sign-in from this IP (surfaces the accounts to pivot on)
    kind: pivot                           # the general IP search — v1 "touch of A"; always first
    param: ip                             # the placeholder family this step injects (see §2)
    dialect: log_analytics
    tables: [SigninLogs]
    kql: |
      SigninLogs
      | where TimeGenerated > ago(7d)
      | where IPAddress == "{{ip}}"
      | project TimeGenerated, UserPrincipalName, ResultType, AppDisplayName, LocationDetails
      | order by TimeGenerated desc
  - id: novelty-baseline
    title: Trust-reduced novelty for an account this IP touched
    kind: scenario
    param: upn                            # FOLLOW-ON entity — analyst fills {{upn}} from step 1 (see §2)
    dialect: log_analytics
    tables: [SigninLogs]
    kql: |
      … | where UserPrincipalName == "{{upn}}" …
```

**Published shape** (`playbooks.json`, schema `schemas/hunt_playbooks.schema.json`, added to `SCHEMA_FOR`; `additionalProperties:false` throughout incl. each `step`):
```jsonc
{ "generated_at": "...", "schema_version": 1,
  "playbooks": [ { id, title, alert_sources[], ioc_types[], techniques[], tested?,
                   source: {kind:"socdesk", url:<github blob>, license:"MIT", author:"SOCDesk"},
                   steps: [ { id, title, kind:"pivot"|"scenario", param, dialect:"log_analytics", tables[], kql } ] } ] }
```
`rationale` is stripped at load (mirrors `load_authored_rules`); `source.url` = the file's own GitHub blob (public provenance trail).

**Loader:** `pipeline/hunt.py::load_playbooks(dir)` — a sibling of `load_authored_rules`: read every `*.yaml`, validate required fields, compose `source`, strip `rationale`, warn+skip malformed files. Composed into `playbooks.json` in `pipeline/publish.py`. **PUBLISH FRESH EVERY RUN — no keep-prior** (playbooks are authored-local and re-read every run; an empty/deleted `playbooks/` means the author removed them, so `playbooks:[]` is the honest publish — `gate()` falls back to prior only on an *invalid* payload, never on a valid-empty one; do NOT add a `ransomware_groups`-style keep-prior branch, which would resurrect deleted playbooks).

---

## §2 IOC parameterization + safety (the correctness-critical section)

**Two namespaces, explicitly mapped.** A step's `param` is a placeholder FAMILY (`ip` | `upn` | later `domain`/`sha256`/…); the enriched indicator's `data.type` is an `IndicatorType` (`ipv4`|`ipv6`|`domain`|`url`|`md5`|`sha1`|`sha256`|`cve`|`email`|`''` — there is **no `'ip'`**). `injectIoc` maps between them:

```
PARAM_FOR_TYPE: { ipv4: 'ip', ipv6: 'ip', domain: 'domain', sha256:'sha256', … }   // v1 uses only ipv4/ipv6→ip
injectIoc(kql, stepParam, iocType, iocValue):
   if PARAM_FOR_TYPE[iocType] === stepParam:  substitute every {{stepParam}} with the escaped IOC
   else:                                       leave {{stepParam}} VISIBLE (a follow-on placeholder)
```

- **IOC-injected** (`kind: pivot`, `param: ip`, IP enrichment): `{{ip}}` → the real IP.
- **Follow-on entity** (`kind: scenario`, `param: upn`): the account is NOT known at enrichment — it's *discovered* by step 1. SOCDesk does NOT fabricate it: `{{upn}}` renders as a **visible, un-substituted placeholder** with a one-line "replace `<upn>` with an account from step 1." This keeps the ladder honest.

**Safe substitution.** `injectIoc` (pure `.ts`) escapes the value as a KQL string literal (`\`→`\\`, `"`→`\"`, drop control chars) before insertion into `"…"`. The IOC is already `detectType`-validated (an ipv4/ipv6 can't contain a quote), and KQL has no `${}` interpolation, so this fully prevents literal break-out — the escaping is belt-and-suspenders. `SigninLogs.IPAddress` is a `string` column, so `== "{{ip}}"` is the correct shape (no typed literal needed).

**CI proof.** `tools/validate_hunt_kql.py` gains a playbook lane: flatten each step into a pseudo-rule `{id, dialect:'log_analytics', kql:<canonical-sample-substituted>}` (`ip → 203.0.113.7`, `upn → user@example.com`), reuse the existing per-dialect DB + `wrap()` (strip trailing `render`, append `| take 0`), validate against the `SigninLogs`/`OfficeActivity`/`AuditLogs` DDL. A step whose sample-substituted KQL fails is dropped with a logged reason (same discipline as the hunt-pack's 30→28). Add `schemas/hunt_playbooks.schema.json` to the workflow's `paths:` so a schema-only edit still triggers.

---

## §3 The enrichment-surface UX

**Placement.** In `ResultRegion` (`components/cockpit/ResultRegion.tsx`), below the `EscalationCard`, gated on `isEnrichable(data.type) && playbooksForType(data.type).length > 0` (mirrors the existing `reportSlot` gate). **The cockpit is the only enrichment surface — `/lookup` is retired (`LookupRedirect.tsx` → `/`).** A new `HuntPlaybookPanel`:
- **Scenario chips** filtered to the IOC type (enrich an ipv4 → the identity scenarios whose `ioc_types` include `ipv4`). No typing.
- **Zero-click default:** before any pick, show the general `SigninLogs` IP pivot (the shared step-1) immediately — even a zero-click enrichment yields a runnable query.
- **On pick:** the ordered playbook expands, each step a collapsed `<details>` with its templated KQL, `CopyKqlButton`, tables, and the honesty/caveat line. Playbook-level **technique chips** in the panel header cross-link to the Adversaries hunt-pack (per-step techniques are NOT in the v1 shape).
- **Selection state is LOCAL** (`useState` in the panel) — no URL persistence in v1.
- **Width:** the cockpit column is `max-w-md`; KQL blocks scroll inside `overflow-x-auto` (as they already do). No full-width route in v1 (none exists; the analyzer's `/analyzer` has no lookup equivalent — building one is v2).

**Reuse, don't fork.** Extract the hunt-pack's per-step renderer (`HuntRowView` + `CopyKqlButton` + `copyPlain` + `DIALECT_CAVEAT`, today unexported in `ActorProfile.tsx`) into a shared module (`web/src/components/views/HuntRow.tsx`) so the playbook and the Adversaries hunt-pack render KQL identically. v1 is single-dialect, so no toggle is added — the extracted renderer keeps the existing "one native dialect + caveat" behavior. (Generalizing to multi-dialect + a toggle is v2, alongside the AH DDL.)

---

## §4 Authoring + validation pipeline
- Playbooks hand-authored clean-room; each keyed to ATT&CK; `log_analytics` only in v1.
- Extend `tools/validate_hunt_kql.py` (playbook lane, §2) + `.github/workflows/hunt-kql.yml` (validate playbooks on the same Kustainer boot; add the new schema to `paths:`). `requirements.txt` already has PyYAML.

---

## §5 v1 scenario set (identity-first, IP-centric, log_analytics)

Six alert scenarios. **Every scenario opens with the general `SigninLogs` IP pivot (step 1) — whose job is to surface the ACCOUNTS that used the IP** — then the scenario step operates on those accounts. Whether the scenario step chains by IP or by the `{{upn}}` follow-on depends on its table:

| Scenario | Alert source | Techniques | Scenario table | Chains by | Reuses authored rule |
|---|---|---|---|---|---|
| Unfamiliar sign-in properties | Entra ID Protection | T1078.004, T1621 | SigninLogs | IP or {{upn}} | `signin-unfamiliar-baseline` |
| Impossible travel / atypical location | Entra ID Protection | T1078.004 | SigninLogs | {{upn}} | new |
| Password spray | Entra ID Protection | T1110.003 | SigninLogs | IP | `signin-correct-password-blocked` |
| MFA fatigue → method added | Entra ID Protection | T1621, T1556.006 | AuditLogs | **{{upn}}** (AuditLogs has no sign-in IP) | `mfa-method-added-after-risky-signin` |
| Malicious inbox rule | Defender for O365 | T1114.003, T1564.008 | OfficeActivity | **{{upn}}** (OfficeActivity IP col is `ClientIP`, not `IPAddress` — does not chain by IP) | `inbox-rule-forward-or-hide` |
| Risky OAuth consent | Entra ID Protection | T1528 | AuditLogs | **{{upn}}** | `oauth-consent-risk-tiering` |

The 5 authored rules are novelty/behavioral hunts (all `log_analytics`); the playbook wraps each with the IP pivot (step 1) + the `{{upn}}` follow-on so it fits the enrichment motion. Every step's sample-substituted KQL must pass the Kustainer lane against the committed DDL before ship (a scenario whose table lacks committed DDL is trimmed until the DDL is sourced).

---

## §6 Honesty + compliance
- Panel header doctrine line: *"Playbooks for the alert that sent you here — parameterized with your indicator, syntax-validated against the Kusto emulator. A starting point, not a detection guarantee: verify table names and your own schema first."*
- Follow-on placeholders visible, never fabricated (§2). No verdict on results.
- Provenance per playbook (SOCDesk · MIT · tested <date>); playbook-level technique chips → the Adversaries hunt-pack.
- No new server route; nothing about the environment leaves the browser (client-side templating). COMPLIANCE R4/R3 untouched (no IOC corpus mirrored; reputation still deep-linked).

---

## §7 Testing
- **Loader (pytest):** `load_playbooks` composes the schema-valid shape, strips `rationale`, sets `source`, warns+skips a broken file; the real `data/hunt/playbooks/*.yaml` gate-validate.
- **Publish (pytest):** `playbooks.json` in `build_site_data`, published FRESH (empty `playbooks/` → `playbooks:[]`, NOT resurrected); schema in `SCHEMA_FOR`.
- **Templating (vitest, node):** `injectIoc` maps `ipv4`/`ipv6`→`ip` and substitutes+escapes (`"`,`\`); leaves a non-matching (`upn` on an IP enrichment) placeholder visible; a `domain` step on an IP enrichment does not inject.
- **Panel (vitest, renderToStaticMarkup):** scenarios filtered by IOC type; zero-click shows the IP pivot with the IP injected; a picked scenario renders its steps + the honesty line + `CopyKqlButton`; an enrichable type with no v1 playbook (domain/hash) renders nothing.
- **CI:** the Kustainer playbook lane validates every sample-substituted step green against the committed DDL.
- **No regression:** the extracted `HuntRow` renders the Adversaries hunt-pack identically (existing ActorProfile hunt-pack tests stay green).

---

## §8 Decomposition (two plans for v1)
- **Plan 1 — backend (headless-shippable):** the YAML data model + `schemas/hunt_playbooks.schema.json` + `load_playbooks` + `SCHEMA_FOR` + `pipeline/publish.py` fresh-publish + the `validate_hunt_kql.py` playbook lane + `hunt-kql.yml` `paths` + the 6 authored playbook YAMLs. Ships `playbooks.json` with CI green; no UI yet.
- **Plan 2 — client:** extract `HuntRow` (shared renderer); `injectIoc` (`.ts`, tested); `HuntPlaybookPanel` (scenario chips, zero-click pivot, local-state selection); wire into `ResultRegion`. Ships the analyst-facing feature.

## §9 Deferred (v2+)
- advanced_hunting dialect + a dialect toggle (needs `AADSignInEventsBeta` DDL sourced into `kusto_ddl/advanced_hunting/` first).
- Endpoint (hash → DeviceProcessEvents/DeviceFileEvents) + network (domain → DnsEvents) scenario families — new YAML, same architecture.
- `alert=` deep-link (net-new: a `parseAlert` reader + a `lookupHash` writer that preserves it + Overview state threading) and a full-width lookup route for comfortable multi-step reading.
- Email/UPN as a first-class huntable indicator (today `email` routes to the report).
- Sentinel saved-search / ARM export; assisted chaining (auto-carry a discovered account into step 2) — deliberately deferred to keep v1 honest-manual.
