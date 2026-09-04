# Hunt Playbooks — KQL at the Enrichment Stage — Design

**Goal:** Close the enrichment dead-end. Today an analyst enriches an IOC in SOCDesk and gets a *verdict* (the EscalationCard) but nothing to **do in their own SIEM**. Hunt Playbooks turn the verdict into action: the analyst picks the alert that triggered their lookup and gets an ordered, IOC-parameterized, syntax-validated KQL playbook to run in Sentinel / Defender — the general IOC pivot first, then scenario-specific hunts.

**Motivating flow (verbatim from the owner):** alert for *unfamiliar sign-in properties* → analyst plugs the suspicious IP into SOCDesk → enriches → **picks "Unfamiliar sign-in properties"** → gets a playbook: (1) every sign-in from this IP, (2) the trust-reduced novelty hunt for the users it touched, (3) new MFA methods / inbox rules after those sign-ins.

**Non-goals (v1):** no execution against the analyst's environment (SOCDesk never touches their SIEM — copy-paste only); no synthesized verdict on the results; no endpoint/network scenario families yet (v2); no automatic entity-chaining that fabricates a discovered account (see §5). v1 is **identity-first, IP-centric**.

---

## Global Constraints
- **Free-tier / no new runtime deps.** Client-side templating; the catalog is committed JSON. No new external calls at enrichment (the IOC is the analyst's own input; nothing about their environment leaves the browser).
- **Honesty doctrine** (`shared/verdict/doctrine.ts`): the playbook is *"parameterized starting points, syntax-validated against the Kusto emulator — not a detection guarantee. Verify table names and your own schema before running."* No verdict on results; absence renders nothing.
- **Clean-room provenance.** Playbooks are hand-authored from PUBLIC frameworks (Sentinel community / SigmaHQ / Microsoft docs / MITRE) — never employer IP, never ported from CARL. Attributed (SOCDesk · MIT), keyed to ATT&CK, and Kustainer-validated in CI — identical bar to the hunt-pack.
- **Two KQL dialects, never interchanged:** Sentinel `log_analytics` (`TimeGenerated`, `SigninLogs`) and Defender `advanced_hunting` (`Timestamp`, `AADSignInEventsBeta`). Every step carries whichever dialect(s) it has; missing dialect renders an honest "no <dialect> form for this step."
- **No inline styles** (`react/forbid-dom-props`); brand system held; **react-refresh** (pure templating/util in `.ts`, components export only components); **committed-dataset tests assert shape**, never live-file content; **`noUnusedLocals`** (an unused local is a build error).
- **Hash-router safety:** SOCDesk reserves the URL hash for routing. A selected scenario deep-links as `#q=<ioc>&alert=<id>` (rides the SAME hash as `q`, per `lookupModel.parseQ`) — never a bare `#<id>` fragment.

---

## Architecture

```
data/hunt/playbooks/*.yaml   (hand-authored, one alert scenario each)
        │  load_playbooks()  (extends pipeline/hunt.py::load_authored_rules pattern)
        ▼
pipeline/publish.py → playbooks.json   (schema-gated, published like hunt_packs.json)
        │  committed to data/state/
        ▼
web:  ResultRegion → EscalationCard (today)
        + HuntPlaybookPanel  ← NEW
             • scenarios filtered to the enriched IOC type
             • pick one (or the zero-click default: the general pivot)
             • each step's KQL templated with the IOC (safe KQL string literal)
             • rendered via the existing HuntPackPanel affordances (copy, dialect, provenance)
```

The catalog is data; the client is a pure renderer + a safe string-templater. The CI-validation lane proves every step's KQL shape before it ships.

---

## §1 Data model — the alert→playbook catalog

One YAML file per alert scenario in `data/hunt/playbooks/`, e.g. `socdesk-unfamiliar-signin-properties.yaml`:

```yaml
id: unfamiliar-signin-properties
title: Unfamiliar sign-in properties
alert_sources: [Entra ID Protection, Microsoft Defender XDR]   # display provenance only
ioc_types: [ipv4, ipv6]           # which ENRICHED indicator types offer this scenario
techniques: [T1078.004, T1621]    # ATT&CK ties → cross-link to the Adversaries hunt-pack
tested: "2026-09-03"
rationale: >                       # human-only; STRIPPED from the published payload
  Public-framework citation + why this ordering. Never shipped to the client.
steps:
  - id: signins-from-ip
    title: Every sign-in from this IP (scope the blast radius)
    kind: pivot                    # the general IOC search — v1 "touch of A"; always first
    param: ip                      # the placeholder this step injects (see §5)
    dialects:
      log_analytics: |
        SigninLogs
        | where TimeGenerated > ago(7d)
        | where IPAddress == "{{ip}}"
        | project TimeGenerated, UserPrincipalName, ResultType, AppDisplayName, LocationDetails
        | order by TimeGenerated desc
      advanced_hunting: |
        AADSignInEventsBeta
        | where Timestamp > ago(7d)
        | where IPAddress == "{{ip}}"
        | project Timestamp, AccountUpn, ErrorCode, Application, Country
    tables: [SigninLogs, AADSignInEventsBeta]
  - id: novelty-baseline
    title: Trust-reduced novelty for the accounts this IP touched
    kind: scenario
    param: upn                     # a FOLLOW-ON entity — analyst fills {{upn}} (see §5)
    dialects: { log_analytics: "…{{upn}}…" }
    tables: [SigninLogs]
```

**Published shape** (`playbooks.json`, schema `schemas/hunt_playbooks.schema.json`, added to `SCHEMA_FOR`):
```jsonc
{ "generated_at": "...", "schema_version": 1,
  "playbooks": [ { id, title, alert_sources[], ioc_types[], techniques[], tested?,
                   source: {kind:"socdesk", url:<github blob>, license:"MIT", author:"SOCDesk"},
                   steps: [ { id, title, kind:"pivot"|"scenario", param, dialects:{log_analytics?, advanced_hunting?}, tables[] } ] } ] }
```
`rationale` is stripped at load (mirrors `load_authored_rules`); `source.url` = the file's own GitHub blob (the public provenance trail).

**Loader:** `pipeline/hunt.py::load_playbooks(dir)` — a sibling of `load_authored_rules`: read every `*.yaml`, validate required fields, compose `source`, strip `rationale`, warn+skip malformed files (never crash the pipeline). Composed into `playbooks.json` in `pipeline/publish.py` alongside `hunt_packs.json`, keep-prior on empty (same degraded-fetch doctrine).

---

## §2 IOC parameterization + safety (the correctness-critical section)

**Typed placeholders.** A step's `param` names the placeholder its `{{…}}` tokens use: `ip` | `domain` | `sha256` | `sha1` | `md5` | `url` | `upn`. Two roles:
- **IOC-injected** (`kind: pivot` and IP-scoped scenario steps): the placeholder matches the *enriched* indicator's type, so SOCDesk substitutes the real IOC at render time.
- **Follow-on entity** (`kind: scenario`, `param: upn` on an IP enrichment): the entity (the account) is NOT known at enrichment — it's discovered by an earlier step. SOCDesk does NOT fabricate it: the `{{upn}}` renders as a **visible, un-substituted placeholder** the analyst fills, with a one-line "replace <upn> with an account from step 1" note. This keeps the ladder honest — we never invent a discovered entity.

**Safe substitution.** `injectIoc(kql, param, iocType, iocValue)` (pure `.ts`): substitutes ONLY when `param` matches the enriched `iocType`; escapes the value as a KQL string literal (`\` → `\\`, `"` → `\"`, strip control chars), so a hostile/odd indicator can't break out of the `"…"`. The IOC is already a validated indicator (`detectType`), but we escape defensively regardless. Un-matched placeholders (follow-on) are left visible.

**CI proof.** `tools/validate_hunt_kql.py` gains a playbook lane: for every step + dialect, substitute a CANONICAL sample per param type (`ip → 203.0.113.7`, `upn → user@example.com`, `sha256 → <64 hex>`, …), then validate against Kustainer with `| take 0` — proving the *templated* query parses. A step whose sample-substituted KQL fails Kustainer is dropped from the allowlist with a logged reason (same 30→28 discipline as the hunt-pack).

---

## §3 The enrichment-surface UX (frictionless selection)

**Placement.** In `ResultRegion` (`components/cockpit/ResultRegion.tsx`), below the `EscalationCard`, gated on `isEnrichable(data.type)` AND `playbooksForType(data.type).length > 0`. A new `HuntPlaybookPanel`:
- **Scenario chips** filtered to the IOC type — e.g. enrich an IP → the identity + network scenarios whose `ioc_types` include `ipv4`. No typing; pick the one that matches your alert.
- **Zero-click default:** before any pick, the panel shows the **general IOC pivot** (the `kind: pivot` step-1, which every scenario shares) immediately — so even a zero-click enrichment yields a runnable query.
- **On pick:** the full ordered playbook expands, rendered with the EXISTING `HuntPackPanel` affordances — collapsed `<details>` per step, per-step copy button, dialect toggle (Sentinel/Defender), tables + technique chips (cross-linking to the Adversaries hunt-pack), provenance line, and the honesty note.
- **Width:** the cockpit column is `max-w-md`; KQL blocks scroll inside `overflow-x-auto`, and an **"Open full playbook →"** link routes to a full-width lookup view via the SAME `#q=<ioc>&alert=<id>` deep link (mirrors the analyzer's existing `Expand →` pattern in `ResultRegion`).
- **Deep-link:** `alert=<id>` in the hash reopens the chosen scenario on a shared/bookmarked enrichment URL.

**Reuse, don't fork.** Extract the per-step renderer from `HuntPackPanel` (ActorProfile.tsx) into a shared component if needed so the playbook and the Adversaries hunt-pack render KQL identically (single source of the copy/dialect/provenance affordance).

---

## §4 Authoring + validation pipeline

- Playbooks hand-authored clean-room; each keyed to ATT&CK; both dialects where a faithful translation exists (a step may ship one dialect honestly).
- Extend `tools/validate_hunt_kql.py` (playbook lane, §2) + `.github/workflows/hunt-kql.yml` (validate playbooks from their allowlist on the same Kustainer boot).
- `requirements.txt` already has PyYAML; no new deps.

---

## §5 v1 scenario set (identity-first, IP-centric)

Six alert scenarios, each built from a public framework + (where they exist) the 5 authored identity rules we already own. Each opens with the general "sign-ins/connections from this IP" pivot, then scenario steps:

| Scenario | Alert source(s) | Techniques | Reuses |
|---|---|---|---|
| Unfamiliar sign-in properties | Entra ID Protection | T1078.004, T1621 | `signin-unfamiliar-baseline` |
| Impossible travel / atypical location | Entra ID Protection | T1078.004 | new |
| Password spray | Entra ID Protection / Defender | T1110.003 | `signin-correct-password-blocked` |
| MFA fatigue → method added | Entra ID Protection | T1621, T1556.006 | `mfa-method-added-after-risky-signin` |
| Malicious inbox rule | Defender for O365 | T1114.003, T1564.008 | `inbox-rule-forward-or-hide` |
| Risky OAuth consent | Entra ID Protection | T1528 | `oauth-consent-risk-tiering` |

(The 5 authored rules are novelty/behavioral hunts; the playbook wraps each with the IP pivot + the follow-on account placeholder so it fits the enrichment motion.)

---

## §6 Honesty + compliance
- Panel header doctrine line: *"Playbooks for the alert that sent you here — parameterized with your indicator, syntax-validated against the Kusto emulator. A starting point, not a detection guarantee: verify table names and your own schema first."*
- Follow-on placeholders are visible, never fabricated (§2).
- Provenance per playbook (SOCDesk · MIT · tested <date>) + per-step technique chips → the Adversaries hunt-pack.
- No new server route, no environment data leaves the browser (client-side templating). COMPLIANCE R4/R3 untouched (no IOC corpus mirrored; reputation still deep-linked).

---

## §7 Testing
- **Loader (pytest):** `load_playbooks` composes the schema-valid shape, strips `rationale`, sets `source`, warns+skips a broken file; the real `data/hunt/playbooks/*.yaml` gate-validate.
- **Publish (pytest):** `playbooks.json` in `build_site_data`; keep-prior on empty; schema in `SCHEMA_FOR`.
- **Templating (vitest, node):** `injectIoc` substitutes a matching param, escapes `"`/`\`, leaves a non-matching (follow-on) placeholder visible; a matching-type IP injects, a `upn` step on an IP enrichment does not.
- **Panel (vitest, renderToStaticMarkup):** scenarios filtered by IOC type; zero-click shows the general pivot; a picked scenario renders its steps + the honesty line + copy affordance; a type with no playbooks renders nothing.
- **CI:** the Kustainer playbook lane validates every sample-substituted step (both dialects) green.

---

## §8 Deferred (v2+)
- Endpoint (hash → DeviceFileEvents/DeviceProcessEvents) + network (domain → DnsEvents/proxy) scenario families — the data model already carries `ioc_types`, so this is new YAML, not new architecture.
- Email/UPN indicator enrichment as a first-class huntable type (today `email` routes to the report).
- Sentinel/Defender saved-search export (a `.kql`/ARM bundle download) — bigger, its own spec.
- Assisted chaining (auto-carry a discovered account into step 2) — deliberately deferred; v1 keeps the follow-on honest-manual.
