# Entity Relationships — Index & Presentation Verdict

2026-08-08. Covers `pipeline/relations.py` → `relations.json` and the honest
answer to "should SOCDesk draw a Maltego-style graph?"

## What the index is

A typed, evidence-carrying edge list derived ONLY from data we own:

| Edge type | Derivation | Evidence |
|---|---|---|
| `uses_technique` | ATT&CK actor profile | `"attack"` |
| `uses_software` | ATT&CK actor profile → malware node | `"attack"` |
| `cooccurs` | cross-type entities named in the same feed item | supporting feed item ids |
| `affects_vendor` / `affects_product` | CVE table, scoped to KEV-listed or feed-referenced CVEs | `"cve-db"` |

Rules (constants in `pipeline/relations.py`): co-occurrence weight = distinct
supporting items; single-item pairs are dropped unless one endpoint is a KEV
CVE; fan-out capped at 40 per node (an edge must fit BOTH endpoints' caps,
ranked weight-first, KEV-preferred, feed-evidence before structure); feed
names resolve through ATT&CK aliases (`Midnight Blizzard` → `APT29`); output
fully deterministic. **No inferred edges. No infrastructure pivots** — we hold
no pDNS/WHOIS/certs (COMPLIANCE.md), so IP↔domain graphs are impossible here
and are not faked.

## Measured (real pipeline run, 2026-08-08)

- 4,621 nodes: 1,613 cve · 1,425 product · 596 malware · 431 vendor ·
  383 technique · 173 actor
- 9,711 edges: 4,145 affects_product · 2,673 uses_technique ·
  1,750 affects_vendor · 1,123 uses_software · **20 cooccurs**
- Payload 1,475,263 B (103 KB gzipped); gate green, `problems=[]`
- 68 nodes sit at the fan-out cap (major actors, Mimikatz, T1003.001,
  Microsoft/Adobe/Apache, android/chrome)

The number that decides everything: of 9,711 edges, **20 come from the live
feed, and only 2 have multi-item support** (APT29↔Microsoft ×2, Check
Point↔CVE-2026-16232 ×2; the other 18 are single-item vendor↔KEV-CVE pairs).
99.8% of the graph is a static encyclopedia — ATT&CK structure and CVE
metadata that changes on quarterly/daily-bulk cadence, not with the news.

## Verdict: NO node-link graph. Build the ranked "Related entities" panel.

A force-directed canvas here would be the classic security-dashboard trap,
and our own numbers prove it: the layout would be dominated by 68 cap-height
hubs and thousands of encyclopedia edges that ATT&CK Navigator already
renders better, while the genuinely current signal — twenty edges — would be
invisible inside the hairball. It photographs well on day one and answers no
question on shift. It also fights the design system: an organic, jittering
physics simulation is the opposite of "a printed intelligence chart, alive"
(§1), and ambient motion beyond the ticker is a hard ban (§7.8).

The question an analyst actually brings — *"I'm looking at X; what else
should I be looking at?"* — is answered by a **ranked list keyed to the
entity in focus**, which this index serves in one O(degree) lookup:

- **Related-entities block in the operations rail** (and on actor/malware/CVE
  rows): top ~8 edges for the focused entity, each row = type chip · name ·
  weight · provenance ("2 feed items" linking to the items, "ATT&CK",
  "CVE db"). Mono data values, 1px hairlines, zero motion — it lands in the
  existing rail pattern with no new visual language.
- **Matrix/adjacency view**: rejected as a page — at 20 live pairs there is
  nothing to cross-tabulate, and the structural side is better served as
  lists. The one worthwhile matrix cell already exists implicitly: KEV
  vendor exposure, and the vuln table covers it.
- **Node-link graph**: rejected now. Revisit ONLY if the feed's extraction
  improves enough that multi-support co-occurrence edges reach ~150+
  (today: 2). If that day comes, the honest form is a build-time-laid-out
  **ego map** (focused entity + 1 hop, ≤25 nodes) emitted as static inline
  SVG by the pipeline — deterministic positions, straight 1px edges, no
  physics, no library, CSP-untouched. Not a global graph; never live d3-force.
  (If a client-side layout were ever forced: d3-force is MIT, self-hostable,
  CSP-clean — but precomputed SVG makes even that dependency unnecessary.)

**Build first:** the rail "RELATED" block reading `relations.json`, focused-
entity keyed, evidence links wired to feed items. It ships value with the
current 20-edge live layer (KEV vendor pairs are exactly what an analyst
pivots on) and grows in place as extraction improves — no new view, no new
dependency, no redesign risk.

## Levers if the payload ever crowds the budget

Payload is at ~1.47 MB of the ~1.5 MB target. In order of preference:
drop `affects_product` for non-KEV CVEs, lower `FANOUT_CAP`, or scope
`affects_*` to feed-referenced CVEs only. Gzipped cost (103 KB) is trivial;
the cap exists for parse time and hairball prevention, not bandwidth.
