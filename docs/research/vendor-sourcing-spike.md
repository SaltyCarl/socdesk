# Spike: Sourcing TTP Depth for Active Ransomware Crews Beyond the CISA Seed

Date: 2026-08-25
Time-boxed research spike — 13 fetches used (10 WebSearch + 3 WebFetch), cap ~12/8min. No code/files changed besides this doc.

## Problem restated

`data/ransomware_intel.json` (10 groups) only covers crews with a public-domain
CISA #StopRansomware / FBI FLASH joint advisory. This week's busiest active
crews — Qilin, Coinbase Cartel, The Gentlemen, Kazu, DragonForce — have none,
so today they get feed-claims (leak-site, per COMPLIANCE.md R3, attributed/
unverified) + generic ATT&CK only: no initial-access CVEs, no tooling, no
in-hand signature depth. Question: can the DEPTH source broaden beyond
public-domain CISA/FBI without breaking the existing compliance posture?

## 1. The facts-vs-expression line for vendor reports

Confirmed against standard US copyright doctrine (Feist Publications v. Rural
Telephone, the controlling case): **facts are not copyrightable — only
original expression, and thin "selection/arrangement" compilation copyright,
are.** This is the same principle COMPLIANCE.md R3 already leans on for
leak-site facts (victim/domain/sector claims, attributed, framed unverified).

Applying it to a vendor blog (SOCRadar, Halcyon, FortiGuard, Unit42,
Bitdefender, etc. — all © all-rights-reserved on their prose):

| What you'd take | Risk | Verdict |
|---|---|---|
| Verbatim paragraphs / screenshots / their exact phrasing | High — straight copyright infringement | **No** |
| A paraphrased TTP narrative ("Qilin typically gains initial access via...") that just synonym-swaps their sentences | Medium — courts look at structure/sequence, not just word choice; a close paraphrase can still infringe | **No** — if you paraphrase, the output must structurally diverge (bullet facts, not narrative prose) |
| A single extracted CVE ID, ATT&CK technique ID, tool name, alias, or first-seen date, republished as a discrete field with attribution ("per FortiGuard") | Low — an individual fact is not copyrightable at all | **Yes** |
| The vendor's own *curated selection* of facts, copied wholesale in their chosen order (e.g. mirroring their exact "Top 5 TTPs" list verbatim in the same order/grouping) | Medium — thin compilation copyright can attach to *original selection/arrangement* of an otherwise-facts-only set | **Avoid** — cross-reference the same fact against ≥1 other source, or reorder/re-select independently, before republishing as a set |

Practical rule for SOCDesk: extract atomic fields only (CVE id, technique id,
tool string, alias, date), attribute per-field or per-group to the vendor,
link out to the original, and never reproduce the vendor's own multi-fact
list structure/order wholesale. This is a direct extension of the
already-approved leak-site-facts model — not a new legal theory.

## 2. Candidate sources checked

| Source | License / status | Covers the active crews (Qilin/DragonForce/Coinbase Cartel/Gentlemen/Kazu)? | Verdict |
|---|---|---|---|
| **MITRE ATT&CK Groups/Software** (already used) | ATT&CK Terms of Use, attribution-licensed, already integrated | **Yes for Qilin** — confirmed real depth: Software entry S1242, 60+ techniques (discovery/defense-evasion/execution/lateral-movement/impact), associated Groups Water Galura (G1050) and Moonstone Sleet (G1036), platform/variant detail. Not a stub. DragonForce/Coinbase Cartel/Gentlemen/Kazu coverage NOT individually confirmed in this spike — needs a per-crew check before build. | **Expand usage** — mine ATT&CK Software/Group objects per-crew, not just the CISA seed's existing cross-refs |
| **HHS HC3** (Health Sector Cybersecurity Coordination Center) threat profiles | TLP:CLEAR, published by a US federal executive agency (HHS) as official duties → same 17 U.S.C. §105 public-domain footing as CISA/FBI | **Confirmed**: a standalone HC3 **Qilin Threat Profile** PDF exists (`hhs.gov/sites/default/files/qilin-threat-profile-tlpclear.pdf`). HC3 also publishes recurring "Top 10 Most Active Ransomware Groups" analyst notes and ad-hoc profiles for crews CISA hasn't done a joint advisory for (Everest, Scattered Spider, Seashell Blizzard, FIN11 confirmed as existing HC3 profiles). Strong pattern of covering *currently active* crews faster/more granularly than the flagship #StopRansomware series. DragonForce/Coinbase Cartel/Gentlemen/Kazu-specific HC3 profiles not individually confirmed — needs a live check of HC3's publication library. | **Best new lead** — same trust tier as the existing seed, just a different DHS-family publisher |
| **MISP galaxy** (`misp-galaxy` ransomware/threat-actor clusters) | **CC0 1.0** — public-domain-equivalent, cleanest license of anything checked | Checked `clusters/ransomware.json`: **stale**, ~2017-era entries (Locky, CryptoMix, Petya, Sage...). None of the five active crews present. (threat-actor.json cluster not checked in this time-box — possible but unconfirmed.) | **License is great, data isn't current** — not usable for these crews as-is |
| **Malpedia** (Fraunhofer FKIE) | CC BY-NC-SA 3.0 (NC actually *fits* a non-commercial project) but **invite-only vetted trust group**, non-public content is TLP:AMBER by default | Unknown — can't check without an account | **Blocked operationally**, not by license — no anonymous/API access for an unvetted party; out of scope for a no-accounts free-tier pipeline |
| **The DFIR Report** | No open-license statement found; their DFIR Labs cloud product has explicit anti-reuse/anti-export ToS. Free blog content's reuse terms unclear from this search — treat as standard © all-rights-reserved | Would need per-post check | **Vendor-blog tier only** — same facts-with-attribution treatment as SOCRadar/Unit42/etc., nothing better |
| **ransomwatch** (joshhighet/GitHub) | Unlicense on the *code* | Tracks leak-site claims (victim/claim data) — same category as ransomware.live, already governed by COMPLIANCE.md R3 | **Doesn't solve the gap** — it's leak-site claim data (already allowed, attributed/unverified), not TTP depth (no CVEs, no tooling, no techniques) |
| **abuse.ch / ThreatFox** | CC0 (already used per COMPLIANCE.md) | IOC-level (hashes/domains/IPs), not group-TTP narrative | Already in the aggregator model; not a depth source for group profiles |
| **CISA #StopRansomware — re-confirmed** | Public domain | Re-checked: no dedicated joint AA-numbered advisory found for Qilin, DragonForce, Coinbase Cartel, The Gentlemen, or Kazu specifically (search results show only general CISA *statements*/warnings about Qilin, not a joint #StopRansomware advisory with an AA-code). Confirms the premise. | Gap is real |

## 3. Recommendation — CONDITIONAL GO

**Go, with a narrow, two-tier expansion — not a wholesale switch to vendor blogs.**

**Tier 1 (do this first, cleanest win): widen the public-domain definition
from "CISA/FBI #StopRansomware" to "any US federal executive-agency
threat-actor product marked TLP:CLEAR"** — concretely, add HHS HC3 threat
profiles and analyst notes as an equal-status source alongside CISA/FBI in
`ransomware_intel.json`, using the exact same schema fields
(`advisory`/`sources`) already in place. Same legal footing (17 U.S.C. §105
public domain), same attribution presentation, zero change to the honesty
doctrine or COMPLIANCE.md posture. A live Qilin HC3 profile already exists —
pull it in directly. Before building, do a 10-minute pass over HC3's
publication library (hhs.gov/hc3) to confirm/deny profiles for DragonForce,
Coinbase Cartel, The Gentlemen, and Kazu specifically.

**Tier 2 (mine harder what's already licensed): pull MITRE ATT&CK Software/
Group objects per-crew**, not just as a cross-reference on top of the CISA
seed but as a first-class depth field when a crew has a substantive ATT&CK
entry (confirmed for Qilin — S1242, 60+ techniques). This requires zero new
licensing work since ATT&CK is already integrated; it just needs to be
checked and pulled per-crew rather than assumed absent.

**Tier 3 (gap-filler only, tightly scoped): for a crew still short on depth
after Tiers 1–2, extract discrete attributed facts from vendor blogs** — CVE
IDs, ATT&CK technique IDs, tool/alias strings, first-seen dates only, each
tagged "per [Vendor], [date]" with a link-out, never a paraphrased narrative,
never the vendor's own full curated list copied wholesale (cross-check each
fact against ≥1 other source before inclusion, mirroring the R3 leak-site
discipline). This is the same facts-not-expression treatment already applied
to leak-site claims — extending it to vendor blogs is a scope increase, not
a new legal theory, so it doesn't need a fresh compliance gate, just the same
per-field-attribution discipline enforced in code review.

**What NOT to do:** don't chase Malpedia (access-gated regardless of decent
license terms), don't treat ransomwatch/MISP-ransomware-galaxy as depth
sources (wrong data shape / stale), and don't mirror DFIR Report or vendor
prose even in paraphrase.

**Fallback (honest default) for any crew that clears none of the three
tiers:** keep it to attributed leak-site facts (existing ransomware.live
link-out model) + generic ATT&CK ransomware TTPs, and re-check as new CISA/
HC3 advisories publish — exactly the project's current honesty framing,
just don't force a fabricated-looking depth panel where no attributable
source exists yet.

## Open follow-ups (not done in this spike — time-boxed out)

- Confirm HC3 profile existence (or absence) for DragonForce, Coinbase
  Cartel, The Gentlemen, Kazu specifically.
- Confirm MITRE ATT&CK Group/Software coverage for the same four (only
  Qilin was verified in-depth here).
- Check MISP `threat-actor.json` galaxy cluster (not just `ransomware.json`)
  for current-crew coverage — CC0 license is the cleanest of anything found,
  worth a second look if the cluster turns out more current than the
  ransomware-specific one.
