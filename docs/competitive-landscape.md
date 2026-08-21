# SOCDesk — Competitive Landscape

**Scope:** SOCDesk (socdesk.io) is a free, 100% client-side CTI console built around the T1/T2 SOC analyst's fast-lookup loop — paste or right-click an IP/domain/URL/hash, get a multi-source consensus "escalation card" (no synthesized verdict, just attributed source-by-source findings), plus a deterministic PowerShell/cmd script analyzer (decode ladder, MITRE technique tally, plain-English "what it did" kill-chain bullets, one-click IOC pivot) and a Manifest V3 browser extension for right-click-in-console use. It is a non-commercial personal portfolio project — no account, no server-side persistence, no case management, no self-hosting, no API for automation.

This document is written to be skeptical of SOCDesk, not promotional. Every competitor claim below was checked against an official source (site, docs, GitHub, or a named secondary source when official pricing was unpublished/unreachable) as of 2026-08-19/20. Anything that could not be directly verified is flagged **unverified** or **partially unverified** rather than stated as fact.

---

## 1. Tools by category

SOCDesk's lane isn't one category — it straddles four. A tool only "competes" on the axes it actually shares with SOCDesk; the per-tool profiles below say which axis.

- **Aggregator / enrichment** (multi- or single-source indicator reputation lookup): IntelOwl, Pulsedive, ThreatFox, urlscan.io, VirusTotal, Maltiverse, GreyNoise Visualizer, AbuseIPDB, AlienVault OTX
- **CTI platform** (case management / knowledge base / org-wide intel program): OpenCTI, MISP, TheHive + Cortex, Recorded Future, Anomali (ThreatStream), ThreatConnect (now Dataminr)
- **Script deobfuscation / analysis**: CyberChef
- **Sandbox / detonation**: ANY.RUN, Joe Sandbox, Hybrid Analysis (Falcon Sandbox), Triage (tria.ge), Filescan.io
- **Adjacent / different lane**: PhishTool (email/phishing forensics, not script or IOC-reputation)
- **Host-search / commercial reputation anchors**: Shodan, Censys, IBM X-Force Exchange, Cisco Talos Intelligence, Cisco Umbrella Investigate
- **Browser extension**: VT4Browsers (official VirusTotal), SOCMaster, SOC Toolkit, Ahtapot, OZZI: IOC Search, IOChaser

---

## 2. Per-tool profiles

### 2.1 Aggregator / enrichment

**IntelOwl**
- What it is: Open-source threat-intel management platform aggregating results from 50+ analyzers (VirusTotal, Shodan, urlscan, OTX, MISP, OpenCTI, Yara, ClamAV, PE/Android/PCAP analysis) behind one API/UI.
- Hosting: Self-hosted only (Docker); no official SaaS (a gated honeypot-project demo exists at intelowl.honeynet.org).
- Free/paid: Fully free, open-source, AGPL-3.0.
- Target user: SOC teams / threat hunters with the appetite to deploy and maintain infrastructure.
- Strength vs. T1/T2 fast lookup: Deepest source count of anything reviewed here — 50+ analyzers under one query.
- Weakness vs. T1/T2 fast lookup: Not usable out of the box by an individual analyst; no zero-install "paste and go" path — the deployment burden is the whole cost.
- Source: [github.com/intelowlproject/IntelOwl](https://github.com/intelowlproject/IntelOwl)

**Pulsedive**
- What it is: Threat-intel search engine / community platform over an indexed IOC database (1M+ IOCs).
- Hosting: SaaS only.
- Free/paid: Free web-UI search; unregistered/free API capped at 10 requests/day, 100/month. Paid "Pro" ≈ $29/mo (screenshots, integrations, higher limits) — exact current Pro limits **unverified** (pricing page fetch was incomplete).
- Target user: Individual analysts and small teams.
- Strength: Free web lookup is fast and low-friction for a one-off check.
- Weakness: API is rate-limited hard for unregistered/free use; it's an indexed database lookup, not a live cross-vendor consensus tally.
- Source: [pulsedive.com/about/pro](https://pulsedive.com/about/pro), [blog.pulsedive.com/pulsedive-plan-updates-2024](https://blog.pulsedive.com/pulsedive-plan-updates-2024/)

**ThreatFox (abuse.ch)**
- What it is: Community IOC-sharing platform (malware-associated IPs/domains/URLs/hashes), run by abuse.ch/Spamhaus. Also one of SOCDesk's own aggregated sources — not purely a competitor, but its own browse UI supports direct analyst lookup.
- Hosting: SaaS (free browse UI + API).
- Free/paid: Fully free, fair-use API key via auth.abuse.ch.
- Target user: Anyone; commonly one ingredient in a larger pipeline.
- Strength: Free, no-friction key signup, strong malware-C2 IOC context.
- Weakness: Single-source community submissions — no cross-vendor consensus, no reputation scoring, no sandboxing.
- Source: [threatfox.abuse.ch](https://threatfox.abuse.ch/), [github.com/abusech/ThreatFox](https://github.com/abusech/ThreatFox)

**urlscan.io**
- What it is: URL sandbox — browses a submitted URL like a real user, records screenshot/DOM/requests/brand-phishing detection.
- Hosting: SaaS.
- Free/paid: Free tier = public scans, private scans capped at 50/day. Paid "Pro" from $50/mo, scaling to enterprise packages reported as high as ≈$4,166/mo.
- Target user: Individual analysts (free) up to enterprise phishing/SOC teams (paid, private scanning at volume).
- Strength: Best-in-class visual/behavioral verification of a suspected phishing URL in one submission.
- Weakness: Free-tier scans are **public by default** — real risk of leaking an internal/sensitive URL or tipping off an attacker; URL-only, not IP/domain/hash reputation.
- Source: [urlscan.io/about](https://urlscan.io/about/), [urlscan.io/pricing](https://urlscan.io/pricing/)

**VirusTotal**
- What it is: Multi-AV-engine file/URL scanning + IOC reputation lookup — the de facto first stop for hash/URL/IP/domain checks; itself a "consensus" tool (60+ engines under one roof), arguably SOCDesk's closest single-tool functional analog on the reputation-lookup axis.
- Hosting: SaaS.
- Free/paid: Public API free tier — 4 req/min, 500/day, **non-commercial use only** (ToS explicitly bars anything competing with/harming the AV industry). Premium/Enterprise: custom rate limits and pricing, not published.
- Target user: Everyone, individual to enterprise; free tier is genuinely usable for manual T1/T2 lookups, paid needed for automation/volume.
- Strength: Largest aggregated engine count for file/URL verdicts; near-universal analyst trust; file/hash detonation-adjacent coverage SOCDesk doesn't replicate (no upload).
- Weakness: Free web/API traffic runs through Google-owned infra with visible community comments; rate limits bite fast in a busy shift; no built-in script deobfuscation.
- Source: [docs.virustotal.com/docs/api-overview](https://docs.virustotal.com/docs/api-overview), [docs.virustotal.com/reference/public-vs-premium-api](https://docs.virustotal.com/reference/public-vs-premium-api)

**Maltiverse**
- What it is: Threat-intel broker aggregating 100+ public/private/community sources into IOCs with history/context.
- Hosting: SaaS.
- Free/paid: Freemium confirmed; tiered by query volume/credits. Exact free-tier limits and paid pricing **unverified** (pricing page returned no substantive content on fetch).
- Target user: Individual researchers through enterprise, per their tiering claims.
- Strength: Very high source count (100+) aggregated with historical context in one lookup.
- Weakness: Pricing opacity is itself a UX weakness against SOCDesk's zero-account/zero-cost model.
- Source: [whatis.maltiverse.com](https://whatis.maltiverse.com/) — pricing unverified

**GreyNoise Visualizer**
- What it is: Internet background-noise/scanner classification — tells you if an IP is mass-scanning infrastructure (benign/malicious/unknown) vs. a targeted threat, a genuinely differentiated signal (not re-aggregation).
- Hosting: SaaS (Visualizer web + Community/Enterprise APIs).
- Free/paid: Community tier free with a business email (major free-mail domains excluded from API-key access) — 50 combined lookups/week across Visualizer + Community API. Enterprise paid for volume/context.
- Target user: SOC analysts triaging scanner noise; enterprise for volume.
- Strength: Unique noise-classification signal most aggregators don't provide — this is exactly why SOCDesk includes it as a source rather than treating it as redundant with the others.
- Weakness: Free tier is IP-only, low-volume (50/week), and requires a business email — more friction than SOCDesk's no-account model.
- Source: [docs.greynoise.io/docs/using-the-greynoise-community-api](https://docs.greynoise.io/docs/using-the-greynoise-community-api) (direct fetch of viz.greynoise.io returned HTTP 403 — UI specifics via secondary source)

**AbuseIPDB**
- What it is: Crowdsourced IP abuse-report/reputation database.
- Hosting: SaaS.
- Free/paid: Free tier = 1,000 IP checks+reports/day, 100 block-checks/day, 10,000-IP blacklist. Basic $25/mo (10,000 checks/day); Premium $99/mo (50,000 checks/day, 500,000-IP blacklist); Enterprise custom. 30-day trial on paid tiers.
- Target user: Individual analysts (generous free tier) through MSSPs/enterprise needing high-volume automated blocklisting.
- Strength: Free-tier limits an individual analyst will essentially never hit manually; trusted crowdsourced IP context.
- Weakness: IP-only; community reports can be noisy/unverified without corroboration from other sources — exactly the gap a consensus tool like SOCDesk closes.
- Source: [abuseipdb.com/pricing](https://www.abuseipdb.com/pricing)

**AlienVault OTX (AT&T/LevelBlue Open Threat Exchange)**
- What it is: Community threat-intel sharing platform — Pulses (curated IOC bundles) plus indicator search. Also one of SOCDesk's own aggregated sources.
- Hosting: SaaS.
- Free/paid: Free to browse; free account + API key required for programmatic lookups.
- Target user: Individual analysts/researchers doing community-driven threat research.
- Strength: Strong campaign/actor-context pulses, not just raw indicator scoring.
- Weakness: Requires account creation; single-source like ThreatFox, not cross-vendor consensus.
- Source: [cybersecurity.att.com/documentation/otx](https://cybersecurity.att.com/documentation/otx/browsing-searching-otx.htm)

---

### 2.2 CTI platforms (case management / knowledge base)

**OpenCTI (Filigran)**
- What it is: Open-source STIX 2.1-structured threat-intel platform unifying technical, operational, and strategic CTI across a team.
- Hosting: Self-hosted Community Edition, or SaaS/managed hosting (Filigran Enterprise Edition, incl. air-gapped option).
- Free/paid: CE is free/open-source, no published limits. EE (paid, price not published, 30-day trial) adds AI-powered import/report generation, NLP search, automated playbooks, PIRs, RBAC, SaaS hosting, support.
- Target user: SOC/CTI teams, IR analysts, MSSPs needing a shared structured intel repository.
- Strength vs. T1/T2 fast lookup: 300+ one-click integrations; strong for correlating an indicator against accumulated org threat-actor/campaign/TTP context once deployed.
- Weakness vs. T1/T2 fast lookup: Requires deployment/administration or an EE contract, plus STIX modeling discipline — it's a knowledge base, not a zero-setup fast-answer console.
- Source: [filigran.io/platform/opencti](https://filigran.io/platform/opencti/)

**MISP**
- What it is: Open-source platform for collecting, storing, correlating, and sharing IOCs/threat intel between trusted communities.
- Hosting: Self-hosted only, no official SaaS.
- Free/paid: 100% free and open source (STIX, OpenIOC, REST API, PyMISP); no paid tiers.
- Target user: Incident analysts, ISACs/sharing communities, malware reversers.
- Strength vs. T1/T2 fast lookup: Free, powerful correlation engine and MITRE ATT&CK galaxy tagging once populated; strong for institutional indicator history.
- Weakness vs. T1/T2 fast lookup: Requires standing up and feeding your own instance before it's useful for anything — no out-of-the-box paste-and-go; reputation is whatever feeds you've imported, not a live multi-source consensus.
- Source: [misp-project.org](https://www.misp-project.org/), [github.com/MISP/MISP](https://github.com/MISP/MISP)

**TheHive + Cortex (StrangeBee)**
- What it is: TheHive = Security Incident Response Platform (case management for SOC/CSIRT/CERT). Cortex = companion observable-analysis engine (300+ analyzers/responders — VirusTotal-class, AbuseIPDB-class, Joe Sandbox, Shodan, DomainTools) usable standalone or plugged into TheHive.
- Hosting: Self-hosted (both), plus StrangeBee-hosted Cloud Platform plans for TheHive.
- Free/paid: Cortex + Cortex-Analyzers remain fully free/open-source (AGPL). TheHive 5.3+ requires registering a free Community-Edition license via StrangeBee's portal (the UI drops to read-only without it) plus paid Gold/Platinum on-prem tiers and separate Cloud Platform plans; exact prices **unverified** (pricing pages returned HTTP 403 on fetch).
- Target user: SOC/CSIRT/CERT teams doing structured incident case management; Cortex useful standalone to any team wanting a self-hosted multi-analyzer enrichment engine.
- Strength vs. T1/T2 fast lookup: Cortex specifically is the closest architectural cousin to SOCDesk's lookup loop — one IOC in, many-source analyzer results out, self-hosted and free.
- Weakness vs. T1/T2 fast lookup: Cortex requires self-hosting and per-source API-key configuration — real setup burden vs. SOCDesk's zero-install/zero-account browser use. TheHive itself is a case-management tool for after triage, not a fast-lookup console, and its "free" CE now has an account/license-registration step SOCDesk doesn't have.
- Source: [strangebee.com](https://strangebee.com/), [docs.strangebee.com/thehive/installation/licenses/about-licenses](https://docs.strangebee.com/thehive/installation/licenses/about-licenses/), [github.com/TheHive-Project/Cortex-Analyzers](https://github.com/TheHive-Project/Cortex-Analyzers)

**Recorded Future**
- What it is: Commercial enterprise threat-intel platform — technical, geopolitical, dark-web, vulnerability, and third-party/vendor-risk intelligence, with proprietary Insikt Group research.
- Hosting: SaaS (vendor-hosted).
- Free/paid: No free tier. Three packages — Core, Professional, Elite. Pricing not published; secondary-source estimates (**unverified**) put annual contracts roughly $50K–$500K+/yr depending on org size/modules.
- Target user: Enterprise/mid-to-large security orgs with a dedicated CTI function and budget.
- Strength vs. T1/T2 fast lookup: Very deep, curated, analyst-augmented intelligence no free/OSS aggregator matches.
- Weakness vs. T1/T2 fast lookup: Not a walk-up-and-paste tool for an individual analyst — a paid, contracted enterprise platform, out of reach/scope except as the ceiling of what "enterprise CTI" looks like. **Notable: Recorded Future's own browser extension (get a verdict in front of the analyst without a copy-paste) was the internal design benchmark for SOCDesk's extension** — see §4.
- Source: [recordedfuture.com/pricing](https://www.recordedfuture.com/pricing)

**Anomali (ThreatStream)**
- What it is: Commercial "Managed Intelligence as a Service" platform — aggregates/curates/confidence-scores threat feeds, correlates IOCs to TTPs/campaigns/actors, API-first, with an "Anomali Copilot" NL-query feature.
- Hosting: SaaS/managed service, not self-hosted.
- Free/paid: No free tier. Secondary-source pricing (**unverified**, not vendor-published): AWS Marketplace listing ≈$150,000/yr for a 3,500-employee Enterprise subscription; average annual cost cited around $93,000 (range up to ≈$180,000).
- Target user: SOC and dedicated CTI teams at mid-to-large enterprises.
- Strength vs. T1/T2 fast lookup: Large curated intel repository plus native SIEM/telemetry fusion — lookups enriched with internal environment context, not just public reputation.
- Weakness vs. T1/T2 fast lookup: Paid-only, managed-service onboarding, built for a CTI program, not a solo walk-up lookup.
- Source: [anomali.com/products/threatstream](https://www.anomali.com/products/threatstream)

**ThreatConnect (now part of Dataminr)**
- What it is: TIP + SOAR platform combining threat-intel aggregation/contextualization, risk-based prioritization, and case management/automation. **Acquired by Dataminr, deal closed 2026 (~$290M)** — content now lives under dataminr.com; threatconnect.com/platform redirects there. Easy-to-miss fact for anyone citing it as a standalone vendor today.
- Hosting: Cloud/SaaS; holds FedRAMP Authorization for gov cloud; 20+ US federal agencies and 250+ global enterprises cited in acquisition coverage.
- Free/paid: No free tier; custom/quotation-based pricing only.
- Target user: Large enterprise and federal government security programs.
- Strength vs. T1/T2 fast lookup: TIP + SOAR + case management in one hub — an indicator can flow straight into automated response.
- Weakness vs. T1/T2 fast lookup: Enterprise/gov procurement-only, custom-quoted, now bundled into a larger AI-intelligence platform post-acquisition — nowhere near a free/instant/no-account experience.
- Source: [dataminr.com/threatconnect](https://www.dataminr.com/threatconnect) (redirect target), [cyberscoop.com/dataminr-threatconnect-acquisition](https://cyberscoop.com/dataminr-threatconnect-acquisition/), [bankinfosecurity.com — Dataminr to buy ThreatConnect for $290M](https://www.bankinfosecurity.com/dataminr-to-buy-threatconnect-for-290m-in-intelligence-push-a-29809)

*Note: Yeti and EclecticIQ were considered as possible additional open-source CTI platforms but did not surface with verifiable current detail in this research pass — flagged as unresearched rather than included speculatively.*

---

### 2.3 Script deobfuscation / analysis

**CyberChef (GCHQ)**
- What it is: Open-source "Cyber Swiss Army Knife" — a browser-based drag-and-drop toolkit for building data-transformation "recipes" (decode, decompress, hash, extract, etc.).
- Hosting: Client-side browser web app; also self-hostable/offline.
- Free/paid: Fully free and open-source (Apache 2.0), no tiers.
- Target user: Technical analysts comfortable building their own operation chains.
- Client-side / no transmission: **Confirmed** — "none of your recipe configuration or input is ever sent to the CyberChef web server" (GitHub README).
- Strength vs. SOCDesk's use case: Extremely flexible low-level primitives (Base64, XOR, regex, entropy, etc.).
- Weakness vs. SOCDesk's use case: **Confirmed it does not compete on the "paste a script, get a plain-English MITRE-mapped breakdown" front.** It has an "Automated encoding detection / Magic" heuristic, but no automated ATT&CK technique tally, no kill-chain narrative, and no IOC-to-reputation pivot. The analyst must manually assemble and interpret the recipe — it's a toolkit, not an analysis engine.
- Source: [github.com/gchq/CyberChef](https://github.com/gchq/CyberChef), [gchq.gov.uk/news/cyberchef-cyber-swiss-army-knife](https://www.gchq.gov.uk/news/cyberchef-cyber-swiss-army-knife)

---

### 2.4 Sandbox / detonation

*(Different mechanism from SOCDesk's static/deterministic analyzer — these execute the artifact rather than parse it. Included because a T1/T2 analyst facing an obfuscated script or suspect file will reach for one of these as the alternative path.)*

**ANY.RUN**
- What it is: Interactive cloud sandbox — live, hands-on malware/URL detonation with a real-time VM.
- Hosting: SaaS. Client-side: **No** — requires submission to ANY.RUN's cloud infrastructure.
- Free/paid: Free "Community" = 20% of functionality, 60s VM timeout, 16MB max file, basic reports, personal/non-commercial license, **public analyses only**. Paid "Hunter" (individual) = 70% functionality, 660s timeout, 100MB, private analyses, price on request. "Enterprise Suite" = 100%, SSO, 1,500+ API tasks/mo, custom price.
- Strength vs. SOCDesk's use case: Best-in-class for watching malware actually execute (process tree, network, registry) — far deeper than any static parser for genuinely packed/obfuscated binaries.
- Weakness vs. SOCDesk's use case: Requires an account and real execution (minutes, not seconds); free-tier submissions are **public by default** — pasting a script containing real org hostnames/IPs is an OPSEC problem SOCDesk's local-only analysis avoids entirely.
- Source: [any.run/plans](https://any.run/plans/)

**Joe Sandbox**
- What it is: Deep automated + interactive malware/phishing sandbox, hybrid static+dynamic analysis.
- Hosting: SaaS (Cloud); on-prem/appliance also sold commercially. Client-side: No.
- Free/paid: Free "Cloud Basic" = max 15 analyses/month, 5/day, limited output. Paid "Cloud Pro" reported ≈$499/month (**unverified**, secondary pricing aggregator, not confirmed on the official site).
- Strength: Very deep automated reports, works against evasive samples via hybrid analysis.
- Weakness vs. SOCDesk's use case: Execution-based, rate-limited free tier (15/month is low for a daily habit), account required — not designed for pasting an ad-hoc console script and getting an instant read.
- Source: [joesandbox.com](https://www.joesandbox.com/), [joesecurity.org/joe-sandbox-cloud](https://www.joesecurity.org/joe-sandbox-cloud)

**Hybrid Analysis (CrowdStrike Falcon Sandbox)**
- What it is: Free public malware sandbox powered by Falcon Sandbox — static + dynamic analysis with MITRE ATT&CK mapping.
- Hosting: SaaS. Client-side: No.
- Free/paid: Free for community use, public API key available; max upload 250MB. **All uploaded files are made available to the community for YARA/string search** — submissions are effectively public.
- Strength vs. SOCDesk's use case: Genuinely does ATT&CK technique mapping on observed behavior (confirmed via CrowdStrike datasheet) plus IOC extraction — closer to SOCDesk's "MITRE tally + IOC extraction" ambition than any other sandbox reviewed, but achieved via execution rather than static/deterministic parsing.
- Weakness: Execution-based (slower); free-tier submissions are shared with the community — a real OPSEC problem for a script containing real internal hostnames/IPs/credentials.
- Source: [hybrid-analysis.com](https://hybrid-analysis.com/), [hybrid-analysis.com/docs/api/v2](https://hybrid-analysis.com/docs/api/v2), CrowdStrike Falcon Sandbox datasheet (PDF)

**Triage / tria.ge (Recorded Future, formerly Hatching Triage)**
- What it is: Free public automated malware sandbox, fast triage-focused.
- Hosting: SaaS (free public cloud); "Recorded Future Enterprise Sandbox" is the paid private version. Client-side: No.
- Free/paid: Free public tier — submissions are **publicly visible and cannot be deleted** (explicit FAQ warning). Enterprise tier = private-by-default, org-restricted, price on request.
- Weakness vs. SOCDesk's use case: Same OPSEC problem as ANY.RUN/Hybrid Analysis — free tier means public, non-deletable submissions, a hard blocker for anything containing real organizational identifiers.
- Source: [tria.ge/docs/faq](https://tria.ge/docs/faq/), [hatching.io/triage](https://hatching.io/triage/)

**Filescan.io (MetaDefender Sandbox)**
- What it is: Free emulation-based sandbox with adaptive/evasion-resistant analysis and IOC extraction; markets some private-upload/encryption options.
- Hosting: SaaS. Client-side: No.
- Free/paid: Free tier available; encrypted-private-upload feature claim is **partially unverified** — found via search-result summary, not independently fetched from the official site.
- Source: [filescan.io](https://www.filescan.io/) — not independently fetched; treat feature/pricing claims as unverified pending direct confirmation.

---

### 2.5 Adjacent (different lane, worth noting)

**PhishTool**
- What it is: Forensic email/phishing analysis platform — parses headers, links, attachments from reported phishing emails. Different lane from script deobfuscation or general IOC reputation lookup; overlaps SOCDesk only tangentially (IOC extraction from a different artifact type).
- Hosting: SaaS.
- Free/paid: Free "Community" = individual analyst, email upload/parse, header/body/link/attachment inspection, analyst notes. "Professional" listed as "Coming Soon" on the official site (300 analyses/month + case in-tray). "Enterprise" = flexible pricing, mailbox ingestion, API, SSO/SAML, multi-user.
- Weakness vs. SOCDesk's use case: Not a script analyzer at all — no PowerShell/cmd deobfuscation, no MITRE tally; requires account signup even for the Community tier.
- Client-side: Unverified (app subdomain returned HTTP 403 to automated fetch; presumed server-side given account-based email ingestion, not confirmed).
- Source: [phishtool.com](https://www.phishtool.com/)

---

### 2.6 Host-search / commercial reputation anchors

**Shodan**
- What it is: Internet-wide device/service/vulnerability search engine — used defensively for exposure/host lookup (what's running on this IP), not reputation scoring.
- Hosting: SaaS.
- Free/paid: Free registered-account API plan is heavily limited (no advanced filters, no vuln search, no batch lookups). Paid: $49 one-time Membership; subscriptions $69/mo (Freelancer) to $1,099/mo (Corporate); Enterprise custom.
- Strength vs. T1/T2 fast lookup: Unmatched host/banner/exposure data if the analyst is investigating what services an IP is running, not whether it's malicious.
- Weakness: Not a reputation/verdict tool — no detection consensus; free tier is crippled enough that real use requires payment.
- Source: [Shodan Book](https://book.shodan.io/getting-started/platform/), [Shodan Enterprise comparison](https://enterprise.shodan.io/product-comparison)

**Censys**
- What it is: Internet-wide host/certificate search platform, Shodan's closest direct competitor.
- Hosting: SaaS.
- Free/paid: 100 credits/month free, host search capped at 1 page/100 results; paid credit packages from $100 (Starter unlocks API access).
- Strength: Strong certificate/infrastructure pivoting.
- Weakness vs. T1/T2 fast lookup: Same gap as Shodan — no reputation consensus, credit-metered even for basics.
- Source: [Censys data access tiers](https://docs.censys.com/docs/data-access-tiers-entitlements), [Censys pricing](https://censys.com/resources/pricing/)

**IBM X-Force Exchange**
- What it is: Web-based CTI portal + API for IP/domain/URL/hash context.
- Hosting: SaaS.
- Free/paid: Guest web login free; non-commercial API free up to 5,000 records/month, then $2,000/10,000 records for commercial API.
- Strength: STIX/TAXII support, deep IBM-curated collections.
- Weakness: Single-vendor view, not a multi-source consensus tool.
- Caveat: Secondary sources reference an EOL migration path for "X-Force Threat Intelligence" toward Palo Alto/QRadar integrations in 2026, but this may refer specifically to the QRadar-integrated feed rather than the public exchange portal — **flagged as ambiguous, not asserted as fact**.
- Source: [X-Force FAQ](https://exchange.xforce.ibmcloud.com/faq) (fetch inconclusive), [secondary EOL reference](https://www.ibm.com/support/pages/node/1193536)

**Cisco Talos Intelligence**
- What it is: Free public reputation lookup for IP/domain/URL/file-hash (Reputation Center + File Reputation tool), ~2M queries/day, data refreshed every 3 hours.
- Hosting: SaaS.
- Free/paid: Full web lookup free; whether basic search requires a Cisco login could not be fully confirmed from the fetched page.
- Strength: Fast, no-account-apparent, high-authority single source.
- Weakness: Single-source (Talos-only) — no cross-vendor consensus, no script analysis, no ticket-ready artifact.
- Source: [Talos File Reputation](https://talosintelligence.com/talos_file_reputation), [Talos Reputation Center](https://talosintelligence.com/reputation_center/)

**Cisco Umbrella Investigate**
- What it is: DNS/passive-DNS/WHOIS relationship-mapping and risk-scoring tool for domains/IPs/files, 5 years of passive DNS history.
- Hosting: SaaS, bundled into the Umbrella platform (not sold standalone per available sources).
- Free/paid: Investigate-specific standalone pricing **could not be verified**; bundled Umbrella platform pricing starts ≈$2.25/user/mo, Pro/Enterprise $4–$8/user/mo.
- Strength: Deep relationship/pivot graph far beyond a reputation card — built for infrastructure attribution.
- Weakness vs. T1/T2 fast lookup: Paid, account-gated, overkill for a single-indicator decision — an investigation tool, not a triage tool.
- Source: [Umbrella Investigate](https://umbrella.cisco.com/products/umbrella-investigate)

---

### 2.7 Browser extensions

*The single most important discovery for this report. Six real, currently-published browser extensions do multi-source or aggregated IOC lookup via right-click or auto-detection. None of them combine that with script/PowerShell deobfuscation — every one either has no script-analysis feature at all, or explicitly links out to CyberChef for decoding rather than embedding it.*

**VT4Browsers + Google TI** (official VirusTotal extension)
- What it is: Auto-detects IOCs on any page, shows detection ratio + Google Threat Intelligence (Mandiant + VT + Google visibility) enrichment inline; proactively scans downloads.
- Scale: 100,000+ users, 4.3★ (327 ratings), free, v5.0.3 — by far the most-installed extension in this space.
- Multi-source: Blends Mandiant/VT/Google signal, but it's a single-vendor (Google) data pipe, not an aggregator of independent third-party services (no AbuseIPDB/GreyNoise/etc.).
- Right-click support and account requirement: not confirmed from the store listing.
- Script/deobfuscation capability: **none found.**
- Source: [Chrome Web Store](https://chromewebstore.google.com/detail/vt4browsers-+-google-ti/efbjojhplkelaegfbieplglfidafgoka)

**SOCMaster**
- What it is: Right-click context-menu lookup ("select or highlight an artifact and right-click") across VirusTotal, AbuseIPDB, AlienVault OTX, Hybrid Analysis, urlscan.io, Pulsedive, Twitter, Google Search — genuine multi-source.
- Scale: 147 users, 5.0★ (3 ratings), free, v0.6.0 (updated Aug 2025).
- Friction: **Requires the analyst to supply their own API key per vendor** for IP/domain/hash/URL scans (only OS-command/registry/event-ID lookups are keyless) — the opposite of SOCDesk's zero-setup model.
- Script/deobfuscation capability: none.
- Source: [Chrome Web Store](https://chromewebstore.google.com/detail/socmaster/mgodnpglndjnfpddlamphecaheodnafc)

**SOC Toolkit**
- What it is: Open-source, cross-browser (Chromium + Firefox) lookup across VirusTotal, AbuseIPDB, GreyNoise, IBM X-Force, Talos, AlienVault OTX, Winbindex — and it **links out to CyberChef** for decoding rather than embedding deobfuscation itself.
- Scale: 34 users, unrated, free.
- Right-click support: not confirmed in the listing text.
- Source: [Chrome Web Store](https://chromewebstore.google.com/detail/soc-toolkit/ibjcnpellfbdleipcipmmhnjdcabhffo)

**Ahtapot**
- What it is: GitHub-published, actively maintained (v3.0.0, Dec 2025). Broadest source list found — VirusTotal, AlienVault OTX, AbuseIPDB, MalwareBazaar, ARIN, Shodan, GreyNoise, URLhaus, Pulsedive, Scamalytics (10 providers) — plus optional AI analysis via user-supplied Claude/Gemini/GPT-4o keys. Right-click "Analyze with Ahtapot" confirmed.
- Friction: **Requires the analyst to bring their own API key for nearly every provider** (only ARIN WHOIS and URLhaus are keyless) — again the inverse of SOCDesk's model, where keyed calls route through SOCDesk's own backend so the analyst never touches a key.
- Script/deobfuscation capability: none documented.
- Free.
- Source: [github.com/abdullahcicekli/ahtapot](https://github.com/abdullahcicekli/ahtapot)

**OZZI: IOC Search**
- What it is: Right-click lookup ("highlight an IOC, right-click, select 'Search OZZI for'") across a very broad per-type source list (IP: VT, Scamalytics, AbuseIPDB, IBM X-Force, ISC SANS, Talos, AlienVault, ARIN, Shodan, Threatminer, Pulsedive — 11 sources; similar breadth for hashes/URLs/ports).
- Scale: 346 users (the highest of the small extensions), 5.0★ (2 ratings), free.
- Mechanism: **Opens each source as a separate background tab — not a single consensus card.** No unified verdict/aggregation UI, which is the core thing SOCDesk's escalation card is built to do.
- No account requirement indicated. No deobfuscation.
- Source: [Chrome Web Store](https://chromewebstore.google.com/detail/ozzi-ioc-search/bfcfhnejnppmdepgdgjeibmcimcmcpli)

**IOChaser**
- What it is: Auto-extracts and normalizes IOCs from a page (including defanged formats), pivots to VirusTotal, AbuseIPDB, Shodan, Censys, GreyNoise.
- Scale: 22 users, 5.0★ (2 ratings), free.
- API keys stored locally, no account creation needed. Right-click support not confirmed. No deobfuscation.
- Source: [Chrome Web Store](https://chromewebstore.google.com/detail/iochaser/gjomgdkjfhpmmmlleefbblnfeanmniem)

**Cross-cutting finding:** Despite deep discovery search, no extension was found that combines script/PowerShell deobfuscation-and-analysis with IOC reputation lookup in a single right-click tool. Every multi-source competitor found does indicator lookup only; several link out to CyberChef rather than embedding decode logic. All are small (22–346 installs) except the official VT4Browsers extension (100k+, but single-vendor data, no third-party aggregation). Most third-party aggregators also require the analyst to supply and manage their own per-vendor API keys — a real friction point SOCDesk's "no account, zero setup" model avoids by routing keyed calls through its own backend function.

---

## 3. Comparison tables

Column definitions (kept strict — a tool only gets a full ✓ if it genuinely meets the bar, not if it's merely adjacent):

- **Fast lookup** — can a T1/T2 analyst get a decision on one pasted indicator in well under a minute, with no unrelated UI to learn first? ✓ = yes, built for exactly this. ~ = possible but not the tool's design center, or requires setup first. ✗ = fundamentally not a single-indicator instant-answer tool.
- **Multi-source consensus** — does it aggregate ≥3 independent third-party sources into one unified view? ✓ = yes. ~ = fans out to multiple sources without unifying them (e.g., opens separate tabs), or blends data that's still ultimately one vendor's pipe. ✗ = single source.
- **Client-side / no-account** — ✓ only if no signup is required for core use **and** sensitive input never has to leave the browser. ~ = no-account but the input necessarily leaves the browser to a third party, or vice versa. ✗ = account/API keys required of the analyst.
- **Script deobfuscation** — ✓ = automated PowerShell/cmd/script decode plus MITRE-mapped interpretation, no execution required. ~ = manual low-level decode primitives (CyberChef-style), or interpretation only achieved via execution (sandboxes). ✗ = none.
- **Ticket-ready artifact** — ✓ = produces a clean, attributed, copy-paste-ready output built specifically for pasting into a ticket/escalation email. ~ = a report exists but isn't designed as a clean escalation artifact. ✗ = none.
- **Extension** — has a browser extension. ✓ / ✗.
- **Self-hostable** — can the whole tool run on your own infrastructure, no vendor dependency? ✓ / ~ (source available but not packaged/supported as self-host) / ✗ (SaaS-only).
- **Cost** — Free / Freemium (with rough paid figure) / Paid-only.

### 3.1 Aggregator / enrichment

| Tool | Fast lookup | Multi-source | Client-side/no-acct | Script deobfusc. | Ticket-ready | Extension | Self-hostable | Cost |
|---|---|---|---|---|---|---|---|---|
| **SOCDesk** | ✓ | ✓ (8 sources) | ✓ | ✓ | ✓ | ✓ | ~ (OSS, not packaged) | Free |
| IntelOwl | ~ (post-deploy) | ✓ (50+ analyzers) | ✗ | ✗ | ~ | ✗ | ✓ | Free/OSS |
| Pulsedive | ✓ | ~ (indexed DB) | ~ | ✗ | ✗ | ✗ | ✗ | Freemium (~$29/mo Pro) |
| ThreatFox | ✓ | ✗ (single-source) | ~ | ✗ | ✗ | ✗ | ✗ | Free |
| urlscan.io | ✓ (URL only) | ✗ (deep single tool) | ~ (public on free) | ✗ | ~ | ✗ | ✗ | Freemium ($50–4,166/mo) |
| VirusTotal | ✓ | ✓ (60+ AV engines, one vendor) | ~ (rate-limited) | ✗ | ~ | ✓ (official) | ✗ | Freemium (noncommercial free) |
| Maltiverse | ✓ | ✓ (100+ sources) | ✗ | ✗ | ~ | ✗ | ✗ | Freemium (pricing unverified) |
| GreyNoise Visualizer | ✓ (IP only) | ✗ (specialist source) | ✗ (biz email req.) | ✗ | ✗ | ✗ | ✗ | Freemium (50/wk free) |
| AbuseIPDB | ✓ (IP only) | ✗ (single source) | ~ | ✗ | ~ | ✗ | ✗ | Freemium ($25–99/mo) |
| AlienVault OTX | ✓ | ✗ (single source) | ✗ (acct req.) | ✗ | ✗ | ✗ | ✗ | Free (account required) |

### 3.2 CTI platforms

| Tool | Fast lookup | Multi-source | Client-side/no-acct | Script deobfusc. | Ticket-ready | Extension | Self-hostable | Cost |
|---|---|---|---|---|---|---|---|---|
| **SOCDesk** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ~ | Free |
| OpenCTI | ✗ (knowledge base) | ✓ (300+ integrations) | ✗ | ✗ | ✗ | ✗ | ✓ (CE) | Free CE / custom EE |
| MISP | ✗ | ~ (whatever's imported) | ✗ | ✗ | ✗ | ✗ | ✓ | Free/OSS |
| TheHive + Cortex | ~ (Cortex alone) | ✓ (Cortex, 300+ analyzers) | ✗ | ~ (some analyzers) | ✗ (case ticket, not escalation card) | ✗ | ✓ (or paid Cloud) | Free Cortex; TheHive free w/ license + paid tiers |
| Recorded Future | ~ (paid extension) | ✓ (proprietary+fused) | ✗ | ✗ | ~ | ✓ (paid-gated) | ✗ | Paid only (~$50K–500K+/yr est.) |
| Anomali (ThreatStream) | ✗ | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ | Paid only (~$93K–180K/yr est.) |
| ThreatConnect (Dataminr) | ✗ | ✓ | ✗ | ✗ | ~ (case mgmt) | ✗ | ✗ | Paid only, custom quote |

### 3.3 Script analysis & sandbox

| Tool | Fast lookup | Multi-source | Client-side/no-acct | Script deobfusc. | Ticket-ready | Extension | Self-hostable | Cost |
|---|---|---|---|---|---|---|---|---|
| **SOCDesk** | ✓ | ✓ | ✓ | ✓ (automated, MITRE-mapped) | ✓ | ✓ | ~ | Free |
| CyberChef | ~ (manual recipes) | ✗ (not an IOC tool) | ✓ | ~ (manual toolkit, no auto MITRE) | ✗ | ✗ | ✓ | Free/OSS |
| ANY.RUN | ✗ (minutes, execution) | ✗ | ✗ (acct, public free tier) | ~ (via execution) | ~ | ✗ | ✗ | Freemium |
| Joe Sandbox | ✗ | ✗ | ✗ | ~ (via execution) | ~ | ✗ | ~ (on-prem sold) | Freemium (15/mo free) |
| Hybrid Analysis | ✗ | ✗ | ✗ (public/shared) | ~ (via execution, MITRE-mapped) | ~ | ✗ | ✗ | Free (public/shared) |
| Triage (tria.ge) | ✗ | ✗ | ✗ (public, non-deletable) | ~ (via execution) | ~ | ✗ | ✗ | Free public / paid Enterprise |
| Filescan.io | ~ | ✗ | ✗ | ~ (via emulation) | ~ | ✗ | ✗ | Freemium (unverified) |

### 3.4 Browser extensions & host-search / commercial anchors

| Tool | Fast lookup | Multi-source | Client-side/no-acct | Script deobfusc. | Ticket-ready | Extension | Self-hostable | Cost |
|---|---|---|---|---|---|---|---|---|
| **SOCDesk** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ~ | Free |
| VT4Browsers (official VT) | ✓ | ~ (single-vendor blend) | ~ | ✗ | ✗ | ✓ | ✗ | Free |
| SOCMaster | ✓ | ✓ | ✗ (BYO API keys) | ✗ | ✗ | ✓ | ✗ | Free (BYO keys) |
| SOC Toolkit | ✓ | ✓ | ✗ (BYO keys likely) | ~ (links to CyberChef) | ✗ | ✓ | ✓ (OSS) | Free |
| Ahtapot | ✓ | ✓ (10 providers) | ✗ (BYO keys, nearly all) | ✗ | ✗ | ✓ | ✓ (OSS) | Free (BYO keys) |
| OZZI: IOC Search | ~ (opens tabs) | ~ (fan-out, not unified) | ✓ (no acct indicated) | ✗ | ✗ | ✓ | ✗ | Free |
| IOChaser | ✓ | ✓ | ~ (local keys, no acct) | ✗ | ✗ | ✓ | ✗ | Free |
| Shodan | ~ (exposure, not reputation) | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | Freemium ($49–1,099+/mo) |
| Censys | ~ (exposure, not reputation) | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | Freemium |
| IBM X-Force Exchange | ✓ | ✗ (single vendor) | ~ (guest login free) | ✗ | ✗ | ✗ | ✗ | Freemium |
| Cisco Talos Intelligence | ✓ | ✗ (single vendor) | ~ | ✗ | ✗ | ✗ | ✗ | Free |
| Cisco Umbrella Investigate | ✗ (investigation tool) | ✗ (deep, single vendor) | ✗ | ✗ | ✗ | ✗ | ✗ | Paid (bundled) |

---

## 4. SOCDesk's distinguishing characteristics — tested against real competitors

Five candidate differentiators, each checked against the closest thing found in this research rather than asserted on faith.

**1. No account, zero setup, for a genuine multi-source consensus lookup.**
*Closest competitors:* VT4Browsers (100k+ users, free, no visible account requirement) and the small right-click extensions (SOCMaster, Ahtapot, SOC Toolkit, IOChaser).
*Verdict — stands apart, precisely.* VT4Browsers has the install base but is a single-vendor (Google/Mandiant/VT) data pipe, not cross-vendor consensus. Every multi-source extension found (SOCMaster, Ahtapot, SOC Toolkit) requires the analyst to obtain and paste in their own API key per vendor before it works — real setup friction SOCDesk avoids by fronting the keys itself through its own Cloudflare Pages Function. IOChaser and OZZI are closer to no-setup, but IOChaser still needs locally-stored keys and OZZI doesn't unify results (it opens separate tabs per source, not a consensus card). No tool found does "paste an indicator, zero account, zero keys, one unified cross-vendor view" simultaneously — SOCDesk is alone on that exact combination.

**2. Deterministic script analyzer paired with reputation lookup in one loop.**
*Closest competitor:* None directly. CyberChef is the only true peer on the "never transmits input" half, but it has no automated IOC-to-reputation pivot and no MITRE-mapped interpretation — it's a manual toolkit. SOC Toolkit acknowledges the same gap by linking out to CyberChef rather than building deobfuscation itself. The sandboxes (ANY.RUN, Joe Sandbox, Hybrid Analysis) achieve a "what did this do" narrative, including MITRE mapping in Hybrid Analysis's case, but only by executing the artifact — slower, account-gated, and (on free tiers) frequently public.
*Verdict — stands apart.* No tool reviewed does automated, execution-free, MITRE-mapped script interpretation *and* one-click pivot of extracted IOCs into a multi-source consensus card in the same product.

**3. The "no synthesized verdict" escalation-card artifact.**
*Closest competitor:* VirusTotal, whose "14 of 94 engines flagged this" tally is explicitly what SOCDesk's own design docs cite as the inspiration.
*Verdict — real but narrower than it first looks.* VT's tally is a single vendor's own engine set, not a cross-service consensus — SOCDesk's contribution is applying that tally model *across* independent services (VT + AbuseIPDB + GreyNoise + MalwareBazaar + OTX, etc.), which none of the single-source tools (Talos, X-Force, GreyNoise, AbuseIPDB) do; those each render their *own* risk classification directly in their own voice. Where SOCDesk is genuinely alone: refusing to say "malicious"/"suspicious"/"safe" in its own voice at all, ever — that's a stricter self-imposed constraint than any competitor profiled here adopts. Combined with the copy-paste-ready formatting (built to be pasted straight into a ticket/email), this is a real, if narrow, differentiator.

**4. The right-click-in-console browser extension.**
*Closest competitors:* SOCMaster and OZZI both do genuine right-click-to-lookup.
*Verdict — the mechanism is not unique; the specific combination is.* Right-click IOC lookup already exists in this space (SOCMaster, OZZI, Ahtapot via context menu). What none of them do: right-click a selection to run it through *script analysis* (not just indicator lookup) in a side panel. Combined with #1 (no BYO keys) and #3 (unified card, not fan-out tabs — OZZI's specific weakness), SOCDesk's extension is the only one found that offers all three at once. But "an extension that right-clicks an indicator" by itself is table stakes, already shipped by at least two small competitors — this should not be oversold as novel on its own.

**5. The data-boundary guarantee (a pasted script never leaves the browser).**
*Closest competitor:* CyberChef, confirmed via its own GitHub README to make the identical guarantee.
*Verdict — not unique in isolation, but unique in combination.* CyberChef got there first and holds the same boundary. Every sandbox (ANY.RUN, Joe Sandbox, Hybrid Analysis, Triage) is the opposite — submission-based, and on free tiers frequently *public*, which is a real OPSEC problem for a script containing an org's actual hostnames/IPs/credentials. SOCDesk's distinguishing move is holding the CyberChef-grade boundary *while also* doing the automated MITRE-mapped interpretation CyberChef doesn't attempt — nobody else in this survey does both.

**Net assessment:** the honest read is that no single element of SOCDesk is unprecedented — every piece has a partial analog somewhere (VT's tally, CyberChef's boundary, SOCMaster's right-click, VT4Browsers' no-account ease). What's actually rare is the *specific combination*, held simultaneously, in one free tool: zero-account multi-source consensus + execution-free MITRE-mapped script interpretation + a boundary guarantee on the script side + a ticket-ready artifact + a right-click extension that does both lookup and analysis. Nothing surfaced in this research does all five at once.

---

## 5. Honest room for improvement, ranked by impact on the T1/T2 loop

**1. No lookup/analysis history (highest impact).** SOCDesk keeps analyst state in `localStorage` (never transmitted, per its own architecture docs) but there is no searchable record of "have I already looked this up," no cross-session recall, and nothing that survives a cleared browser or a different device/shift. An analyst re-triaging the same scanner IP three times in a week, or a handoff between two analysts on the same shift, gets zero benefit from the first lookup. Every CTI platform reviewed (MISP, OpenCTI, TheHive/Cortex, and the paid enterprise anchors) treats institutional indicator memory as core, not optional. **To close:** a local, client-side-only lookup history (IndexedDB or expanded localStorage) with search/filter — no server, no account, stays inside the existing zero-infrastructure architecture. Genuinely closeable without compromising the non-commercial/no-account posture.

**2. No fallback when the script analyzer honestly hits a wall (high impact).** SOCDesk's analyzer is deliberately execution-free and marks unresolved content "opaque" rather than guessing — an honest design choice, not a bug — but for a heavily obfuscated or custom-encrypted payload beyond static analysis's reach, the loop dead-ends inside SOCDesk with no next step offered. ANY.RUN/Hybrid Analysis/Joe Sandbox would actually reveal behavior by running it. **To close (partially, without abandoning the no-execution promise):** a clearly labeled "static analysis reached its limit — here's where to go next" pivot to a free sandbox (e.g., a deep link to ANY.RUN or Hybrid Analysis, the same deep-link-not-mirror pattern SOCDesk already uses for its reputation sources) would close the loop without SOCDesk itself ever executing anything.

**3. Source breadth versus specialist deep-pivot tools (medium impact).** SOCDesk's 8 sources (VirusTotal, AbuseIPDB, GreyNoise, MalwareBazaar, ipinfo, urlscan, RDAP, AlienVault OTX) cover the highest-value day-to-day checks well, but there's no exposure/banner data (Shodan/Censys), no passive-DNS history (Umbrella Investigate), and nothing close to IntelOwl's 50+ or Maltiverse's 100+ analyzer counts. This bites only when the 8-source card comes back inconclusive and the analyst needs one more pivot — not the common case, but a real one. **To close:** cheap in principle — SOCDesk already treats most of its sources as click-through deep links rather than mirrored data; adding a "go deeper" deep-link row (Shodan, Censys, Umbrella Investigate) costs little and stays inside the existing architecture.

**Lower-impact / correctly out of scope for the loop itself (see §6):** no case/team management, no packaged self-hosting, no public automation API, no community contribution/redistribution.

---

## 6. So what — given this is a non-commercial portfolio, not an enterprise CTI platform

**Worth closing**, because each is cheap, stays inside the existing zero-infrastructure/no-account architecture, and directly improves the T1/T2 loop itself:
- Local-only lookup history (§5.1) — the single highest-leverage gap; no server or account needed to fix it.
- A labeled "static analysis hit its limit, try a sandbox" deep-link pivot (§5.2) — closes the analyzer's honest dead-end without compromising the no-execution promise.
- A couple more deep-link pivots for exposure/passive-DNS questions (§5.3) — minor engineering cost, matches the pattern already used for the other 8 sources.

**Correctly out of scope**, because building them would either contradict the tool's actual differentiators or duplicate infrastructure a SOC already has:
- **Case management / team workflow** (TheHive/OpenCTI territory) — a T1/T2 lookup tool feeding into a ticketing system is the right shape; rebuilding a case manager inside a personal portfolio project duplicates what every MSSP's actual ticketing/SOAR stack already does, for no analyst benefit.
- **Packaged self-hosting** — the source is already public on GitHub; formalizing it as a supported self-host product (docs, versioned releases, generic multi-tenant config) is a real, ongoing support burden disproportionate to a non-commercial project, and doesn't change what any individual analyst experiences using the hosted instance.
- **A public automation API** — would turn a free hobby project into an availability dependency for someone else's production SOAR playbook, in direct tension with the "zero infrastructure, no bill" constraint that makes the whole thing sustainable as a portfolio piece.
- **Sandbox/detonation** — directly contradicts the data-boundary guarantee that is one of SOCDesk's few genuinely rare differentiators (§4.5); building it would trade away an identity trait to partially chase a category (malware sandboxing) SOCDesk was never trying to compete in.
- **Community contribution / redistribution** — already closed off deliberately by the repo's own R4 licensing reasoning (`DATA-SOURCES.md`, `COMPLIANCE.md`); not worth relitigating for a non-commercial tool with no legal team behind it.

The overall picture: SOCDesk is not under-featured relative to its actual competitive set — the T1/T2 fast-lookup + script-triage loop, done with zero account and zero setup — it is under-featured relative to enterprise CTI platforms it was never trying to be, and the gaps worth closing are exactly the ones that make the *existing* loop faster, not the ones that would turn it into a different product.


