# SOCDesk — Session Handoff

**Written:** 2026-08-08 · **Read this first, then `docs/AUTOMATION.md`, `COMPLIANCE.md`, `design-system.md`.**

---

## 1. What this is

**SOCDesk** — a free, public, static threat-intelligence console. An analyst
pastes any indicator (IP, domain, hash, URL, CVE, email) and gets:

1. **A verdict** — authoritative for CVEs (CISA KEV + NVD CVSS + FIRST EPSS);
   for other types an honest "not in corpus" plus type-aware deep links to the
   right public reputation services.
2. **A ticket-ready escalation summary** — the differentiator. No other public
   tool writes the write-up.
3. A ranked threat feed, KEV/EPSS vulnerability triage, ATT&CK actor and
   malware profiles, collection health, source registry, and an analyst
   toolbelt (defang, UTF-16LE Base64 decode, PowerShell parser, IOC extract,
   LOLBin lookup).

Personal project by Carlos Sanchez (SaltyCarl), sibling to his portfolio
**SanchezOnSecurity.com**. Used by his MSSP SOC team; also a portfolio piece.

**Live:** https://saltycarl.github.io/socdesk/
**Repo:** https://github.com/SaltyCarl/socdesk
**Local path:** `C:\Users\Carl\Desktop\Projects\VIGIL\` ⚠️ *folder is still named
VIGIL; the product was renamed to SOCDesk on 2026-08-08. Do not be confused.*
**Domain:** `socdesk.io` registered (Cloudflare), **DNS not yet pointed** — see §8.

---

## 2. Architecture

Three tiers, each independently degradable:

- **Tier 1 — collection.** GitHub Actions cron (`:11`/`:41`) runs 5 Python
  collectors → normalised JSON → schema gate with last-known-good fallback →
  deploy. `data/state/` is committed (last-known-good + daily history
  snapshots); `site/data/` is gitignored and regenerated every run.
- **Tier 2 — brief (not built).** Framework Desktop will write `data/brief.json`
  via local LLM; the pipeline already passes it through and the site already
  renders an absent-state. Deploy-key pushes retrigger the workflow;
  `GITHUB_TOKEN` state commits do not — that asymmetry is intentional.
- **Tier 3 — site.** Static, vanilla ES modules, no framework, no build step.
  GSAP + d3 from CDN with SRI. Analyst state in localStorage only.

**Collectors (all keyless/public):** CISA KEV · NVD (recent-modified **plus the
full KEV catalogue via `hasKev`**) · FIRST EPSS · Ransomware.live (group-level
only) · RSS pool (9 feeds).

**Aggregator rule (COMPLIANCE.md):** we publish only clearly-redistributable
data. Reputation corpora (abuse.ch, VirusTotal, AbuseIPDB) are reached by
**user-clicked deep links, never mirrored**. This is why there is no
`iocs.json`.

---

## 3. Current state

- **47 Playwright + 47 pytest green** (counts drift as work lands; run both).
- Pipeline clean: `problems=[]`.
- CSP is strict — `default-src 'none'`, **no `unsafe-inline`, no `unsafe-eval`**.
  Served via `_headers` (Cloudflare) and a `<meta>` tag (GitHub Pages).
- Self-hosted fonts (no Google requests), PNG OG card, mug favicon.
- Service worker gives offline capability.

**Recently fixed, do not regress:**
- **CVE join** — was 42 of 1,662 KEV rows with CVSS (2.5%); now **1,662/1,662**.
  Root cause: NVD only fetched a 2-day modified window while KEV spans
  2014-2026. Fixed with a second `hasKev` query in `collectors/nvd.py`.
- **Feed relevance** — `pipeline/relevance.py` scores every item 0-100 with an
  explainable `why` array, and groups repetitive ransomware victim-claim stubs.
  594 items → 302.

---

## 4. In flight RIGHT NOW (check before doing anything)

Two agents were dispatched and may still be mid-edit:

1. **Front-end console rebuild** — owns `site/index.html`, `site/css/*`,
   `site/js/*`. Converting the editorial scroll-page into an operational
   console: verdict gets its own full-width region under the search (no scroll
   jump), escalation summary rendered as a docket instead of raw markdown,
   hash deep-linking (`#q=<indicator>`), topbar nav switches views in place,
   feed becomes a score-sorted work queue, masthead collapses, mobile
   breakpoint added, status dot turned green.
2. **Relationship index** — owns `pipeline/relations.py`, `schemas/`, `tests/`,
   `docs/RELATIONSHIPS.md`. Building an evidence-backed entity graph
   (ATT&CK actor→technique→software + feed co-occurrence) and delivering a
   verdict on whether to visualise it as a node-link graph or a ranked
   "related entities" list.

**First action in a new session:** `git status` and `git log --oneline -10` to
see whether their work landed. If `site/css/panels.css` contains `.vconsole`
rules, the front-end agent got at least partway.

---

## 5. Design law (binding)

`design-system.md` v4 **"Chart Room"** — brutalist-editorial print.

- Ink `#0F161C` · panel `#141D26` · line `#263644` / `#3C566C`
- Paper/accent **bone `#E8E1CF`** (carries the brand; solid fills with dark text)
- **Vermilion `#E2513A` at stamp scale ONLY** — seal, never illumination
- Severity as desaturated print inks; **purple = AI content only**;
  **gray = unknown, never green**
- Archivo (variable, expanded caps) + IBM Plex Mono for all data values
- **Zero border-radius. No shadows. No glows. No gradients on components.**
- Motion is scarce and data-honest; the only ambient motion is the ticker,
  status pings, and the mug's steam

**The mark:** a pixel coffee mug, a deliberate sibling of the SoS logo (**no
handle** — the parent has none). Agreed lockup law: *the seal always lives at
the O.* Word ≤32px → the mug **is** the O (letter cut). Word >32px → the type O
returns and the same-size mug is struck **inside its counter**. The mug never
scales; the word does. Favicon = the seal alone.

**Direction is settled — do not re-litigate.** An art-direction review
confirmed Chart Room works and that a pivot would burn weeks. The owner's
complaints were about *information architecture and data plumbing*, not the
visual language.

---

## 6. Environment gotchas (each of these cost real time)

- **Service worker masks your changes.** The shell is cached cache-first.
  **Bump `VERSION` in `site/sw.js` on every shell change** or you (and every
  returning visitor) will see the old UI. Masked three changes this session.
- **CSP has no `unsafe-inline`** — a single `style=""` attribute or inline
  `<script>` breaks it. `csp.spec.js` catches it. Use classes or
  `el.style.setProperty()` (CSSOM writes are allowed).
- **`<use href="#symbol">` renders into shadow DOM** — outer CSS cannot style
  non-inheritable properties (opacity, animation) there. Inline the SVG if you
  need to animate it.
- **IntersectionObserver `threshold` > 0 never fires on elements taller than
  the viewport.** Use `threshold: 0`. This left 18 elements permanently
  invisible once.
- **Python:** no `python` on PATH. Use `.venv\Scripts\python.exe`.
  (Installed 3.12.10 via winget this session.)
- **Playwright MCP browser lock:** if it errors "browser is already in use",
  kill Chrome processes whose command line contains `ms-playwright-mcp`, then
  retry. `file://` is blocked — serve over HTTP.
- **Local servers:** `:8473` serves `site/`, `:8471` serves the repo root
  (mockups). Node one-liners; restart if a session ends.
- **Domain checks:** Comcast DNS hijacks NXDOMAIN so everything looks
  registered. Use `https://rdap.org/domain/<name>` (404 = available).
- **Agents die** emitting >32k output tokens — instruct chunked Write+Edit
  builds under ~15KB per call, always. Agent transcripts also expire; re-brief
  fresh rather than assuming a resume works.
- **Rebase conflicts on `data/state/*.json`** are generated data — take either
  side and re-run the pipeline.

---

## 7. Verification discipline (non-negotiable)

The cautionary tale: sanitization was committed, declared safe, and shipped
with **two working XSS bypasses** (an unterminated tag borrowing a `>` from
surrounding markup; a scheme-prefix URL check allowing attribute breakout).
Both now have regression tests.

- "Fixed" requires a test that fails without the fix.
- "Renders" requires a screenshot and a clean console.
- "Works" requires pasted command output.
- Never trust an agent's summary — re-run it yourself.
- A green first run of a new test suite is suspicious.

---

## 8. Pending — owner actions

- **DNS for socdesk.io** (only blocker): Cloudflare → CNAME, name `@`, target
  `saltycarl.github.io`, **proxy DNS-only (grey cloud)** — GitHub can't issue
  the cert through the proxy. Then: ship `site/CNAME.pending` → `site/CNAME`,
  set `og:image`/`og:url` to the socdesk.io host, enable HTTPS enforcement.
- Optional: read the employment IP-assignment clause before promoting widely
  (parked by owner; still gates the honeypot phase).

---

## 9. Backlog, in priority order

1. Finish/verify the two in-flight agent workstreams (§4).
3. **Enrichment Worker** — spec written:
   `docs/superpowers/specs/2026-08-07-enrichment-worker-spec.md`. One stateless
   Cloudflare Worker gives real reputation verdicts instead of pivot links,
   plus **urlscan screenshot previews (search only — never submit)**. Biggest
   remaining capability gain; still $0.
4. Static-tier wins left: client-side fuzzy search, CVE corpus sharding.
5. **Cloudflare Pages** instead of GitHub Pages — regains `_headers` (real
   header CSP with `frame-ancestors`) and easier custom domain. Lateral, cheap.
6. Phase C — Framework brief loop (`data/brief.json`).
7. Phase D — own Cowrie honeypot sensor. Architecture and security review in
   `BACKLOG.md`; **gated on the IP question**. Non-negotiables: no Tailscale on
   the sensor, cloud-plane egress deny, publish /24s not full IPs, allowlist
   published tokens, rebuild from cloud-init never snapshots.
8. Wave-2 collectors (FeodoTracker, C2IntelFeeds, PhishTank, APTnotes) —
   see `BACKLOG.md`.

---

## 10. Key documents

| File | What it holds |
|---|---|
| `docs/AUTOMATION.md` | The autonomous build loop, Definition of Done, when to swarm, hard gates |
| `COMPLIANCE.md` | Licensing/legal findings + launch gates. **Read before adding any data source.** |
| `design-system.md` | Chart Room v4 — binding visual law |
| `design/brand.md` | Brand book (partly stale: "lit I" rule and triangulation mark are dead — mug seal replaced them) |
| `BACKLOG.md` | Wave-2 collectors, knock-knock review, honeypot architecture + security review, CARL port notes |
| `docs/INFRASTRUCTURE-OPTIONS.md` | What each infra tier unlocks and costs |
| `docs/superpowers/plans/` | Phase A (pipeline, done) and Phase B (site) plans |
| `design/mockups/g-chartroom.html` | The approved visual reference |
| `design/mockups/h-sensor.html` | Honeypot dashboard mockup w/ 3 globe styles |

**Attribution policy:** all commits are SaltyCarl with **no AI attribution**
anywhere, including automated ones. Non-negotiable.
