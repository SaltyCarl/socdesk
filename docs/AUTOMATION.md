# VIGIL — Autonomous Build Loop

Operating doctrine for driving VIGIL to deployment-ready with minimal human
input. Written 2026-08-07. Survives context resets: an agent picking this repo
up cold should read this file, `COMPLIANCE.md`, `design-system.md`, and the
active plan in `docs/superpowers/plans/`, then resume at step 1.

## The enhanced instruction

> Drive VIGIL to deployment-ready autonomously. Each cycle: assess actual repo
> state against the Definition of Done; pick the largest slice of remaining
> work; fan out a swarm **only where work is genuinely independent**; integrate
> and verify the results yourself; commit; repeat. Never mark work done on an
> agent's say-so — verify by running it. Stop only at a Hard Gate, and when you
> stop, say precisely what is needed and from whom.

## 1. Definition of Done (the loop's terminating condition)

Deployment-ready means ALL of:

- [ ] `pytest tests/ -q` green; `python run_pipeline.py` clean (`problems=[]`).
- [ ] Production site in `site/` renders every spec-§4 capability against real
      `site/data/*.json` — no sample/mock data anywhere.
- [ ] Playwright suite green, including: an XSS-injection fixture rendering
      inert, a CDN-failure path still showing all data, and a
      reduced-motion path.
- [ ] `_headers` ships a CSP with **no** `unsafe-inline`; zero inline scripts,
      handlers or `style=""` in production output.
- [ ] Visual parity with `design/mockups/g-chartroom.html`, verified by
      screenshot comparison at 1440px — the mockup is the acceptance test.
- [ ] Every COMPLIANCE.md must-fix closed: no mirrored reputation corpora, no
      victim names, disclosure banner prominent, escalation card passes the
      generic test, EPSS attribution present, `noindex` set.
- [ ] Payload budget: total `site/data/` under 10 MB gzipped.
- [ ] README setup steps accurate against a clean clone.

## 2. Cycle structure

1. **Assess** — run the tests and the pipeline; diff repo state against the
   Definition of Done. Never trust the previous cycle's claims; re-verify.
2. **Slice** — take the largest coherent chunk of remaining work.
3. **Swarm or solo** (rules in §3).
4. **Integrate** — the orchestrator (not the agents) wires modules together and
   resolves contract mismatches.
5. **Verify** — run it in a browser. Screenshot. Read the console. Zero errors
   is the bar, not "the agent said it works."
6. **Commit** per logical unit, conventional-commit style, SaltyCarl identity,
   no AI attribution.
7. **Repeat** until the Definition of Done is fully checked or a Hard Gate hits.

## 3. When to swarm, when not to

**Swarm (parallel agents) when tasks are independent — no shared files, no
shared contract:** research sweeps, per-source collectors, isolated utility
ports, test-suite authoring, audits (design conformance, accessibility,
security), documentation, competing design directions.

**Never swarm:** two agents on the same file (they will clobber each other);
anything defining an interface another task consumes; integration/wiring — the
orchestrator holds the DOM/module contract and must do it; final QA judgement.

**Swarm hygiene (learned the hard way this session):**
- Agents die emitting >32k output tokens — instruct chunked Write + Edit builds
  under ~15KB per call, always.
- Agent transcripts expire; re-dispatch fresh with full context rather than
  assuming a resume will work.
- Give every agent the design law, the compliance constraints, and the
  verification command. An unbriefed agent produces off-brand work.
- Require agents to verify in a real browser and report what they actually ran.

## 4. Hard Gates — stop and ask the human

Stop for these; do not proceed autonomously:
- **Secrets / credentials** — Cloudflare tokens, any key. Never enter or
  fabricate them.
- **Public deployment** of anything new, or making a private repo public.
- **Compliance gates in COMPLIANCE.md** that require a human decision —
  notably R2 (employment IP clause) before the honeypot phase.
- **Anything destructive or irreversible** — force-push, history rewrite,
  deleting user data, publishing under someone's identity.
- **Scope changes** the user must choose between (design direction, product
  positioning, feature cut).

Everything else — code, tests, refactors, docs, mockups, research, commits —
proceeds without asking.

## 5. Verification discipline (non-negotiable)

The XSS incident this session is the cautionary tale: sanitization was
committed, declared safe, and shipped with two working bypasses. Therefore:
- A claim of "fixed" requires a test that fails without the fix.
- A claim of "renders" requires a screenshot and a clean console.
- A claim of "works" requires the actual command output pasted in the summary.
- Security-relevant code gets an adversarial review pass before it counts as
  done.

## 6. Phase map

- **Phase A — pipeline.** DONE (5 collectors, schema gate, workflow).
- **Phase B — production site.** IN PROGRESS. Plan:
  `docs/superpowers/plans/2026-08-02-vigil-phase-b-site.md` (+ 2026-08-06
  aggregator amendment).
- **Phase C — Framework brief loop.** Queued; `data/brief.json` integration
  point already wired in the pipeline and site.
- **Phase D — own sensor.** Gated on COMPLIANCE R2. Architecture and safety
  controls in `BACKLOG.md`.
