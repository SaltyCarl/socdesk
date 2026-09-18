# SOCDesk PICKET — reference

**Status:** P1 foundation, pre-dogfood. The sensor box has not yet been
provisioned by the owner, so nothing in this document that depends on running
hardware is asserted as observed — those places say **pre-dogfood** or
**pending dogfood** explicitly, and mean it literally: not yet run.

**Audience:** a reviewer who has not read the design spec. Every term is
defined on first use.

**Source of truth:** this document describes the CODE on `feat/picket-p1` as
it exists today, not the spec's aspirational shape. Where the two differ, the
code wins, and the difference is called out — see "Spec divergences" in §2
and the field-level notes in §5.

Related documents:
- [`docs/superpowers/specs/2026-09-17-picket-sensor-design.md`](superpowers/specs/2026-09-17-picket-sensor-design.md) — the design spec this reference is built from (referenced below as "the spec").
- [`tools/picket/README.md`](../tools/picket/README.md) — the box runbook: provision, harden, install knock-knock, install the exporter, verify, rebuild from scratch, incident response.
- [`docs/ARCHITECTURE.md`](ARCHITECTURE.md), [`docs/DATA-SOURCES.md`](DATA-SOURCES.md) — house style and how Picket fits into the rest of the pipeline.

---

## 1. What Picket is / is not

Picket is SOCDesk's own honeypot: a small internet-facing server, provisioned
and operated by the SOCDesk owner, running nothing but
[knock-knock](https://github.com/djkurlander/knock-knock) — an MIT-licensed
honeypot that emulates SSH, Telnet, FTP, RDP, SMB, SIP, HTTP and SMTP well
enough that automated attack tooling tries to log in, brute-force, or upload
to it (§3). It exists to be attacked. Nobody has a legitimate reason to
connect to it. Every inbound connection that gets far enough for knock-knock
to record it is a **knock** — the unit Picket counts, and the word used
throughout this document and the code for "one recorded attempt."

Picket answers one question SOCDesk could not otherwise answer: *what do
automated bots actually try, right now, against a server nobody invited them
to touch?* It publishes counts — of source IPs, protocols, countries, ISPs,
attempted usernames, attempted passwords — derived from those knocks. It does
**not** publish a verdict. A high knock count from an IP means "this IP
knocked on Picket a lot," not "this IP is malicious," not "block this IP,"
not "this network is compromised." Every PICKET surface repeats this framing
in its own copy (§9) and in the payload's own `attribution` string
(`pipeline/picket.py`): *"Counts of automated break-in attempts against an
unsolicited sensor — context, never a verdict on any network or operator."*
No red/amber/green appears anywhere in PICKET; SOCDesk's colour law (bound in
`CLAUDE.md`) reserves those for an actual verdict, and Picket never renders
one.

**Threat model of the box.** Picket is bait. The working assumption is that
it *will* be compromised — that is what a honeypot is for, not a failure
condition. `tools/picket/README.md` §1 states this directly: *"Treat it as
bait: assume it gets compromised."* The box:

- holds no production data and no production credentials;
- has no network path back into SOCDesk's real infrastructure, the pipeline,
  or socdesk.io;
- has exactly one outbound relationship to the rest of the system: a
  `git push` of a small, bounded, sanitized `export.json` file to a
  **separate public, data-only** GitHub repository
  (`SaltyCarl/socdesk-picket-export`), on a schedule (§4).

**Blast radius if the box is fully owned by an attacker:** the box itself,
and — until the deploy key is rotated (runbook §8, Incident response) — the
ability to push garbage commits to that one export repository. That is the
entire exposure. The export repository has no write path into this
repository; the pipeline only ever *reads* a public raw URL from it
(`collectors/picket.py`), and every string in whatever it fetches is
independently re-validated against the raw schema and re-sanitized on arrival
— the second, independent application of the PII fence (§6). A vandalized or
malformed export is refused outright, and the site keeps serving its
last-known-good snapshot (§7, §8). The box compromise cannot corrupt anything
SOCDesk publishes; it can only, at worst, stall Picket's own numbers, which
render honestly as stale/silent rather than silently freezing or lying.

**What Picket is not, in P1 or at all:**

- **Not a live feed.** SOCDesk stays on its existing 30-minute-cadence,
  static-core architecture (`INFRASTRUCTURE-OPTIONS.md` §5 discipline); the
  spec explicitly rules out a live/WebSocket feed inside SOCDesk (spec §0).
  "Live" novelty comes from what the intelligence layer does with the
  numbers, not from streaming.
- **Not a mirror of anyone else's threat intel.** Every row Picket publishes
  is first-party telemetry from SOCDesk's own sensor — the
  aggregator-not-mirror rule (`COMPLIANCE.md`, `CLAUDE.md`) that governs the
  rest of the pipeline applies here too, trivially, because there is nothing
  upstream to mirror.
- **Not a credential-pair leak.** Usernames and passwords are published as
  two separate aggregate top-N lists; the `(username, password)` pairs bots
  actually submit are never published, anywhere, and no schema field exists
  that could carry one (§6).
- **Not, in P1, a lookup enrichment, a globe-map layer, or an export pack.**
  Those are P2/P3 work, described but not yet built (§2, §11).

---

## 2. Architecture

The diagram below is the spec's §2 diagram, updated to what P1 actually
built. Tiers and lines marked `[P2]` / `[P3]` are designed in the spec but do
not exist in the code yet — they are shown greyed-out-in-text so a reviewer
can see the target shape without mistaking it for what ships today.

```
Internet bots
   |  SSH / TELNET / FTP / RDP / SMB / SIP / HTTP / SMTP
   |  (P1's "core eight" — knock-knock ENABLED_PROTOCOLS; optional IoT/OT
   |   set MQTT/Node-RED/Modbus/S7/SNMP is a later owner toggle, not on) [P4]
   v
+- Tier S . sensor box (isolated VPS) --------------------------------------+
| knock-knock (Docker, host networking)                                    |
|   -> SQLite rollups: ip_intel, ip_intel_proto, user_intel, pass_intel,   |
|      isp_intel, country_intel, monitor_heartbeats                       |
| tools/picket/exporter.py  (systemd timer, :05 and :35)                  |
|   reads rollups + GeoLite2-Country -> delta ring (state.json, 7 days)   |
|   -> export.json (schema-validated on-box, PII-fenced, <=512 KB)        |
|   -> git push -> SaltyCarl/socdesk-picket-export (public, data-only)    |
+----------------------------------------------------------------------------+
   |  raw.githubusercontent.com  (keyless GET, <=2,000,000-byte cap)
   v
+- Tier P . GitHub Actions pipeline (cron :11 and :41) ---------------------+
| collectors/picket.py                                                     |
|   -> re-validate against the raw schema + clean_text + the fence AGAIN   |
|      (second, independent pass) -> CollectorResult.extra["picket"]      |
| pipeline/picket.py                                                       |
|   -> picket.json (the panel) + picket_ips.json (globe-layer ROWS —      |
|      produced now, not yet rendered anywhere; see note below)           |
|   [P2: picket_lookup.json, known_to/lead_time, report_candidates,       |
|         exports/ (Knock -> Block pack)]                                 |
| pipeline/asn.py            [P2: "picket" folded into SOURCES]           |
| pipeline/validate.py gate() -> last-known-good on any schema failure    |
+----------------------------------------------------------------------------+
   |  data/state/ + web/public/data/state/  (dual-write, unchanged)
   v
+- Tier W . web/ (static) -------------------+  +- /api/enrich -------------+
| /desk#picket tab (PicketView.tsx)          |  | [P2: loadPicket() +      |
| landing-board teaser (PicketTeaser.tsx)    |  |  SOCDESK_PICKET row,     |
| /about#picket (About.tsx)                  |  |  kind:"context"]         |
| [P2: picket_ips.json on the ambient globe] |  +----------------------------+
+----------------------------------------------+
+- Tier G . owner-moderated give-back  [P3] ---------------------------------+
| /admin Picket tab <- picket.json.report_candidates + GET /api/admin/     |
| picket (D1 decisions) -> POST /api/admin/picket {ip, action}             |
|   approve -> AbuseIPDB /api/v2/report (existing key) -> D1 row on 200    |
+------------------------------------------------------------------------------+
```

**What P1 actually shipped** (Tiers S and P fully; Tier W partially): the box
runbook and exporter code (not yet run against a live box); the keyless
collector with a second sanitization pass; `pipeline/picket.py` producing
`picket.json` and `picket_ips.json` every run, gated and dual-written like
every other payload; the three new schemas; the `/desk#picket` tab, the
landing teaser, and the `/about#picket` transparency section.

**What is explicitly P2/P3/P4** (designed in the spec, not built): the
`picket_lookup.json` enrichment index, the `SOCDESK_PICKET` context row on
`/lookup`, folding `"picket"` into the ASN leaderboard's `SOURCES`, rendering
`picket_ips.json` on the ambient globe, the lead-time-vs-feeds statistic, the
four-file "Knock → Block" export pack (Defender/Sentinel/Entra/plain
blocklist), and the owner-moderated AbuseIPDB give-back queue in `/admin`
(D1 migration, Functions, UI). Phase 4 (separate spec later) adds a STIX 2.1
bundle, week-over-week trends, the optional IoT/OT protocol set, and a
possible knock-knock upstream contribution.

### Spec divergences

Three places where the code (or the current operational state) differs from
what a literal reading of the spec would lead a reviewer to expect:

1. **`ENABLED_PROTOCOLS` is not written by `install.sh`.** Spec §3.1 states
   "`ENABLED_PROTOCOLS` = the core eight ... in P1" as a settled decision.
   `tools/picket/install.sh` copies knock-knock's own `.env.example` and only
   explicitly sets `WEB_HOST`, `SOURCE_ID`, and comments out `SAVE_KNOCKS` —
   it never writes an `ENABLED_PROTOCOLS` line. The core-eight set is
   therefore whatever the pinned tag's `.env.example` ships as its default,
   not something this repo's tooling enforces. Confirm the actual enabled
   set on the box (runbook §6) before relying on "the core eight" as a fact
   rather than an intent.
2. **The per-IP `protocols[].hits_7d` field is not a 7-day figure.** Both
   `schemas/picket_export.schema.json` and `schemas/picket.schema.json`
   describe `top_ips[].protocols[].hits_7d` as *"attempts in the last 7 days
   on this protocol."* `assemble_export()`
   (`tools/picket/assemble.py:47-54`) actually publishes that IP/protocol
   pair's **all-time** hit count from knock-knock's `ip_intel_proto.hits`
   column, gated to `0` unless the IP has *any* positive 7-day delta at all
   — it is not independently windowed per protocol. See §5's field table and
   footnote for the exact expression. This is a genuine discrepancy between
   the schema's own description and the code's behavior, not a spec-vs-code
   gap; it is flagged here because a reviewer reading only the schema would
   draw the wrong conclusion, and because the existing test fixtures happen
   to use equal all-time/7-day values (`tests/test_picket_assemble.py`), so
   the gap is invisible to current test coverage.
3. **`picket_ips.json` is produced but not yet consumed.**
   `pipeline/picket.py::build_picket` writes `picket_ips.json` on every run
   in P1 (matching spec §9's P1 bullet, "producing `picket.json` (+
   `picket_ips.json`)"), but `web/src/components/hero/heroLayers.ts` has no
   Picket layer yet — nothing renders those rows on the globe. This is
   consistent with the spec's own P1/P2 split (globe rendering is a P2 exit
   criterion, spec §9), not a contradiction, but the §2 diagram in the spec
   does not visually distinguish "payload produced" from "payload consumed,"
   so it is easy to misread. The diagram above marks this explicitly.

---

## 3. The sensor

The sensor box runs a **pinned** knock-knock release — never `main` — so
protocol IDs and the `.env` shape stay stable between exporter runs
(`tools/picket/README.md` §4). The tag is supplied as the required `KK_TAG`
environment variable to `install.sh`; re-provisioning with a new tag is the
only supported way to "update" (`git pull` inside `/opt/knock-knock` is
explicitly disallowed by the runbook).

**Protocols enabled (P1).** The spec's decision (§3.1) is the "core eight" —
SSH, Telnet, FTP, RDP, SMB, SIP, HTTP, SMTP — with an optional IoT/OT set
(MQTT, Node-RED, Modbus, S7, SNMP) deferred as "a later owner toggle" (not P1;
see the Spec-divergences note above for how loosely `install.sh` actually
pins this).

**`SAVE_KNOCKS` is off, and why.** Knock-knock's default behavior can persist
a per-knock row for every single connection. `install.sh` rewrites that line
to a comment (`# SAVE_KNOCKS off: rollups only`) so the box keeps only
knock-knock's cumulative SQLite **rollup** tables (`ip_intel`,
`ip_intel_proto`, `user_intel`, `pass_intel`, `country_intel`, `isp_intel`) —
running counters per entity, not a log of individual events. The reason is
exposure, not storage cost: an internet-facing box that has already been
treated as bait should not also hold a growing, attacker-influenced
event-by-event log at rest. Picket gets a time series a different way — the
exporter's own **delta ring** (§4) — specifically so `SAVE_KNOCKS` can stay
off. Verify it on the box with
`grep -n '^SAVE_KNOCKS' /opt/knock-knock/.env` — expected: the line is
commented out, not `SAVE_KNOCKS=true` (runbook §4).

**The dashboard is not public, and why.** knock-knock ships its own live
web dashboard (`WEB_PORT`, default 8080). Approach "expose it publicly" was
explicitly considered and declined by the owner (spec §0, §3.1) — the public
value it would have provided is instead re-created inside SOCDesk itself
(§9). `install.sh` writes `WEB_HOST=127.0.0.1` into `.env` as its best guess
at the binding variable, but the runbook flags this as an unverified
guess — a **build-time check**: *"knock-knock's actual variable name can
differ by release"* (README §4) — and gives the `grep` command to confirm it
on the pinned tag, plus the `curl` command from an external machine that must
fail/timeout. To view the dashboard at all, the owner tunnels over SSH
(`ssh -p 2222 -L 8080:127.0.0.1:8080 root@<ip>`) rather than opening the port.

**Self-redaction.** Knock-knock has its own default behavior of not
recording/reporting its own public IP or hostname as if it were an attacker
fact — the runbook calls this "self-redaction" and states it "stays on (it
is default behaviour, not a toggle)" (spec §3.1). That mechanism lives in
knock-knock's own code, outside this repository, so it cannot be verified by
reading this repo — it is a documented behavior of the upstream project, not
a guarantee this repo's code enforces. What *this* repo's code does enforce,
independently, is the second half of the same invariant: the collector
explicitly drops any `top_ips` row whose SHA-256 matches the sensor's own
published `public_ip_sha256` (§6) — so even if self-redaction ever failed
on-box, the sensor's own IP still cannot reach a published payload.

**MaxMind.** Per-IP country resolution uses the free GeoLite2-Country
database (`geoip2` Python reader), configured on-box only via
`MAXMIND_ACCOUNT_ID` / `MAXMIND_LICENSE_KEY` in knock-knock's `.env` — never
committed to this repository. If the database is missing, per-IP `country`
is simply omitted (an optional schema field); knock-knock's own city-level
`lat`/`lng` (used for `geo_precision:"city"`) is unaffected (spec §5 failure
table, reproduced in §8). MaxMind's GeoLite2 End User License Agreement
requires an attribution line wherever the data is used — carried in the
published `attribution` string (`pipeline/picket.py`) and in the runbook's
own attribution section (README §9).

### Protocol map

**Pre-dogfood — derived from knock-knock's registry; confirm on the box per
README §6.** The exporter refuses to guess protocol IDs at all — it loads
`knock-knock`'s own `protocols/registry.py` at runtime
(`tools/picket/exporter.py::load_proto_names`) and raises if an ID it sees in
the rollups isn't in that map (`tools/picket/assemble.py:47-51`,
`test_unknown_protocol_id_fails_loudly`). What follows is what the spec and
runbook already establish about each protocol; the integer `proto_id` values
themselves only exist on the box and are not reproduced here (the runbook
gives the exact command to dump them: `python3 -c "from protocols.registry
import PROTOCOL_META; print(...)"`, README §6).

| Protocol | Port(s) (README §3, expected `nmap` result) | Is a knock an auth attempt or a bare connect? |
|---|---|---|
| SSH | 22/tcp | **To confirm.** Spec §3.9(a) lists SSH unconditionally among the credential-bearing protocols the give-back candidate rule counts on, i.e. the spec's working assumption is "auth attempt" — but the runbook explicitly requires an on-box `grep -RniE 'record_knock\|log_knock\|on_connect\|on_auth' protocols/*.py` check (README §6) before that assumption is relied on. |
| TELNET | 23/tcp | **To confirm**, same basis as SSH — spec §3.9(a) assumes auth-attempt; not yet verified on the box. |
| FTP | 21/tcp | **To confirm**, same basis as SSH — spec §3.9(a) assumes auth-attempt; not yet verified on the box. |
| RDP | 3389/tcp | **To confirm**, same basis as SSH — spec §3.9(a) assumes auth-attempt; not yet verified on the box. |
| SMB | 445/tcp | **To confirm**, same basis as SSH — spec §3.9(a) assumes auth-attempt; not yet verified on the box. |
| SIP | 5060/tcp+udp | **To confirm — genuinely unaddressed.** Spec §3.9(a)'s candidate-rule protocol list does not mention SIP at all; nothing in this repo states whether a SIP knock implies a credential/registration attempt or a bare probe. |
| HTTP | 80/tcp | **To confirm — spec flags this one explicitly.** Spec §3.9(a): "SMTP/HTTP only when knock-knock's module records an auth attempt" — the spec itself treats this as unresolved pending a build-time check, not an assumption either way. |
| SMTP | 25/tcp | **To confirm — spec flags this one explicitly**, same basis as HTTP above. |

The optional IoT/OT set (MQTT, Node-RED, Modbus, S7, SNMP) is **not enabled
in P1** at all (spec §3.1: "a later owner toggle") and so has no protocol-map
entry here.

Per README §6, the protocol-ID map and the per-module
auth-attempt-vs-bare-connect answer, once actually confirmed on the box, are
recorded back into this section — this document, not just the runbook, is
where "future exporter runs and readers of the export" are meant to find it.

---

## 4. The exporter

The exporter (`tools/picket/exporter.py`) is the only thing that runs off the
box's SQLite database. It never writes per-knock data anywhere — it reads
knock-knock's cumulative rollup tables, turns their *increase since the last
run* into a small time series of its own, assembles and validates the export
document, and pushes it (or refuses to).

### The delta ring — what it is and why it exists

Knock-knock's rollup tables (`ip_intel`, `ip_intel_proto`, `user_intel`,
`pass_intel`, `country_intel`, `isp_intel`) are **cumulative all-time
counters**: `hits` only ever goes up (barring a reset), with no per-period
buckets. With `SAVE_KNOCKS` off (§3), there is no per-knock row to derive a
time series from after the fact. The exporter's `tools/picket/ring.py`
therefore keeps its own tiny piece of state:

- A **bucket** is a fixed 30-minute time slot
  (`BUCKET_SECONDS = 1800` in `tools/picket/ring.py`).
- The **ring** is a fixed-length circular array of 336 buckets — 7 days ×
  48 half-hour buckets/day (`RING_LEN = 336`, same file). Every entry is an
  integer knock count for that half hour.
- Every exporter run (every 30 minutes, matching the bucket width) snapshots
  the current cumulative totals — overall and per protocol, IP, username,
  password, country, and ISP — and diffs that snapshot against the *previous
  run's* snapshot. The positive difference for each entity is a **delta**:
  the knocks that happened in this one bucket. Deltas are stored in
  `state.json`, which lives only on the box (`/var/lib/picket/state.json`)
  and is never pushed anywhere.
- Everything published as a "7-day" or "24-hour" or "hourly" figure is a sum
  over some slice of these deltas — never a re-read of the cumulative
  counters, which don't carry time information at all.

**`state.json`'s shape** (`tools/picket/ring.py::new_state`):

```json
{
  "version": 1,
  "last_bucket": 1000000,
  "prev": { "total": 1130, "proto": {"SSH": 900}, "ip": {"5.6.7.8": 630}, "user": {...}, "pass": {...}, "country": {...}, "isp": {...} },
  "ring": [0, 0, "...", 50, 80],
  "deltas": {
    "proto": {}, "ip": {"9.10.11.12": [[999999, 20], [1000000, 80]]},
    "user": {}, "pass": {}, "country": {}, "isp": {}
  }
}
```

`ring` is always exactly 336 integers. `deltas` is sparse per entity kind —
most IPs/usernames/etc. are only active in a handful of buckets, so each
entity's list holds only `[bucket_index, delta]` pairs, pruned every run to
drop anything older than the 336-bucket window
(`tools/picket/ring.py::apply_snapshot`, the pruning loop). This is what
keeps `state.json` bounded regardless of how long the box has been running
(`test_state_is_bounded_by_pruning_old_sparse_deltas`).

### Worked example: three runs, then a reset

Bucket width is 30 minutes; assume the exporter runs exactly on schedule.

**Run 1 — T+0 (the box's very first export).** Rollup snapshot:
`knocks_total = 1000`; IP `5.6.7.8` has cumulative `hits = 600`; IP
`9.10.11.12` has cumulative `hits = 400`. `apply_snapshot()` finds
`state["prev"]` is `None` (nothing to diff against yet), so **no deltas are
recorded at all** — this run only establishes the baseline. `state["prev"]`
is set to this snapshot. Published: `ring.buckets` = 336 zeros;
`top_ips[].hits_7d` = 0 for both IPs (nothing has happened *yet*, by
definition of "since the last run").

**Run 2 — T+30min.** Rollup snapshot: `knocks_total = 1050` (Δ = +50);
`5.6.7.8` = 630 (Δ = +30); `9.10.11.12` = 420 (Δ = +20). A previous snapshot
now exists, so `total_delta = 50` is added to the ring's newest bucket
(`ring[-1] += 50`); each IP's positive delta is appended to its sparse delta
list. Published: `ring.buckets` = 335 zeros, then `50`;
`top_ips[].hits_7d`: `5.6.7.8` → 30, `9.10.11.12` → 20.

**Run 3 — T+60min.** Rollup snapshot: `knocks_total = 1130` (Δ = +80);
`5.6.7.8` = 630 (Δ = +0 — nobody hit this IP in the last half hour);
`9.10.11.12` = 500 (Δ = +80 — all of this run's activity was against this
one IP). The ring slides one slot (`_advance_ring`: `ring[gap:] + [0]*gap`)
so run 2's `50` moves back one position, and `total_delta = 80` lands in the
new newest slot: `ring.buckets` = 334 zeros, then `50`, then `80`. Per-entity: `5.6.7.8`'s
delta is `0`, which is **not** appended (`apply_snapshot` skips `d <= 0`), so
its window sum is unchanged from run 2 — still `30`. `9.10.11.12` gets a
second delta entry, `[[run3_bucket, 80]]`, added to its existing `[[run2_bucket,
20]]` — window sum `20 + 80 = 100`.

Published after run 3: `top_ips[].hits_7d`: `5.6.7.8` → **30**,
`9.10.11.12` → **100**. `totals.knocks_total` (all-time, not delta) =
**1130**, read straight from the cumulative counter, not summed from the
ring. `sum(ring.buckets)` = `50 + 80` = **130**, which matches
`30 (5.6.7.8) + 100 (9.10.11.12)` — the ring total and the per-entity totals
agree because, in this example, every knock is attributed to exactly one of
these two IPs.

**Run 4 — T+90min, a counter reset.** Suppose knock-knock's database is
reset or pruned between runs, so the *cumulative* counters go backward:
`knocks_total` reads `20` (down from 1130); `5.6.7.8` reads `5` (down from
630); `9.10.11.12` reads `10` (down from 500). `apply_snapshot()` computes
each of these deltas as negative, **clamps every one of them to `0`**, and
sets the run's `reset` flag to `True`
(`tools/picket/ring.py:49-58`, `test_counter_decrease_is_clamped_and_flagged_as_reset`).
The ring's newest bucket gets `+0`, not a bogus negative-turned-huge spike.
The exporter then stamps `sensor.ring_reset_at` with the current time
(`tools/picket/exporter.py:129-130`) — this is the **only** time
`ring_reset_at` is set; a normal fresh-box start (no prior `state.json`)
does **not** set it (runbook §7: *"a fresh box starts with `new_state()` ...
The exported `sensor.ring_reset_at` field will not be set (that only fires
when a counter goes backwards, not on a fresh start)"*). Crucially, the
*already-recorded* window sums for `5.6.7.8` (30) and `9.10.11.12` (100) are
**not retroactively corrected** — only the reset run's own delta is
clamped — so those figures keep counting down normally as they age out of
the 336-bucket window over the following days. `pipeline/picket.py` surfaces
this to the reader as "counters reset on \<date>" rather than pretending
nothing happened (spec §5 failure table, §8 below).

### Cadence, size, and the public-IP hash

- **Cadence:** a systemd timer (`tools/picket/systemd/picket-export.timer`)
  runs the exporter at **`:05` and `:35`** past every hour
  (`OnCalendar=*-*-* *:05,35:00`) — six minutes ahead of the pipeline's own
  cron, which runs at **`:11` and `:41`**
  (`.github/workflows/collect-and-deploy.yml:5`, `cron: "11,41 * * * *"`),
  so every pipeline run sees a fresh export. The push is idempotent: the
  exporter `git add`s the file and checks `git diff --cached --quiet`; if
  nothing changed it reports `"unchanged"` and does not create an empty
  commit (`tools/picket/exporter.py::_git_push`).
- **Size — the refusal constant.** The exporter refuses to write an export
  larger than **`MAX_EXPORT_BYTES = 512 * 1024` bytes = 524,288 bytes
  (512 KiB)**, defined in `tools/picket/exporter.py:32`. This matches the
  spec's "≤ 512 KB" language exactly — there is no brief-vs-code discrepancy
  here, but the precise figure is 524,288 bytes, not a round decimal 512,000.
  On refusal it prints `REFUSED (size): <n> > 524288` to stderr and exits
  with status `3`, leaving the previously-pushed export standing
  (`tools/picket/exporter.py:137-138`). Schema bounds (§5) make this
  structurally very hard to reach in practice — it is a belt-and-braces
  check, not the primary defense.
- **The collector's own cap, on the other side.** Independently,
  `collectors/picket.py` caps the *fetch* at
  `MAX_BYTES = 2_000_000` bytes (2,000,000 bytes; decimal "2 MB", not a
  binary 2 MiB) and raises `ValueError` — treated by `run_all` as a failed
  collection, never a crash — if the fetched body is larger
  (`collectors/picket.py:21,62-63`, `test_oversize_body_is_a_failed_collection`).
- **The public-IP hash.** The exporter never writes the sensor's own
  plaintext public IP anywhere. It shells out to `curl -4 -s --max-time 5
  https://ifconfig.me` (falling back to a local DNS lookup) purely to
  compute `sensor.public_ip_sha256 = sha256(public_ip)`
  (`tools/picket/exporter.py:77-80,127`) — a 64-character lowercase hex
  digest, structurally enforced by the export schema's pattern
  `^[a-f0-9]{64}$`. The plaintext value exists only transiently in the
  exporter process's memory; it is never written to `state.json`,
  `export.json`, or any log line shown in the runbook. The pipeline uses
  this hash a second time, independently, to drop any `top_ips` row whose
  own SHA-256 matches it (§3, §6) — the sensor cannot appear as its own
  attacker even if a knock-knock bug ever logged a connection from itself.

### What happens on refusal or a network problem

If `validate_export()` finds schema errors, the exporter prints
`REFUSED (schema): <first error>` and exits `2` — no push, and the previous
export (already live in the export repo) stands (`tools/picket/exporter.py:132-135`,
matching spec §5's "Export fails its own schema on-box" row, §8 below). Both
refusal paths are checked by `journalctl -u picket-export` in the runbook's
verification steps (README §5).

---

## 5. Data contracts

Three JSON documents matter here. `export.json` is the raw box → repo
contract — it lives in the external `socdesk-picket-export` repository, not
in this repo's `data/state/`, and is validated twice: on-box before push
(`tools/picket/assemble.py::validate_export`) and again by the collector
after fetch (same function, imported from `tools/picket/assemble.py` into
`collectors/picket.py`). `picket.json` and `picket_ips.json` are what the
pipeline actually publishes to `data/state/` and
`web/public/data/state/` — registered in `pipeline/validate.py:SCHEMA_FOR`
(lines 27–28) and gated like every other payload (§7). All three schemas are
`additionalProperties:false` with a `description` on every property; the
tables below summarize those descriptions rather than repeat them verbatim.

Note that `picket_lookup.json` (the ≤5,000-entry enrich index) does **not**
exist yet — it is P2 (§2, §11).

### 5.1 `export.json` — [`schemas/picket_export.schema.json`](../schemas/picket_export.schema.json)

Top level (all required):

| Field | Type / bound | Meaning | Example (`tests/fixtures/picket/export_ok.json`) |
|---|---|---|---|
| `schema_version` | integer | Export schema version. | `1` |
| `exported_at` | string, `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$` | UTC time the exporter ran; freshness is measured from this (§7). | `"2026-07-28T11:35:00Z"` |
| `sensor` | object, see below | Identity/status of the box that produced this export. | — |
| `totals` | object, see below | All-time knock totals. | — |
| `ring` | object, see below | The 336-bucket delta ring (§4). | — |
| `by_protocol` | array, ≤16 | Per-protocol 7-day/all-time totals. | 2 rows (SSH, TELNET) |
| `top_ips` | array, ≤2000 | Public source IPs, most active first. | 3 rows |
| `top_usernames` / `top_passwords` | array, ≤50 (`$defs/credlist`) | Fenced aggregate credential values (§6). | 2 / 1 rows |
| `top_countries` | array, ≤50 | Source countries by knock volume. | 1 row (`CN`) |
| `top_isps` | array, ≤50 | Source ISPs by knock volume. | 1 row |

`sensor` (required: `id`, `public_ip_sha256`, `protocols`, `uptime_minutes`, `knockknock_version`):

| Field | Type / bound | Meaning | Example |
|---|---|---|---|
| `id` | string, ≤32 | Stable sensor identifier. | `"picket-1"` |
| `public_ip_sha256` | string, `^[a-f0-9]{64}$` | SHA-256 of the box's own public IP — the plaintext never leaves the box (§4). | `"aaaa...aaaa"` (64 chars) |
| `country` | string, ≤2, optional | ISO 3166-1 alpha-2 of the sensor itself. | `"DE"` |
| `protocols` | array, ≤16 items, each ≤8 chars | Protocol names the sensor listens on. | `["SSH","TELNET"]` |
| `uptime_minutes` | integer, ≥0 | Continuous uptime. | `4320` (3 days) |
| `knockknock_version` | string, ≤32 | knock-knock version string. | `"1.9.0"` |
| `ring_reset_at` | string, ≤20, optional | Set only when a counter decrease was clamped (§4). | absent in the fixture |

`totals` (required: `knocks_total`, `since`):

| Field | Type / bound | Meaning | Example |
|---|---|---|---|
| `knocks_total` | integer, ≥0 | All-time cumulative knock count, read straight from `SUM(ip_intel_proto.hits)` (`tools/picket/exporter.py:49`) — not derived from the ring. | `9001` |
| `since` | string, ≤20 | `exported_at` minus `uptime_minutes` — when the all-time counter has been accumulating from. | `"2026-07-25T11:35:00Z"` |

`ring` (required: `bucket_minutes`, `buckets`):

| Field | Type / bound | Meaning | Example |
|---|---|---|---|
| `bucket_minutes` | `const: 30` | Bucket width; always 30. | `30` |
| `buckets` | array, exactly 336 integers ≥0 | 7 days of half-hour deltas, oldest first (§4). | 335 zeros, then `42` |

`by_protocol[]` (required: `proto`, `hits_7d`, `hits_total`):

| Field | Type / bound | Meaning | Example |
|---|---|---|---|
| `proto` | string, ≤8 | Protocol name. | `"SSH"` |
| `hits_7d` | integer, ≥0 | Trailing-7-day knocks on this protocol (a true ring sum — see the §2 footnote on the *nested per-IP* field, which is different). | `900` |
| `hits_total` | integer, ≥0 | All-time knocks on this protocol. | `8000` |

`top_ips[]` (required: `ip`, `hits_7d`, `hits_total`, `first_seen`, `last_seen`, `protocols`):

| Field | Type / bound | Meaning | Example |
|---|---|---|---|
| `ip` | string, ≤45 | Public source IP literal (IPv4 or IPv6; never CIDR). | `"5.6.7.8"` |
| `hits_7d` | integer, ≥0 | Trailing-7-day knocks from this IP (a true ring sum). | `900` |
| `hits_total` | integer, ≥0 | All-time knocks from this IP. | `8000` |
| `first_seen` / `last_seen` | string, ≤20 | Timestamps, converted from knock-knock's `YYYY-MM-DD HH:MM:SS` to ISO `Z` (`tools/picket/assemble.py::_ts`). | `"2026-07-20T01:00:00Z"` / `"2026-07-28T11:00:00Z"` |
| `protocols` | array, ≤16, each `{proto, hits_7d}` | Per-protocol breakdown for this IP. **See the footnote below** — the nested `hits_7d` here is not what its name or the schema description say it is. | `[{"proto":"SSH","hits_7d":900}]` |
| `country` | string, ≤2, optional | From GeoLite2-Country, keyed by IP (§3), not from knock-knock's own rollups. | `"CN"` |
| `asn` | integer, ≥0, optional | From `ip_intel.asn`. | `64500` |
| `isp` | string, ≤120, optional | Joined from `isp_intel` by ASN. | `"Example Hosting"` |
| `lat` / `lng` | number, optional | knock-knock's own city-level geolocation. | `39.9` / `116.4` |
| `geo_precision` | `"city"` \| `"country"`, optional | Set to `"city"` when `lat`/`lng` are present (`tools/picket/assemble.py:72-74`); omitted from `export.json` entirely otherwise — the export's own assembler never writes `"country"` into this field (see §5.3 for how `picket_ips.json`'s own default works, which is a separate function). | `"city"` |

> **Footnote — the nested `protocols[].hits_7d` field.** Despite its name and
> the schema's own description ("attempts in the last 7 days on this
> protocol"), `assemble_export()` publishes this value as the IP/protocol
> pair's **all-time** hit count from `ip_intel_proto.hits`
> (`tools/picket/assemble.py:52-54`), gated to `0` unless that IP had *any*
> positive delta anywhere in the trailing 7 days
> (`hits7d["ip"].get(r["ip"], 0) > 0`). It is not an independently
> time-windowed per-protocol figure the way the top-level `by_protocol[]`
> array's `hits_7d` is. This flows unchanged into the published
> `picket.json` (`pipeline/picket.py::_panel` copies `top_ips` verbatim) and
> is not currently rendered as a number anywhere in the UI — `PicketView.tsx`
> only lists the protocol *names* for a row, not this per-protocol figure
> (`web/src/components/views/PicketView.tsx:117`) — but it is present in the
> JSON any P2 consumer (fusion, exports) would read. See the Spec
> divergences note in §2.

`top_usernames` / `top_passwords` — `$defs/credlist` (required: `value`, `hits_7d`):

| Field | Type / bound | Meaning | Example |
|---|---|---|---|
| `value` | string, 1–32 chars | The fenced credential value, standalone — never paired with the other list (§6). | `"root"`, `"123456"` |
| `hits_7d` | integer, **≥3** | Occurrences in the last 7 days; the floor is enforced structurally by the schema's own `minimum:3`, not just in code (§6). | `400` |
| `hits_total` | integer, ≥0, optional | All-time occurrences. | `3000` |

`top_countries[]` (required: `iso`, `hits_7d`) and `top_isps[]` (required: `isp`, `hits_7d`) follow the same `{code/name, hits_7d, hits_total}` shape; see the schema file directly for the exact optional fields (`name` on countries, `asn` on ISPs).

### 5.2 `picket.json` — [`schemas/picket.schema.json`](../schemas/picket.schema.json)

The panel payload — what `/desk#picket` and the landing teaser read. Same
`top_ips`/credential/country/ISP row shapes as `export.json` above (capped
tighter: `top_ips` ≤100, not ≤2000), plus an envelope and a computed `sensor`
block that differ from the raw export:

| Field | Type / bound | Meaning | Example (from a P1 pipeline run over the fixture) |
|---|---|---|---|
| `generated_at` | string | When this payload was generated/published — re-stamped every run, even on keep-prior (§7). | — |
| `schema_version` | integer | `1` | `1` |
| `attribution` | string, ≤1000 | The MaxMind + knock-knock attribution and the context-not-verdict framing, verbatim from `pipeline/picket.py::ATTRIBUTION`. | *"SOCDesk PICKET: telemetry from SOCDesk's own internet-facing honeypot sensor ..."* |
| `collected_at` | string | When the underlying export was **actually** last collected — stamped only on a real collection, carried through keep-prior (§7). | `"2026-07-28T12:00:00Z"` |
| `sensor` | object | See below — adds `status`/`export_age_minutes`/`uptime_days` (computed), drops `public_ip_sha256`. | — |
| `totals` | object | Adds `knocks_24h`, `knocks_7d`, `unique_ips_7d` to the export's `knocks_total`/`since`. | `knocks_7d: 42` |
| `histogram_7d` | array, exactly 168 integers | Hourly knocks for the trailing 7 days, oldest first — the 336 half-hour ring buckets summed pairwise (`pipeline/picket.py::_hourly`). | 167 zeros, then `42` |
| `by_protocol[]` | array, ≤16 | Adds `share_pct` to the export's `proto`/`hits_7d`/`hits_total`. | `{"proto":"SSH","hits_7d":900,"hits_total":8000,"share_pct":90.0}` |
| `top_ips` / `top_usernames` / `top_passwords` / `top_countries` / `top_isps` | as §5.1, `top_ips` capped at 100 | Passed through from the export mostly unchanged (`top_ips` is sliced, not re-derived). | — |

`picket.schema.json` tightens a few of §5.1's optional fields to required —
the builder always populates them, so this is a schema-strictness
difference, not a behavior difference: `hits_total` is required on
`top_usernames`/`top_passwords` (`credlist_item`) and on `top_countries` and
`top_isps`, and `name` is additionally required on `top_countries`
(`schemas/picket.schema.json`'s `credlist_item.required` and
`top_countries`/`top_isps` item `required` arrays), where
`schemas/picket_export.schema.json` leaves `hits_total` and `name` optional
on the corresponding items. `isp` itself is required on `top_isps` in
**both** schemas — that one was never optional.

`sensor` in `picket.json` (required: `id`, `uptime_days`, `protocols`, `status`, `export_age_minutes`, `exported_at`, `knockknock_version`):

| Field | Meaning | Example |
|---|---|---|
| `uptime_days` | `uptime_minutes // 1440` from the export. | `3` |
| `status` | `"live"` \| `"stale"` \| `"silent"` — computed from `exported_at` age (§7). | `"live"` |
| `export_age_minutes` | Minutes since `exported_at`, as of `generated_at`. | `25` |
| (no `public_ip_sha256`) | Intentionally dropped — the panel payload never needs or carries even the hash. | — |

`by_protocol[].share_pct` is `round(100 * hits_7d / denom, 1)` where `denom`
is the sum of `hits_7d` across **all** `by_protocol` rows (i.e. the
trailing-7-day total across every protocol), or `0.0` when that sum is zero
(`pipeline/picket.py:63-65`).

### 5.3 `picket_ips.json` — [`schemas/picket_ips.schema.json`](../schemas/picket_ips.schema.json)

The globe-layer row set — a **separate** schema (copied from, not merged
into, `threat_ips.schema.json`) so the existing threat-IPs contract stays
untouched (spec §4.4). Produced in P1; not yet rendered (§2).

| Field | Type / bound | Meaning | Example |
|---|---|---|---|
| `generated_at` / `schema_version` / `attribution` | as §5.2 | Envelope, same values as `picket.json`. | — |
| `count` | integer, ≥0 | Number of rows in `ips`. | e.g. `1` (of the fixture's 3 `top_ips` rows, only `5.6.7.8` has both `lat` and `lng`; `test_ips_layer_only_has_finite_coords_and_source_picket` confirms 1 row) |
| `ips[]` | array, ≤1000 | One row per IP **with finite `lat`/`lng`** — IPs without a resolved coordinate are silently excluded from this file (not an error; `pipeline/picket.py::_ips_layer` skips non-numeric lat/lng). | — |

`ips[]` row (required: `ip`, `lat`, `lng`, `source`, `hits_7d`, `first_seen`, `last_seen`, `geo_precision`):

| Field | Type / bound | Meaning | Example |
|---|---|---|---|
| `ip` | string, ≤45 | Public source IP. | `"5.6.7.8"` |
| `country` | string, ≤2, optional | ISO alpha-2, when known. | `"CN"` |
| `lat` / `lng` | number, -90..90 / -180..180 | Resolved geolocation. | `39.9` / `116.4` |
| `source` | `const: "picket"` | Payload origin tag, always `"picket"` — this is how a future globe layer would distinguish these pins from `threat_ips.json`'s. | `"picket"` |
| `hits_7d` | integer, ≥0 | Trailing-7-day knocks from this IP. | `900` |
| `first_seen` / `last_seen` | string, ≤20 | As in `top_ips`. | — |
| `geo_precision` | `"city"` \| `"country"` | Copied from the export row's own `geo_precision` when present; defaults to **`"city"`** — not `"country"` — when absent (`r.get("geo_precision", "city")`, `pipeline/picket.py:89`). In practice this default is unreachable today: `_ips_layer` only processes rows that already passed a finite-`lat`/`lng` check (line 85), and `assemble_export` always sets `geo_precision="city"` whenever `lat`/`lng` are present (§5.1, `tools/picket/assemble.py:72-74`), so every row reaching this function already carries an explicit `"city"` value. | `"city"` |

### 5.4 knock-knock rollup column → export field

| knock-knock rollup | Column(s) | Export field(s) | Notes |
|---|---|---|---|
| `ip_intel` | `ip`, `hits`, `first_seen`, `last_seen`, `lat`, `lng`, `asn` | `top_ips[].ip/hits_total/first_seen/last_seen/lat/lng/asn` | `hits_total` is this table's `hits` directly; `hits_7d` comes from the ring, not this table. |
| `ip_intel_proto` | `ip`, `proto`, `hits` | `top_ips[].protocols[].proto/hits_7d` (see the §5.1 footnote), `by_protocol[].hits_total`, `totals.knocks_total` (via `SUM(hits)`) | Cumulative per (IP, protocol) pair. |
| `user_intel` | `username`, `hits` | `top_usernames[]` (via the fence, §6) | `hits` is the all-time count; `hits_7d` comes from the ring. |
| `pass_intel` | `password`, `hits` | `top_passwords[]` (via the fence, §6) | Same shape as `user_intel`. |
| `country_intel` | `iso_code`, `country`, `hits` | `top_countries[].iso/name/hits_total` | `name` passes through `clean_text`. |
| `isp_intel` | `isp`, `hits`, `asn` | `top_isps[].isp/hits_total/asn`, joined into `top_ips[].isp` by ASN | `isp` passes through `clean_text`, capped at 120 chars. |
| `monitor_heartbeats` | `uptime_minutes` | `sensor.uptime_minutes`, `totals.since` | `since = exported_at − uptime_minutes`. |
| GeoLite2-Country (not a knock-knock table) | — | `top_ips[].country`, keyed by IP | Resolved on-box by the exporter, joined in after reading rollups (`tools/picket/exporter.py::_country_by_ip`). |
| the delta ring (derived, not a table) | — | `ring.buckets`, `by_protocol[].hits_7d`, `top_ips[].hits_7d`, `top_usernames/passwords[].hits_7d`, `top_countries/isps[].hits_7d` | Everything genuinely time-windowed comes from `tools/picket/ring.py`, never straight from a rollup column. |

---

## 6. The PII fence

**Fence** is this project's term for the set of rules that decide which
attacker-supplied strings are safe to publish at all. Attackers replay
credential-stuffing lists that can contain real people's email addresses and
passwords; a honeypot that logged in with a bot's stolen credentials must
never republish them as if they were data about the bot. The rules live in
[`tools/picket/fence.py`](../tools/picket/fence.py) and are the same rules
both times they run (§4, §3):

1. **Aggregate only — no pairs, ever.** `top_usernames` and `top_passwords`
   are top-N lists of standalone values; no schema anywhere has a field that
   could hold a `(username, password)` pair, so this is enforced
   structurally, not just by code discipline (spec §3.6.1).
2. **Floor: `hits_7d ≥ 3`.** `MIN_CRED_HITS = 3`
   (`tools/picket/fence.py:14`) — a credential seen only once or twice in
   the trailing 7 days could be one real leaked credential replayed a
   handful of times, not a commodity brute-force term. The floor is checked
   in code at both fence sites (`tools/picket/assemble.py::_credlist`,
   `collectors/picket.py::_creds`) **and** structurally by the schema's
   `credlist.hits_7d.minimum: 3` (§5.1) — three independent backstops.
3. **`fence_credential()`'s drop rules**, applied to every candidate username
   and password value (`tools/picket/fence.py:23-33`):
   - runs `clean_text()` first (the same sanitizer every other collector in
     this repo uses, `collectors/base.py`) — strips/unescapes markup to a
     fixpoint;
   - drops anything longer than `MAX_CRED_LEN = 32` chars
     (`tools/picket/fence.py:13`) or empty after cleaning;
   - drops anything matching an email pattern
     (`_EMAIL_RE = r"[^\s@]+@[^\s@]+\.[^\s@]+"`);
   - drops anything matching an account-handle pattern
     (`_ACCOUNT_RE = r"^[A-Za-z0-9._-]+@[A-Za-z0-9.-]+$"` — catches
     `bob@corp`-style values with no dot in the host part, which the email
     regex alone would miss);
   - drops anything containing a 9-or-more-digit run allowing separators
     (`_LONG_DIGITS_RE = r"\d[\d\-\s.]{7,}\d"`, checked only once at least 9
     raw digits are present) — phone numbers, card numbers, SSN-like
     strings.
   Markup itself is **stripped, not dropped** — `<b>admin</b>` becomes
   `"admin"`, and an unterminated tag like `<img src=x onerror=alert(1)//`
   survives as inert text (`"img src=x onerror=alert(1)//"`) rather than
   being rejected outright (`test_markup_is_stripped_not_dropped`) — the
   value is still real attacker-submitted data, just rendered harmless.
4. **Sensor self-identifiers.** knock-knock's own on-box self-redaction
   (external to this repo, §3) is the first layer; the collector's explicit
   `sha256(ip) == sensor.public_ip_sha256` comparison
   (`collectors/picket.py:42`) is the second, code-verifiable layer — any
   `top_ips` row matching the sensor's own hashed public IP is dropped.
5. **Attacker IPs are published, deliberately.** `is_public_ip()`
   (`tools/picket/fence.py:36-43`) is a structural filter, not a privacy
   redaction: it excludes private, loopback, link-local, multicast,
   reserved, and unspecified address ranges, and **never** accepts CIDR
   notation (`ipaddress.ip_address` rejects a `/`-suffixed string outright).
   A public IP that brute-forced an unsolicited sensor is published as a
   fact about a host, framed as context (§1) — the same posture the ASN
   leaderboard already takes with abuse.ch/community IPs (spec §3.6.5).
6. **The Entra banned-password export's extra filter** (4–16 chars,
   case-deduped) does not exist yet — it is part of the P2 "Knock → Block"
   export pack (§2, §11), not the credential fence itself.

**Enforced twice, and it is literally the same code both times.**
`tools/picket/assemble.py` (on the box) and `collectors/picket.py` (in the
pipeline) both `import` `fence_credential` and `is_public_ip` from the one
module, `tools.picket.fence` — the second pass is not an independently
re-implemented fence that could drift from the first, it is the identical
function running again against attacker-influenced input that has now
crossed a trust boundary (a public GitHub raw URL, §1). `test_hostile_export_is_made_inert_and_fenced`
exercises this against `tests/fixtures/picket/export_hostile.json` — a fixture
containing a raw `<img src=x onerror=alert(1)//` username, an
`alice@example.com` value, HTML-entity-encoded markup in an ISP name, and a
private-range IP (`10.0.0.5`) mixed in among legitimate rows — and asserts
every one of them is either stripped to inert text or dropped outright by the
time the collector is done.

**What the schema forbids structurally, independent of any code path:**
`additionalProperties:false` on every object in all three schemas; no field
named or shaped to hold a username/password pair anywhere; `credlist.value`
bounded to 1–32 characters; `credlist.hits_7d` bounded to `minimum:3`;
`sensor.public_ip_sha256` constrained to the pattern `^[a-f0-9]{64}$`, which
makes it structurally impossible for that field to ever carry a plaintext IP
address, however the code that fills it might change in the future.

---

## 7. Freshness state machine

**Keep-prior** is this pipeline's general pattern (used elsewhere for
`actors.json` and others) for what happens when a collector fails to produce
fresh data: instead of publishing nothing or an empty/error payload, the
pipeline republishes the last successfully-collected payload, restamping
only the metadata that should always reflect "now" — so the site never goes
blank just because one fetch failed, but also never claims fresher data than
it has. For Picket, `pipeline/picket.py::restamp_prior` is the keep-prior
implementation: it re-stamps `generated_at` to now on both files, and, for
`picket.json`, **recomputes `sensor.status` and `sensor.export_age_minutes`
against the current time** — so a sensor that was `"live"` yesterday
correctly shows `"stale"` or `"silent"` today even though nothing about the
underlying data changed (this is the "HONEST status" the module's own
docstring calls out, `pipeline/picket.py:1-9,98-108`).

Status is computed by `pipeline/picket.py::sensor_status(exported_at, now)`
from the age of the export's own `exported_at` timestamp — never from
whether the *collector* succeeded this run, since a collector can succeed
while fetching a stale export (the box up, but its own timer stalled) just
as easily as it can fail outright:

| State | Condition (`pipeline/picket.py`) | UI copy (`web/src/components/views/picketModel.ts::statusCopy`) | What the pipeline does with prior data |
|---|---|---|---|
| `live` | `export_age_minutes < LIVE_MINUTES` (`LIVE_MINUTES = 90`) | *"Sensor reporting · last export \{age\} ago"* | A fresh `collect()` succeeded this run; `_panel()` builds a brand-new payload and `collected_at` is stamped to `now` (`pipeline/picket.py::build_picket`). |
| `stale` | `LIVE_MINUTES ≤ export_age_minutes < SILENT_MINUTES` (`SILENT_MINUTES = 24 * 60 = 1440`) | *"Sensor stale · no export for \{age\} — figures below are the last received"* | Either a fresh collection whose own `exported_at` is already old (the box is up but its export timer stalled), computed status fresh — or, more commonly, the collector failed and `restamp_prior()` recomputed status against `now` while holding `collected_at` at the last real collection. |
| `silent` | `export_age_minutes ≥ SILENT_MINUTES` | *"Sensor silent · no export for \{age\} — the sensor or its uplink is down; figures below are the last received"* | Same `restamp_prior()` path as `stale`, or an unparseable/garbage `exported_at` (`sensor_status` returns `("silent", 0)` as the safe default when the timestamp can't be parsed at all — `pipeline/picket.py:32-34`). |
| *(no payload)* | Collector never succeeded once, and no prior snapshot exists in `data/state/` | *"No sensor telemetry yet. The Picket sensor has not published an export the pipeline could read. Everything else on the desk still works."* (`PicketView.tsx`'s `EmptyState`); teaser shows *"No sensor telemetry yet."* | `build_picket()` returns `None`; nothing is written for `picket.json`/`picket_ips.json` this run (`test_collector_down_with_no_prior_is_none`). |

`export_age_minutes` is formatted for display by
`picketModel.ts::formatAge`: under 60 minutes as `"N min"`, under 24 hours
(1440 min) as a rounded `"N h"`, otherwise a rounded `"N d"`. The tab's status
chip itself carries no verdict colour either — it uses the neutral `accent`
(periwinkle) tone only when `status === 'live'`, and the plain `muted` tone
for both `stale` and `silent` (`PicketView.tsx:71-73`) — a freshness
indicator, not a severity one.

---

## 8. Failure modes

This is the spec's own §5 table (`docs/superpowers/specs/2026-09-17-picket-sensor-design.md`
lines 246–258), reproduced verbatim in the first two columns. Per the
controller's ruling on this task (R21), the **Observed (dogfood)** column is
added but every cell reads `pending dogfood` — the sensor box has not been
run yet, so no row of this table has been exercised against real hardware.
Nothing here is inferred or fabricated; it is only what the spec designed and
what §4/§7's code already implements.

| Failure | Behaviour (spec §5, as designed) | Observed (dogfood) |
|---|---|---|
| Box down / export repo unreachable / fetch > 2 MB | Collector `ok:false`; pipeline keeps last-known-good `picket*.json`, re-stamps `generated_at`; `sensor.status` computed from `exported_at` age → `stale` (90 min–24 h) / `silent` (> 24 h); panel + teaser render the state in words. `health.json` shows the error. Everything else unaffected. | pending dogfood |
| Export fails its own schema on-box | Exporter does **not** push; previous export stands; a local log line. | pending dogfood |
| Export passes on-box but fails the collector's re-validation / bounds | Treated as a failed collection (above). Vandalism containment. | pending dogfood |
| knock-knock DB reset | Deltas clamp to 0; `ring_reset_at` set; panel notes "counters reset \<date\>". | pending dogfood |
| `picket_lookup.json` missing in the Function | `loadPicket` returns null (not memoized); `SOCDESK_PICKET` omits itself; the card is byte-identical to today. | pending dogfood *(also not yet buildable — `picket_lookup.json` and `loadPicket` are P2, §2, §11)* |
| D1 read-only path unavailable in CI | Candidates published without the 30-day dedupe; `/admin` still shows decisions from its own read. | pending dogfood *(also not yet buildable — the candidate rule and D1 path are P3, §2, §11)* |
| AbuseIPDB non-200 on approve | Nothing persisted; 502 with the upstream message + quota headers; owner retries. | pending dogfood *(also not yet buildable — P3, §2, §11)* |
| MaxMind DB missing on-box | Per-IP `country` omitted (optional field); country/lat/lng from knock-knock's own GeoIP still present. | pending dogfood |

The first four rows are exercisable today by unit tests even before dogfood
— `tests/test_picket_pipeline.py::test_collector_down_restamps_prior_and_degrades_status`
and `test_collector_down_with_no_prior_is_none` cover row 1's pipeline-side
behavior directly; `tests/test_picket_ring.py::test_counter_decrease_is_clamped_and_flagged_as_reset`
and the per-entity variant cover row 4. "Observed (dogfood)" is deliberately
kept separate from "covered by a unit test" — a passing test proves the code
does what it was written to do against a fixture; it is not the same claim
as "this was seen to happen on the real box," which is what this column is
reserved for.

---

## 9. Surfaces

Three places a person can see Picket's data today; screenshots are called
out separately below and are **not** included in this commit (see the note
at the end of this section).

### `/desk#picket` — the tab

`PicketRoute.tsx` reads the committed `picket.json` snapshot (no API call,
no account — same no-account read path as every other Desk tab) and renders
`PicketView.tsx`. Top to bottom:

- A `ViewHeader` with eyebrow `SOCDESK · PICKET`, title `Picket`, and the
  intro line *"Telemetry from SOCDesk's own internet-facing honeypot: what
  automated bots try against an unsolicited sensor. Context, never a verdict
  on any network or operator."*, plus a relative "updated \{time\}" aside
  once data has loaded.
- A status strip: the freshness chip and copy from §7, plus a monospace line
  of `protocols joined by " · "` · `up N d` · `knock-knock \{version\}`, and
  (only when set) `· counters reset \{relative time\}`.
- Three KPI blocks: Knocks · 24h, Knocks · 7d, Distinct IPs · 7d.
- A "Seven days, by day" block: a `Sparkline` fed by
  `histogramPoints(histogram_7d, generated_at)`
  (`web/src/components/views/picketModel.ts`), which **downsamples the 168
  hourly values into daily points** — `Math.floor(168/24) = 7` points, one
  per day, each the sum of that day's 24 hourly buckets — not an hour-by-hour
  chart despite the payload carrying hourly resolution.
- A "By protocol · 7 d" bar list, one row per `by_protocol[]` entry, showing
  `share_pct` as both a bar width and a percentage label.
- A "Top sources · 7 d" table: IP, Attempts (bar + count), Protocols (names
  only, joined — see the §5.1 footnote for why the underlying per-protocol
  figure isn't shown), Country, `ASN · ISP`, First seen, Last seen. Column
  headers use `scope="col"` (house accessibility convention, commit
  `3c5e6d7b`).
- Side-by-side "Usernames tried · 7 d" and "Passwords tried · 7 d" blocks
  (`CredList`) — each row is one aggregate value with a bar and a count;
  never a pair. Empty-state copy when a list has nothing above the floor:
  *"None above the publication floor (3 attempts) this week."* A fixed
  caption underneath both lists restates the honesty framing: *"Credentials
  are shown as separate aggregate lists — never as the pairs bots submit —
  and anything resembling a real identity is dropped before publication."*
- "Countries · 7 d" and "Networks · 7 d" bar lists.
- The payload's own `attribution` string, rendered verbatim as a footer line.

When `picket.json` is entirely absent, the whole view is replaced by
`EmptyState`: *"No sensor telemetry yet. The Picket sensor has not published
an export the pipeline could read. Everything else on the desk still
works."*

### The landing-board teaser

`PicketTeaser.tsx` is a `BoardPanel` on the landing board (same idiom as the
ASN leaderboard's teaser): eyebrow `SOCDESK · PICKET`, title *"Picket —
telemetry from my own sensor,"* a `SourceStamp` reading *"knock-knock ·
GeoLite2,"* and a footer showing `\{knocks_7d\} knocks · \{unique_ips_7d\} IPs
· 7 d` (or `"no export yet"`) beside a `DeskLink` to the tab. The body shows
the same `statusCopy`, a large 24-hour knock count, the same daily sparkline
as the tab, and, when available, a `"most from \{country\} · \{protocols\}"`
line — the sensor's own protocol list is appended after the top country,
not just the country alone (`PicketTeaser.tsx:39`). Empty state: *"No
sensor telemetry yet."*

### `/about#picket` — the transparency section

`web/src/routes/About.tsx`, section `id="picket"`. An accent-tinted "In
short" callout — *"Picket is an internet-facing honeypot SOCDesk runs
itself. It records what automated bots try against a server nobody invited
them to — and publishes counts. It is context, never a verdict on any
network or operator."* — followed by plain-language paragraphs: what is
collected (attempt counts by IP/protocol/country/network, plus the two
separate top-N credential lists, with the floor and identity-filtering
stated in prose), what is *not* collected (no victims, no per-attempt logs,
no real-user traffic), how the data reaches the site (bounded export,
re-checked and re-sanitized, 30-minute refresh, honest silence), that
upstream reporting is owner-moderated (this paragraph describes the P3
design intent — nothing reports anywhere automatically today, and the
reporting mechanism itself does not exist yet, §2, §11), a disputes/removal
paragraph (`abuse@socdesk.io`, "Removal is the response"), and an attribution
paragraph naming knock-knock (MIT) and MaxMind GeoLite2.

### Screenshots

Per the controller's ruling on this task, no screenshots were taken and no
`docs/img/picket/` directory or image file was created by this task — Task
14 produces them. This document references the six paths it expects to
exist once that task runs, each with a fixed caption:

- `docs/img/picket/tab-light.png` — *"Rendered from fixture data
  (`tests/fixtures/picket/export_ok.json`) via `vite preview`; pre-dogfood."*
- `docs/img/picket/tab-dark.png` — same caption.
- `docs/img/picket/teaser-light.png` — same caption.
- `docs/img/picket/teaser-dark.png` — same caption.
- `docs/img/picket/about-light.png` — same caption.
- `docs/img/picket/about-dark.png` — same caption.

---

## 10. Compliance & attribution

**First-party posture.** Every row Picket publishes is telemetry SOCDesk's
own sensor generated — not a redistribution of anyone else's corpus. This is
what makes it clearly redistributable under `COMPLIANCE.md`'s
aggregator-not-mirror rule without the case-by-case terms review that
applies to a third-party feed: there are no third-party terms to satisfy,
because there is no third party's data in `export.json`, `picket.json`, or
`picket_ips.json`. (A `COMPLIANCE.md` entry documenting this posture formally
is a separate P1 documentation deliverable per the spec's §10 table; it had
not been added as of this writing — this document does not speak for
`COMPLIANCE.md`, only summarizes the posture its own rules already
establish.)

**Why attacker IPs are published.** Spec §3.6.5: *"a public IP that
brute-forced an unsolicited sensor is a fact about a host, not personal
data."* SOCDesk already publishes third-party abuse IPs this way (the ASN
leaderboard, `threat_ips.json`); Picket applies the identical framing to
IPs the sensor observed directly, which is if anything a stronger footing
since it is first-party observation, not a claim about someone else's report.
The IP itself is the redistributable datum; nothing about the IP's owner or
operator is asserted (§1).

**Attribution lines.** Both required attributions are carried in-band in the
published payload's `attribution` string (`pipeline/picket.py::ATTRIBUTION`,
≤1000 chars per schema) so they travel with the data wherever it's read, and
are repeated in the runbook (`tools/picket/README.md` §9) and on
`/about#picket` (§9 above):

- **knock-knock** — MIT License, © the knock-knock project contributors
  (github.com/djkurlander/knock-knock). SOCDesk runs it unmodified, at a
  pinned tag (§3); the MIT license text is preserved wherever the software
  itself is redistributed (it is not — SOCDesk runs knock-knock, it does not
  redistribute its source).
- **MaxMind GeoLite2** — *"This product includes GeoLite2 data created by
  MaxMind, available from https://www.maxmind.com,"* required by MaxMind's
  GeoLite2 End User License Agreement wherever the database is used
  (per-IP country resolution, §3).

**Dispute path.** `abuse@socdesk.io` (the same address used for the
community-reports dispute path, `web/src/routes/About.tsx:19`). The stated
posture is unconditional: *"Removal is the response"* — no adjudication
process is promised beyond the owner acting on the request.

---

## 11. Roadmap

**P2 — fusion + exports** (spec §3.7, §3.8, §3.10, §3.11's "Globe" bullet,
§9). Adds, additively, without changing anything P1 already publishes:
`picket_lookup.json` (the ≤5,000-entry enrich index) and the
`SOCDESK_PICKET` `kind:"context"` row on `/lookup` (`lib/enrich.mjs`,
`functions/api/enrich.js::loadPicket`); folding `"picket"` into
`pipeline/asn.py`'s `SOURCES` so the ASN leaderboard counts it as a third
source; rendering `picket_ips.json` on the ambient globe
(`heroLayers.ts`); the lead-time statistic (*"X of Y new attacker IPs this
week were unknown to the feeds SOCDesk holds"*), with its C2-feed-not-
brute-force-feed honesty caveat rendered in-band; and the four-file "Knock →
Block" export pack (Defender for Endpoint indicators CSV, Sentinel watchlist
CSV + KQL hunt pack, Entra Password Protection banned-list, plain blocklist)
with per-product import cards.

**P3 — moderated give-back** (spec §3.9, §9). Adds the D1 migration
`migrations/0002_picket.sql` (a `picket_reports` table: IP, decision,
timestamp — no PII by construction); the owner-gated
`GET /api/admin/picket` / `POST /api/admin/picket` Functions; the `/admin`
Picket tab (`PicketQueue.tsx`); the `data/picket/benign_scanners.json`
owner-curated allow-list; and the report-candidate rule (≥10 hits on
credential-bearing protocols, not already on abuse.ch, not benign-scanner,
no D1 decision in 30 days) with its dedupe against the existing read-only D1
path.

**P4 — separate spec, later** (spec §3.10 "Phase 4" note, §9). A STIX 2.1
bundle export for Sentinel's STIX-objects API or any other TIP; week-over-
week trend movement for Picket's own numbers; the optional IoT/OT protocol
set (MQTT, Node-RED, Modbus, S7, SNMP) as an owner toggle; and a possible
knock-knock upstream protocol contribution.

---

## 12. Change log

**2026-09-17 — P1 foundation — created.**

`docs/PICKET.md` created alongside the P1 implementation on `feat/picket-p1`.
Full commit range (`git log --oneline f532b53..HEAD`, oldest first):

1. `3fe8038f` — feat(picket): credential PII fence + public-IP test (pure, box+pipeline shared)
2. `aa521f02` — fix(picket): fence dotted/hyphenated/underscored handle@host credentials
3. `c8010ce8` — feat(picket): 30-min delta ring for 7-day series without per-knock storage
4. `245be0ca` — test(picket): cover per-entity-only reset clamp and partial window slide
5. `678a9e37` — feat(picket): raw export schema (bounded, described) + fenced assembler
6. `6794d6e3` — feat(picket): exporter CLI, systemd timer, box bootstrap + runbook
7. `05e7a2a5` — docs(picket): runbook — stage exporter files before install.sh; exhaustive copy list
8. `4b62e2fb` — docs(picket): runbook — rsync --relative so staged files land under /opt/socdesk; admin port after hardening
9. `128b8326` — feat(picket): keyless collector with second-pass sanitizer + fence
10. `14d2b52e` — feat(picket): published payload + globe-layer schemas and builder (honest stale/silent)
11. `dfffeb0b` — feat(picket): wire collector + builder into run_pipeline (gate + keep-prior + dual-write)
12. `8b653cbe` — feat(picket): web types + pure view model (status copy, age, daily histogram)
13. `e5f1b159` — fix(picket): asn is an optional integer in PicketIp/PicketIsp, matching picket.schema.json
14. `f1403624` — feat(picket): /desk#picket tab — sensor status, histogram, protocols, sources, fenced credentials
15. `3c5e6d7b` — fix(picket): scope="col" on the sources table headers (house a11y convention)
16. `f0b9c618` — feat(picket): landing-board teaser panel
17. `ea4cb430` — feat(picket): /about#picket transparency section

This document itself lands as the next commit after `ea4cb430`.
