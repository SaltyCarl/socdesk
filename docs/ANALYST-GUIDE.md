# SOCDesk — Analyst Guide

For the person actually using the tool on shift. No setup, no code.

SOCDesk does two things: it collapses the six-tab indicator lookup into one
paste, and it writes the escalation for you afterwards. Everything else on the
page supports those two.

**Before anything else, two rules that are not negotiable:**

> **Use public indicators only.** Clicking a pivot link discloses that
> indicator to the third-party service you clicked. urlscan publishes public
> scans. Do not paste indicators from a live client incident into a public
> tool.
>
> **Absence is not clearance.** "NOT IN CORPUS" means this tool holds no data
> about that indicator. It never means the indicator is safe.

---

## Looking something up

Paste into the search box at the top and press Enter. Press `/` from anywhere
to jump to it.

The type is detected automatically and shown as a chip beside the box: IPv4,
domain, URL, MD5, SHA-1, SHA-256, CVE, or email. Defanged input is understood —
`evil[.]com`, `hxxp://`, `1.2.3[.]4`, `user[at]example.com` all refang
themselves before the lookup runs.

You can also paste an actor or malware **name** — "volt typhoon", "Midnight
Blizzard", "Mimikatz". Aliases resolve, so you do not need the canonical
spelling.

Results open in a panel directly under the search. The page does not jump.
`Esc` or **Clear** closes it.

Every lookup writes itself into the URL as `#q=<indicator>`, so the address bar
is a shareable link to that exact result, and a **Recent** row keeps your last
12 lookups one click away.

## Looking something up without leaving the page you are on

Switching tabs to paste an indicator is most of the friction in using a tool
like this, so there is a bookmarklet that removes it. Open **Toolbelt**, find
the *Bookmarklet* card at the bottom, and drag the **SOCDesk lookup** button
onto your bookmarks bar. If your bookmarks bar is hidden, **Copy URL instead**
gives you the same thing to paste into a bookmark you create by hand.

After that, on any page — a SIEM result, a ticket, an email header — select an
indicator and click the bookmark. A tab opens with the verdict already
resolved. Select a block containing several indicators and you get the bulk
table instead.

It reads a selection made inside a search box or text area, not just ordinary
page text, because that is where indicators usually are.

Two things worth knowing. The indicator travels in the URL *fragment*, the part
after the `#`, which browsers never include in the request they send — so
nothing you look up is transmitted to this site's host, the same guarantee the
toolbelt gives. And the bookmark records whichever address you installed it
from, so if you install it now and the site later moves to its own domain, redo
the drag once to follow it.

## What the verdict means — and what it does not

There are three kinds of result, and telling them apart matters.

### 1. A CVE — a real verdict

This is the only indicator type where SOCDesk has an authoritative answer,
because CISA KEV, NVD and FIRST EPSS are public-domain data the tool actually
holds.

| Verdict word | What triggered it | What it means |
|---|---|---|
| **ACTIVELY EXPLOITED** | The CVE is on the CISA KEV catalogue | CISA has confirmed exploitation in the wild. Treat exposed instances as urgent |
| **LIKELY EXPLOITED** | EPSS ≥ 50% | Statistical probability of exploitation in the next 30 days — a forecast, not an observation |
| **CRITICAL SEVERITY** | CVSS ≥ 9.0 | Severe *if* exploited. Says nothing about whether anyone is exploiting it |
| **TRACKED** | In the corpus, none of the above | Known and scored, nothing alarming |

The number in the gauge is **the EPSS probability as a percentage** — not a
composite risk score, and not a severity. A gauge reading 87 means "EPSS puts
this at an 87% chance of exploitation activity in the next 30 days". A KEV-listed
CVE with a low gauge is still the more urgent of the two: KEV is an
observation, EPSS is a prediction.

Under it, the **Public data** block shows the evidence the verdict was built
from — KEV listing date and ransomware-use flag, CVSS base score and severity,
EPSS probability and percentile, vendor/product, publication date. Every line
is a fact from a named source, not an inference.

What a CVE verdict does **not** tell you: whether *your* environment is
exposed, whether a patch exists, or whether an alert referencing this CVE is a
true positive. It tells you how the rest of the world is treating this
vulnerability today.

**If a CVE returns NOT IN CORPUS**, it is outside the 180-day window and is not
KEV-listed. Reserved and very old identifiers land here. Check NVD directly —
the pivot is right there.

### 2. Any other indicator — a router verdict

IPs, domains, URLs, hashes and email addresses always return **NOT IN CORPUS**
with the same explanation: this tool holds no reputation corpus for that type,
by design, because those corpora are not licensed for redistribution. What you
get instead is the correct set of pivots for that type, chosen so you are not
guessing which service is worth checking:

- **IPv4** — VirusTotal, AbuseIPDB, GreyNoise, Shodan, Censys, Spamhaus, urlscan
- **Domain** — VirusTotal, urlscan, Pulsedive, IBM X-Force, Censys
- **URL** — VirusTotal, urlscan search, Pulsedive, PhishTank, and three
  sandboxes marked with a warning glyph
- **Hash** — VirusTotal, MalwareBazaar, MetaDefender, Hybrid Analysis, Tria.ge,
  ANY.RUN
- **Email** — Have I Been Pwned and Hudson Rock only; file and URL reputation
  services are deliberately omitted because they answer nothing about an address

Two things about the sandbox links. They are marked with a warning glyph
because **submitting a URL detonates it**, which is a much bigger disclosure
than reading a scan someone else already ran. For URLs the list deliberately
leads with urlscan *search* — check for an existing public scan before you
create a new one.

Nothing is ever fetched on your behalf. The tool cannot contact any of these
services; it only builds the link. One click goes to one service.

### 3. A name — an ATT&CK profile

Actor and malware names return the MITRE ATT&CK profile: aliases, description,
technique IDs, and associated software. Each piece of software is a button that
looks itself up, so you can walk a toolset without retyping. The ATT&CK link
takes you to the source page.

## The escalation write-up

Beside every verdict is the artifact most people came for: a formatted
**Escalation summary** containing the defanged indicator, its type, the
assessment and its basis, the public evidence, suggested next steps tailored to
the indicator type, and the external references — timestamped, with a
verify-independently caveat.

Three buttons: **Copy markdown**, **Copy text**, **Download .md**. What you see
rendered on screen is exactly what copies; there is no hidden second version.

The next-steps list is type-aware. A CVE gets exposure identification, patch
confirmation, and log hunting, with a ransomware line added when KEV flags
known ransomware use. An IP gets perimeter and proxy log searches plus a
reminder to check for shared infrastructure before blocking. A hash gets EDR
telemetry, sandbox retrieval, and parent-process capture.

**Read it before you send it.** It is a scaffold written from public data — it
is deliberately generic, it does not know your environment, your severity
taxonomy, or your client, and it is not a substitute for your own assessment.
If a copy button reports **COPY BLOCKED** instead of **COPIED**, the clipboard
was genuinely denied and nothing was copied; the button will not lie to you
about that.

## Bulk lookup

Paste more than one indicator — separated by spaces, newlines, commas,
semicolons or pipes — and you get a table instead of a single verdict. Up to
200 at a time. Anything that is not a recognised indicator type is silently
dropped, so you can paste a whole block of alert text without cleaning it first.

Exports: **CSV** (indicator, type, assessment, score), **JSON**, and
**Defanged TXT** for pasting somewhere that would otherwise make the indicators
clickable.

The toolbelt's **Lookup all** button feeds extracted IOCs straight into this
table.

## The feed as a work queue

The feed is sorted by **Priority**, not by time. That is the point — the newest
item is rarely the one to look at first.

Every item carries a score from 0 to 100 and, next to it, the reasons it scored
— the **why** row. The reasons are the entire basis of the ranking; there is no
hidden model. What contributes:

| Signal | Weight |
|---|---|
| Item references a KEV-listed CVE | 40 |
| Referenced CVE has EPSS ≥ 50% | 25 |
| Referenced CVE has EPSS ≥ 10% | 12 |
| Critical severity | 18 |
| Referenced CVE has CVSS ≥ 9 | 10 |
| High severity | 10 |
| Names a tracked adversary | 8 |
| Names tracked malware | 6 |
| Published in the last 6 hours | 12 |
| Published in the last 24 hours | 6 |

Capped at 100. Recency is a tiebreaker, not the ranking. The score colour bands
are 80+, 60+, 40+, and below — a red 90 is a "look at this now", a grey 15 is
background.

Because the reasons are shown, you can disagree with the order and see exactly
why it happened. If an item scored 40 on nothing but "KEV-listed CVE", that is
all the tool is claiming.

**Digest rows.** When one ransomware group posts four or more victim claims in
the window, they collapse into a single row marked `digest · N reports`.
Victim organisation names are never republished here — the claim link has the
detail. Treat every one of these as an unverified criminal claim, because that
is what it is.

**Toggle to Newest** for chronology. Only in Newest order do you get the "N new
since last visit" boundary marker — it is a chronological claim, so it would be
a lie in Priority order.

**Keyboard triage:**

| Key | Action |
|---|---|
| `/` | Jump to the search box |
| `j` / `k` | Next / previous item |
| `r` | Mark reviewed (dims the row) |
| `n` | Flag notable (feeds the handoff digest) |
| `Esc` | Close the verdict panel |

The filter box searches title, summary, and every extracted entity. Category
chips and the stat band above the feed filter to ransomware, vulnerability,
APT, malware, campaign, or report. **Export JSON** downloads exactly the rows
currently visible, filters and ordering included.

Selecting a row opens detail on the right: the full summary, the source link,
extracted entities as clickable chips that look themselves up, and copy buttons
for the defanged URL, the raw URL, and a ready-made awareness blurb.

## The shift handoff

Press `n` on anything worth passing along. The **Handoff** button shows a
running count, and clicking it copies a markdown digest — every flagged item
with its title, source, link and the time you flagged it, in the order you
flagged them.

Flags live in your browser only. They do not reach anyone else, they do not
survive **Clear analyst state**, and the next shift sees them only because you
pasted the digest somewhere.

## Vulnerability triage

The full CVE table: a 180-day window plus every KEV entry regardless of age.
Sort by CVE, CVSS, EPSS, publication date, or the composite risk column. Filter
to **KEV only**, or to your watchlist.

**The watchlist** is a list of vendor or product strings — `fortinet`, `citrix`,
whatever you own. Matching rows get a marker, and **Watchlist only** filters the
table to them. Note what it does *not* do: it does not re-rank the feed. The
ranking is computed in the pipeline before your browser is involved, and your
watchlist never leaves your browser. It is a display and filter tool.

**Trends** sits above the table and answers "what changed": the biggest
exploitation-probability rises since the comparison date, and what was newly
added to KEV. Both are built by diffing committed daily snapshots. On a fresh
deployment there is nothing to compare against, and the panel says so rather
than inventing movement.

## The toolbelt

Five utilities that run entirely in your browser. Nothing you paste there is
transmitted anywhere — there is a test in the suite that asserts the toolbelt
makes zero network requests.

- **Defang / refang** — make indicators safe to paste, or undo it
- **IOC extract** — pull IPs, domains, URLs, hashes, emails and CVEs out of
  alert text, email headers or a report paragraph. **Lookup all** pushes them
  into the bulk table
- **Base64 decode, UTF-16LE aware** — tries UTF-16LE first, which is what
  PowerShell `-EncodedCommand` uses, then falls back to UTF-8
- **PowerShell command parser** — expands abbreviated flags to their full
  names, flags evasion patterns, and decodes an embedded payload
- **LOLBin lookup** — 33 living-off-the-land binaries with their ATT&CK
  technique, risk rating, and the meaning of their abused flags

Output is always text, never live markup.

## Freshness, and how to tell

The masthead shows the edition date, the tracked-object count, an elapsed
counter since the last ingest, and a countdown to the next scheduled pull.
Collectors run twice an hour. The counters measure the tool's own clock — they
never pretend to be real-time.

- **FEED STALE** appears when the feed is more than 90 minutes old.
- **OFFLINE · CACHED DATA** appears when your browser is offline. The site keeps
  working off the last cached pull, and the elapsed counter keeps telling you
  its true age.
- **Health** shows every collector, its item count, and how long since it last
  succeeded. One red source does not invalidate the page; it means that slice
  of data is as old as the timestamp says.

If something looks wrong, check Health first. A quiet feed is usually a source
that has been down for a few hours, not a bug.

## Privacy

There is no backend, no account, and no analytics. Your lookups, reviewed
marks, notable flags, watchlist and history live in your browser's local
storage and are never transmitted — the page's security policy blocks outbound
requests to anywhere but its own origin, so this is a property of the
architecture rather than a promise.

The exception, and it matters: **clicking a pivot link discloses that indicator
to that service.** That is the one moment information leaves.

**Clear analyst state** wipes everything this browser holds and reloads. Use it
on a shared workstation, and use it before handing the screen to anyone.

## What this tool is not

Be direct about the limits — an escalation built on a misunderstanding of them
is worse than no escalation.

1. **It is aggregation and routing, not proprietary intelligence.** SOCDesk
   generates no telemetry, runs no sensors, and detects nothing. Its value is
   that it gets you to the right public sources fast and writes up what they
   said.
2. **NOT IN CORPUS is not a clean verdict.** For everything except CVEs it is
   the *only* possible answer, and it carries no information about the
   indicator at all.
3. **It is a snapshot, not a live query.** Data is up to 30 minutes old at
   best. If a source retracts something, a static snapshot will not know until
   the next pull.
4. **KEV and EPSS mean specific things.** "Known exploited" and "probability of
   exploitation" are not "malicious". Do not translate a vulnerability verdict
   into a statement about a file or a host.
5. **Ransomware claims are unverified.** They are criminal advertising, not
   confirmed breaches.
6. **The feed window is 30 days and the CVE window is 180 days**, plus all of
   KEV. Older material is not absent from the world, only from here.
7. **No warranty.** Verify independently before acting on any indicator. This
   is a personal project, not a vendor product, and not an official tool of any
   organization.
