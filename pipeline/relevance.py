"""Feed relevance scoring — the difference between a news page and a console.

Reverse-chronological is a newspaper. An operational feed promotes what an
analyst should look at FIRST, which is rarely the newest thing. Every signal
here is derived from data we already hold, so the score is explainable: each
item carries the reasons it scored, and the UI shows them.
"""

WEIGHTS = {
    "kev": 40,          # a referenced CVE is confirmed exploited in the wild
    "epss_high": 25,    # referenced CVE has >=50% exploitation probability
    "epss_med": 12,
    "cvss_critical": 10,
    "watchlist": 30,    # touches something the analyst asked to be told about
    "severity_critical": 18,
    "severity_high": 10,
    "actor": 8,         # names a tracked adversary
    "malware": 6,
    "fresh_6h": 12,     # recency is a tiebreaker, not the ranking
    "fresh_24h": 6,
}
CAP = 100


def score_item(item, cve_index, now_iso, watchlist=(), tracked_actors=()):
    """Return (score, reasons). Pure and deterministic — no clock reads.

    `tracked_actors` is the lowercased set of curated adversary names. The
    "tracked adversary" bonus fires ONLY for an actor in that set — a raw
    ransomware.live leak-site group, injected wholesale into an item's actors,
    must not read as a tracked adversary (that inflated ~half the feed by 8).
    """
    reasons, score = [], 0
    ents = item.get("entities") or {}

    best_kev = False
    best_epss = 0.0
    best_cvss = 0.0
    for cve in ents.get("cves") or []:
        row = cve_index.get(cve.upper())
        if not row:
            continue
        best_kev = best_kev or bool(row.get("kev"))
        best_epss = max(best_epss, row.get("epss") or 0.0)
        best_cvss = max(best_cvss, row.get("cvss") or 0.0)

    if best_kev:
        score += WEIGHTS["kev"]; reasons.append("KEV-listed CVE")
    if best_epss >= 0.5:
        score += WEIGHTS["epss_high"]
        reasons.append(f"EPSS {round(best_epss * 100)}%")
    elif best_epss >= 0.1:
        score += WEIGHTS["epss_med"]
        reasons.append(f"EPSS {round(best_epss * 100)}%")
    if best_cvss >= 9:
        score += WEIGHTS["cvss_critical"]; reasons.append(f"CVSS {best_cvss}")

    if watchlist:
        hay = " ".join([item.get("title", "")] + list(ents.get("vendors") or [])).lower()
        hit = next((w for w in watchlist if w and w in hay), None)
        if hit:
            score += WEIGHTS["watchlist"]; reasons.append(f"watchlist: {hit}")

    sev = item.get("severity")
    if sev == "critical":
        score += WEIGHTS["severity_critical"]; reasons.append("critical severity")
    elif sev == "high":
        score += WEIGHTS["severity_high"]

    tracked_hit = next(
        (a for a in ents.get("actors") or [] if a.lower() in tracked_actors), None)
    if tracked_hit:
        score += WEIGHTS["actor"]
        reasons.append(f"actor: {tracked_hit}")
    if ents.get("malware"):
        score += WEIGHTS["malware"]
        reasons.append(f"malware: {ents['malware'][0]}")

    pub = item.get("published_at") or ""
    if pub:
        # string comparison on ISO timestamps — same ordering, no parsing
        if pub >= _shift(now_iso, hours=-6):
            score += WEIGHTS["fresh_6h"]; reasons.append("last 6h")
        elif pub >= _shift(now_iso, hours=-24):
            score += WEIGHTS["fresh_24h"]

    return min(score, CAP), reasons


def _shift(now_iso, hours):
    from datetime import datetime, timedelta, timezone
    t = datetime.strptime(now_iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    return (t + timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")


def apply_scores(items, cve_rows, now_iso, watchlist=(), tracked_actors=()):
    """Annotate items in place with `score` and `why`, newest-first as tiebreak."""
    idx = {c["cve"].upper(): c for c in cve_rows}
    for it in items:
        s, why = score_item(it, idx, now_iso, watchlist, tracked_actors)
        it["score"] = s
        it["why"] = why[:4]
    return items


def _sector_of(summary):
    """Pull the sector label out of a claim summary of the form
    '... Sector: <sector> — Country: <country>.' — robust to any prose prefix
    before 'Sector:' (the claim summary now leads with an attribution clause)."""
    if not summary or "Sector:" not in summary:
        return ""
    after = summary.split("Sector:", 1)[1]
    return after.split("—", 1)[0].strip().rstrip(".").strip()


def group_repetitive(items, source, key_fn, threshold=4):
    """Collapse a run of near-identical items from one source into a digest.

    Ransomware victim-claim stubs are ~55% of the feed and individually
    uninformative; as a grouped row ("akira posted 6 claims") they are useful
    and stop drowning everything else.
    """
    from collections import defaultdict
    buckets, out = defaultdict(list), []
    for it in items:
        if it.get("source") == source:
            buckets[key_fn(it)].append(it)
        else:
            out.append(it)
    for key, group in buckets.items():
        if len(group) < threshold:
            out.extend(group)
            continue
        head = dict(group[0])
        head["title"] = f"{key} posted {len(group)} victim claims"
        sectors = sorted({s for g in group if (s := _sector_of(g.get("summary") or ""))})
        head["summary"] = ("Grouped: " + ", ".join(sectors[:6]))[:400]
        head["grouped"] = len(group)
        head["score"] = max(g.get("score", 0) for g in group)
        head["why"] = [f"{len(group)} claims in window"]

        # The digest represents MANY victims — carry them all so the profile
        # can expand the list, instead of inheriting group[0]'s single
        # victim/domain (which silently dropped every other victim from the
        # published feed for the busiest groups).
        claims = []
        for g in group:
            victim = g.get("victim")
            if not victim:
                continue
            claim = {"victim": victim}
            domain = g.get("domain")
            if domain:
                claim["domain"] = domain
            claim["date"] = g.get("published_at")
            claim["url"] = g.get("url")
            claims.append(claim)
        claims.sort(key=lambda c: c.get("date") or "", reverse=True)
        head["claims"] = claims[:100]
        head.pop("victim", None)
        head.pop("domain", None)

        out.append(head)
    out.sort(key=lambda i: (i.get("score", 0), i.get("published_at", "")), reverse=True)
    return out
