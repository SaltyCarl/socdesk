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


def score_item(item, cve_index, now_iso, watchlist=()):
    """Return (score, reasons). Pure and deterministic — no clock reads."""
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

    if ents.get("actors"):
        score += WEIGHTS["actor"]
        reasons.append(f"actor: {ents['actors'][0]}")
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


def apply_scores(items, cve_rows, now_iso, watchlist=()):
    """Annotate items in place with `score` and `why`, newest-first as tiebreak."""
    idx = {c["cve"].upper(): c for c in cve_rows}
    for it in items:
        s, why = score_item(it, idx, now_iso, watchlist)
        it["score"] = s
        it["why"] = why[:4]
    return items


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
        head["summary"] = ("Grouped: " + ", ".join(
            sorted({(g.get('summary') or '').split('—')[0].replace('Sector:', '').strip()
                    for g in group if g.get('summary')})[:6]))[:400]
        head["grouped"] = len(group)
        head["score"] = max(g.get("score", 0) for g in group)
        head["why"] = [f"{len(group)} claims in window"]
        out.append(head)
    out.sort(key=lambda i: (i.get("score", 0), i.get("published_at", "")), reverse=True)
    return out
