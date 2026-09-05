"""Feed cross-source clustering — group feed items sharing a primary entity AND
corroborated by >=2 distinct OUTLETS into one story row (spec
2026-09-05-feed-clustering-design).

Why outlet, not source: all 9 news feeds arrive under source="rss"; the outlet
is the `[Outlet]` prefix in the title (a Python port of FeedView.tsx sourceLabel).
A story requires >=2 DISTINCT outlets, which excludes single-outlet leak-site
tallies (already aggregated on Profiles). Deltas come from the CVE catalog
(cve_rows), not the ransomware cve_context (which covers only seed CVEs).
"""
import re

# Mirror of FeedView.tsx:64 — the outlet name is the leading [Bracketed] token.
_OUTLET_RE = re.compile(r"^\s*\[([^\]]+)\]\s*")
_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}
MEMBER_CAP = 12


def story_outlet(item):
    """The human outlet for a feed item — port of FeedView.tsx:93 sourceLabel."""
    src = item.get("source", "")
    if src == "kev":
        return "CISA KEV"
    if src == "ransomwarelive":
        return "ransomware.live"
    m = _OUTLET_RE.match(item.get("title") or "")
    return m.group(1).strip() if m else (src or "unknown")


def _strip_outlet(title):
    return _OUTLET_RE.sub("", title or "").strip()


def established_actors(actors, intel, feed_items):
    """Actors that may anchor a story — a real tracked entity (ATT&CK fingerprint
    OR intel seed OR >=1 leak-site claim). Mirror of profiles.ts `keep`; kills the
    "play" = Google Play false positive fusing news with Play-ransomware claims."""
    est = set()
    for p in actors or []:
        if p.get("name"):
            est.add(p["name"].lower())
        for a in p.get("aliases") or []:
            if a:
                est.add(str(a).lower())
    for g in intel or []:
        if g.get("slug"):
            est.add(str(g["slug"]).lower())
        for a in (g.get("slug_aliases") or []) + (g.get("aliases") or []):
            if a:
                est.add(str(a).lower())
    for it in feed_items or []:
        if it.get("source") == "ransomwarelive":
            acts = (it.get("entities") or {}).get("actors") or []
            if acts and acts[0]:
                est.add(str(acts[0]).lower())
    return est


def primary_entity(item, established):
    """The entity a feed item clusters on, deterministic (CVE > established actor >
    malware). Returns (etype, evalue) or None (a 1:1 row, never a story)."""
    e = item.get("entities") or {}
    if e.get("cves"):
        return ("cve", str(e["cves"][0]).upper())
    actors = e.get("actors") or []
    if actors and str(actors[0]).lower() in established:
        return ("actor", str(actors[0]).lower())
    if e.get("malware"):
        return ("malware", str(e["malware"][0]).lower())
    return None


def _max_severity(members):
    best, rank = "", -1
    for m in members:
        s = str(m.get("severity") or "").lower()
        if _SEV_RANK.get(s, 0) > rank:
            rank, best = _SEV_RANK.get(s, 0), m.get("severity") or ""
    return best


def build_stories(feed_items, cve_rows, trends, actors, intel):
    """Returns {"stories": [...]} — the sibling payload. Only clusters spanning
    >=2 distinct outlets survive."""
    established = established_actors(actors, intel, feed_items)
    cve_by_id = {str(r["cve"]).upper(): r for r in (cve_rows or []) if r.get("cve")}
    movers = {str(m["cve"]).upper(): m
              for m in (trends.get("epss_movers") or []) if m.get("cve")}

    groups = {}
    for it in feed_items or []:
        key = primary_entity(it, established)
        if key:
            groups.setdefault(key, []).append(it)

    stories = []
    for (etype, evalue), members in groups.items():
        outlets, seen = [], set()
        for m in members:
            o = story_outlet(m)
            if o.lower() not in seen:
                seen.add(o.lower())
                outlets.append(o)
        if len(outlets) < 2:
            continue  # not corroborated — a single-outlet cluster is not a story
        members_sorted = sorted(
            members, key=lambda x: x.get("published_at") or "", reverse=True)
        newest = members_sorted[0]
        story = {
            "key": f"{etype}:{evalue}",
            "entity": evalue,
            "entity_type": etype,
            "title": _strip_outlet(newest.get("title") or ""),
            "outlets": outlets,
            "member_ids": [m["id"] for m in members_sorted[:MEMBER_CAP]],
            "member_count": len(members),
            "published_at": newest.get("published_at") or "",
            "severity": _max_severity(members),
        }
        if etype == "cve":
            row = cve_by_id.get(evalue)
            delta = {}
            if row:
                if row.get("kev"):
                    delta["kev"] = True
                if row.get("kev_ransomware"):
                    delta["kev_ransomware"] = True
                if row.get("epss") is not None:
                    delta["epss"] = round(float(row["epss"]), 5)
            mv = movers.get(evalue)
            if mv and mv.get("from") is not None and mv.get("to") is not None:
                delta["epss_from"] = round(float(mv["from"]), 5)
                delta["epss_to"] = round(float(mv["to"]), 5)
            if delta:
                story["delta"] = delta
        stories.append(story)

    stories.sort(
        key=lambda s: (
            1 if s.get("delta") else 0,
            1 if (s.get("delta") or {}).get("kev") else 0,
            s["member_count"],
            s["published_at"],
        ),
        reverse=True,
    )
    return {"stories": stories}
