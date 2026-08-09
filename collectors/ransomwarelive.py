from collectors.base import CollectorResult, iso, make_item

SOURCE = "ransomwarelive"
URL = "https://api.ransomware.live/v2/recentvictims"


def collect(fetch, now):
    """Group-level activity only.

    Victim organisation names are deliberately NOT republished: the postings
    are unverified criminal claims, upstream retractions would never propagate
    to a static mirror, and Ransomware.live's terms gate reuse. Detail stays
    behind the claim link. The victim name is still used inside the hashed
    native id so dedup stays stable across runs (a SHA1 discloses nothing).
    """
    data = fetch(URL)
    items = []
    for v in data:
        group = (v.get("group") or "unknown").strip()
        sector = (v.get("activity") or "unknown sector").strip()
        country = (v.get("country") or "?").strip()
        # Upstream sends either "2026-08-08 02:15:00" or an offset-aware
        # "2026-08-08 02:15:00+00:00". Appending Z to the latter produced
        # "…+00:00Z", which Date.parse rejects — rows then rendered "—" for age.
        published = (v.get("discovered") or "").replace(" ", "T")
        for cut in ("+", "Z"):
            if cut in published[10:]:
                published = published[:10] + published[10:].split(cut)[0]
                break
        items.append(make_item(
            SOURCE, f"{group}:{v.get('victim', '')}:{v.get('discovered', '')}",
            "ransomware",
            f"{group} posted a new victim claim",
            f"Sector: {sector} — Country: {country}. Claim detail at the "
            f"source; victim names are not republished here.",
            v.get("claim_url") or "https://ransomware.live",
            "high",
            published + "Z" if published else iso(now), now,
            entities={"actors": [group], "malware": [], "vendors": [], "cves": []},
        ))
    return CollectorResult(source=SOURCE, items=items)
