from collectors.base import CollectorResult, iso, make_item

SOURCE = "ransomwarelive"
URL = "https://api.ransomware.live/v2/recentvictims"


def collect(fetch, now):
    data = fetch(URL)
    items = []
    for v in data:
        group = (v.get("group") or "unknown").strip()
        victim = (v.get("victim") or "unnamed victim").strip()
        published = (v.get("discovered") or "").replace(" ", "T")
        items.append(make_item(
            SOURCE, f"{group}:{victim}:{v.get('discovered', '')}", "ransomware",
            f"{group} claims {victim}",
            f"Sector: {v.get('activity', 'unknown')} — Country: {v.get('country', '?')}",
            v.get("claim_url") or "https://ransomware.live",
            "high",
            published + "Z" if published else iso(now), now,
            entities={"actors": [group], "malware": [], "vendors": [], "cves": []},
        ))
    return CollectorResult(source=SOURCE, items=items)
