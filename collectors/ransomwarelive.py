import re

from collectors.base import CollectorResult, clean_text, iso, make_item

SOURCE = "ransomwarelive"
URL = "https://api.ransomware.live/v2/recentvictims"


def collect(fetch, now):
    """Group-level activity, plus the attributed victim identity.

    Victim organisation name and domain ARE republished, but only as a
    leak-site fact attributed to the posting group and framed unverified —
    not a SOCDesk verdict. This is an unverified criminal claim: upstream
    retractions never propagate to a static mirror, so the summary always
    carries the "Unverified claim by <group>" framing rather than asserting
    a breach occurred. Ransomware.live's own editorial description/screenshot
    are never republished — only the bare victim/domain facts. The victim
    name is still used inside the hashed native id so dedup stays stable
    across runs (a SHA1 discloses nothing).
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
        item = make_item(
            SOURCE, f"{group}:{v.get('victim', '')}:{v.get('discovered', '')}",
            "ransomware", f"{group} posted a new victim claim",
            f"Unverified claim by {group}, per its leak site. "
            f"Sector: {sector} — Country: {country}.",
            v.get("claim_url") or "https://ransomware.live", "high",
            published + "Z" if published else iso(now), now,
            entities={"actors": [group], "malware": [], "vendors": [], "cves": []},
        )
        # victim is attacker-influenced free text — inert-clean it like every
        # other upstream string (title/summary go through clean_text via
        # make_item; these fields are set post-call so must do it explicitly).
        victim = clean_text(v.get("victim") or "").strip()
        # domain becomes a possible link target downstream — hold it to a bare
        # hostname (a real domain never carries a path, markup, or entities):
        # take the authority up to the first slash/space, then charset-guard.
        domain = (v.get("domain") or "").strip().lower().removeprefix("www.")
        domain = re.split(r"[/\s]", domain, 1)[0]
        domain = re.sub(r"[^a-z0-9.-]", "", domain)
        if victim:
            item["victim"] = victim[:200]
        if domain:
            item["domain"] = domain[:253]
        items.append(item)
    return CollectorResult(source=SOURCE, items=items)
