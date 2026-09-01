from collectors.base import CollectorResult, clean_text

SOURCE = "ransomwarelive_groups"
URL = "https://api.ransomware.live/v2/groups"
CACHE_DAYS = 3  # pipeline skips this collector while the committed list is fresher

# The published list is schema-capped; the live list is ~394 groups (2026-09),
# so 1000 leaves years of headroom without letting a hostile upstream balloon it.
MAX_GROUPS = 1000


def collect(fetch, now):
    """Name-only ransomware-group coverage layer (R3-gated).

    Republishes ONLY each group's name — a bare fact attributed to
    ransomware.live, so an analyst searching a long-tail group (Nitrogen) finds
    a directory entry that links OUT instead of a false "no matches". Every
    editorial field the endpoint carries (description, locations, ttps, tools)
    is deliberately discarded: COMPLIANCE.md R3 permits facts, never
    ransomware.live's editorial. The endpoint is rate-limited (1 req/min,
    personal use) and ~764 KB, which is why this collector is freshness-gated
    to every CACHE_DAYS rather than riding the twice-hourly cycle.

    The literal group name "unknown" is excluded — it is the upstream's own
    catch-all tracking label AND this repo's recentvictims sentinel, so a card
    for it would be noise wearing a name.
    """
    data = fetch(URL)
    names = {}
    for entry in data if isinstance(data, list) else []:
        if not isinstance(entry, dict):
            continue
        name = clean_text(entry.get("name") or "").strip()
        if not name or name.lower() == "unknown":
            continue
        # case-insensitive dedupe, first casing wins
        names.setdefault(name.lower(), name[:200])
    group_names = sorted(names.values(), key=str.lower)[:MAX_GROUPS]
    return CollectorResult(source=SOURCE, extra={"group_names": group_names})
