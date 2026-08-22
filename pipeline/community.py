"""Phase-3 community-reports export: D1 (status='approved') -> committed JSON.

Read-only against D1 via the REST *query* API. The projecting, indicator-level
SELECT names no `id`/`evidence`/`comment` and reads `github_id` ONLY inside
COUNT(DISTINCT ...), so no reporter identity is ever materialized (privacy
fence, spec 3.6.1). The schema's additionalProperties:false is the second,
machine-checked fence.

build_community_reports returns the FULL committed payload (envelope +
indicators map) or None on any D1 failure / missing config. On None the caller
keeps last-known-good (spec 5). It NEVER raises for upstream reasons and NEVER
overwrites a good snapshot with an empty one.

NO per-lookup path and NO D1 binding on /api/enrich touch this — the read path
consults the committed JSON only (Option A invariant).
"""
from collectors.base import iso

SCHEMA_VERSION = 1

ATTRIBUTION = (
    "Community-submitted abuse reports from SOCDesk contributors, owner-"
    "moderated. Counts of reports, not independent confirmations; a report is "
    "an allegation reviewed before publication, not a verdict."
)

# Indicator-level aggregation (spec 3.1 + owner ruling 10.1). `reporters` is a
# true distinct-contributor count; `n_reports` (COUNT(*)) is a bare volume
# integer summed into the envelope's report_count only — never per-indicator,
# never rendered. github_id is read ONLY inside COUNT(DISTINCT ...): the column
# is counted, never projected, so no id value leaves D1. `evidence`/`comment`/
# `id` are never named.
SQL = (
    "SELECT ioc_type, ioc_value, "
    "COUNT(DISTINCT github_id) AS reporters, "
    "COUNT(*) AS n_reports, "
    "GROUP_CONCAT(DISTINCT category) AS categories, "
    "MIN(created_at) AS first_at, MAX(created_at) AS latest_at "
    "FROM reports WHERE status = 'approved' "
    "GROUP BY ioc_type, ioc_value"
)

_HASH_TYPES = {"md5", "sha1", "sha256"}


def community_key(ioc_type, ioc_value):
    """Byte-identical mirror of lib/enrich.mjs communityKey (guarded by the
    shared key_parity.json fixture). Only hashes are lowercased; every other
    type is already validate()-normalized on the write path."""
    v = str(ioc_value).lower() if ioc_type in _HASH_TYPES else str(ioc_value)
    return f"{ioc_type}|{v}"


def _split_categories(group_concat):
    """GROUP_CONCAT(DISTINCT category) -> deduped, sorted list. Category enum
    values contain no commas, so the split is unambiguous."""
    parts = [c.strip() for c in str(group_concat or "").split(",") if c.strip()]
    return sorted(set(parts))


def _rows_from_d1(resp):
    """Pull the row list out of a D1 REST query response, or None if the shape
    is wrong (treated as a failure -> last-known-good)."""
    try:
        rows = resp["result"][0]["results"]
    except (KeyError, IndexError, TypeError):
        return None
    return rows if isinstance(rows, list) else None


def build_community_reports(fetch, now, env):
    """Query D1 for approved reports and assemble the committed payload.

    Returns the full payload dict, or None on missing config / any D1 failure
    (caller keeps last-known-good). Never raises for upstream reasons.
    """
    account = env.get("CLOUDFLARE_ACCOUNT_ID")
    database = env.get("CLOUDFLARE_D1_DATABASE_ID")
    token = env.get("CF_D1_READ_TOKEN") or env.get("CLOUDFLARE_API_TOKEN")
    if not (account and database and token):
        return None                          # inert until owner-config (spec 9)

    url = (f"https://api.cloudflare.com/client/v4/accounts/{account}"
           f"/d1/database/{database}/query")
    try:
        resp = fetch(url, method="POST", json={"sql": SQL},
                     headers={"Authorization": f"Bearer {token}"})
    except Exception:
        return None                          # D1 unreachable -> last-known-good

    rows = _rows_from_d1(resp)
    if rows is None:
        return None

    indicators = {}
    report_count = 0
    for r in rows:
        ioc_type = r["ioc_type"]
        ioc_value = r["ioc_value"]
        report_count += int(r.get("n_reports") or 0)
        # Whitelist projection: ONLY these six keys. Any stray field on the row
        # (evidence/comment/github_id/id/login) is dropped here (privacy fence).
        indicators[community_key(ioc_type, ioc_value)] = {
            "type": ioc_type,
            "value": ioc_value,
            "reporters": int(r["reporters"]),          # distinct contributors, taken directly
            "categories": _split_categories(r.get("categories")),
            "first_reported": str(r.get("first_at") or "")[:10],
            "latest_reported": str(r.get("latest_at") or "")[:10],
        }

    return {
        "generated_at": iso(now),
        "schema_version": SCHEMA_VERSION,
        "attribution": ATTRIBUTION,
        "count": len(indicators),
        "report_count": report_count,
        "indicators": indicators,
    }
