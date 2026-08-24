import re

from collectors.base import iso

IPINFO_URL = "https://ipinfo.io/{ip}/json?token={token}"
_ORG_RE = re.compile(r"^(AS\d+)\s+(.*)$")   # byte-mirror of lib/enrich.mjs:367

CAP = 200            # networks published (ranked); backstop below the schema's 1000
EXAMPLE_CAP = 3
SOURCES = ("community", "abuse.ch")   # switch to ("community",) for community-only

ATTRIBUTION = (
    "Networks (ASN / ISP) ranked by the volume of abusive IPs reported to "
    "SOCDesk (community, owner-moderated) and published on the abuse.ch Feodo "
    "Tracker / ThreatFox blocklists. A count of reported/blocklisted IPs hosted "
    "on a network — NOT a verdict on the network or its operator. ASN/ISP "
    "mapping by IPinfo (https://ipinfo.io); a report is an allegation reviewed "
    "before publication, not a confirmation."
)


def parse_org(org):
    """'AS60729 Zwiebelfreunde e.V.' -> ('AS60729', 'Zwiebelfreunde e.V.').
    Returns (None, None) when the string has no leading AS number (some IPinfo
    orgs are name-only or empty) — the IP is then UNATTRIBUTED, never faked."""
    m = _ORG_RE.match(str(org or "").strip())
    return (m.group(1), m.group(2).strip()) if m else (None, None)


def resolve_asn(ip, cache, fetch, token):
    """Cache-first ASN lookup. Returns {'asn','isp','country'} or None.
    (1) cache hit -> no call; (2) IPinfo when fetch+token present, cached on
    success; (3) None (UNATTRIBUTED). Never raises for upstream reasons —
    copies the geo.resolve discipline (geo.py:89-113)."""
    hit = cache.get(ip)
    if isinstance(hit, dict) and hit.get("asn"):
        return hit
    if fetch is None or not token:
        return None
    try:
        data = fetch(IPINFO_URL.format(ip=ip, token=token))
    except Exception:                          # noqa: BLE001 — network/HTTP, never fatal
        return None
    if not isinstance(data, dict):
        return None
    asn_num, isp = parse_org(data.get("org"))
    if not asn_num:
        return None
    rec = {"asn": asn_num, "isp": isp or asn_num,
           "country": (data.get("country") or "").strip().upper()[:2]}
    cache[ip] = rec                            # persisted for next run
    return rec
