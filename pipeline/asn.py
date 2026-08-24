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
