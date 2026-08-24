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


def _distinct_abusive_ips(community, threat_ips):
    """Yield (ip, source, category_or_None, is_report) for every ipv4/ipv6
    abusive indicator. Domains/urls/hashes have no ASN -> skipped (NOT counted
    as unattributed; they are simply not network-scoped)."""
    if "community" in SOURCES:
        for entry in (community or {}).get("indicators", {}).values():
            if entry.get("type") in ("ipv4", "ipv6"):
                cats = entry.get("categories") or []
                if cats:
                    for cat in cats:
                        yield entry["value"], "community", cat, True
                else:
                    yield entry["value"], "community", None, True
    if "abuse.ch" in SOURCES:
        for row in (threat_ips or {}).get("ips", []):
            yield row["ip"], "abuse.ch", None, False   # malware family != category enum


def build_asn_leaderboard(community, threat_ips, cache, fetch, now, token):
    """Fold the two committed inputs into a ranked, capped network leaderboard.
    Pure over its inputs except the cache-first IPinfo call in resolve_asn.
    Returns the full envelope, or None on a structural failure (the caller then
    keeps last-known-good)."""
    try:
        # 1. fold indicators -> per-IP {sources, categories, is_report}
        per_ip = {}
        for ip, source, category, is_report in _distinct_abusive_ips(community, threat_ips):
            rec = per_ip.setdefault(ip, {"sources": set(), "categories": set(),
                                         "is_report": False})
            rec["sources"].add(source)
            if category:
                rec["categories"].add(category)
            rec["is_report"] = rec["is_report"] or is_report

        # 2. resolve ASN per DISTINCT ip (cache-first); None -> unattributed
        networks = {}
        unattributed = 0
        seen = set()
        for ip, rec in per_ip.items():
            seen.add(ip)
            placed = resolve_asn(ip, cache, fetch, token)
            if placed is None:
                unattributed += 1
                continue
            net = networks.setdefault(placed["asn"], {
                "asn": placed["asn"], "isp": placed["isp"], "countries": {},
                "ips": set(), "report_ips": set(), "categories": set(), "sources": set()})
            net["ips"].add(ip)
            if rec["is_report"]:
                net["report_ips"].add(ip)
            net["categories"] |= rec["categories"]
            net["sources"] |= rec["sources"]
            cc = placed.get("country")
            if cc:
                net["countries"][cc] = net["countries"].get(cc, 0) + 1

        # 3. finalize rows (modal country: highest count, then alpha; deterministic)
        rows = []
        for net in networks.values():
            row = {
                "asn": net["asn"],
                "isp": net["isp"],
                "ip_count": len(net["ips"]),
                "report_count": len(net["report_ips"]),
                "categories": sorted(net["categories"]),
                "sources": sorted(net["sources"]),
                "examples": sorted(net["ips"])[:EXAMPLE_CAP],
            }
            if net["countries"]:
                row["country"] = sorted(net["countries"].items(),
                                        key=lambda kv: (-kv[1], kv[0]))[0][0]
            rows.append(row)

        # 4. rank by ip_count desc, asn tie-break; cap
        rows.sort(key=lambda r: (-r["ip_count"], r["asn"]))
        capped = rows[:CAP]

        # 5. prune cache to IPs seen this run (threat_ips.py:79-82 pattern)
        for ip in list(cache):
            if ip not in seen:
                del cache[ip]

        return {
            "generated_at": iso(now),
            "schema_version": 1,
            "attribution": ATTRIBUTION,
            "count": len(capped),
            "total_abusive_ips": len(per_ip),
            "unattributed_ips": unattributed,
            "cap": CAP,
            "truncated": len(rows) > CAP,
            "networks": capped,
        }
    except Exception:                              # noqa: BLE001 — structural -> last-known-good
        return None
