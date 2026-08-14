from pipeline import geo

CAP = 300
SOURCES = ("feodotracker", "threatfox")

ATTRIBUTION = (
    "abuse.ch Feodo Tracker + ThreatFox (botnet C2 / blocklist IPs, published "
    "for blocking). Geolocation by IPinfo (https://ipinfo.io), city-level and "
    "cached, with a public-domain country-centroid fallback plus deterministic "
    "per-IP jitter. IP geolocation is approximate — it reflects "
    "hosting/registrar, not operator location."
)


def _merge(kept, dup):
    """Fold a duplicate IP (same address, second source) into the kept row.

    The first-inserted row is canonical, so its coordinate and precision win
    (both sources resolve the same IP to the same cached geo anyway); only the
    activity window, malware label and port are widened from the duplicate.
    """
    firsts = [t for t in (kept["first_seen"], dup["first_seen"]) if t]
    return dict(kept,
                first_seen=min(firsts) if firsts else "",
                last_seen=max(kept["last_seen"], dup["last_seen"]),
                malware=kept["malware"] or dup["malware"],
                port=kept["port"] if kept["port"] is not None else dup["port"])


def build_threat_ips(ok, now, fetch=None, cache=None, token=None, cap=CAP):
    """Assemble the geolocated threat-IP surface from the abuse.ch collectors.

    ``ok`` maps source -> CollectorResult for collectors that succeeded. Every
    raw row is geolocated (IPinfo when ``fetch``+``token`` are supplied, else the
    country-centroid fallback), de-duplicated by IP (sources merged), ranked
    most-recent-first and capped for a globe. IPs that cannot be placed are
    counted in ``dropped_no_geo`` rather than plotted at a fabricated point.
    Feodo is processed before ThreatFox so its country-bearing row stays
    canonical on a collision.

    ``cache`` is a mutable IP -> geo map (persisted alongside the state
    snapshots): IPinfo hits are written into it and only IPs *not* already
    cached trigger an API call, keeping the twice-hourly pipeline inside the
    free quota. The cache is pruned to the IPs seen this run so the committed
    file stays bounded.
    """
    cache = cache if cache is not None else {}
    raw = []
    for src in SOURCES:
        r = ok.get(src)
        if r is not None:
            raw.extend(r.extra.get("ips", []))

    by_ip = {}
    seen = set()
    dropped = 0
    for rec in raw:
        ip = rec["ip"]
        seen.add(ip)
        placed = geo.resolve(ip, rec.get("country"), cache, fetch, token)
        if placed is None:
            dropped += 1
            continue
        lat, lng, country, _city, precision = placed
        item = {
            "ip": ip,
            "country": country,
            "lat": lat,
            "lng": lng,
            "source": rec["source"],
            "malware": rec.get("malware"),
            "port": rec.get("port"),
            "first_seen": rec.get("first_seen", ""),
            "last_seen": rec.get("last_seen", ""),
            "geo_precision": precision,
        }
        by_ip[ip] = _merge(by_ip[ip], item) if ip in by_ip else item

    # Keep the cache bounded: drop entries for IPs no longer on any list.
    for ip in list(cache):
        if ip not in seen:
            del cache[ip]

    # Most-recent / most-active first; ip as a stable final tie-break so the
    # ordering is deterministic across runs.
    ips = sorted(by_ip.values(),
                 key=lambda i: (i["last_seen"], i["first_seen"], i["ip"]),
                 reverse=True)
    total = len(ips)
    return {
        "ips": ips[:cap],
        "attribution": ATTRIBUTION,
        "count": min(total, cap),
        "total_before_cap": total,
        "cap": cap,
        "truncated": total > cap,
        "dropped_no_geo": dropped,
    }
