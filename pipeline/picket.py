"""PICKET publish step: the collector's normalized export -> picket.json (the
panel) + picket_ips.json (the globe layer).

Invariants: every payload is bounded and validated by gate(); a dead sensor
is published as status 'stale'/'silent' computed from exported_at — never as
zero attacks; collected_at is stamped only on a REAL collection and carried
through keep-prior (the actors.json lesson, run_pipeline.py:55-60); P2 adds
lead-time/known_to/exports ADDITIVELY — nothing here changes shape then.
"""
from datetime import datetime, timezone

from collectors.base import iso

SCHEMA_VERSION = 1
LIVE_MINUTES = 90
SILENT_MINUTES = 24 * 60
CAP_TOP_IPS = 100
CAP_GLOBE_IPS = 1000

ATTRIBUTION = (
    "SOCDesk PICKET: telemetry from SOCDesk's own internet-facing honeypot sensor "
    "(knock-knock, MIT, github.com/djkurlander/knock-knock). Counts of automated "
    "break-in attempts against an unsolicited sensor — context, never a verdict on "
    "any network or operator. Credentials are published as aggregate values only, "
    "never as pairs. This product includes GeoLite2 data created by MaxMind, "
    "available from https://www.maxmind.com."
)


def sensor_status(exported_at, now):
    try:
        t = datetime.strptime(exported_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return "silent", 0
    age = max(0, int((now - t).total_seconds() // 60))
    if age < LIVE_MINUTES:
        return "live", age
    if age < SILENT_MINUTES:
        return "stale", age
    return "silent", age


def _hourly(buckets):
    return [int(buckets[i]) + int(buckets[i + 1]) for i in range(0, 336, 2)]


def _panel(export, now, collected_at):
    status, age = sensor_status(export["exported_at"], now)
    hourly = _hourly(export["ring"]["buckets"])
    k7 = sum(hourly)
    sensor = {
        "id": export["sensor"]["id"],
        "uptime_days": int(export["sensor"]["uptime_minutes"]) // 1440,
        "protocols": export["sensor"]["protocols"],
        "status": status,
        "export_age_minutes": age,
        "exported_at": export["exported_at"],
        "knockknock_version": export["sensor"]["knockknock_version"],
    }
    for k in ("country", "ring_reset_at"):
        if export["sensor"].get(k):
            sensor[k] = export["sensor"][k]
    denom = sum(p["hits_7d"] for p in export["by_protocol"])
    by_proto = [dict(p, share_pct=round(100.0 * p["hits_7d"] / denom, 1) if denom else 0.0)
                for p in export["by_protocol"]]
    return {
        "generated_at": iso(now), "schema_version": SCHEMA_VERSION, "attribution": ATTRIBUTION,
        "collected_at": collected_at,
        "sensor": sensor,
        "totals": {"knocks_total": export["totals"]["knocks_total"], "since": export["totals"]["since"],
                   "knocks_24h": sum(hourly[-24:]), "knocks_7d": k7,
                   "unique_ips_7d": sum(1 for r in export["top_ips"] if r["hits_7d"] > 0)},
        "histogram_7d": hourly,
        "by_protocol": by_proto,
        "top_ips": export["top_ips"][:CAP_TOP_IPS],
        "top_usernames": export["top_usernames"], "top_passwords": export["top_passwords"],
        "top_countries": export["top_countries"], "top_isps": export["top_isps"],
    }


def _ips_layer(export, now):
    rows = []
    for r in export["top_ips"]:
        lat, lng = r.get("lat"), r.get("lng")
        if not isinstance(lat, (int, float)) or not isinstance(lng, (int, float)):
            continue
        row = {"ip": r["ip"], "lat": float(lat), "lng": float(lng), "source": "picket",
               "hits_7d": r["hits_7d"], "first_seen": r["first_seen"], "last_seen": r["last_seen"],
               "geo_precision": r.get("geo_precision", "city")}
        if r.get("country"):
            row["country"] = r["country"]
        rows.append(row)
    rows = rows[:CAP_GLOBE_IPS]
    return {"generated_at": iso(now), "schema_version": SCHEMA_VERSION, "attribution": ATTRIBUTION,
            "count": len(rows), "ips": rows}


def restamp_prior(prior, now):
    """Keep-prior with an HONEST status: recompute live/stale/silent against now."""
    out = {}
    if "picket.json" in prior:
        p = dict(prior["picket.json"], generated_at=iso(now))
        status, age = sensor_status(p.get("sensor", {}).get("exported_at", ""), now)
        p["sensor"] = dict(p["sensor"], status=status, export_age_minutes=age)
        out["picket.json"] = p
    if "picket_ips.json" in prior:
        out["picket_ips.json"] = dict(prior["picket_ips.json"], generated_at=iso(now))
    return out


def build_picket(ok, prior, now):
    r = ok.get("picket")
    if r is None or not r.extra.get("picket"):
        return restamp_prior(prior, now) or None
    export = r.extra["picket"]
    return {"picket.json": _panel(export, now, collected_at=iso(now)),
            "picket_ips.json": _ips_layer(export, now)}
