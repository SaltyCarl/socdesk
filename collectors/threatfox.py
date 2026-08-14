import os

from collectors.base import CollectorResult, clean_text

SOURCE = "threatfox"
URL = "https://threatfox-api.abuse.ch/api/v1/"
ENV_KEY = "ABUSECH_API_KEY"
LOOKBACK_DAYS = 1


def _split_ip_port(ioc):
    """'139.180.203.104:443' -> ('139.180.203.104', 443). rpartition keeps
    IPv6 hosts (colon-rich) intact and only peels the trailing port."""
    ip, sep, port = (ioc or "").rpartition(":")
    if not sep or not ip:
        return None, None
    try:
        return ip, int(port)
    except ValueError:
        return ip, None


def _ts(value):
    """ThreatFox timestamps look like '2026-08-10 14:05:23 UTC'."""
    v = (value or "").strip().replace(" UTC", "").replace(" ", "T")
    if not v:
        return ""
    return v.split("+")[0].replace("Z", "") + "Z"


def collect(fetch, now):
    """ThreatFox ip:port IOCs (botnet C2 / payload delivery).

    Requires the free abuse.ch Auth-Key in ``ABUSECH_API_KEY`` (a GitHub Actions
    secret). Absent — local dev — the collector skips gracefully and the
    pipeline proceeds on Feodo alone. ThreatFox returns no geolocation, so a
    placed row needs the optional offline IP->country DB wired in
    ``pipeline/geo.py``; without it these rows are dropped from the globe rather
    than given a fabricated location. Rows ride on ``extra["ips"]``.
    """
    key = os.environ.get(ENV_KEY)
    if not key:                            # graceful local skip
        return CollectorResult(source=SOURCE, extra={"ips": []})

    resp = fetch(URL, method="POST",
                 json={"query": "get_iocs", "days": LOOKBACK_DAYS},
                 headers={"Auth-Key": key})
    rows = (resp.get("data")
            if isinstance(resp, dict) and resp.get("query_status") == "ok"
            else None)
    ips = []
    for row in rows or []:
        if row.get("ioc_type") != "ip:port":
            continue
        ip, port = _split_ip_port(row.get("ioc"))
        if not ip:
            continue
        malware = row.get("malware_printable") or row.get("malware") or ""
        tags = row.get("tags") or []
        if not malware and tags:
            malware = tags[0]
        conf = row.get("confidence_level")
        ips.append({
            "ip": ip,
            "port": port,
            "country": None,               # ThreatFox carries no geolocation
            "malware": clean_text(malware)[:96] or None,
            "first_seen": _ts(row.get("first_seen")),
            "last_seen": _ts(row.get("last_seen")),
            "confidence": conf if isinstance(conf, int) else None,
            "source": SOURCE,
        })
    return CollectorResult(source=SOURCE, extra={"ips": ips})
