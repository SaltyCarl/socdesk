from collectors.base import CollectorResult, clean_text

SOURCE = "feodotracker"
URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"


def _ts(value):
    """Normalise abuse.ch timestamps to ISO-8601 Z.

    Upstream sends either 'YYYY-MM-DD HH:MM:SS' (first_seen) or a bare date
    'YYYY-MM-DD' (last_online). Both become '...T...Z'; anything else -> ''.
    """
    v = (value or "").strip().replace(" ", "T")
    if not v:
        return ""
    if len(v) == 10:                       # date only
        v += "T00:00:00"
    return v.split("+")[0].replace("Z", "") + "Z"


def collect(fetch, now):
    """Feodo Tracker botnet C2 IP blocklist.

    These are C2/blocklist IPs — public threat intelligence published expressly
    so defenders can block them, unlike ransomware victim names (which stay at
    the source). The actual IP is the useful datum, so it is republished with
    abuse.ch attribution. This collector only normalises the raw rows; the
    geolocation and de-duplication happen in ``pipeline/threat_ips.py`` so every
    source flows through one placement path. Rows are carried on ``extra["ips"]``
    (they are a globe payload, not feed items).
    """
    data = fetch(URL)
    ips = []
    for row in data or []:
        ip = (row.get("ip_address") or "").strip()
        if not ip:
            continue
        port = row.get("port")
        ips.append({
            "ip": ip,
            "port": port if isinstance(port, int) else None,
            "country": (row.get("country") or "").strip().upper() or None,
            "malware": clean_text(row.get("malware") or "")[:96] or None,
            "first_seen": _ts(row.get("first_seen")),
            "last_seen": _ts(row.get("last_online")),
            "source": SOURCE,
        })
    return CollectorResult(source=SOURCE, extra={"ips": ips})
