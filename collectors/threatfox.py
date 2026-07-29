import os

from collectors.base import CollectorResult, iso

SOURCE = "threatfox"
URL = "https://threatfox-api.abuse.ch/api/v1/"

TYPE_MAP = {"ip:port": "ipv4", "domain": "domain", "url": "url",
            "md5_hash": "md5", "sha256_hash": "sha256"}


def _ts(value, fallback):
    # "2026-07-27 14:00:00 UTC" -> "2026-07-27T14:00:00Z"
    if not value:
        return fallback
    return value.replace(" UTC", "").replace(" ", "T") + "Z"


def collect(fetch, now):
    data = fetch(URL, method="POST", json={"query": "get_iocs", "days": 1},
                 headers={"Auth-Key": os.environ.get("ABUSECH_AUTH_KEY", "")})
    if data.get("query_status") != "ok":
        raise RuntimeError(f"threatfox query_status={data.get('query_status')}")
    iocs = []
    for d in data.get("data", []):
        ioc_type = TYPE_MAP.get(d.get("ioc_type", ""))
        if not ioc_type:
            continue
        value = d["ioc"].split(":")[0] if d["ioc_type"] == "ip:port" else d["ioc"]
        first = _ts(d.get("first_seen"), iso(now))
        iocs.append({
            "type": ioc_type, "value": value, "source": SOURCE,
            "malware": d.get("malware_printable") or "",
            "confidence": int(d.get("confidence_level") or 0),
            "first_seen": first,
            "last_seen": _ts(d.get("last_seen"), first),
        })
    return CollectorResult(source=SOURCE, extra={"iocs": iocs})
