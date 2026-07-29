import os

from collectors.base import CollectorResult, iso

SOURCE = "urlhaus"
URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/"

_MALWARE_TAG_SKIP = {"exe", "dll", "zip", "elf", "apk", "js", "vbs", "doc", "xll"}


def _ts(value, now):
    if not value:
        return iso(now)
    return value.replace(" UTC", "").replace(" ", "T") + "Z"


def collect(fetch, now):
    data = fetch(URL, method="POST", json={"limit": 1000},
                 headers={"Auth-Key": os.environ.get("ABUSECH_AUTH_KEY", "")})
    if data.get("query_status") != "ok":
        raise RuntimeError(f"urlhaus query_status={data.get('query_status')}")
    iocs = []
    for u in data.get("urls", []):
        tags = u.get("tags") or []
        malware = next((t for t in tags if t.lower() not in _MALWARE_TAG_SKIP), "")
        added = _ts(u.get("date_added"), now)
        iocs.append({
            "type": "url", "value": u["url"], "source": SOURCE,
            "malware": malware, "confidence": 50,
            "first_seen": added, "last_seen": added,
        })
    return CollectorResult(source=SOURCE, extra={"iocs": iocs})
