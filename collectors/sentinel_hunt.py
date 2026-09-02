import hashlib
import json
import re
from pathlib import Path

import yaml

from collectors.base import CollectorResult

SOURCE = "sentinel_hunt"
ALLOWLIST_PATH = Path("data/hunt/sentinel_allowlist.json")
RAW_BASE = "https://raw.githubusercontent.com/Azure/Azure-Sentinel"
BLOB_BASE = "https://github.com/Azure/Azure-Sentinel/blob"
MAX_KQL_BYTES = 16384

# Conservative known-table extraction: only names in this list are ever
# reported as a rule's tables (a bare-word regex over KQL would false-hit
# variables). Grows with the Kustainer DDL catalog — the two lists are the
# same curation surface (spec §1.6).
KNOWN_TABLES = (
    "DeviceProcessEvents", "DeviceNetworkEvents", "DeviceFileEvents",
    "DeviceRegistryEvents", "DeviceLogonEvents", "DeviceImageLoadEvents",
    "DeviceEvents", "DeviceInfo", "SecurityEvent", "SigninLogs",
    "Event", "WindowsEvent",
    "AuditLogs", "OfficeActivity", "EmailEvents", "IdentityLogonEvents",
)
_TABLE_RE = re.compile(r"\b(" + "|".join(KNOWN_TABLES) + r")\b")


def _load_allowlist(path=ALLOWLIST_PATH):
    raw = Path(path).read_bytes()
    return json.loads(raw.decode("utf-8")), hashlib.sha1(raw).hexdigest()


def collect(fetch, now, allowlist_path=None):
    """Curated Microsoft Sentinel community hunting queries (MIT).

    Fetches ONLY the SHA-pinned files in data/hunt/sentinel_allowlist.json —
    immutable raw URLs, so a run is reproducible and the license trail is
    auditable. Each doc is a full YAML file with a `query:` key (NOT
    front-matter). The allowlist's `techniques[]`/`dialect` are authoritative
    (upstream `relevantTechniques` is unevenly populated). Per-entry failures
    are accumulated into CollectorResult.error with ok=True (the rss.py
    pattern — health shows the loss, the batch survives); ALL entries failing
    raises, so a total outage reads red, never green-with-zero.
    """
    # module-global read at CALL time so run_pipeline can retarget the path
    # (sources_path-derived) without default-arg binding freezing the original.
    allowlist, allowlist_sha1 = _load_allowlist(allowlist_path or ALLOWLIST_PATH)
    entries = allowlist.get("rules", [])
    rules, failures = [], []
    for e in entries:
        try:
            url = f"{RAW_BASE}/{e['sha']}/{e['path']}"
            doc = yaml.safe_load(fetch(url, text=True))
            if not isinstance(doc, dict) or not doc.get("query"):
                raise ValueError("no query key in document")
            kql = str(doc["query"]).strip()
            if len(kql.encode("utf-8")) > MAX_KQL_BYTES:
                raise ValueError(f"kql exceeds {MAX_KQL_BYTES} bytes")
            if doc.get("id") and e.get("upstream_id") and doc["id"] != e["upstream_id"]:
                failures.append(f"{e['id']}: upstream id drift ({doc['id']})")
            rules.append({
                "id": e["id"],
                "title": str(doc.get("name") or e["id"])[:200],
                "kql": kql,
                "techniques": e.get("techniques", []),
                "tables": sorted(set(_TABLE_RE.findall(kql))),
                "dialect": e.get("dialect", "log_analytics"),
                "source": {
                    "kind": "sentinel",
                    "url": f"{BLOB_BASE}/{e['sha']}/{e['path']}",
                    "license": "MIT",
                    **({"modified": e["modified"]} if e.get("modified") else {}),
                },
            })
        except Exception as exc:  # noqa: BLE001 — per-entry isolation is the point
            failures.append(f"{e.get('id', e.get('path', '?'))}: {exc}")
    if entries and not rules:
        raise RuntimeError(f"all {len(entries)} allowlist fetches failed: {failures[:3]}")
    error = "; ".join(failures[:10]) if failures else ""
    return CollectorResult(
        source=SOURCE,
        extra={"rules": rules, "allowlist_sha1": allowlist_sha1},
        error=error,
    )
