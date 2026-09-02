import hashlib
import json
from pathlib import Path

from collectors.base import CollectorResult

SOURCE = "sigma_hunt"
ALLOWLIST_PATH = Path("data/hunt/sigma_allowlist.json")
RAW_BASE = "https://raw.githubusercontent.com/SigmaHQ/sigma"
BLOB_BASE = "https://github.com/SigmaHQ/sigma/blob"
MAX_KQL_BYTES = 16384


def _load_allowlist(path):
    raw = Path(path).read_bytes()
    return json.loads(raw.decode("utf-8")), hashlib.sha1(raw).hexdigest()


def _convert(text):
    """One Sigma YAML → one advanced-hunting KQL string via the production
    microsoft_xdr pipeline. A FRESH pipeline+backend per rule — pipelines
    carry per-conversion state. Lazy imports so `import collectors` (the
    package registry) never hard-requires pysigma."""
    from sigma.backends.kusto import KustoBackend
    from sigma.collection import SigmaCollection
    from sigma.pipelines.microsoftxdr import microsoft_xdr_pipeline

    queries = KustoBackend(
        processing_pipeline=microsoft_xdr_pipeline()).convert(
        SigmaCollection.from_yaml(text))
    if len(queries) != 1:
        raise ValueError(f"converted to {len(queries)} queries, expected 1")
    return queries[0]


def collect(fetch, now, allowlist_path=None):
    """Curated SigmaHQ rules converted to advanced-hunting KQL (DRL 1.1).

    Deterministic toolchain conversion at collect time — never hand-patched:
    a rule that fails to convert is skipped + reported (spec §1.2). DRL
    clause 1 requires AUTHOR attribution, so the rule's `author` field rides
    into source.author. Output dialect is advanced_hunting BY CONSTRUCTION
    (the xdr pipeline emits Device* tables); techniques come from the
    allowlist when present, else the rule's attack.t* tags (uppercased —
    Sigma tags are lowercase, the schema pattern is not). Same per-entry
    isolation / all-failed-raises contract as sentinel_hunt.
    """
    import yaml

    from collectors.sentinel_hunt import _TABLE_RE

    allowlist, allowlist_sha1 = _load_allowlist(allowlist_path or ALLOWLIST_PATH)
    entries = allowlist.get("rules", [])
    rules, failures = [], []
    for e in entries:
        try:
            url = f"{RAW_BASE}/{e['sha']}/{e['path']}"
            text = fetch(url, text=True)
            doc = yaml.safe_load(text)
            if not isinstance(doc, dict):
                raise ValueError("not a rule document")
            kql = _convert(text).strip()
            if len(kql.encode("utf-8")) > MAX_KQL_BYTES:
                raise ValueError(f"kql exceeds {MAX_KQL_BYTES} bytes")
            tags = [str(t) for t in (doc.get("tags") or [])]
            tag_techniques = sorted({
                t.split("attack.")[1].upper()
                for t in tags
                if t.startswith("attack.t") and t.split("attack.")[1][1:2].isdigit()
            })
            techniques = e.get("techniques") or tag_techniques
            author = str(doc.get("author") or "").strip()
            # PyYAML parses sigma date:/modified: into datetime.date — str() it.
            modified = str(doc.get("modified") or doc.get("date") or "")[:10]
            rules.append({
                "id": e["id"],
                "title": str(doc.get("title") or e["id"])[:200],
                "kql": kql,
                "techniques": techniques,
                "tables": sorted(set(_TABLE_RE.findall(kql))),
                "dialect": "advanced_hunting",
                "source": {
                    "kind": "sigma",
                    "url": f"{BLOB_BASE}/{e['sha']}/{e['path']}",
                    "license": "DRL",
                    **({"author": author[:120]} if author else {}),
                    **({"rule_id": str(doc["id"])} if doc.get("id") else {}),
                    **({"modified": modified} if modified else {}),
                },
            })
        except Exception as exc:  # noqa: BLE001 — per-entry isolation is the point
            failures.append(f"{e.get('id', e.get('path', '?'))}: {exc}")
    if entries and not rules:
        raise RuntimeError(f"all {len(entries)} sigma conversions failed: {failures[:3]}")
    error = "; ".join(failures[:10]) if failures else ""
    return CollectorResult(
        source=SOURCE,
        extra={"rules": rules, "allowlist_sha1": allowlist_sha1},
        error=error,
    )
