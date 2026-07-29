import hashlib
from dataclasses import dataclass, field


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class CollectorResult:
    source: str
    items: list = field(default_factory=list)
    extra: dict = field(default_factory=dict)
    ok: bool = True
    error: str = ""


def make_item(source, native_id, category, title, summary, url, severity,
              published_at, now, entities=None, iocs=None):
    return {
        "id": hashlib.sha1(f"{source}:{native_id}".encode("utf-8")).hexdigest(),
        "source": source,
        "category": category,
        "title": title.strip()[:300],
        "summary": (summary or "").strip()[:500],
        "url": url,
        "severity": severity,
        "entities": entities or {"actors": [], "malware": [], "vendors": [], "cves": []},
        "iocs": iocs or [],
        "published_at": published_at,
        "collected_at": iso(now),
    }


def run_all(collector_modules, fetch, now):
    """Run every collector; one raising never affects the others."""
    results, health = [], []
    for mod in collector_modules:
        try:
            r = mod.collect(fetch, now)
        except Exception as e:  # noqa: BLE001 — fault isolation is the point
            r = CollectorResult(source=mod.SOURCE, ok=False, error=str(e)[:300])
        results.append(r)
        count = len(r.items) + sum(
            len(v) for v in r.extra.values() if isinstance(v, list))
        health.append({
            "source": r.source,
            "ok": r.ok,
            "error": r.error,
            "items": count,
            "last_success_at": iso(now) if r.ok else "",
        })
    return results, health
