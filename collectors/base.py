import hashlib
import html
import re
from dataclasses import dataclass, field

_TAG_RE = re.compile(r"<[^>]+>")


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def clean_text(text):
    """Strip HTML tags and entities from upstream text. Upstream strings are
    attacker-influenced (RSS titles, victim names); nothing markup-shaped may
    enter published data."""
    return _TAG_RE.sub("", html.unescape(text or "")).strip()


def safe_url(url):
    """Only http(s) URLs are publishable as links."""
    u = (url or "").strip()
    return u if u.startswith(("http://", "https://")) else ""


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
        "title": clean_text(title)[:300],
        "summary": clean_text(summary)[:500],
        "url": safe_url(url),
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
