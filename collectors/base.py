import hashlib
import html
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

_TAG_RE = re.compile(r"<[^>]*>")
# Anything that could break out of an HTML attribute or start markup.
_URL_BAD = re.compile(r"""[\s"'<>\\`{}|^]""")


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def clean_text(text):
    """Reduce upstream text to inert plain text.

    Upstream strings are attacker-influenced (RSS titles, and — once a sensor
    exists — usernames and shell commands chosen by whoever is attacking it).
    Two bypasses this must defeat:
      * entity-encoded markup surviving a single strip pass, so unescape first
        and strip to a fixpoint;
      * an UNTERMINATED tag (`<img src=x onerror=alert(1)//`) sailing through a
        `<[^>]*>` regex and then borrowing the `>` from surrounding template
        markup — so every residual angle bracket is deleted outright.
    """
    s = html.unescape(text or "")
    prev = None
    while prev != s:                      # entity/tag nesting -> fixpoint
        prev = s
        s = _TAG_RE.sub("", s)
    s = s.replace("<", "").replace(">", "")   # residual/unterminated markup
    return s.strip()


def safe_url(url):
    """Only well-formed http(s) URLs are publishable as links.

    A scheme-prefix check is NOT sufficient: `http://x/" onmouseover="…`
    starts with http:// and still breaks out of an href attribute.
    """
    u = (url or "").strip()
    if not u or _URL_BAD.search(u):
        return ""
    parts = urlsplit(u)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        return ""
    return u


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
