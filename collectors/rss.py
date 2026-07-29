import calendar

import feedparser

from collectors.base import CollectorResult, iso, make_item
from pipeline.entities import classify_category, extract_entities

SOURCE = "rss"

FEEDS = [
    {"name": "Cisco Talos", "url": "https://blog.talosintelligence.com/rss/"},
    {"name": "Unit 42", "url": "https://unit42.paloaltonetworks.com/feed/"},
    {"name": "The DFIR Report", "url": "https://thedfirreport.com/feed/"},
    {"name": "Microsoft Threat Intelligence", "url": "https://www.microsoft.com/en-us/security/blog/feed/"},
    {"name": "Google Threat Intelligence", "url": "https://cloud.google.com/blog/topics/threat-intelligence/rss/"},
    {"name": "SANS ISC", "url": "https://isc.sans.edu/rssfeed.xml"},
    {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/"},
    {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews"},
    {"name": "Securelist", "url": "https://securelist.com/feed/"},
]


def _published(entry, now):
    parsed = entry.get("published_parsed") or entry.get("updated_parsed")
    if not parsed:
        return iso(now)
    from datetime import datetime, timezone
    return iso(datetime.fromtimestamp(calendar.timegm(parsed), tz=timezone.utc))


def collect(fetch, now):
    items, errors = [], []
    for feed in FEEDS:
        try:
            raw = fetch(feed["url"], text=True)
            parsed = feedparser.parse(raw)
            for entry in parsed.entries[:20]:
                title = entry.get("title", "").strip()
                if not title:
                    continue
                summary = entry.get("summary", "")
                entities = extract_entities(f"{title} {summary}")
                category = classify_category(title, entities)
                has_entities = any(entities.values())
                items.append(make_item(
                    SOURCE, entry.get("link", title), category,
                    f"[{feed['name']}] {title}", summary,
                    entry.get("link", ""),
                    "medium" if has_entities else "info",
                    _published(entry, now), now, entities=entities))
        except Exception as e:  # noqa: BLE001 — one dead feed must not kill the pool
            errors.append(f"{feed['name']}: {str(e)[:100]}")
    if errors and len(errors) == len(FEEDS):
        raise RuntimeError("; ".join(errors))
    return CollectorResult(source=SOURCE, items=items,
                           error="; ".join(errors)[:300])
