from datetime import timedelta

from collectors.base import iso

FEED_DAYS = 30
IOC_DAYS = 90
SCHEMA_VERSION = 1
IOC_TYPES = ("ipv4", "domain", "url", "md5", "sha256")


def _envelope(now, **body):
    return {"generated_at": iso(now), "schema_version": SCHEMA_VERSION, **body}


def merge_feed(prior_items, new_items, days, now):
    cutoff = iso(now - timedelta(days=days))
    merged = {i["id"]: i for i in prior_items}
    merged.update({i["id"]: i for i in new_items})     # fresh wins
    kept = [i for i in merged.values() if i["published_at"] >= cutoff]
    return sorted(kept, key=lambda i: i["published_at"], reverse=True)


def merge_iocs(prior_entries, new_entries, days, now):
    cutoff = iso(now - timedelta(days=days))
    merged = {}
    for e in list(prior_entries) + list(new_entries):
        key = (e["type"], e["value"], e["source"])
        if key in merged:
            old = merged[key]
            e = dict(e, first_seen=min(old["first_seen"], e["first_seen"]),
                     last_seen=max(old["last_seen"], e["last_seen"]))
        merged[key] = e
    by_type = {t: [] for t in IOC_TYPES}
    for e in merged.values():
        if e["last_seen"] >= cutoff:
            by_type[e["type"]].append(
                {k: v for k, v in e.items() if k != "type"})
    for t in by_type:
        by_type[t].sort(key=lambda e: e["last_seen"], reverse=True)
    return by_type


def _flatten_prior_iocs(prior_iocs_payload):
    out = []
    for t, entries in prior_iocs_payload.get("iocs", {}).items():
        out.extend(dict(e, type=t) for e in entries)
    return out


def build_site_data(results, cve_rows, health, prior, now):
    ok = {r.source: r for r in results if r.ok}

    new_feed = [i for r in ok.values() for i in r.items]
    prior_feed = prior.get("feed.json", {}).get("items", [])
    feed = merge_feed(prior_feed, new_feed, FEED_DAYS, now)

    new_iocs = [i for r in ok.values() for i in r.extra.get("iocs", [])]
    iocs = merge_iocs(_flatten_prior_iocs(prior.get("iocs.json", {})),
                      new_iocs, IOC_DAYS, now)

    prior_success = {e["source"]: e["last_success_at"]
                     for e in prior.get("health.json", {}).get("sources", [])}
    health_out = [dict(e, last_success_at=e["last_success_at"]
                       or prior_success.get(e["source"], ""))
                  for e in health]

    payloads = {
        "feed.json": _envelope(now, items=feed),
        "iocs.json": _envelope(now, iocs=iocs),
        "cves.json": _envelope(now, cves=cve_rows),
        "health.json": _envelope(now, sources=health_out),
    }

    if "attack" in ok:
        payloads["actors.json"] = _envelope(now, profiles=ok["attack"].extra["actors"])
        payloads["malware.json"] = _envelope(now, profiles=ok["attack"].extra["malware"])
    else:
        for name in ("actors.json", "malware.json"):
            if name in prior:
                payloads[name] = dict(prior[name], generated_at=iso(now))
    return payloads
