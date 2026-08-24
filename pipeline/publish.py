import os
from datetime import timedelta

from collectors.base import iso
from pipeline.entities import tracked_actor_set
from pipeline.relations import build_relations
from pipeline.relevance import apply_scores, group_repetitive
from pipeline.threat_ips import build_threat_ips

FEED_DAYS = 30
SCHEMA_VERSION = 1


def _envelope(now, **body):
    return {"generated_at": iso(now), "schema_version": SCHEMA_VERSION, **body}


def _fix_ts(value):
    """Repair '2026-08-08T02:15:00+00:00Z' — an offset AND a Z, which
    Date.parse rejects. Items already carried in state keep their original
    malformed value, so normalise on every merge, not just at collection."""
    v = value or ""
    if len(v) > 10 and ("+" in v[10:] or v[10:].count("Z") > 1):
        base = v[:10] + v[10:].split("+")[0].replace("Z", "")
        return base + "Z"
    return v


def merge_feed(prior_items, new_items, days, now):
    cutoff = iso(now - timedelta(days=days))
    merged = {i["id"]: i for i in prior_items}
    merged.update({i["id"]: i for i in new_items})     # fresh wins
    for i in merged.values():
        i["published_at"] = _fix_ts(i.get("published_at"))
    kept = [i for i in merged.values() if i["published_at"] >= cutoff]
    return sorted(kept, key=lambda i: i["published_at"], reverse=True)


def build_site_data(results, cve_rows, health, prior, now, fetch=None,
                    geo_cache=None):
    """Assemble published payloads.

    No IOC corpus is published (see COMPLIANCE.md): reputation data is reached
    by user-clicked deep links at render time, not mirrored here. The one
    reputation-adjacent payload is ``threat_ips.json`` — abuse.ch C2/blocklist
    IPs, which are indicators published expressly to be blocked. ``fetch`` and
    ``geo_cache`` are threaded through only so those IPs can be geolocated via
    IPinfo with a persistent cache.
    """
    ok = {r.source: r for r in results if r.ok}

    new_feed = [i for r in ok.values() for i in r.items]
    prior_feed = prior.get("feed.json", {}).get("items", [])
    feed = merge_feed(prior_feed, new_feed, FEED_DAYS, now)

    # Operational ordering: score every item, then collapse the repetitive
    # ransomware victim-claim stubs into one digest row per group. The site
    # ships ranked — it does not re-sort a newspaper in the browser.
    apply_scores(feed, cve_rows, iso(now), tracked_actors=tracked_actor_set())
    feed = group_repetitive(
        feed, "ransomwarelive",
        lambda i: (i.get("entities", {}).get("actors") or ["unknown"])[0])

    prior_success = {e["source"]: e["last_success_at"]
                     for e in prior.get("health.json", {}).get("sources", [])}
    health_out = [dict(e, last_success_at=e["last_success_at"]
                       or prior_success.get(e["source"], ""))
                  for e in health]

    payloads = {
        "feed.json": _envelope(now, items=feed),
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

    # Geolocated threat surface (abuse.ch C2/blocklist IPs). Fresh data wins; a
    # transient upstream failure keeps last-known-good rather than blanking the
    # globe; the very first run with neither publishes the empty envelope.
    threat_ips = build_threat_ips(ok, now, fetch=fetch, cache=geo_cache,
                                  token=os.environ.get("IPINFO_TOKEN"))
    if threat_ips["total_before_cap"] > 0 or "threat_ips.json" not in prior:
        payloads["threat_ips.json"] = _envelope(now, **threat_ips)
    else:
        payloads["threat_ips.json"] = dict(prior["threat_ips.json"],
                                           generated_at=iso(now))

    # Relationship index: derived from the published feed + ATT&CK + CVE table,
    # so every evidence id resolves against payloads shipped alongside it.
    payloads["relations.json"] = _envelope(now, **build_relations(
        feed, cve_rows,
        payloads.get("actors.json", {}).get("profiles", []),
        payloads.get("malware.json", {}).get("profiles", [])))
    return payloads
