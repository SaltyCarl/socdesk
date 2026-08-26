import json
import os
import shutil
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from collectors import CACHED_COLLECTORS, COLLECTORS, attack
from collectors.base import iso, run_all
from pipeline.asn import build_asn_leaderboard
from pipeline.community import build_community_reports
from pipeline.cves import build_cve_rows, enrich_epss
from pipeline.history import (build_trends, daily_snapshot, prune_history,
                              snapshot_name)
from pipeline.intel_staleness import check_intel_staleness
from pipeline.publish import build_site_data
from pipeline.validate import gate

BRIEF_SRC = Path("data/brief.json")
GEO_CACHE_NAME = "geo_cache.json"    # IP -> {lat,lng,country,city,precision}
ASN_CACHE_NAME = "asn_cache.json"    # IP -> {asn,isp,country}


def _history(state_dir, cve_rows, feed_count, now):
    """Read the snapshot series, add/replace today's, prune, return (snapshots,
    to_write). Git is the datastore — one small file per day."""
    hdir = Path(state_dir) / "history"
    existing = {}
    if hdir.exists():
        for p in sorted(hdir.glob("*.json")):
            try:
                existing[p.name] = json.loads(p.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                pass
    existing[snapshot_name(now)] = daily_snapshot(cve_rows, feed_count, now)
    kept = prune_history(existing)
    return list(kept.values()), kept


def _load_state(state_dir):
    state = {}
    if state_dir.exists():
        for p in state_dir.glob("*.json"):
            try:
                state[p.name] = json.loads(p.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                pass
    return state


def _attack_is_fresh(state, now):
    gen = state.get("actors.json", {}).get("generated_at", "")
    fresh = gen >= iso(now - timedelta(days=attack.CACHE_DAYS))
    # Also require the technique-name catalog: it landed after actors.json, so a
    # fresh actors snapshot can predate it. Absent it, treat attack as stale so
    # the collector runs once and produces the catalog (then caches normally).
    return fresh and "technique_names.json" in state


def run(fetch, now, out_dir, state_dir, schemas_dir, sources_path, web_dir=None,
        env=None):
    out_dir, state_dir = Path(out_dir), Path(state_dir)
    web_dir = Path(web_dir) if web_dir else None
    state = _load_state(state_dir)

    modules = list(COLLECTORS)
    if not _attack_is_fresh(state, now):
        modules += CACHED_COLLECTORS
    results, health = run_all(modules, fetch, now)

    prior_cves = state.get("cves.json", {}).get("cves", [])
    cve_rows = build_cve_rows(results, prior_cves, now)
    health.append(enrich_epss(fetch, cve_rows, now))

    # Persistent IP->geo cache (committed with the state snapshots): only IPs
    # new since the last run hit IPinfo, keeping the twice-hourly pipeline
    # inside the free quota. build_site_data mutates it in place.
    geo_cache = state.get(GEO_CACHE_NAME, {})
    if not isinstance(geo_cache, dict):
        geo_cache = {}

    payloads = build_site_data(results, cve_rows, health, state, now,
                               fetch=fetch, geo_cache=geo_cache)
    sources = json.loads(Path(sources_path).read_text(encoding="utf-8"))
    payloads["sources.json"] = dict(sources, generated_at=iso(now))

    # Curated ransomware-intel seed (CISA-sourced, public-domain facts) —
    # published like sources.json: read the committed file, envelope it, gate it.
    # No collector: it is curation, not a fetch. Path derived from sources_path so
    # tests that point sources_path at a fixture dir pick up a sibling seed too.
    intel_path = Path(sources_path).parent / "ransomware_intel.json"
    if intel_path.exists():
        payloads["ransomware_intel.json"] = dict(
            json.loads(intel_path.read_text(encoding="utf-8")), generated_at=iso(now))

    # Staleness/drift guard (spec §3.4): soft warnings only, never a publish
    # blocker — run against the seed groups actually loaded above and the
    # real KEV-ransomware CVE set, so it can surface real drift instead of
    # never running at all.
    stale = []
    if "ransomware_intel.json" in payloads:
        kev_rs = {r["cve"] for r in cve_rows if r.get("kev_ransomware")}
        stale = check_intel_staleness(
            payloads["ransomware_intel.json"]["groups"], kev_rs, iso(now)[:10])

    feed_count = len(payloads.get("feed.json", {}).get("items", []))
    snapshots, history_files = _history(state_dir, cve_rows, feed_count, now)
    payloads["trends.json"] = dict(
        build_trends(snapshots, cve_rows, now),
        generated_at=iso(now), schema_version=1)

    # Community reports (Phase 3): D1 approved rows -> committed JSON, consulted
    # by the enrich read path as a kind:"context" source. On any D1 failure the
    # builder returns None and we re-publish the prior snapshot (the committed
    # seed guarantees one exists from run 1), so the layer degrades to
    # last-known-good and the served asset is never blanked. NO D1 read path,
    # NO DB binding on /api/enrich (Option A invariant).
    community = build_community_reports(fetch=fetch, now=now, env=env or {})
    if community is not None:
        payloads["community_reports.json"] = community
    elif "community_reports.json" in state:
        payloads["community_reports.json"] = dict(
            state["community_reports.json"], generated_at=iso(now))

    # ASN abuse-leaderboard (Phase 4): aggregate the already-published,
    # PII-stripped community + abuse.ch IPs by network via IPinfo's `org` field
    # (cache-first, only new IPs cost a call). Built AFTER community + threat_ips
    # so it consumes their fresh payloads (falling back to the committed prior).
    # Placed before gate() so it inherits schema validation + last-known-good +
    # triple dual-write. NO D1, NO identity — inputs are already PII-stripped.
    asn_cache = state.get(ASN_CACHE_NAME, {})
    if not isinstance(asn_cache, dict):
        asn_cache = {}
    leaderboard = build_asn_leaderboard(
        payloads.get("community_reports.json") or state.get("community_reports.json"),
        payloads.get("threat_ips.json") or state.get("threat_ips.json"),
        asn_cache, fetch, now, token=(env or {}).get("IPINFO_TOKEN"))
    if leaderboard is not None:
        payloads["asn_leaderboard.json"] = leaderboard
    elif "asn_leaderboard.json" in state:
        payloads["asn_leaderboard.json"] = dict(
            state["asn_leaderboard.json"], generated_at=iso(now))

    published, problems = gate(payloads, state, schemas_dir)
    warnings = problems + stale
    if warnings:
        published["health.json"] = dict(
            published.get("health.json", payloads["health.json"]),
            pipeline_warnings=warnings)

    out_dir.mkdir(parents=True, exist_ok=True)
    state_dir.mkdir(parents=True, exist_ok=True)
    if web_dir:                                # dual-write: the web app's data
        web_dir.mkdir(parents=True, exist_ok=True)   # dir (gitignored, rebuilt)
    for name, payload in published.items():
        blob = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        (out_dir / name).write_text(blob, encoding="utf-8")
        (state_dir / name).write_text(blob, encoding="utf-8")
        if web_dir:
            (web_dir / name).write_text(blob, encoding="utf-8")

    # Persist the geo cache next to the state snapshots (sorted for stable
    # diffs). CI's `git add data/state` commits it, so the next run reuses it.
    (state_dir / GEO_CACHE_NAME).write_text(
        json.dumps(geo_cache, ensure_ascii=False, sort_keys=True,
                   separators=(",", ":")),
        encoding="utf-8")

    (state_dir / ASN_CACHE_NAME).write_text(
        json.dumps(asn_cache, ensure_ascii=False, sort_keys=True,
                   separators=(",", ":")),
        encoding="utf-8")

    hdir = state_dir / "history"               # snapshot series lives in git
    hdir.mkdir(parents=True, exist_ok=True)
    for name in list(p.name for p in hdir.glob("*.json")):
        if name not in history_files:
            (hdir / name).unlink()             # pruned beyond the window
    for name, snap in history_files.items():
        (hdir / name).write_text(
            json.dumps(snap, ensure_ascii=False, separators=(",", ":")),
            encoding="utf-8")

    if BRIEF_SRC.exists():                     # Tier 2 output, pass through
        shutil.copy(BRIEF_SRC, out_dir / "brief.json")

    print(f"published {sorted(published)}; problems={problems}")
    return published, problems


if __name__ == "__main__":
    from pipeline.http import http_fetch
    _, problems = run(fetch=http_fetch, now=datetime.now(timezone.utc),
                      out_dir="site/data", state_dir="data/state",
                      schemas_dir="schemas", sources_path="data/sources.json",
                      web_dir="web/public/data/state", env=os.environ)
    sys.exit(0)   # upstream problems are health data, never a CI failure
