import json
import shutil
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from collectors import CACHED_COLLECTORS, COLLECTORS, attack
from collectors.base import iso, run_all
from pipeline.cves import build_cve_rows, enrich_epss
from pipeline.history import (build_trends, daily_snapshot, prune_history,
                              snapshot_name)
from pipeline.publish import build_site_data
from pipeline.validate import gate

BRIEF_SRC = Path("data/brief.json")


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
    return gen >= iso(now - timedelta(days=attack.CACHE_DAYS))


def run(fetch, now, out_dir, state_dir, schemas_dir, sources_path):
    out_dir, state_dir = Path(out_dir), Path(state_dir)
    state = _load_state(state_dir)

    modules = list(COLLECTORS)
    if not _attack_is_fresh(state, now):
        modules += CACHED_COLLECTORS
    results, health = run_all(modules, fetch, now)

    prior_cves = state.get("cves.json", {}).get("cves", [])
    cve_rows = build_cve_rows(results, prior_cves, now)
    health.append(enrich_epss(fetch, cve_rows, now))

    payloads = build_site_data(results, cve_rows, health, state, now)
    sources = json.loads(Path(sources_path).read_text(encoding="utf-8"))
    payloads["sources.json"] = dict(sources, generated_at=iso(now))

    feed_count = len(payloads.get("feed.json", {}).get("items", []))
    snapshots, history_files = _history(state_dir, cve_rows, feed_count, now)
    payloads["trends.json"] = dict(
        build_trends(snapshots, cve_rows, now),
        generated_at=iso(now), schema_version=1)

    published, problems = gate(payloads, state, schemas_dir)
    if problems:
        published["health.json"] = dict(
            published.get("health.json", payloads["health.json"]),
            pipeline_warnings=problems)

    out_dir.mkdir(parents=True, exist_ok=True)
    state_dir.mkdir(parents=True, exist_ok=True)
    for name, payload in published.items():
        blob = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        (out_dir / name).write_text(blob, encoding="utf-8")
        (state_dir / name).write_text(blob, encoding="utf-8")

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
                      schemas_dir="schemas", sources_path="data/sources.json")
    sys.exit(0)   # upstream problems are health data, never a CI failure
