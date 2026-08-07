"""Daily snapshots and derived trends.

Static-tier capability: git is the database. Each run writes one compact
snapshot per day into `data/state/history/`, committed like any other state.
Trends are then a diff between files — which is how a site with no backend
answers "what CHANGED this week", the question an analyst actually cares about.
"""
from datetime import timedelta

HISTORY_DAYS = 90        # snapshots retained
MOVER_WINDOW = 7         # days back for the "what moved" comparison
MOVER_LIMIT = 10
VOLUME_DAYS = 30
MIN_DELTA = 0.05         # ignore noise-level EPSS drift


def snapshot_name(now):
    return now.strftime("%Y-%m-%d") + ".json"


def daily_snapshot(cve_rows, feed_count, now):
    """One compact row per scored CVE. Unscored CVEs are omitted — a snapshot
    full of nulls is dead weight in git forever."""
    epss, kev = {}, []
    for c in cve_rows:
        if c.get("epss") is not None:
            epss[c["cve"]] = round(float(c["epss"]), 5)
        if c.get("kev"):
            kev.append(c["cve"])
    return {"date": now.strftime("%Y-%m-%d"), "feed_count": int(feed_count),
            "epss": epss, "kev": sorted(kev)}


def prune_history(history, keep=HISTORY_DAYS):
    """history: {filename: payload}. Keeps the newest `keep` by filename."""
    return {k: history[k] for k in sorted(history)[-keep:]}


def _closest_before(snapshots, target_date):
    older = [s for s in snapshots if s.get("date", "") <= target_date]
    return older[-1] if older else None


def build_trends(snapshots, cve_rows, now):
    """Derive the published trends payload from the snapshot series."""
    snapshots = sorted([s for s in snapshots if s.get("date")],
                       key=lambda s: s["date"])
    current = snapshots[-1] if snapshots else {"epss": {}, "kev": [],
                                               "feed_count": 0, "date": ""}
    baseline_date = (now - timedelta(days=MOVER_WINDOW)).strftime("%Y-%m-%d")
    prior = _closest_before(snapshots[:-1], baseline_date) or (
        snapshots[-2] if len(snapshots) > 1 else None)

    by_cve = {c["cve"]: c for c in cve_rows}

    movers = []
    if prior:
        for cve, now_score in current["epss"].items():
            was = prior["epss"].get(cve)
            if was is None:
                continue
            delta = now_score - was
            if delta < MIN_DELTA:
                continue
            row = by_cve.get(cve, {})
            movers.append({
                "cve": cve, "from": round(was, 5), "to": round(now_score, 5),
                "delta": round(delta, 5), "kev": bool(row.get("kev")),
                "product": (row.get("products") or [None])[0]
                           or (row.get("vendors") or [None])[0] or "",
            })
    movers.sort(key=lambda m: m["delta"], reverse=True)

    # "New to KEV" comes from CISA's own dateAdded, never from snapshot
    # diffing: on the first run there is no prior snapshot, and diffing would
    # report the entire back catalogue — Heartbleed included — as new today.
    kev_cutoff = (now - timedelta(days=MOVER_WINDOW)).strftime("%Y-%m-%d")
    new_kev = []
    for c in current["kev"]:
        row = by_cve.get(c, {})
        added = (row.get("kev_date_added") or "")[:10]
        if not added or added < kev_cutoff:
            continue
        new_kev.append({
            "cve": c, "added": added, "epss": row.get("epss"),
            "product": (row.get("products") or [None])[0]
                       or (row.get("vendors") or [None])[0] or "",
        })
    new_kev.sort(key=lambda k: (k["added"], k["epss"] or 0), reverse=True)
    prior_kev = set(prior["kev"]) if prior else set()

    volume = [{"date": s["date"], "count": s.get("feed_count", 0)}
              for s in snapshots[-VOLUME_DAYS:]]

    yesterday = snapshots[-2] if len(snapshots) > 1 else None
    return {
        "epss_movers": movers[:MOVER_LIMIT],
        "new_kev": new_kev[:MOVER_LIMIT],
        "volume": volume,
        "totals": {
            "feed_count": current.get("feed_count", 0),
            "feed_delta": current.get("feed_count", 0) - yesterday["feed_count"]
                          if yesterday else 0,
            "kev_count": len(current["kev"]),
            "kev_delta": len(current["kev"]) - len(prior_kev) if prior else 0,
            "compared_to": prior["date"] if prior else "",
        },
    }
