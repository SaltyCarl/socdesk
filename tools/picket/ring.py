"""On-box delta ring: 7-day time series WITHOUT per-knock storage.

knock-knock's rollups are cumulative all-time counters. Every exporter run
snapshots them and turns the increase since the previous run into deltas —
a dense 336×30-min ring for the global histogram, and sparse per-entity
delta lists (most IPs are active in a handful of buckets) for 7-day hits.

Invariants: a counter that goes DOWN (DB reset/prune) is clamped to 0 and
flagged (`reset`) rather than published as a spike; nothing older than
RING_LEN buckets survives, so `state.json` stays bounded.
"""

BUCKET_SECONDS = 1800
RING_LEN = 336            # 7 days × 48 half-hours
KINDS = ("proto", "ip", "user", "pass", "country", "isp")


def bucket_index(epoch_seconds):
    return int(epoch_seconds) // BUCKET_SECONDS


def new_state():
    return {"version": 1, "last_bucket": None, "prev": None,
            "ring": [0] * RING_LEN, "deltas": {k: {} for k in KINDS}}


def _advance_ring(state, cur_bucket):
    last = state["last_bucket"]
    if last is None:
        return
    gap = cur_bucket - last
    if gap <= 0:
        return
    ring = state["ring"]
    if gap >= RING_LEN:
        state["ring"] = [0] * RING_LEN
    else:
        state["ring"] = ring[gap:] + [0] * gap


def apply_snapshot(state, snapshot, now_epoch):
    cur = bucket_index(now_epoch)
    _advance_ring(state, cur)
    prev = state["prev"]
    reset = False
    floor = cur - RING_LEN + 1

    if prev is not None:
        total_delta = int(snapshot["total"]) - int(prev["total"])
        if total_delta < 0:
            reset, total_delta = True, 0
        state["ring"][-1] += total_delta
        for kind in KINDS:
            prev_k, cur_k = prev.get(kind, {}), snapshot.get(kind, {})
            for key, hits in cur_k.items():
                d = int(hits) - int(prev_k.get(key, 0))
                if d < 0:
                    reset, d = True, 0
                if d <= 0:
                    continue
                lst = state["deltas"][kind].setdefault(key, [])
                if lst and lst[-1][0] == cur:
                    lst[-1][1] += d
                else:
                    lst.append([cur, d])

    # prune every sparse list to the window; drop empties
    for kind in KINDS:
        for key in list(state["deltas"][kind].keys()):
            kept = [[b, d] for b, d in state["deltas"][kind][key] if b >= floor]
            if kept:
                state["deltas"][kind][key] = kept[-RING_LEN:]
            else:
                del state["deltas"][kind][key]

    state["prev"] = snapshot
    state["last_bucket"] = cur

    hits_7d = {kind: {key: sum(d for _, d in lst) for key, lst in state["deltas"][kind].items()}
               for kind in KINDS}
    return {"ring": list(state["ring"]), "hits_7d": hits_7d,
            "unique_ips_7d": len(hits_7d["ip"]), "reset": reset}
