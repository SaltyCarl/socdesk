from tools.picket.ring import BUCKET_SECONDS, RING_LEN, apply_snapshot, bucket_index, new_state

T0 = 1_800_000_000  # any epoch; multiple of 1800 for clean buckets


def snap(total, ip=None, user=None):
    return {"total": total, "proto": {"SSH": total}, "ip": ip or {}, "user": user or {},
            "pass": {}, "country": {}, "isp": {}}


def test_bucket_index_is_30_minutes():
    assert BUCKET_SECONDS == 1800 and RING_LEN == 336
    assert bucket_index(T0 + 1799) == bucket_index(T0)
    assert bucket_index(T0 + 1800) == bucket_index(T0) + 1


def test_first_snapshot_records_baseline_no_deltas():
    st = new_state()
    out = apply_snapshot(st, snap(100, ip={"1.1.1.1": 100}), T0)
    assert sum(out["ring"]) == 0 and out["hits_7d"]["ip"] == {} and out["unique_ips_7d"] == 0
    assert out["reset"] is False and st["prev"]["total"] == 100


def test_deltas_land_in_current_bucket_and_sum_over_window():
    st = new_state()
    apply_snapshot(st, snap(100, ip={"1.1.1.1": 100}), T0)
    out = apply_snapshot(st, snap(130, ip={"1.1.1.1": 120, "2.2.2.2": 10}), T0 + 1800)
    assert out["ring"][-1] == 30            # newest bucket is the last slot
    assert out["hits_7d"]["ip"] == {"1.1.1.1": 20, "2.2.2.2": 10}
    assert out["hits_7d"]["proto"] == {"SSH": 30}
    assert out["unique_ips_7d"] == 2


def test_skipped_buckets_are_zero_filled_and_window_slides():
    st = new_state()
    apply_snapshot(st, snap(0), T0)
    apply_snapshot(st, snap(5, ip={"9.9.9.9": 5}), T0 + 1800)
    # jump 8 days: everything ages out
    out = apply_snapshot(st, snap(5, ip={"9.9.9.9": 5}), T0 + 1800 + 8 * 86400)
    assert sum(out["ring"]) == 0 and out["hits_7d"]["ip"] == {} and out["unique_ips_7d"] == 0


def test_counter_decrease_is_clamped_and_flagged_as_reset():
    st = new_state()
    apply_snapshot(st, snap(500, ip={"1.1.1.1": 500}), T0)
    out = apply_snapshot(st, snap(3, ip={"1.1.1.1": 3}), T0 + 1800)   # knock-knock DB reset
    assert out["ring"][-1] == 0 and out["hits_7d"]["ip"] == {} and out["reset"] is True


def test_same_bucket_twice_accumulates_not_overwrites():
    st = new_state()
    apply_snapshot(st, snap(0), T0)
    apply_snapshot(st, snap(4), T0 + 60)
    out = apply_snapshot(st, snap(10), T0 + 120)
    assert out["ring"][-1] == 10


def test_state_is_bounded_by_pruning_old_sparse_deltas():
    st = new_state()
    apply_snapshot(st, snap(0), T0)
    for i in range(1, 400):   # 400 buckets of activity on one IP
        apply_snapshot(st, snap(i, ip={"1.1.1.1": i}), T0 + i * 1800)
    assert len(st["deltas"]["ip"]["1.1.1.1"]) <= RING_LEN
