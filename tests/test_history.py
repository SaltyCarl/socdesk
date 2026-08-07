from pipeline.history import (build_trends, daily_snapshot, prune_history,
                             snapshot_name)
from tests.conftest import FIXED_NOW

CVES = [
    {"cve": "CVE-2026-1111", "epss": 0.87, "kev": True, "kev_date_added": "2026-07-27",
     "cvss": 9.8, "vendors": ["Fortinet"], "products": ["FortiOS"], "title": "t1"},
    {"cve": "CVE-2026-2222", "epss": 0.04, "kev": False, "kev_date_added": "",
     "cvss": 7.1, "vendors": ["ExampleCorp"], "products": ["Server"], "title": "t2"},
    {"cve": "CVE-2026-3333", "epss": None, "kev": False, "kev_date_added": "",
     "cvss": None, "vendors": [], "products": [], "title": "t3"},
]


def test_snapshot_is_compact_and_dated():
    snap = daily_snapshot(CVES, feed_count=500, now=FIXED_NOW)
    assert snap["date"] == "2026-07-28"
    assert snap["feed_count"] == 500
    # only scored CVEs are kept — a snapshot of nulls is dead weight
    assert "CVE-2026-3333" not in snap["epss"]
    assert snap["epss"]["CVE-2026-1111"] == 0.87
    assert "CVE-2026-1111" in snap["kev"]
    assert "CVE-2026-2222" not in snap["kev"]


def test_snapshot_name():
    assert snapshot_name(FIXED_NOW) == "2026-07-28.json"


def test_prune_keeps_window():
    hist = {f"2026-0{m}-15.json": {} for m in range(1, 8)}
    kept = prune_history(hist, keep=3)
    assert list(kept) == ["2026-05-15.json", "2026-06-15.json", "2026-07-15.json"]


def test_trends_finds_epss_movers():
    week_ago = {"date": "2026-07-21", "feed_count": 400,
                "epss": {"CVE-2026-1111": 0.31, "CVE-2026-2222": 0.03}, "kev": []}
    today = daily_snapshot(CVES, feed_count=500, now=FIXED_NOW)
    t = build_trends([week_ago, today], CVES, now=FIXED_NOW)
    top = t["epss_movers"][0]
    assert top["cve"] == "CVE-2026-1111"
    assert round(top["delta"], 2) == 0.56          # 0.31 -> 0.87
    assert top["from"] == 0.31 and top["to"] == 0.87
    assert top["kev"] is True


def test_trends_reports_new_kev_and_volume():
    week_ago = {"date": "2026-07-21", "feed_count": 400, "epss": {}, "kev": []}
    today = daily_snapshot(CVES, feed_count=500, now=FIXED_NOW)
    t = build_trends([week_ago, today], CVES, now=FIXED_NOW)
    assert "CVE-2026-1111" in [k["cve"] for k in t["new_kev"]]
    assert t["volume"][-1] == {"date": "2026-07-28", "count": 500}
    assert t["totals"]["feed_delta"] == 100        # 500 - 400


def test_trends_survives_a_single_snapshot():
    """First ever run: no history to compare against, must not explode."""
    today = daily_snapshot(CVES, feed_count=500, now=FIXED_NOW)
    t = build_trends([today], CVES, now=FIXED_NOW)
    assert t["epss_movers"] == [] and t["totals"]["feed_delta"] == 0
    assert t["volume"] == [{"date": "2026-07-28", "count": 500}]


def test_new_kev_uses_cisa_date_not_snapshot_diff():
    """Regression: with no prior snapshot, diffing reported the ENTIRE KEV back
    catalogue as 'new today' — Heartbleed and all."""
    old_kev = dict(CVES[0], cve="CVE-2014-0160", kev_date_added="2014-04-08")
    rows = CVES + [old_kev]
    today = daily_snapshot(rows, feed_count=500, now=FIXED_NOW)
    t = build_trends([today], rows, now=FIXED_NOW)          # single snapshot
    names = [k["cve"] for k in t["new_kev"]]
    assert "CVE-2014-0160" not in names                     # 2014 is not new
    assert "CVE-2026-1111" in names                         # added 2026-07-27
