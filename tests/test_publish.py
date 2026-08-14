from collectors.base import CollectorResult, iso, make_item
from pipeline.publish import build_site_data, merge_feed
from tests.conftest import FIXED_NOW

NEW_ITEM = make_item("rss", "n1", "report", "Fresh", "s", "https://x/1",
                     "info", "2026-07-28T01:00:00Z", FIXED_NOW)
RECENT_OLD = dict(NEW_ITEM, id="b" * 40, published_at="2026-07-10T00:00:00Z")
ANCIENT = dict(NEW_ITEM, id="c" * 40, published_at="2026-01-01T00:00:00Z")


def test_merge_feed_window_and_dedup():
    merged = merge_feed([RECENT_OLD, ANCIENT, dict(NEW_ITEM)], [NEW_ITEM],
                        days=30, now=FIXED_NOW)
    ids = [i["id"] for i in merged]
    assert NEW_ITEM["id"] in ids and RECENT_OLD["id"] in ids
    assert ANCIENT["id"] not in ids
    assert len(ids) == len(set(ids))
    assert merged[0]["published_at"] >= merged[-1]["published_at"]  # newest first


def test_build_site_data_shapes():
    results = [
        CollectorResult(source="rss", items=[NEW_ITEM]),
        CollectorResult(source="attack", extra={
            "actors": [{"name": "A", "attack_id": "G1", "aliases": [],
                        "description": "", "techniques": [], "software": []}],
            "malware": []}),
    ]
    health = [{"source": "rss", "ok": True, "error": "", "items": 1,
               "last_success_at": iso(FIXED_NOW)}]
    payloads = build_site_data(results, cve_rows=[], health=health,
                               prior={}, now=FIXED_NOW)
    assert set(payloads) == {"feed.json", "cves.json", "health.json",
                             "actors.json", "malware.json", "relations.json",
                             "threat_ips.json"}
    for p in payloads.values():
        assert p["generated_at"] == iso(FIXED_NOW) and p["schema_version"] == 1


def test_no_ioc_corpus_is_published():
    """Compliance gate: reputation data is deep-linked at render time, never
    mirrored (COMPLIANCE.md R4)."""
    results = [CollectorResult(source="rss", items=[NEW_ITEM],
                               extra={"iocs": [{"type": "ipv4", "value": "1.2.3.4"}]})]
    payloads = build_site_data(results, cve_rows=[], health=[], prior={},
                               now=FIXED_NOW)
    assert "iocs.json" not in payloads
    assert "1.2.3.4" not in str(payloads)


def test_health_carries_forward_last_success():
    prior_health = {"health.json": {
        "generated_at": "x", "schema_version": 1, "sources": [
            {"source": "rss", "ok": True, "error": "", "items": 5,
             "last_success_at": "2026-07-27T00:00:00Z"}]}}
    health = [{"source": "rss", "ok": False, "error": "boom", "items": 0,
               "last_success_at": ""}]
    payloads = build_site_data([], cve_rows=[], health=health,
                               prior=prior_health, now=FIXED_NOW)
    entry = payloads["health.json"]["sources"][0]
    assert entry["last_success_at"] == "2026-07-27T00:00:00Z"
