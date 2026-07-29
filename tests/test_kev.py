from collectors import kev
from tests.conftest import FIXED_NOW


def _result(fake_fetch):
    fetch = fake_fetch({kev.URL: "kev/feed.json"})
    return kev.collect(fetch, FIXED_NOW)


def test_kev_rows(fake_fetch):
    r = _result(fake_fetch)
    assert r.ok
    rows = {row["cve"]: row for row in r.extra["kev"]}
    assert rows["CVE-2026-1111"]["kev_ransomware"] is True
    assert rows["CVE-2026-1111"]["vendor"] == "Fortinet"
    assert len(rows) == 2


def test_recent_kev_additions_become_feed_items(fake_fetch):
    r = _result(fake_fetch)
    assert len(r.items) == 1                      # only the 2026 addition
    item = r.items[0]
    assert item["category"] == "vulnerability"
    assert item["severity"] == "critical"         # ransomware-linked KEV
    assert "CVE-2026-1111" in item["entities"]["cves"]
