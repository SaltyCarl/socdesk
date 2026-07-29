from collectors import ransomwarelive
from tests.conftest import FIXED_NOW


def test_victims_become_feed_items(fake_fetch):
    fetch = fake_fetch({ransomwarelive.URL: "ransomwarelive/recent.json"})
    r = ransomwarelive.collect(fetch, FIXED_NOW)
    assert r.ok and len(r.items) == 2
    item = r.items[0]
    assert item["category"] == "ransomware"
    assert item["severity"] == "high"
    assert item["entities"]["actors"] == ["akira"]
    assert "Example Manufacturing" in item["title"]
    assert item["published_at"] == "2026-07-28T02:15:00Z"
