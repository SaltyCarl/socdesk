from collectors import ransomwarelive
from tests.conftest import FIXED_NOW


def _items(fake_fetch):
    fetch = fake_fetch({ransomwarelive.URL: "ransomwarelive/recent.json"})
    return ransomwarelive.collect(fetch, FIXED_NOW)


def test_group_activity_becomes_feed_items(fake_fetch):
    r = _items(fake_fetch)
    assert r.ok and len(r.items) == 1
    item = r.items[0]
    assert item["category"] == "ransomware"
    assert item["severity"] == "high"
    assert item["entities"]["actors"] == ["akira"]
    assert item["published_at"] == "2026-08-24T17:51:12Z"


def test_claim_carries_attributed_victim_and_domain(fake_fetch):
    """Reversal of the old withhold-names policy: victim identity is now
    republished as a leak-site fact, attributed to the group and framed
    unverified — not a SOCDesk verdict."""
    fetch = fake_fetch({ransomwarelive.URL: "ransomwarelive/recent.json"})
    r = ransomwarelive.collect(fetch, FIXED_NOW)
    it = r.items[0]
    assert it["victim"] == "Furnished Quarters"
    assert it["domain"] == "furnishedquarters.com"
    # attribution/framing stays: title names the group + "claim"; summary marks unverified
    assert "claim" in it["title"].lower()
    assert "unverified" in it["summary"].lower()


def test_offset_aware_timestamps_do_not_become_invalid(fake_fetch):
    """Regression: an offset-aware upstream value plus our 'Z' produced
    '...+00:00Z', which Date.parse rejects — the UI showed '—' for age."""
    fetch = lambda url, **kw: [
        {"victim": "X", "group": "akira", "discovered": "2026-08-08 02:15:00+00:00",
         "country": "US", "activity": "Manufacturing", "claim_url": "https://x.test/1"}]
    item = ransomwarelive.collect(fetch, FIXED_NOW).items[0]
    assert item["published_at"] == "2026-08-08T02:15:00Z"
    assert item["published_at"].count("Z") == 1 and "+" not in item["published_at"]


def test_ids_stay_stable_per_victim(fake_fetch):
    """The hashed id still keys on the victim so dedup works across runs."""
    fetch = lambda url, **kw: [
        {"victim": "Example Manufacturing", "group": "akira",
         "discovered": "2026-07-28 02:15:00", "country": "US",
         "activity": "Manufacturing", "claim_url": "https://ransomware.live/id/x1"},
        {"victim": "Beispiel GmbH", "group": "play",
         "discovered": "2026-07-27 22:00:00", "country": "DE",
         "activity": "Logistics", "claim_url": "https://ransomware.live/id/x2"},
    ]
    a, b = ransomwarelive.collect(fetch, FIXED_NOW).items
    assert a["id"] != b["id"]
    assert len(a["id"]) == 40
