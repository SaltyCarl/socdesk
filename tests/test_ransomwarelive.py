from collectors import ransomwarelive
from tests.conftest import FIXED_NOW


def _items(fake_fetch):
    fetch = fake_fetch({ransomwarelive.URL: "ransomwarelive/recent.json"})
    return ransomwarelive.collect(fetch, FIXED_NOW)


def test_group_activity_becomes_feed_items(fake_fetch):
    r = _items(fake_fetch)
    assert r.ok and len(r.items) == 2
    item = r.items[0]
    assert item["category"] == "ransomware"
    assert item["severity"] == "high"
    assert item["entities"]["actors"] == ["akira"]
    assert item["published_at"] == "2026-07-28T02:15:00Z"


def test_victim_names_are_never_republished(fake_fetch):
    """Compliance gate: unverified criminal claims about named orgs stay at
    the source. Sector/country context is fine."""
    r = _items(fake_fetch)
    blob = " ".join(i["title"] + " " + i["summary"] for i in r.items)
    assert "Example Manufacturing" not in blob
    assert "Beispiel GmbH" not in blob
    assert "Manufacturing" in blob and "US" in blob      # sector/country kept
    assert "akira posted a new victim claim" == r.items[0]["title"]


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
    a, b = _items(fake_fetch).items
    assert a["id"] != b["id"]
    assert len(a["id"]) == 40
