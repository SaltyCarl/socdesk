from collectors import threatfox
from tests.conftest import FIXED_NOW


def test_threatfox_ioc_normalization(fake_fetch, monkeypatch):
    monkeypatch.setenv("ABUSECH_AUTH_KEY", "test-key")
    fetch = fake_fetch({threatfox.URL: "threatfox/recent.json"})
    r = threatfox.collect(fetch, FIXED_NOW)
    assert r.ok and r.items == []            # IOC-repository source: no feed items
    iocs = r.extra["iocs"]
    by_value = {i["value"]: i for i in iocs}
    assert by_value["45.61.136.9"]["type"] == "ipv4"       # port stripped
    assert by_value["evil-updates.example"]["type"] == "domain"
    assert by_value["evil-updates.example"]["malware"] == "Lumma Stealer"
    assert by_value["evil-updates.example"]["last_seen"] == "2026-07-28T03:00:00Z"
    sha = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
    assert by_value[sha]["type"] == "sha256"
    assert all(i["source"] == "threatfox" for i in iocs)
