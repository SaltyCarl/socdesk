from collectors import malwarebazaar, urlhaus
from tests.conftest import FIXED_NOW


def test_urlhaus(fake_fetch, monkeypatch):
    monkeypatch.setenv("ABUSECH_AUTH_KEY", "test-key")
    r = urlhaus.collect(fake_fetch({urlhaus.URL: "urlhaus/recent.json"}), FIXED_NOW)
    assert r.ok and r.items == []
    ioc = r.extra["iocs"][0]
    assert ioc == {"type": "url", "value": "http://bad.example/payload.exe",
                   "source": "urlhaus", "malware": "Amadey", "confidence": 50,
                   "first_seen": "2026-07-28T04:00:00Z",
                   "last_seen": "2026-07-28T04:00:00Z"}


def test_malwarebazaar(fake_fetch, monkeypatch):
    monkeypatch.setenv("ABUSECH_AUTH_KEY", "test-key")
    r = malwarebazaar.collect(
        fake_fetch({malwarebazaar.URL: "malwarebazaar/recent.json"}), FIXED_NOW)
    assert r.ok and r.items == []
    ioc = r.extra["iocs"][0]
    assert ioc["type"] == "sha256" and ioc["malware"] == "RedLineStealer"
    assert ioc["source"] == "malwarebazaar"
