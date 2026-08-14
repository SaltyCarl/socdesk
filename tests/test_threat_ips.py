from collectors import feodotracker, threatfox
from collectors.base import CollectorResult
from pipeline import geo
from pipeline.threat_ips import build_threat_ips
from pipeline.validate import validate_payload
from tests.conftest import FIXED_NOW


def _feodo(fake_fetch):
    fetch = fake_fetch({feodotracker.URL: "feodotracker/ipblocklist.json"})
    return feodotracker.collect(fetch, FIXED_NOW)


def _threatfox(fake_fetch, monkeypatch, key="test-key"):
    monkeypatch.setenv(threatfox.ENV_KEY, key)
    fetch = fake_fetch({threatfox.URL: "threatfox/get_iocs.json"})
    return threatfox.collect(fetch, FIXED_NOW)


# --- Feodo Tracker collector -------------------------------------------------

def test_feodo_normalises_rows(fake_fetch):
    r = _feodo(fake_fetch)
    assert r.ok and len(r.extra["ips"]) == 5
    row = r.extra["ips"][0]
    assert row["ip"] == "162.243.103.246"
    assert row["port"] == 8080
    assert row["country"] == "US"
    assert row["malware"] == "Emotet"
    assert row["source"] == "feodotracker"
    # 'YYYY-MM-DD HH:MM:SS' -> ISO Z; bare date -> midnight Z
    assert row["first_seen"] == "2022-06-04T21:24:53Z"
    assert row["last_seen"] == "2026-03-07T00:00:00Z"


# --- ThreatFox collector -----------------------------------------------------

def test_threatfox_filters_to_ip_port(fake_fetch, monkeypatch):
    r = _threatfox(fake_fetch, monkeypatch)
    # 3 of the 4 fixture rows are ip:port; the domain row is dropped.
    assert r.ok and len(r.extra["ips"]) == 3
    assert all(row["source"] == "threatfox" for row in r.extra["ips"])
    first = r.extra["ips"][0]
    assert first["ip"] == "139.180.203.104" and first["port"] == 443
    assert first["malware"] == "Cobalt Strike"
    assert first["country"] is None            # ThreatFox has no geolocation
    assert first["first_seen"] == "2026-08-13T09:14:22Z"


def test_threatfox_skips_without_key(fake_fetch, monkeypatch):
    monkeypatch.delenv(threatfox.ENV_KEY, raising=False)
    # No network call must happen: an unmapped fetch would raise.
    fetch = fake_fetch({})
    r = threatfox.collect(fetch, FIXED_NOW)
    assert r.ok and r.extra["ips"] == []


def test_threatfox_malware_falls_back_to_tag():
    row = {"ioc": "1.2.3.4:80", "ioc_type": "ip:port",
           "malware": "", "malware_printable": None,
           "first_seen": "2026-08-13 00:00:00 UTC", "last_seen": None,
           "confidence_level": 40, "tags": ["Latrodectus"]}
    resp = {"query_status": "ok", "data": [row]}
    import os
    os.environ[threatfox.ENV_KEY] = "k"
    try:
        r = threatfox.collect(lambda url, **kw: resp, FIXED_NOW)
    finally:
        del os.environ[threatfox.ENV_KEY]
    assert r.extra["ips"][0]["malware"] == "Latrodectus"


# --- Geolocation -------------------------------------------------------------

def test_locate_is_deterministic():
    a = geo.locate("162.243.103.246", "US")
    b = geo.locate("162.243.103.246", "US")
    assert a == b and a is not None
    lat, lng, country, precision = a
    assert country == "US" and precision == "country"
    assert -90 <= lat <= 90 and -180 <= lng <= 180


def test_locate_scatters_two_ips_in_the_same_country():
    a = geo.locate("162.243.103.246", "US")
    b = geo.locate("50.16.16.211", "US")
    assert (a[0], a[1]) != (b[0], b[1])        # no stacked single point


def test_locate_drops_unplaceable_ip():
    # No source country and no IPinfo -> cannot be placed, not faked.
    assert geo.locate("45.148.10.62", None) is None


# --- IPinfo geolocation + persistent cache -----------------------------------

def test_resolve_uses_ipinfo_and_caches(fake_fetch):
    ip, token = "139.180.203.104", "tok"
    url = geo.IPINFO_URL.format(ip=ip, token=token)
    fetch = fake_fetch({url: "ipinfo/139.180.203.104.json"})
    cache = {}
    lat, lng, country, city, precision = geo.resolve(ip, None, cache, fetch, token)
    assert (precision, country, city) == ("city", "SG", "Singapore")
    assert (lat, lng) == (1.2897, 103.8501)      # IPinfo coords used as-is
    assert cache[ip]["precision"] == "city"      # written back for reuse
    # A subsequent run hits the cache — no token, no fetch, same answer.
    again = geo.resolve(ip, None, cache, fetch=None, token=None)
    assert again == (lat, lng, country, city, precision)


def test_resolve_falls_back_to_centroid_without_token():
    cache = {}
    lat, lng, country, city, precision = geo.resolve(
        "162.243.103.246", "US", cache, fetch=None, token=None)
    assert precision == "country" and country == "US" and city is None
    assert cache == {}                           # fallbacks are never cached


def test_resolve_falls_back_when_ipinfo_fails():
    def fetch(url, **kw):
        raise RuntimeError("ipinfo 500")
    cache = {}
    res = geo.resolve("162.243.103.246", "US", cache, fetch=fetch, token="tok")
    assert res[4] == "country" and cache == {}   # failure -> centroid, uncached


def test_build_geolocates_threatfox_via_ipinfo(fake_fetch, monkeypatch):
    tf = _threatfox(fake_fetch, monkeypatch)     # 3 ip:port rows, no country
    token = "tok"
    mapping = {geo.IPINFO_URL.format(ip=row["ip"], token=token):
               f"ipinfo/{row['ip']}.json" for row in tf.extra["ips"]}
    fetch = fake_fetch(mapping)
    cache = {}
    body = build_threat_ips({"threatfox": tf}, FIXED_NOW, fetch=fetch,
                            cache=cache, token=token)
    # With IPinfo, ThreatFox rows (no country of their own) are now placed.
    assert body["count"] == 3 and body["dropped_no_geo"] == 0
    assert all(i["geo_precision"] == "city" for i in body["ips"])
    assert len(cache) == 3                       # all three cached for next run


def test_build_prunes_stale_cache_entries():
    feodo = CollectorResult(source="feodotracker", extra={"ips": [{
        "ip": "162.243.103.246", "port": 443, "country": "US",
        "malware": "Emotet", "first_seen": "2026-08-10T00:00:00Z",
        "last_seen": "2026-08-11T00:00:00Z", "source": "feodotracker"}]})
    cache = {"9.9.9.9": {"lat": 0.0, "lng": 0.0, "country": "US",
                         "city": "Gone", "precision": "city"}}
    build_threat_ips({"feodotracker": feodo}, FIXED_NOW, cache=cache)
    assert "9.9.9.9" not in cache                 # IP no longer listed -> pruned


# --- Payload assembly --------------------------------------------------------

def test_build_places_feodo_and_counts_dropped_threatfox(fake_fetch, monkeypatch):
    ok = {"feodotracker": _feodo(fake_fetch),
          "threatfox": _threatfox(fake_fetch, monkeypatch)}
    body = build_threat_ips(ok, FIXED_NOW)
    # All 5 Feodo rows carry a country and get placed; the 3 ThreatFox rows have
    # none (no offline DB in the test env) and are dropped, not fabricated.
    assert body["count"] == 5
    assert body["total_before_cap"] == 5
    assert body["dropped_no_geo"] == 3
    assert body["truncated"] is False
    item = body["ips"][0]
    assert set(item) == {"ip", "country", "lat", "lng", "source", "malware",
                         "port", "first_seen", "last_seen", "geo_precision"}
    assert item["geo_precision"] == "country"
    assert "abuse.ch" in body["attribution"]


def test_build_dedupes_by_ip_merging_sources():
    feodo = CollectorResult(source="feodotracker", extra={"ips": [{
        "ip": "185.220.101.51", "port": 443, "country": "DE",
        "malware": "QakBot", "first_seen": "2026-08-10T00:00:00Z",
        "last_seen": "2026-08-11T00:00:00Z", "source": "feodotracker"}]})
    tf = CollectorResult(source="threatfox", extra={"ips": [{
        "ip": "185.220.101.51", "port": 443, "country": "DE",
        "malware": "Sliver", "first_seen": "2026-08-12T00:00:00Z",
        "last_seen": "2026-08-13T00:00:00Z", "source": "threatfox"}]})
    body = build_threat_ips({"feodotracker": feodo, "threatfox": tf}, FIXED_NOW)
    assert body["count"] == 1                  # one row, not two
    row = body["ips"][0]
    assert row["source"] == "feodotracker"     # first-inserted stays canonical
    assert row["first_seen"] == "2026-08-10T00:00:00Z"   # earliest kept
    assert row["last_seen"] == "2026-08-13T00:00:00Z"    # latest kept


def test_build_caps_and_flags_truncation():
    rows = [{"ip": f"10.0.{i // 256}.{i % 256}", "port": 443, "country": "US",
             "malware": "Emotet", "first_seen": "2026-08-01T00:00:00Z",
             "last_seen": f"2026-08-{(i % 27) + 1:02d}T00:00:00Z",
             "source": "feodotracker"} for i in range(360)]
    ok = {"feodotracker": CollectorResult(source="feodotracker",
                                          extra={"ips": rows})}
    body = build_threat_ips(ok, FIXED_NOW, cap=300)
    assert body["truncated"] is True
    assert body["count"] == 300 and len(body["ips"]) == 300
    assert body["total_before_cap"] == 360


def test_built_payload_passes_schema(fake_fetch, monkeypatch):
    ok = {"feodotracker": _feodo(fake_fetch),
          "threatfox": _threatfox(fake_fetch, monkeypatch)}
    payload = dict(build_threat_ips(ok, FIXED_NOW),
                   generated_at="2026-08-13T12:00:00Z", schema_version=1)
    assert validate_payload("threat_ips.json", payload, "schemas") == []
