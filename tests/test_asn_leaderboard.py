import json
from pathlib import Path

from pipeline import asn
from pipeline.validate import SCHEMA_FOR, validate_payload
from tests.conftest import FIXED_NOW

FIXTURES = Path(__file__).parent / "fixtures" / "asn"


def test_parse_org_parity_fixture():
    parity = json.loads((FIXTURES / "org_parity.json").read_text(encoding="utf-8"))
    for row in parity:
        assert asn.parse_org(row["org"]) == (row["asn"], row["isp"])


def test_parse_org_name_only_and_empty_are_none():
    assert asn.parse_org("Cloudflare, Inc.") == (None, None)
    assert asn.parse_org("") == (None, None)
    assert asn.parse_org(None) == (None, None)
    assert asn.parse_org("   ") == (None, None)


def _ipinfo_fetch(orgs, calls=None):
    """fetch(url) mapping IP -> {'org','country'} from `orgs`; records every
    looked-up IP into `calls` (to assert cache-first skips the call)."""
    def fetch(url, *, method="GET", json=None, headers=None, text=False):
        assert url.startswith("https://ipinfo.io/") and "/json?token=" in url
        ip = url[len("https://ipinfo.io/"):].split("/json", 1)[0]
        if calls is not None:
            calls.append(ip)
        return orgs.get(ip, {})       # missing -> empty body -> unattributed
    return fetch


def test_resolve_cache_hit_makes_no_call():
    cache = {"9.9.9.9": {"asn": "AS19281", "isp": "Quad9", "country": "CH"}}
    calls = []
    got = asn.resolve_asn("9.9.9.9", cache, _ipinfo_fetch({}, calls), "tok")
    assert got == {"asn": "AS19281", "isp": "Quad9", "country": "CH"}
    assert calls == []                # a hit never touches the network


def test_resolve_new_ip_is_fetched_once_and_cached():
    orgs = {"1.2.3.4": {"org": "AS64500 Example ISP", "country": "us"}}
    cache, calls = {}, []
    got = asn.resolve_asn("1.2.3.4", cache, _ipinfo_fetch(orgs, calls), "tok")
    assert got == {"asn": "AS64500", "isp": "Example ISP", "country": "US"}
    assert calls == ["1.2.3.4"] and cache["1.2.3.4"]["asn"] == "AS64500"


def test_resolve_no_token_returns_none_without_calling():
    calls = []
    assert asn.resolve_asn("1.2.3.4", {}, _ipinfo_fetch({}, calls), None) is None
    assert calls == []


def test_resolve_name_only_org_is_unattributed():
    orgs = {"1.2.3.4": {"org": "Some ISP Without ASN", "country": "US"}}
    assert asn.resolve_asn("1.2.3.4", {}, _ipinfo_fetch(orgs), "tok") is None


def test_resolve_network_error_returns_none():
    def boom(url, **kw):
        raise RuntimeError("ipinfo 503")
    assert asn.resolve_asn("1.2.3.4", {}, boom, "tok") is None
