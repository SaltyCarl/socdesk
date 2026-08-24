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


def _community(*entries):
    """entries: (value, [categories]) -> a community_reports-shaped payload."""
    return {"indicators": {
        f"ipv4|{v}": {"type": "ipv4", "value": v, "reporters": 1,
                      "categories": list(cats)} for v, cats in entries}}


def _threat(*ips):
    return {"ips": [{"ip": ip, "source": "feodotracker"} for ip in ips]}


def _orgs_for(*pairs):
    return {ip: {"org": org, "country": cc} for ip, org, cc in pairs}


def test_aggregates_ips_on_one_asn_ranked():
    orgs = _orgs_for(
        ("185.220.101.34", "AS60729 Zwiebelfreunde e.V.", "DE"),
        ("185.220.101.42", "AS60729 Zwiebelfreunde e.V.", "DE"),
        ("162.243.103.246", "AS14061 DigitalOcean, LLC", "US"))
    community = _community(("185.220.101.34", ["phishing"]),
                          ("185.220.101.42", ["scanner", "phishing"]))
    board = asn.build_asn_leaderboard(
        community, _threat("162.243.103.246"), {},
        _ipinfo_fetch(orgs), FIXED_NOW, token="tok")
    assert board["count"] == 2
    assert board["total_abusive_ips"] == 3 and board["unattributed_ips"] == 0
    assert board["cap"] == 200 and board["truncated"] is False
    assert [n["asn"] for n in board["networks"]] == ["AS60729", "AS14061"]  # ip_count desc
    top = board["networks"][0]
    assert top["asn"] == "AS60729" and top["isp"] == "Zwiebelfreunde e.V."
    assert top["ip_count"] == 2 and top["report_count"] == 2
    assert top["categories"] == ["phishing", "scanner"]   # deduped + sorted union
    assert top["sources"] == ["community"] and top["country"] == "DE"
    assert len(top["examples"]) <= asn.EXAMPLE_CAP
    assert top["examples"] == sorted(top["examples"])


def test_rank_tie_breaks_on_asn():
    orgs = _orgs_for(("1.1.1.1", "AS200 B Net", "US"),
                     ("2.2.2.2", "AS100 A Net", "US"))
    board = asn.build_asn_leaderboard(
        _community(("1.1.1.1", ["ssh"]), ("2.2.2.2", ["ssh"])), {},
        {}, _ipinfo_fetch(orgs), FIXED_NOW, token="tok")
    assert [n["asn"] for n in board["networks"]] == ["AS100", "AS200"]  # equal count -> asn asc


def test_feed_only_asn_has_zero_report_count():
    orgs = _orgs_for(("162.243.103.246", "AS14061 DigitalOcean, LLC", "US"))
    board = asn.build_asn_leaderboard(
        {}, _threat("162.243.103.246"), {}, _ipinfo_fetch(orgs), FIXED_NOW, token="tok")
    (row,) = board["networks"]
    assert row["report_count"] == 0 and row["sources"] == ["abuse.ch"]
    assert row["categories"] == []                 # abuse.ch malware family != category enum
    assert row["report_count"] <= row["ip_count"]


def test_both_sources_merge_on_one_asn():
    orgs = _orgs_for(("1.1.1.1", "AS100 Shared Net", "US"),
                     ("2.2.2.2", "AS100 Shared Net", "US"))
    board = asn.build_asn_leaderboard(
        _community(("1.1.1.1", ["ssh"])), _threat("2.2.2.2"),
        {}, _ipinfo_fetch(orgs), FIXED_NOW, token="tok")
    (row,) = board["networks"]
    assert row["ip_count"] == 2 and row["report_count"] == 1
    assert row["sources"] == ["abuse.ch", "community"]   # sorted union


def test_unattributed_ip_gets_no_fabricated_asn():
    orgs = _orgs_for(("1.2.3.4", "Some ISP Without ASN", "US"))
    board = asn.build_asn_leaderboard(
        _community(("1.2.3.4", ["ssh"])), {}, {}, _ipinfo_fetch(orgs), FIXED_NOW, token="tok")
    assert board["networks"] == []
    assert board["unattributed_ips"] == 1 and board["total_abusive_ips"] == 1


def test_non_ip_indicators_are_not_unattributed():
    community = {"indicators": {"domain|evil.example": {
        "type": "domain", "value": "evil.example", "reporters": 1,
        "categories": ["phishing"]}}}
    board = asn.build_asn_leaderboard(community, {}, {}, _ipinfo_fetch({}), FIXED_NOW, token="tok")
    assert board["total_abusive_ips"] == 0 and board["unattributed_ips"] == 0


def test_cache_pruned_to_ips_seen_this_run():
    orgs = _orgs_for(("1.2.3.4", "AS64500 Example ISP", "US"))
    cache = {"5.5.5.5": {"asn": "AS1", "isp": "old", "country": "US"}}
    asn.build_asn_leaderboard(
        _community(("1.2.3.4", ["ssh"])), {}, cache, _ipinfo_fetch(orgs), FIXED_NOW, token="tok")
    assert "5.5.5.5" not in cache and "1.2.3.4" in cache


def test_cached_ip_is_not_refetched_by_builder():
    cache = {"9.9.9.9": {"asn": "AS19281", "isp": "Quad9", "country": "CH"}}
    calls = []
    asn.build_asn_leaderboard(
        _community(("9.9.9.9", ["scanner"])), {}, cache,
        _ipinfo_fetch({}, calls), FIXED_NOW, token="tok")
    assert calls == []                             # cache-first: quota discipline


def test_sources_switch_to_community_only(monkeypatch):
    monkeypatch.setattr(asn, "SOURCES", ("community",))
    orgs = _orgs_for(("1.1.1.1", "AS100 Community Net", "US"))
    board = asn.build_asn_leaderboard(
        _community(("1.1.1.1", ["ssh"])), _threat("162.243.103.246"),
        {}, _ipinfo_fetch(orgs), FIXED_NOW, token="tok")
    assert {s for n in board["networks"] for s in n["sources"]} == {"community"}
    assert board["total_abusive_ips"] == 1         # abuse.ch IP excluded entirely


def test_missing_token_all_unattributed_but_valid():
    board = asn.build_asn_leaderboard(
        _community(("1.2.3.4", ["ssh"])), _threat("5.6.7.8"),
        {}, _ipinfo_fetch({}), FIXED_NOW, token=None)
    assert board is not None and board["networks"] == []
    assert board["unattributed_ips"] == 2 and board["total_abusive_ips"] == 2
    assert board["generated_at"] == asn.iso(FIXED_NOW)


def test_fetch_raising_on_every_ip_still_valid():
    def boom(url, **kw):
        raise RuntimeError("ipinfo 503")
    board = asn.build_asn_leaderboard(
        _community(("1.2.3.4", ["ssh"])), {}, {}, boom, FIXED_NOW, token="tok")
    assert board is not None and board["networks"] == [] and board["unattributed_ips"] == 1


def test_structural_error_returns_none():
    bad = {"indicators": {"ipv4|x": {"type": "ipv4"}}}   # no "value" -> KeyError inside build
    assert asn.build_asn_leaderboard(bad, {}, {}, _ipinfo_fetch({}), FIXED_NOW, token="tok") is None


def test_schema_is_registered():
    assert SCHEMA_FOR["asn_leaderboard.json"] == "asn_leaderboard.schema.json"


def test_built_payload_validates_against_schema():
    orgs = _orgs_for(("185.220.101.34", "AS60729 Zwiebelfreunde e.V.", "DE"),
                     ("162.243.103.246", "AS14061 DigitalOcean, LLC", "US"))
    board = asn.build_asn_leaderboard(
        _community(("185.220.101.34", ["phishing"])), _threat("162.243.103.246"),
        {}, _ipinfo_fetch(orgs), FIXED_NOW, token="tok")
    assert validate_payload("asn_leaderboard.json", board, "schemas") == []


def test_committed_empty_seed_is_valid():
    seed = json.loads(Path("data/state/asn_leaderboard.json").read_text(encoding="utf-8"))
    assert validate_payload("asn_leaderboard.json", seed, "schemas") == []
    assert seed["networks"] == [] and seed["count"] == 0


def test_no_pii_tokens_in_serialized_payload():
    # DEFENSIVE mock: even if a community indicator carried identity fields, the
    # builder never projects them (it reads only type/value/categories).
    community = {"indicators": {"ipv4|1.2.3.4": {
        "type": "ipv4", "value": "1.2.3.4", "reporters": 1, "categories": ["ssh"],
        "github_id": 4242, "evidence": "internal 10.0.0.5 log", "comment": "side note"}}}
    orgs = _orgs_for(("1.2.3.4", "AS64500 Example ISP", "US"))
    board = asn.build_asn_leaderboard(community, {}, {}, _ipinfo_fetch(orgs), FIXED_NOW, token="tok")
    blob = json.dumps(board)
    for forbidden in ("github_id", "evidence", "comment", "4242",
                      "internal 10.0.0.5", "side note"):
        assert forbidden not in blob


def test_injected_extra_field_fails_the_schema_fence():
    orgs = _orgs_for(("1.2.3.4", "AS64500 Example ISP", "US"))
    board = asn.build_asn_leaderboard(
        _community(("1.2.3.4", ["ssh"])), {}, {}, _ipinfo_fetch(orgs), FIXED_NOW, token="tok")
    board["networks"][0]["reporter"] = "octocat"   # stray row-level field
    assert validate_payload("asn_leaderboard.json", board, "schemas") != []
    bad_envelope = dict(board, leaked="x")          # stray envelope-level field
    board["networks"][0].pop("reporter")
    assert validate_payload("asn_leaderboard.json", bad_envelope, "schemas") != []


def test_max_size_network_row_validates():
    # Proves the fence doesn't gate-drop a legitimate fully-active network row:
    # all 10 categories (enum size), both real sources, EXAMPLE_CAP=3 examples.
    row = {
        "asn": "AS64500", "isp": "Example ISP", "country": "US",
        "ip_count": 50, "report_count": 40,
        "categories": ["brute-force", "ssh", "port-scan", "web-app-attack", "phishing",
                        "malware-c2", "scanner", "spam", "exploited-host", "other"],
        "sources": ["abuse.ch", "community"],
        "examples": ["1.1.1.1", "2.2.2.2", "3.3.3.3"],
    }
    envelope = {
        "generated_at": asn.iso(FIXED_NOW), "schema_version": 1,
        "attribution": "x", "count": 1, "total_abusive_ips": 50,
        "unattributed_ips": 0, "cap": 200, "truncated": False,
        "networks": [row],
    }
    assert validate_payload("asn_leaderboard.json", envelope, "schemas") == []
