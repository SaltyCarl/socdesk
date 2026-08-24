import json
from pathlib import Path

from pipeline.validate import SCHEMA_FOR, validate_payload

FIXTURES = Path(__file__).parent / "fixtures" / "community"
SCHEMA = json.loads(Path("schemas/community_reports.schema.json").read_text(encoding="utf-8"))
# The LIVE committed dataset — a living artifact the pipeline rewrites as reports
# are approved, so it is NOT necessarily empty. Used only to assert it stays
# schema-valid. Tests needing a known-clean base use EMPTY_ENVELOPE (a literal).
COMMITTED = json.loads(Path("data/state/community_reports.json").read_text(encoding="utf-8"))
CATEGORIES = json.loads((FIXTURES / "categories.json").read_text(encoding="utf-8"))

EMPTY_ENVELOPE = {
    "generated_at": "2026-08-22T00:00:00Z", "schema_version": 1,
    "attribution": "test", "count": 0, "report_count": 0, "indicators": {},
}


def _schema_category_enum():
    return (SCHEMA["properties"]["indicators"]["additionalProperties"]
            ["properties"]["categories"]["items"]["enum"])


def test_schema_is_registered():
    assert SCHEMA_FOR["community_reports.json"] == "community_reports.schema.json"


def test_committed_dataset_stays_schema_valid():
    # The committed community_reports.json is a living artifact the pipeline
    # rewrites as reports are approved — it may be empty OR populated. The
    # invariant is that it always validates (a corrupt published file would
    # break gate()'s last-known-good) — NOT that it is empty.
    assert validate_payload("community_reports.json", COMMITTED, "schemas") == []


def test_empty_envelope_is_valid():
    assert validate_payload("community_reports.json", EMPTY_ENVELOPE, "schemas") == []
    assert EMPTY_ENVELOPE["indicators"] == {} and EMPTY_ENVELOPE["count"] == 0


def test_schema_category_enum_matches_shared_fixture():
    # Drift here silently freezes the WHOLE dataset to last-known-good on the
    # next new-category approval (fail-closed but total). The JS side asserts
    # CATEGORIES (validate.mjs) == this same fixture, so schema == validate.mjs
    # transitively.
    assert _schema_category_enum() == CATEGORIES


def test_extra_indicator_field_fails_the_privacy_fence():
    bad = dict(EMPTY_ENVELOPE, indicators={"ipv4|203.0.113.4": {
        "type": "ipv4", "value": "203.0.113.4", "reporters": 1,
        "categories": ["ssh"], "first_reported": "2026-08-10",
        "latest_reported": "2026-08-10", "github_id": 42}})
    assert validate_payload("community_reports.json", bad, "schemas") != []


from collectors.base import iso
from tests.conftest import FIXED_NOW
from pipeline.community import build_community_reports, community_key

ENV = {"CLOUDFLARE_ACCOUNT_ID": "acct", "CLOUDFLARE_D1_DATABASE_ID": "db",
       "CF_D1_READ_TOKEN": "tok"}


def _d1(rows):
    """A fetch stub returning a D1 REST query response wrapping `rows`. Asserts
    the builder POSTs to the D1 query endpoint (no accidental GET/other host)."""
    def fetch(url, *, method="GET", json=None, headers=None, text=False):
        assert method == "POST" and "d1/database" in url and url.endswith("/query")
        assert headers and headers.get("Authorization") == "Bearer tok"
        return {"result": [{"results": rows, "success": True}], "success": True}
    return fetch


def test_aggregates_one_entry_per_indicator():
    rows = [
        {"ioc_type": "ipv4", "ioc_value": "203.0.113.4", "reporters": 2,
         "n_reports": 3, "categories": "ssh,brute-force,ssh",
         "first_at": "2026-08-10T09:00:00Z", "latest_at": "2026-08-20T22:00:00Z"},
        {"ioc_type": "domain", "ioc_value": "evil.example", "reporters": 1,
         "n_reports": 1, "categories": "phishing",
         "first_at": "2026-08-18T00:00:00Z", "latest_at": "2026-08-19T00:00:00Z"},
    ]
    body = build_community_reports(_d1(rows), FIXED_NOW, ENV)
    assert body["count"] == 2 and body["report_count"] == 4
    ip = body["indicators"]["ipv4|203.0.113.4"]
    assert ip["reporters"] == 2
    assert ip["categories"] == ["brute-force", "ssh"]      # deduped + sorted
    assert ip["first_reported"] == "2026-08-10"            # sliced YYYY-MM-DD
    assert ip["latest_reported"] == "2026-08-20"
    assert body["generated_at"] == iso(FIXED_NOW)
    assert body["schema_version"] == 1 and "SOCDesk" in body["attribution"]


def test_distinct_contributor_count_is_not_inflated():
    # Same github_id re-reporting after approval: n_reports=2 but the query's
    # COUNT(DISTINCT github_id)=1. The builder takes `reporters` directly and
    # never uses n_reports per-indicator (owner ruling spec 10.1).
    rows = [{"ioc_type": "ipv4", "ioc_value": "198.51.100.7", "reporters": 1,
             "n_reports": 2, "categories": "scanner",
             "first_at": "2026-08-01T00:00:00Z", "latest_at": "2026-08-02T00:00:00Z"}]
    body = build_community_reports(_d1(rows), FIXED_NOW, ENV)
    assert body["indicators"]["ipv4|198.51.100.7"]["reporters"] == 1
    assert body["report_count"] == 2                       # raw volume, envelope only


def test_hash_key_is_lowercased():
    rows = [{"ioc_type": "sha256",
             "ioc_value": "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
             "reporters": 1, "n_reports": 1, "categories": "malware-c2",
             "first_at": "2026-08-01T00:00:00Z", "latest_at": "2026-08-01T00:00:00Z"}]
    body = build_community_reports(_d1(rows), FIXED_NOW, ENV)
    (key,) = body["indicators"].keys()
    assert key == "sha256|e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_key_parity_fixture_matches_js_mirror():
    parity = json.loads((FIXTURES / "key_parity.json").read_text(encoding="utf-8"))
    for row in parity:
        assert community_key(row["type"], row["value"]) == row["key"]


def test_privacy_fence_drops_forbidden_fields():
    # A DEFENSIVE mock: even if a D1 row carried these, the builder's whitelist
    # projection must not let them survive into the payload.
    rows = [{"ioc_type": "ipv4", "ioc_value": "203.0.113.9", "reporters": 1,
             "n_reports": 1, "categories": "ssh",
             "first_at": "2026-08-10T00:00:00Z", "latest_at": "2026-08-10T00:00:00Z",
             "id": "8f3c-report-uuid", "github_id": 4242,
             "evidence": "internal 10.0.0.5 log excerpt",
             "comment": "reporter side note", "login": "octocat"}]
    body = build_community_reports(_d1(rows), FIXED_NOW, ENV)
    entry = body["indicators"]["ipv4|203.0.113.9"]
    assert set(entry) == {"type", "value", "reporters", "categories",
                          "first_reported", "latest_reported"}
    blob = json.dumps(body)
    for forbidden in ("github_id", "evidence", "comment", "login",
                      "8f3c-report-uuid", "internal 10.0.0.5",
                      "reporter side note", "octocat"):
        assert forbidden not in blob


def test_missing_config_returns_none():
    assert build_community_reports(_d1([]), FIXED_NOW, {}) is None


def test_d1_network_failure_returns_none_not_crash():
    def boom(url, **kw):
        raise RuntimeError("D1 500")
    assert build_community_reports(boom, FIXED_NOW, ENV) is None


def test_bad_response_shape_returns_none():
    def bad(url, **kw):
        return {"success": False, "errors": [{"message": "nope"}]}
    assert build_community_reports(bad, FIXED_NOW, ENV) is None


def test_empty_but_successful_query_publishes_empty_map():
    body = build_community_reports(_d1([]), FIXED_NOW, ENV)
    assert body is not None and body["indicators"] == {} and body["count"] == 0


def test_built_payload_validates_against_schema():
    rows = [{"ioc_type": "ipv4", "ioc_value": "203.0.113.4", "reporters": 2,
             "n_reports": 3, "categories": "ssh,brute-force",
             "first_at": "2026-08-10T00:00:00Z", "latest_at": "2026-08-20T00:00:00Z"}]
    body = build_community_reports(_d1(rows), FIXED_NOW, ENV)
    assert validate_payload("community_reports.json", body, "schemas") == []
