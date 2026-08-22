import json
from pathlib import Path

from pipeline.validate import SCHEMA_FOR, validate_payload

FIXTURES = Path(__file__).parent / "fixtures" / "community"
SCHEMA = json.loads(Path("schemas/community_reports.schema.json").read_text(encoding="utf-8"))
SEED = json.loads(Path("data/state/community_reports.json").read_text(encoding="utf-8"))
CATEGORIES = json.loads((FIXTURES / "categories.json").read_text(encoding="utf-8"))


def _schema_category_enum():
    return (SCHEMA["properties"]["indicators"]["additionalProperties"]
            ["properties"]["categories"]["items"]["enum"])


def test_schema_is_registered():
    assert SCHEMA_FOR["community_reports.json"] == "community_reports.schema.json"


def test_committed_seed_validates_and_is_empty():
    assert validate_payload("community_reports.json", SEED, "schemas") == []
    assert SEED["indicators"] == {} and SEED["count"] == 0


def test_schema_category_enum_matches_shared_fixture():
    # Drift here silently freezes the WHOLE dataset to last-known-good on the
    # next new-category approval (fail-closed but total). The JS side asserts
    # CATEGORIES (validate.mjs) == this same fixture, so schema == validate.mjs
    # transitively.
    assert _schema_category_enum() == CATEGORIES


def test_extra_indicator_field_fails_the_privacy_fence():
    bad = dict(SEED, indicators={"ipv4|203.0.113.4": {
        "type": "ipv4", "value": "203.0.113.4", "reporters": 1,
        "categories": ["ssh"], "first_reported": "2026-08-10",
        "latest_reported": "2026-08-10", "github_id": 42}})
    assert validate_payload("community_reports.json", bad, "schemas") != []
