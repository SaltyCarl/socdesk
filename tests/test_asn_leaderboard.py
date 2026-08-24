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
