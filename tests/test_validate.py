from pipeline.validate import validate_payload, gate

GOOD_FEED = {
    "generated_at": "2026-07-28T12:00:00Z", "schema_version": 1,
    "items": [{
        "id": "a" * 40, "source": "rss", "category": "report",
        "title": "t", "summary": "s", "url": "https://x.test/a",
        "severity": "info",
        "entities": {"actors": [], "malware": [], "vendors": [], "cves": []},
        "iocs": [], "published_at": "2026-07-28T10:00:00Z",
        "collected_at": "2026-07-28T12:00:00Z",
    }],
}
BAD_FEED = {"generated_at": "2026-07-28T12:00:00Z", "schema_version": 1,
            "items": [{"id": "x"}]}


def test_valid_payload_passes():
    assert validate_payload("feed.json", GOOD_FEED, "schemas") == []


def test_invalid_payload_reports_errors():
    assert validate_payload("feed.json", BAD_FEED, "schemas") != []


def test_gate_falls_back_to_prior_on_invalid():
    published, problems = gate(
        {"feed.json": BAD_FEED}, {"feed.json": GOOD_FEED}, "schemas")
    assert published["feed.json"] == GOOD_FEED
    assert problems and "feed.json" in problems[0]


def test_gate_rejects_oversized_payload():
    """Adversarial or runaway upstream data must not blow up the build."""
    from pipeline import validate
    huge = {"generated_at": "2026-07-28T12:00:00Z", "schema_version": 1,
            "items": [dict(GOOD_FEED["items"][0])]}
    original = validate.MAX_PAYLOAD_BYTES
    validate.MAX_PAYLOAD_BYTES = 50          # force the cap
    try:
        published, problems = validate.gate({"feed.json": huge},
                                            {"feed.json": GOOD_FEED}, "schemas")
    finally:
        validate.MAX_PAYLOAD_BYTES = original
    assert published["feed.json"] == GOOD_FEED       # kept last-known-good
    assert any("cap" in p for p in problems)


def test_cves_gets_a_higher_cap_than_the_default():
    """cves.json is legitimately large (180-day window + every KEV entry); it
    must clear the default backstop that would (and did) freeze the catalog at
    last-known-good, while small payloads keep the tight default guard."""
    from pipeline import validate
    assert validate.cap_for("cves.json") > validate.MAX_PAYLOAD_BYTES
    assert validate.cap_for("feed.json") == validate.MAX_PAYLOAD_BYTES


def test_schema_bounds_reject_unbounded_strings():
    over = {"generated_at": "2026-07-28T12:00:00Z", "schema_version": 1,
            "items": [dict(GOOD_FEED["items"][0], title="x" * 5000)]}
    assert validate_payload("feed.json", over, "schemas") != []


def test_gate_skips_invalid_with_no_prior():
    published, problems = gate({"feed.json": BAD_FEED}, {}, "schemas")
    assert "feed.json" not in published
    assert problems


def test_ransomware_intel_seed_validates():
    """The committed seed validates against its schema (shape/rules, not content)."""
    import json
    from pathlib import Path
    seed = json.loads(Path("data/ransomware_intel.json").read_text(encoding="utf-8"))
    payload = dict(seed, generated_at="2026-08-24T00:00:00Z")
    assert validate_payload("ransomware_intel.json", payload, "schemas") == []


def test_ransomware_intel_rejects_bad_cve_and_nonhost_advisory():
    bad = {"generated_at": "x", "schema_version": 1, "groups": [
        {"slug": "x", "name": "X", "initial_access_cves": ["not-a-cve"],
         "advisory": {"id": "A", "url": "https://evil.example/x"}}]}
    errs = validate_payload("ransomware_intel.json", bad, "schemas")
    assert errs != []
