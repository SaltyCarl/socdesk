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


def test_feed_digest_with_claims_validates():
    """A grouped digest carrying its collapsed victims (Finding #1 fix) must
    still validate — the feed item schema is additionalProperties:false, so a
    `claims` field emitted without the matching schema addition would fail
    EVERY digest and silently freeze feed.json at last-known-good (the
    cves.json-freeze pattern)."""
    digest = dict(GOOD_FEED["items"][0])
    digest["grouped"] = 6
    digest["claims"] = [
        {"victim": "A Corp", "domain": "acorp.example",
         "date": "2026-07-28T09:00:00Z", "url": "https://x.test/a"},
        {"victim": "B Corp", "date": "2026-07-28T08:00:00Z",
         "url": "https://x.test/b"},
    ]
    payload = {"generated_at": "2026-07-28T12:00:00Z", "schema_version": 1,
               "items": [digest]}
    assert validate_payload("feed.json", payload, "schemas") == []


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


def test_ransomware_intel_seed_dates_are_isoish():
    """Every advisory_date/last_reviewed on the committed seed matches YYYY-MM-DD —
    a shape/rule assertion, never the group list or count."""
    import json
    import re
    from pathlib import Path
    seed = json.loads(Path("data/ransomware_intel.json").read_text(encoding="utf-8"))
    date_re = re.compile(r"^\d{4}-\d{2}-\d{2}$")
    seen = {"advisory_date": 0, "last_reviewed": 0}
    for group in seed["groups"]:
        for field in ("advisory_date", "last_reviewed"):
            if field in group:
                seen[field] += 1
                assert date_re.match(group[field]), f"{group['slug']}.{field}={group[field]!r}"
    # a hardening guard: if these fields ever vanished from the seed the loop
    # above would silently no-op and this test would pass vacuously.
    assert seen["advisory_date"] >= 1
    assert seen["last_reviewed"] >= 1


def test_ransomware_intel_seed_note_images_are_cisa_hosted():
    """Every note_image on the committed seed points at cisa.gov — shape/rule only."""
    import json
    from urllib.parse import urlsplit
    from pathlib import Path
    seed = json.loads(Path("data/ransomware_intel.json").read_text(encoding="utf-8"))
    seen = 0
    for group in seed["groups"]:
        if "note_image" in group:
            seen += 1
            host = urlsplit(group["note_image"]).netloc
            assert host.endswith("cisa.gov"), f"{group['slug']}.note_image host={host!r}"
    # a hardening guard: if note_image ever vanished from the seed the loop
    # above would silently no-op and this test would pass vacuously.
    assert seen >= 1


def test_ransomware_intel_schema_rejects_non_cisa_note_image():
    bad = {"generated_at": "x", "schema_version": 1, "groups": [
        {"slug": "x", "name": "X", "note_image": "https://evil.example/note.png"}]}
    errs = validate_payload("ransomware_intel.json", bad, "schemas")
    assert errs != []


def test_ransomware_intel_note_image_host_is_anchored_not_substring():
    """The note_image pattern must anchor the HOST as www.cisa.gov, not merely
    contain 'cisa.gov' anywhere — a path-injected URL that carries the string in
    its path must be rejected (the pattern is the R3 public-domain-host gate)."""
    bad = {"generated_at": "x", "schema_version": 1, "groups": [
        {"slug": "x", "name": "X",
         "note_image": "https://evil.example/cisa.gov/note.png"}]}
    assert validate_payload("ransomware_intel.json", bad, "schemas") != []


def test_ransomware_intel_schema_accepts_hhs_hc3_advisory_host():
    """R3 gate widened to admit HHS HC3 (17 U.S.C. §105 public domain, same
    footing as CISA) — a well-formed hhs.gov advisory URL must validate."""
    good = {"generated_at": "x", "schema_version": 1, "groups": [
        {"slug": "qilin", "name": "Qilin",
         "advisory": {"id": "202406181500",
                      "url": "https://www.hhs.gov/sites/default/files/qilin-threat-profile-tlpclear.pdf"}}]}
    assert validate_payload("ransomware_intel.json", good, "schemas") == []


def test_ransomware_intel_schema_accepts_hhs_hc3_note_image_host():
    good = {"generated_at": "x", "schema_version": 1, "groups": [
        {"slug": "qilin", "name": "Qilin",
         "note_image": "https://www.hhs.gov/sites/default/files/qilin-figure.png"}]}
    assert validate_payload("ransomware_intel.json", good, "schemas") == []


def test_ransomware_intel_schema_accepts_aspr_hhs_subdomain():
    """HC3 products are also mirrored under aspr.hhs.gov — the gate is
    subdomain-tolerant for both admitted hosts, not just the bare www."""
    good = {"generated_at": "x", "schema_version": 1, "groups": [
        {"slug": "qilin", "name": "Qilin",
         "advisory": {"id": "x", "url": "https://aspr.hhs.gov/HC3/some-product.pdf"}}]}
    assert validate_payload("ransomware_intel.json", good, "schemas") == []


def test_ransomware_intel_schema_rejects_non_gov_advisory_host():
    """The widened gate still must reject an arbitrary non-gov domain — only
    public-domain US-gov hosts (cisa.gov, hhs.gov and their subdomains) are
    admitted."""
    bad = {"generated_at": "x", "schema_version": 1, "groups": [
        {"slug": "x", "name": "X",
         "advisory": {"id": "A", "url": "https://evil.example/x"}}]}
    assert validate_payload("ransomware_intel.json", bad, "schemas") != []


def test_ransomware_intel_schema_rejects_hhs_lookalike_subdomain_injection():
    """A host that merely CONTAINS 'hhs.gov' as a subdomain-injection suffix
    (e.g. attacker-controlled 'hhs.gov.evil.example') must NOT pass — the
    pattern anchors the real registrable host, not a substring."""
    bad = {"generated_at": "x", "schema_version": 1, "groups": [
        {"slug": "x", "name": "X",
         "advisory": {"id": "A", "url": "https://www.hhs.gov.evil.example/x"}}]}
    assert validate_payload("ransomware_intel.json", bad, "schemas") != []


def test_ransomware_intel_schema_rejects_non_gov_note_image_host():
    bad = {"generated_at": "x", "schema_version": 1, "groups": [
        {"slug": "x", "name": "X", "note_image": "https://evil.example/hhs.gov/note.png"}]}
    assert validate_payload("ransomware_intel.json", bad, "schemas") != []


def test_ransomware_intel_schema_accepts_provenance_fields():
    """Schema shape check: advisory_date/last_reviewed/note_image/sources[] are
    accepted when well-formed (independent of what the seed currently contains)."""
    good = {"generated_at": "x", "schema_version": 1, "groups": [
        {"slug": "xx", "name": "X",
         "advisory_date": "2026-08-24", "last_reviewed": "2026-08-24",
         "note_image": "https://www.cisa.gov/sites/default/files/foo.png",
         "sources": [{"id": "ic3-flash", "url": "https://www.ic3.gov/CSA/2026/260824.pdf"}]}]}
    assert validate_payload("ransomware_intel.json", good, "schemas") == []


def test_ransomware_intel_schema_accepts_vendor_entry_with_no_advisory():
    """Vendor-sourced Tier-3 depth (COMPLIANCE-sensitive): a group with NO
    `advisory` at all — the gov-vs-vendor discriminator the render keys off —
    but WITH `sources[]` (vendor URLs are allowed there; only `advisory.url`
    is gov-host-locked) plus atomic facts (aliases/first_seen/raas/
    initial_access_cves/tools) must still validate. `group.required` is only
    [slug, name], so omitting `advisory` entirely is legal shape."""
    good = {"generated_at": "x", "schema_version": 1, "groups": [
        {"slug": "vendor-crew", "name": "Vendor Crew", "aliases": ["VC"],
         "first_seen": "2025-06", "raas": True,
         "initial_access_cves": ["CVE-2025-1234"],
         "tools": ["Rclone", "SmokeLoader"],
         "sources": [
             {"id": "unit42", "url": "https://unit42.paloaltonetworks.com/vendor-crew-report/"},
             {"id": "socradar", "url": "https://socradar.io/blog/vendor-crew/"},
         ],
         "last_reviewed": "2026-08-25"}]}
    errs = validate_payload("ransomware_intel.json", good, "schemas")
    assert errs == [], errs
    assert "advisory" not in good["groups"][0]


def test_ransomware_intel_schema_still_rejects_non_gov_advisory_even_with_sources():
    """The vendor path must never be usable to smuggle a vendor URL into the
    gov-locked `advisory.url` field — sources[] is the ONLY unlocked-host
    field. A group that supplies both a vendor `sources[]` entry AND a
    non-gov `advisory.url` must still be rejected."""
    bad = {"generated_at": "x", "schema_version": 1, "groups": [
        {"slug": "vendor-crew", "name": "Vendor Crew",
         "advisory": {"id": "x", "url": "https://unit42.paloaltonetworks.com/x"},
         "sources": [{"id": "unit42", "url": "https://unit42.paloaltonetworks.com/x"}]}]}
    assert validate_payload("ransomware_intel.json", bad, "schemas") != []


def test_ransomware_intel_seed_vendor_entries_have_no_advisory_or_note_image():
    """Shape/rule guard over the COMMITTED seed (not content-pinning specific
    crews): every group that carries `sources[]` but NO `advisory` — the
    vendor-tier discriminator — must also carry NO `note_image` (vendor
    figures are not public-domain, per the render's gov-vs-vendor split) and
    must carry at least one atomic fact (aliases/first_seen/raas/
    initial_access_cves/tools) rather than an empty stub."""
    import json
    from pathlib import Path
    seed = json.loads(Path("data/ransomware_intel.json").read_text(encoding="utf-8"))
    vendor_groups = [g for g in seed["groups"] if "advisory" not in g and g.get("sources")]
    assert len(vendor_groups) >= 1
    fact_fields = ("aliases", "first_seen", "raas", "initial_access_cves", "tools")
    for g in vendor_groups:
        assert "note_image" not in g, f"{g['slug']} is vendor-sourced but carries note_image"
        assert any(g.get(f) for f in fact_fields), f"{g['slug']} has no atomic facts"
