from pipeline.intel_staleness import check_intel_staleness

REF = "2026-08-24"


def _group(slug, last_reviewed, cves=None):
    return {"slug": slug, "name": slug, "last_reviewed": last_reviewed,
            "initial_access_cves": cves or []}


def test_stale_entry_warns():
    groups = [_group("akira", "2025-01-01")]  # well over a year before REF
    warnings = check_intel_staleness(groups, set(), REF)
    assert any("akira" in w and "STALE" in w for w in warnings)


def test_fresh_entry_does_not_warn():
    groups = [_group("akira", "2026-08-01")]  # 23 days before REF
    warnings = check_intel_staleness(groups, set(), REF)
    assert warnings == []


def test_exactly_at_threshold_does_not_warn():
    """180 days before the reference date is the boundary — only STRICTLY
    more than max_age_days counts as stale."""
    groups = [_group("akira", "2026-02-25")]  # exactly 180 days before REF
    warnings = check_intel_staleness(groups, set(), REF, max_age_days=180)
    assert warnings == []


def test_one_day_past_threshold_warns():
    groups = [_group("akira", "2026-02-24")]  # 181 days before REF
    warnings = check_intel_staleness(groups, set(), REF, max_age_days=180)
    assert any("STALE" in w for w in warnings)


def test_kev_drift_fires_for_unseeded_ransomware_cve():
    """KEV flags a CVE ransomware-associated that no seed group carries in
    initial_access_cves anywhere — the hand curation hasn't caught up."""
    groups = [_group("akira", REF, cves=["CVE-2020-3259"])]
    kev = {"CVE-2026-9999"}
    warnings = check_intel_staleness(groups, kev, REF)
    assert any("CVE-2026-9999" in w and "DRIFT" in w for w in warnings)


def test_kev_drift_does_not_fire_when_seed_already_has_the_cve():
    groups = [_group("akira", REF, cves=["CVE-2026-9999"])]
    kev = {"CVE-2026-9999"}
    warnings = check_intel_staleness(groups, kev, REF)
    assert warnings == []


def test_kev_drift_checks_across_all_groups_not_just_one():
    """A CVE only needs to appear in ONE group's initial_access_cves
    anywhere in the seed to count as covered — KEV's kev_ransomware flag
    says a CVE is ransomware-linked in general, not which actor uses it,
    so the check can't require a specific group to carry it."""
    groups = [
        _group("akira", REF, cves=["CVE-2020-3259"]),
        _group("clop", REF, cves=["CVE-2026-9999"]),
    ]
    kev = {"CVE-2026-9999"}
    warnings = check_intel_staleness(groups, kev, REF)
    assert warnings == []


def test_empty_inputs_produce_no_warnings():
    assert check_intel_staleness([], set(), REF) == []


def test_never_raises_on_malformed_last_reviewed():
    """Soft-warn philosophy: a bad date on one entry must not blow up the
    whole check for every other entry."""
    groups = [_group("bad", "not-a-date")]
    warnings = check_intel_staleness(groups, set(), REF)
    assert warnings == []


def test_never_raises_on_malformed_reference_date():
    """The guard must not itself become the hard failure it exists to prevent:
    a misconfigured CI-supplied reference_date returns a soft GUARD warning,
    never an uncaught raise."""
    for bad_ref in ("not-a-date", "", None):
        warnings = check_intel_staleness([_group("akira", REF)], set(), bad_ref)
        assert len(warnings) == 1 and warnings[0].startswith("GUARD:")


def test_runs_on_the_actual_committed_seed_shape():
    """The guard was imported nowhere in prod/CI (Finding #2) — it could never
    surface real drift. This proves it runs on the REAL seed shape without
    raising. Type/no-raise only — asserting specific warning CONTENT of the
    live seed would be brittle (the seed changes over time)."""
    import json
    from pathlib import Path
    seed = json.loads(Path("data/ransomware_intel.json").read_text(encoding="utf-8"))
    kev_rs = {"CVE-2026-9999"}
    warnings = check_intel_staleness(seed["groups"], kev_rs, REF)
    assert isinstance(warnings, list)
