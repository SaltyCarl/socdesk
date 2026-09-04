import sys
from pathlib import Path

from pipeline.validate import validate_payload
from pipeline.hunt import load_playbooks

# ---- Task 1: schema + SCHEMA_FOR ----

VALID = {
    "generated_at": "2026-09-04T00:00:00Z", "schema_version": 1,
    "playbooks": [{
        "id": "unfamiliar-signin-properties", "title": "Unfamiliar sign-in properties",
        "alert_sources": ["Entra ID Protection"], "ioc_types": ["ipv4", "ipv6"],
        "techniques": ["T1078.004"], "tested": "2026-09-04",
        "source": {"kind": "socdesk", "url": "https://x/y.yaml", "license": "MIT", "author": "SOCDesk"},
        "steps": [{
            "id": "signins-from-ip", "title": "Every sign-in from this IP",
            "kind": "pivot", "param": "ip", "dialect": "log_analytics",
            "tables": ["SigninLogs"], "kql": 'SigninLogs | where IPAddress == "{{ip}}"'}]}]}


def test_valid_playbook_payload_passes():
    assert validate_payload("playbooks.json", VALID, "schemas") == []


def test_empty_playbooks_list_is_valid():
    # fresh-publish honesty: an emptied playbooks/ dir → playbooks:[] must validate
    assert validate_payload("playbooks.json", dict(VALID, playbooks=[]), "schemas") == []


def test_step_rejects_unknown_property():
    bad = {**VALID, "playbooks": [{**VALID["playbooks"][0],
        "steps": [{**VALID["playbooks"][0]["steps"][0], "surprise": 1}]}]}
    assert validate_payload("playbooks.json", bad, "schemas") != []


def test_step_rejects_non_log_analytics_dialect():
    bad = {**VALID, "playbooks": [{**VALID["playbooks"][0],
        "steps": [{**VALID["playbooks"][0]["steps"][0], "dialect": "advanced_hunting"}]}]}
    assert validate_payload("playbooks.json", bad, "schemas") != []


# ---- Task 2: load_playbooks ----

GOOD = """\
id: unfamiliar-signin-properties
title: Unfamiliar sign-in properties
alert_sources: [Entra ID Protection]
ioc_types: [ipv4, ipv6]
techniques: [T1078.004]
tested: "2026-09-04"
rationale: human-only note, must be stripped
steps:
  - id: signins-from-ip
    title: Every sign-in from this IP
    kind: pivot
    param: ip
    dialect: log_analytics
    tables: [SigninLogs]
    kql: |
      SigninLogs
      | where IPAddress == "{{ip}}"
"""


def test_load_playbooks_composes_schema_valid_shape(tmp_path):
    (tmp_path / "unfamiliar.yaml").write_text(GOOD, encoding="utf-8")
    (tmp_path / "broken.yaml").write_text("id: x\ntitle: no steps\n", encoding="utf-8")
    playbooks, warnings = load_playbooks(tmp_path)
    assert len(playbooks) == 1 and len(warnings) == 1
    pb = playbooks[0]
    assert pb["source"] == {
        "kind": "socdesk",
        "url": "https://github.com/SaltyCarl/socdesk/blob/main/data/hunt/playbooks/unfamiliar.yaml",
        "license": "MIT", "author": "SOCDesk"}
    assert "rationale" not in pb
    assert pb["steps"][0]["kind"] == "pivot" and pb["steps"][0]["param"] == "ip"
    payload = {"generated_at": "x", "schema_version": 1, "playbooks": playbooks}
    assert validate_payload("playbooks.json", payload, "schemas") == []


def test_load_playbooks_missing_dir_is_empty():
    assert load_playbooks("no/such/dir") == ([], [])


# ---- Task 4: CI sample substitution ----

def test_substitute_samples_fills_every_placeholder():
    sys.path.insert(0, "tools")
    from validate_hunt_kql import substitute_samples
    out = substitute_samples('SigninLogs | where IPAddress == "{{ip}}" or UserPrincipalName == "{{upn}}"')
    assert "{{" not in out
    assert "203.0.113.7" in out and "user@example.com" in out


# ---- Task 5: the committed exemplar playbooks ----

def test_committed_playbooks_load_and_validate():
    playbooks, warnings = load_playbooks("data/hunt/playbooks")
    assert warnings == []            # every committed file is well-formed
    assert len(playbooks) >= 2
    ids = {p["id"] for p in playbooks}
    assert "unfamiliar-signin-properties" in ids and "password-spray" in ids
    payload = {"generated_at": "x", "schema_version": 1, "playbooks": playbooks}
    assert validate_payload("playbooks.json", payload, "schemas") == []
    for p in playbooks:              # step 1 always opens the ladder with the IP pivot
        assert p["steps"][0]["kind"] == "pivot" and p["steps"][0]["param"] == "ip"
