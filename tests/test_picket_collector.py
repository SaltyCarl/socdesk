import hashlib
import json
from pathlib import Path

import pytest

from collectors import picket
from collectors.base import CollectorResult
from tests.conftest import FIXED_NOW

FIX = Path(__file__).parent / "fixtures" / "picket"


def test_collect_returns_normalized_extra(fake_fetch):
    fetch = fake_fetch({picket.EXPORT_URL: "picket/export_ok.json"})
    r = picket.collect(fetch, FIXED_NOW)
    assert isinstance(r, CollectorResult) and r.ok and r.source == "picket"
    assert r.extra["picket"]["sensor"]["id"] == "picket-1"
    assert r.extra["picket"]["exported_at"] == "2026-07-28T11:35:00Z"


def _inert(s):
    return "<" not in s and ">" not in s


def test_hostile_export_is_made_inert_and_fenced(fake_fetch):
    fetch = fake_fetch({picket.EXPORT_URL: "picket/export_hostile.json"})
    out = picket.collect(fetch, FIXED_NOW).extra["picket"]
    users = [u["value"] for u in out["top_usernames"]]
    assert "alice@example.com" not in users
    assert all(_inert(u) for u in users)
    assert all(picket.is_public_ip(r["ip"]) for r in out["top_ips"])
    assert all(_inert(i["isp"]) for i in out["top_isps"])
    assert all(_inert(c["name"]) for c in out["top_countries"])
    sensor_hash = out["sensor"]["public_ip_sha256"]
    assert all(hashlib.sha256(r["ip"].encode()).hexdigest() != sensor_hash for r in out["top_ips"])

    # M8: an over-eager fence that dropped everything would pass the negatives above.
    assert "1.2.3.4" in [r["ip"] for r in out["top_ips"]]
    assert "root" in users
    assert "Example Hosting" in [i["isp"] for i in out["top_isps"]]
    assert "China" in [c["name"] for c in out["top_countries"]]

    # I1: EVERY string the export schema allows is re-sanitised here, not only the
    # five normalize() used to touch — JSX escaping is the render-side half, this is
    # the collection-side half, and the repo rule is to keep both.
    assert out["sensor"]["protocols"] == ["SSH", "TELNET"]
    assert out["sensor"]["knockknock_version"] == "1.9.0alert(1)"
    assert out["sensor"]["country"] == "D"
    assert out["totals"]["since"] == "2026-07-25T11:35Z"
    assert [p["proto"] for p in out["by_protocol"]] == ["SSH", "TELNET"]
    first = next(r for r in out["top_ips"] if r["ip"] == "5.6.7.8")
    assert first["protocols"][0]["proto"] == "SSH"
    assert first["country"] == "C" and first["last_seen"] == "2026-07-28T11:00Z"
    assert [c["iso"] for c in out["top_countries"]][0] == "C"
    assert all(_inert(r.get("country", "")) and _inert(r["last_seen"]) and _inert(r.get("first_seen", ""))
               and all(_inert(p["proto"]) for p in r["protocols"]) for r in out["top_ips"])


def test_overlong_credential_is_refused_not_trimmed():
    # Schema maxLength 32 on credlist.value: a 33-char value REFUSES the document
    # (the fence would have trimmed to None; the raw-schema gate fires first).
    doc = json.loads((FIX / "export_hostile.json").read_text(encoding="utf-8"))
    doc["top_usernames"].append({"value": "a" * 33, "hits_7d": 5, "hits_total": 5})
    with pytest.raises(ValueError, match="schema"):
        picket.normalize(doc)


def test_credential_floor_is_enforced_again_in_pipeline():
    doc = json.loads((FIX / "export_ok.json").read_text(encoding="utf-8"))
    doc["top_passwords"].append({"value": "hunter2", "hits_7d": 3, "hits_total": 3})
    out = picket.normalize(doc)
    assert {"value": "hunter2", "hits_7d": 3, "hits_total": 3} in out["top_passwords"]
    doc["top_passwords"][-1]["hits_7d"] = 2         # simulate a box that skipped the fence
    with pytest.raises(ValueError):                 # raw schema minimum:3 -> refused, not silently kept
        picket.normalize(doc)


def test_oversize_body_is_a_failed_collection(fake_fetch):
    big = "{" + '"x":"' + "a" * (picket.MAX_BYTES + 10) + '"}'
    fetch = fake_fetch({picket.EXPORT_URL: big})
    with pytest.raises(ValueError, match="exceeds"):
        picket.collect(fetch, FIXED_NOW)            # run_all turns this into ok:false


def test_network_error_propagates_for_run_all(fake_fetch):
    fetch = fake_fetch({})                          # unexpected URL -> RuntimeError
    with pytest.raises(RuntimeError):
        picket.collect(fetch, FIXED_NOW)
