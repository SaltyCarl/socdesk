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


def test_hostile_export_is_made_inert_and_fenced(fake_fetch):
    fetch = fake_fetch({picket.EXPORT_URL: "picket/export_hostile.json"})
    out = picket.collect(fetch, FIXED_NOW).extra["picket"]
    users = [u["value"] for u in out["top_usernames"]]
    assert "alice@example.com" not in users
    assert all("<" not in u and ">" not in u for u in users)
    assert all(picket.is_public_ip(r["ip"]) for r in out["top_ips"])
    assert all("<" not in i["isp"] and ">" not in i["isp"] for i in out["top_isps"])
    assert all("<" not in c["name"] and ">" not in c["name"] for c in out["top_countries"])
    sensor_hash = out["sensor"]["public_ip_sha256"]
    assert all(hashlib.sha256(r["ip"].encode()).hexdigest() != sensor_hash for r in out["top_ips"])


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
