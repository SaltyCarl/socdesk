import json
from datetime import timedelta
from pathlib import Path

from collectors.base import CollectorResult
from pipeline import picket as pk
from pipeline.validate import validate_payload
from tests.conftest import FIXED_NOW

FIX = Path(__file__).parent / "fixtures" / "picket"


def _ok():
    doc = json.loads((FIX / "export_ok.json").read_text(encoding="utf-8"))
    return {"picket": CollectorResult(source="picket", extra={"picket": doc})}


def test_status_thresholds():
    assert pk.sensor_status("2026-07-28T11:35:00Z", FIXED_NOW) == ("live", 25)
    assert pk.sensor_status("2026-07-28T10:00:00Z", FIXED_NOW) == ("stale", 120)
    assert pk.sensor_status("2026-07-26T12:00:00Z", FIXED_NOW) == ("silent", 2880)
    assert pk.sensor_status("garbage", FIXED_NOW) == ("silent", 0)


def test_build_publishes_valid_payloads():
    out = pk.build_picket(_ok(), {}, FIXED_NOW)
    assert set(out) == {"picket.json", "picket_ips.json"}
    for name, payload in out.items():
        assert validate_payload(name, payload, "schemas") == [], name
    p = out["picket.json"]
    assert p["sensor"]["status"] == "live" and p["sensor"]["export_age_minutes"] == 25
    assert p["sensor"]["uptime_days"] == 3
    assert len(p["histogram_7d"]) == 168 and sum(p["histogram_7d"]) == 42
    assert p["totals"]["knocks_7d"] == 42 and p["totals"]["knocks_24h"] == 42
    assert p["by_protocol"][0]["share_pct"] == 90.0
    assert "MaxMind" in p["attribution"] and "knock-knock" in p["attribution"]
    assert p["collected_at"] == "2026-07-28T12:00:00Z"


def test_ips_layer_only_has_finite_coords_and_source_picket():
    ips = pk.build_picket(_ok(), {}, FIXED_NOW)["picket_ips.json"]["ips"]
    assert ips and all(r["source"] == "picket" for r in ips)
    assert all(isinstance(r["lat"], float) and isinstance(r["lng"], float) for r in ips)


def test_collector_down_restamps_prior_and_degrades_status():
    prior = pk.build_picket(_ok(), {}, FIXED_NOW)
    later = FIXED_NOW + timedelta(hours=30)
    out = pk.build_picket({}, prior, later)             # no ok result
    assert out["picket.json"]["sensor"]["status"] == "silent"
    assert out["picket.json"]["generated_at"] == "2026-07-29T18:00:00Z"
    assert out["picket.json"]["collected_at"] == "2026-07-28T12:00:00Z"   # a REAL collection stamp survives
    assert validate_payload("picket.json", out["picket.json"], "schemas") == []


def test_collector_down_with_no_prior_is_none():
    assert pk.build_picket({}, {}, FIXED_NOW) is None
