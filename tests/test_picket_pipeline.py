import json
from datetime import timedelta
from pathlib import Path

from jsonschema import Draft202012Validator

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
    assert p["top_ips"][0]["protocols"] == [{"proto": "SSH", "hits_total": 900}]   # R29 rename carried through


def test_unique_ips_7d_prefers_the_export_value_and_falls_back():
    # I2: the box counts distinct active IPs from the ring (beyond the 2,000-row cap);
    # an older export without the key falls back to counting active top_ips rows.
    doc = json.loads((FIX / "export_ok.json").read_text(encoding="utf-8"))
    doc["totals"]["unique_ips_7d"] = 2500
    ok = {"picket": CollectorResult(source="picket", extra={"picket": doc})}
    assert pk.build_picket(ok, {}, FIXED_NOW)["picket.json"]["totals"]["unique_ips_7d"] == 2500
    doc["totals"]["unique_ips_7d"] = 0                  # present and legitimately zero is honoured
    assert pk.build_picket(ok, {}, FIXED_NOW)["picket.json"]["totals"]["unique_ips_7d"] == 0
    del doc["totals"]["unique_ips_7d"]
    assert pk.build_picket(ok, {}, FIXED_NOW)["picket.json"]["totals"]["unique_ips_7d"] == 3


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


def test_ips_layer_omits_first_seen_when_absent():
    doc = json.loads((FIX / "export_ok.json").read_text(encoding="utf-8"))
    for row in doc["top_ips"]:
        if row["ip"] == "5.6.7.8":
            del row["first_seen"]
    ok = {"picket": CollectorResult(source="picket", extra={"picket": doc})}
    out = pk.build_picket(ok, {}, FIXED_NOW)
    ips_row = next(r for r in out["picket_ips.json"]["ips"] if r["ip"] == "5.6.7.8")
    assert "first_seen" not in ips_row
    assert out["picket_ips.json"]["count"] == 1
    for name, schema in (("picket.json", "schemas/picket.schema.json"),
                          ("picket_ips.json", "schemas/picket_ips.schema.json")):
        schema_doc = json.loads(Path(schema).read_text(encoding="utf-8"))
        errors = list(Draft202012Validator(schema_doc).iter_errors(out[name]))
        assert errors == []
