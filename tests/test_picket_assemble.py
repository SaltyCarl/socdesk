import json
from datetime import datetime, timezone
from pathlib import Path

from tools.picket.assemble import assemble_export, validate_export
from tests.conftest import FIXED_NOW

FIX = Path(__file__).parent / "fixtures" / "picket"
SCHEMA = Path("schemas/picket_export.schema.json")
PROTO = {1: "SSH", 2: "TELNET"}
SENSOR = {"id": "picket-1", "public_ip_sha256": "a" * 64, "protocols": ["SSH", "TELNET"],
          "knockknock_version": "1.9.0", "country": "DE"}


def rollups(**over):
    base = {
        "ip_intel": [
            {"ip": "5.6.7.8", "hits": 900, "first_seen": "2026-07-20 01:00:00",
             "last_seen": "2026-07-28 11:00:00", "lat": 39.9, "lng": 116.4, "asn": 64500},
            {"ip": "10.0.0.7", "hits": 50, "first_seen": None, "last_seen": None, "lat": None, "lng": None, "asn": None},
        ],
        "ip_intel_proto": [{"ip": "5.6.7.8", "proto": 1, "hits": 900}],
        "user_intel": [{"username": "root", "hits": 400}, {"username": "alice@example.com", "hits": 9}],
        "pass_intel": [{"password": "123456", "hits": 200}, {"password": "once", "hits": 1}],
        "country_intel": [{"iso_code": "CN", "country": "China", "hits": 500}],
        "isp_intel": [{"isp": "Example <b>Hosting</b>", "hits": 300, "asn": 64500}],
        "heartbeat_minutes": 4320, "knocks_total": 9001,
        "country_by_ip": {"5.6.7.8": "CN"},
    }
    base.update(over)
    return base


def hits7d():
    return {"proto": {"SSH": 900}, "ip": {"5.6.7.8": 900, "10.0.0.7": 50},
            "user": {"root": 400, "alice@example.com": 9},
            "pass": {"123456": 200, "once": 1}, "country": {"CN": 500}, "isp": {"Example <b>Hosting</b>": 300}}


def test_fixture_validates():
    doc = json.loads((FIX / "export_ok.json").read_text(encoding="utf-8"))
    assert validate_export(doc, SCHEMA) == []


def test_assembled_export_validates_and_is_fenced():
    out = assemble_export(rollups(), hits7d(), [0] * 335 + [42], SENSOR, FIXED_NOW, PROTO)
    assert validate_export(out, SCHEMA) == []
    ips = [r["ip"] for r in out["top_ips"]]
    assert ips == ["5.6.7.8"]                           # private IP dropped
    assert out["top_ips"][0]["country"] == "CN"
    assert out["top_ips"][0]["protocols"] == [{"proto": "SSH", "hits_7d": 900}]
    assert out["top_ips"][0]["first_seen"] == "2026-07-20T01:00:00Z"
    assert [u["value"] for u in out["top_usernames"]] == ["root"]   # email fenced
    assert [p["value"] for p in out["top_passwords"]] == ["123456"] # singleton fenced (<3)
    assert out["top_isps"][0]["isp"] == "Example Hosting"          # markup stripped
    assert out["totals"] == {"knocks_total": 9001, "since": "2026-07-25T12:00:00Z"}
    assert out["exported_at"] == "2026-07-28T12:00:00Z"
    assert out["sensor"]["uptime_minutes"] == 4320
    assert "ring_reset_at" not in out["sensor"]


def test_reset_marker_is_carried():
    sensor = dict(SENSOR, ring_reset_at="2026-07-28T11:30:00Z")
    out = assemble_export(rollups(), hits7d(), [0] * 336, sensor, FIXED_NOW, PROTO)
    assert out["sensor"]["ring_reset_at"] == "2026-07-28T11:30:00Z"


def test_unknown_protocol_id_fails_loudly():
    bad = rollups(ip_intel_proto=[{"ip": "5.6.7.8", "proto": 99, "hits": 1}])
    try:
        assemble_export(bad, hits7d(), [0] * 336, SENSOR, FIXED_NOW, PROTO)
    except KeyError as e:
        assert "99" in str(e)
    else:
        raise AssertionError("unknown protocol id must not be guessed")


def test_first_seen_is_omitted_when_the_rollup_has_none():
    ip_intel = rollups()["ip_intel"] + [
        {"ip": "5.6.7.9", "hits": 50, "first_seen": None, "last_seen": "2026-07-28 11:00:00",
         "lat": None, "lng": None, "asn": None},
    ]
    out = assemble_export(rollups(ip_intel=ip_intel), hits7d(), [0] * 336, SENSOR, FIXED_NOW, PROTO)
    row = next(r for r in out["top_ips"] if r["ip"] == "5.6.7.9")
    assert "first_seen" not in row
    assert row["last_seen"] == "2026-07-28T11:00:00Z"
    assert validate_export(out, SCHEMA) == []


def test_caps_are_enforced():
    many = [{"ip": f"203.0.{i // 250}.{i % 250 + 1}", "hits": 5, "first_seen": None, "last_seen": None,
             "lat": None, "lng": None, "asn": None} for i in range(2500)]
    h = hits7d(); h["ip"] = {r["ip"]: 5 for r in many}
    out = assemble_export(rollups(ip_intel=many, ip_intel_proto=[]), h, [0] * 336, SENSOR, FIXED_NOW, PROTO)
    assert len(out["top_ips"]) == 2000 and validate_export(out, SCHEMA) == []
