import hashlib
import json
import sqlite3
import sys
from types import SimpleNamespace

from tools.picket import exporter
from tools.picket.exporter import (
    _country_by_ip,
    _public_ip,
    knockknock_version,
    load_enabled_protocols,
    load_proto_names,
    read_rollups,
    snapshot_from_rollups,
)

DDL = """
CREATE TABLE user_intel (username TEXT PRIMARY KEY, hits INTEGER, last_seen DATETIME);
CREATE TABLE pass_intel (password TEXT PRIMARY KEY, hits INTEGER, last_seen DATETIME);
CREATE TABLE country_intel (iso_code TEXT PRIMARY KEY, country TEXT, hits INTEGER, last_seen DATETIME);
CREATE TABLE isp_intel (isp TEXT PRIMARY KEY, hits INTEGER, last_seen DATETIME, asn INTEGER);
CREATE TABLE ip_intel (ip TEXT PRIMARY KEY, hits INTEGER, last_seen DATETIME, lat REAL, lng REAL,
  hits_since_cleared INTEGER NOT NULL DEFAULT 0, ban_until INTEGER, ban_count INTEGER NOT NULL DEFAULT 0);
CREATE TABLE ip_intel_proto (ip TEXT, proto INTEGER, hits INTEGER, last_seen DATETIME, lat REAL, lng REAL, PRIMARY KEY (ip, proto));
CREATE TABLE monitor_heartbeats (id INTEGER PRIMARY KEY, uptime_minutes INTEGER NOT NULL DEFAULT 0);
"""


def _db(path=":memory:"):
    c = sqlite3.connect(str(path))
    c.executescript(DDL)
    c.execute("INSERT INTO ip_intel (ip,hits,last_seen,lat,lng) VALUES ('203.0.113.5',900,'2026-07-28 11:00:00',39.9,116.4)")
    c.execute("INSERT INTO ip_intel_proto (ip,proto,hits) VALUES ('203.0.113.5',1,900)")
    c.execute("INSERT INTO user_intel VALUES ('root',400,'2026-07-28 11:00:00')")
    c.execute("INSERT INTO pass_intel VALUES ('123456',200,'2026-07-28 11:00:00')")
    c.execute("INSERT INTO country_intel VALUES ('CN','China',500,'2026-07-28 11:00:00')")
    c.execute("INSERT INTO isp_intel VALUES ('Example Hosting',300,'2026-07-28 11:00:00',64500)")
    c.execute("INSERT INTO monitor_heartbeats (id, uptime_minutes) VALUES (1, 4320)")
    c.commit()
    return c


def test_read_rollups_shapes_rows_as_dicts():
    r = read_rollups(_db())
    assert r["ip_intel"][0]["ip"] == "203.0.113.5"
    assert r["ip_intel"][0]["hits"] == 900 and "asn" not in r["ip_intel"][0] and "first_seen" not in r["ip_intel"][0]
    assert r["ip_intel_proto"] == [{"ip": "203.0.113.5", "proto": 1, "hits": 900}]
    assert r["user_intel"] == [{"username": "root", "hits": 400}]
    assert r["heartbeat_minutes"] == 4320
    assert r["knocks_total"] == 900          # SUM(ip_intel_proto.hits)


def test_snapshot_from_rollups_keys_by_protocol_name():
    snap = snapshot_from_rollups(read_rollups(_db()), {1: "SSH"})
    assert snap["total"] == 900 and snap["proto"] == {"SSH": 900}
    assert snap["ip"] == {"203.0.113.5": 900} and snap["user"] == {"root": 400}
    assert snap["pass"] == {"123456": 200} and snap["country"] == {"CN": 500}
    assert snap["isp"] == {"Example Hosting": 300}


def _clean_protocols_module(tmp_path):
    for mod in ("protocols", "protocols.registry"):
        sys.modules.pop(mod, None)
    if str(tmp_path) in sys.path:
        sys.path.remove(str(tmp_path))


def test_load_proto_names_reads_v3_registry_definitions(tmp_path):
    proto_dir = tmp_path / "protocols"
    proto_dir.mkdir()
    (proto_dir / "__init__.py").write_text("")
    (proto_dir / "registry.py").write_text(
        "from types import SimpleNamespace as _D\n"
        "DEFINITIONS = [_D(name=\"SSH\", proto_id=0), _D(name=\"TNET\", proto_id=1)]\n"
    )
    _clean_protocols_module(tmp_path)
    try:
        assert load_proto_names(tmp_path) == {0: "SSH", 1: "TNET"}
    finally:
        _clean_protocols_module(tmp_path)


def test_load_enabled_protocols_parses_env_and_intersects_registry(tmp_path):
    (tmp_path / ".env").write_text(
        "# comment\nWEB_PORT=8080\nENABLED_PROTOCOLS=SSH,TNET,HTTP:80,HTTP:443,BOGUS\n"
    )
    assert load_enabled_protocols(tmp_path, {"SSH", "TNET", "HTTP", "SMTP"}) == ["HTTP", "SSH", "TNET"]


def test_load_enabled_protocols_falls_back_to_registry_when_unset(tmp_path):
    assert load_enabled_protocols(tmp_path, {"SSH", "TNET"}) == sorted({"SSH", "TNET"})
    (tmp_path / ".env").write_text("ENABLED_PROTOCOLS=\n")
    assert load_enabled_protocols(tmp_path, {"SSH", "TNET"}) == sorted({"SSH", "TNET"})


def test_load_enabled_protocols_last_assignment_wins(tmp_path):
    (tmp_path / ".env").write_text(
        "ENABLED_PROTOCOLS=SSH,TNET\nENABLED_PROTOCOLS=HTTP,SMTP\n"
    )
    assert load_enabled_protocols(tmp_path, {"SSH", "TNET", "HTTP", "SMTP"}) == ["HTTP", "SMTP"]


def test_knockknock_version_prefers_file_then_unknown(tmp_path):
    (tmp_path / "VERSION").write_text("3.0.0\n")
    assert knockknock_version(tmp_path) == "3.0.0"
    other = tmp_path / "other"
    other.mkdir()
    assert knockknock_version(other) == "unknown"


def _knockknock_dir(tmp_path):
    """A minimal knock-knock checkout: just the v3 registry main() reads."""
    kk = tmp_path / "knock-knock"
    (kk / "protocols").mkdir(parents=True)
    (kk / "protocols" / "__init__.py").write_text("")
    (kk / "protocols" / "registry.py").write_text(
        "from types import SimpleNamespace as _D\nDEFINITIONS = [_D(name=\"SSH\", proto_id=1)]\n"
    )
    return kk


def _main_argv(tmp_path, kk):
    return ["--db", str(tmp_path / "knock_knock.db"), "--state", str(tmp_path / "state.json"),
            "--out", str(tmp_path / "export.json"), "--repo-dir", str(tmp_path),
            "--sensor-id", "picket-1", "--knockknock-dir", str(kk), "--no-push"]


def test_public_ip_is_empty_when_curl_yields_nothing(monkeypatch):
    # I3: a hostname-derived address is NOT the public IP — it is usually private or
    # loopback, so its hash matches nothing and the pipeline's second pass is blind.
    monkeypatch.setattr(exporter.subprocess, "run", lambda *a, **k: SimpleNamespace(stdout=""))
    assert _public_ip() == ""
    monkeypatch.setattr(exporter.subprocess, "run", lambda *a, **k: SimpleNamespace(stdout="<html>rate limited</html>"))
    assert _public_ip() == ""                              # not an IP literal either
    monkeypatch.setattr(exporter.subprocess, "run", lambda *a, **k: SimpleNamespace(stdout="10.0.0.7\n"))
    assert _public_ip() == ""                              # a private address is not the PUBLIC ip
    monkeypatch.setattr(exporter.subprocess, "run", lambda *a, **k: SimpleNamespace(stdout="5.6.7.9\n"))
    assert _public_ip() == "5.6.7.9"


def test_main_refuses_when_public_ip_unknown(tmp_path, monkeypatch, capsys):
    _db(tmp_path / "knock_knock.db").close()
    kk = _knockknock_dir(tmp_path)
    monkeypatch.setattr(exporter, "_public_ip", lambda: "")
    _clean_protocols_module(kk)
    try:
        rc = exporter.main(_main_argv(tmp_path, kk))
    finally:
        _clean_protocols_module(kk)
    assert rc == 4
    assert "REFUSED (public-ip)" in capsys.readouterr().err
    assert not (tmp_path / "export.json").exists()       # nothing written ...
    assert not (tmp_path / "state.json").exists()        # ... and the ring did not consume this tick


def test_main_writes_export_and_drops_the_sensors_own_ip(tmp_path, monkeypatch):
    # Two genuinely public rows on top of _db()'s 203.0.113.5 (a TEST-NET address,
    # which is_public_ip drops as is_private — so it never appears either way).
    c = _db(tmp_path / "knock_knock.db")
    c.execute("INSERT INTO ip_intel (ip,hits,last_seen) VALUES ('5.6.7.8',12,'2026-07-28 11:00:00')")
    c.execute("INSERT INTO ip_intel (ip,hits,last_seen) VALUES ('5.6.7.9',3,'2026-07-28 11:00:00')")
    c.execute("INSERT INTO ip_intel_proto (ip,proto,hits) VALUES ('5.6.7.8',1,12)")
    c.execute("INSERT INTO ip_intel_proto (ip,proto,hits) VALUES ('5.6.7.9',1,3)")
    c.commit(); c.close()
    kk = _knockknock_dir(tmp_path)
    monkeypatch.setattr(exporter, "_public_ip", lambda: "5.6.7.9")   # the box's own address
    _clean_protocols_module(kk)
    try:
        rc = exporter.main(_main_argv(tmp_path, kk))
    finally:
        _clean_protocols_module(kk)
    assert rc == 0
    export = json.loads((tmp_path / "export.json").read_text(encoding="utf-8"))
    assert [r["ip"] for r in export["top_ips"]] == ["5.6.7.8"]
    assert export["sensor"]["public_ip_sha256"] == hashlib.sha256(b"5.6.7.9").hexdigest()
    assert (tmp_path / "state.json").exists()


def test_country_by_ip_without_database_returns_empty(tmp_path, capsys):
    # Spec §5: "MaxMind DB missing on-box -> per-IP country omitted". A missing
    # .mmdb (or a missing geoip2 module) must NOT abort the run — the export is
    # still published, just without `country`, and one stderr line says why.
    assert _country_by_ip(None, ["1.2.3.4"]) == {}                              # not configured
    assert _country_by_ip(str(tmp_path / "missing.mmdb"), ["1.2.3.4"]) == {}   # configured, absent
    err = capsys.readouterr().err
    assert "geoip:" in err and "without country" in err
