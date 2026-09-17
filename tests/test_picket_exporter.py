import sqlite3

from tools.picket.exporter import read_rollups, snapshot_from_rollups

DDL = """
CREATE TABLE user_intel (username TEXT PRIMARY KEY, hits INTEGER, last_seen DATETIME);
CREATE TABLE pass_intel (password TEXT PRIMARY KEY, hits INTEGER, last_seen DATETIME);
CREATE TABLE country_intel (iso_code TEXT PRIMARY KEY, country TEXT, hits INTEGER, last_seen DATETIME);
CREATE TABLE isp_intel (isp TEXT PRIMARY KEY, hits INTEGER, last_seen DATETIME, asn INTEGER);
CREATE TABLE ip_intel (ip TEXT PRIMARY KEY, hits INTEGER, last_seen DATETIME, lat REAL, lng REAL,
  hits_since_cleared INTEGER NOT NULL DEFAULT 0, ban_until INTEGER, ban_count INTEGER NOT NULL DEFAULT 0,
  first_seen DATETIME, asn INTEGER);
CREATE TABLE ip_intel_proto (ip TEXT, proto INTEGER, hits INTEGER, last_seen DATETIME, lat REAL, lng REAL, PRIMARY KEY (ip, proto));
CREATE TABLE monitor_heartbeats (id INTEGER PRIMARY KEY, uptime_minutes INTEGER NOT NULL DEFAULT 0);
"""


def _db():
    c = sqlite3.connect(":memory:")
    c.executescript(DDL)
    c.execute("INSERT INTO ip_intel (ip,hits,last_seen,lat,lng,first_seen,asn) VALUES ('203.0.113.5',900,'2026-07-28 11:00:00',39.9,116.4,'2026-07-20 01:00:00',64500)")
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
    assert r["ip_intel"][0]["ip"] == "203.0.113.5" and r["ip_intel"][0]["asn"] == 64500
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
