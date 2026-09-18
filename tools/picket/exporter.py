"""PICKET exporter — runs ON THE SENSOR BOX (systemd timer :05/:35).

Reads knock-knock's SQLite rollups (never per-knock rows), feeds the delta
ring, assembles + validates export.json, and pushes it to the public
data-only repo SaltyCarl/socdesk-picket-export. The plaintext public IP is
hashed here and never written. geoip2 and git are imported lazily so the pure
parts stay testable in CI without them.

Usage (see README.md):
  exporter.py --db /path/knocks.db --state /var/lib/picket/state.json \
              --out /srv/picket-export/export.json --repo-dir /srv/picket-export \
              --sensor-id picket-1 --knockknock-dir /opt/knock-knock \
              [--geoip-db /usr/share/GeoIP/GeoLite2-Country.mmdb] [--no-push]
"""
import argparse
import hashlib
import json
import os
import socket
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from tools.picket.assemble import assemble_export, validate_export
from tools.picket.ring import apply_snapshot, new_state

HERE = Path(__file__).resolve().parent
SCHEMA = HERE.parent.parent / "schemas" / "picket_export.schema.json"
MAX_EXPORT_BYTES = 512 * 1024


def _rows(conn, sql):
    conn.row_factory = sqlite3.Row
    return [dict(r) for r in conn.execute(sql)]


def read_rollups(conn):
    return {
        "ip_intel": _rows(conn, "SELECT ip,hits,last_seen,lat,lng FROM ip_intel"),
        "ip_intel_proto": _rows(conn, "SELECT ip,proto,hits FROM ip_intel_proto"),
        "user_intel": _rows(conn, "SELECT username,hits FROM user_intel"),
        "pass_intel": _rows(conn, "SELECT password,hits FROM pass_intel"),
        "country_intel": _rows(conn, "SELECT iso_code,country,hits FROM country_intel"),
        "isp_intel": _rows(conn, "SELECT isp,hits,asn FROM isp_intel"),
        "heartbeat_minutes": int((conn.execute("SELECT uptime_minutes FROM monitor_heartbeats WHERE id=1").fetchone() or [0])[0]),
        "knocks_total": int((conn.execute("SELECT COALESCE(SUM(hits),0) FROM ip_intel_proto").fetchone() or [0])[0]),
    }


def snapshot_from_rollups(rollups, proto_names):
    proto = {}
    for r in rollups["ip_intel_proto"]:
        name = proto_names[int(r["proto"])]
        proto[name] = proto.get(name, 0) + int(r["hits"] or 0)
    return {
        "total": int(rollups["knocks_total"]),
        "proto": proto,
        "ip": {r["ip"]: int(r["hits"] or 0) for r in rollups["ip_intel"]},
        "user": {r["username"]: int(r["hits"] or 0) for r in rollups["user_intel"]},
        "pass": {r["password"]: int(r["hits"] or 0) for r in rollups["pass_intel"]},
        "country": {r["iso_code"]: int(r["hits"] or 0) for r in rollups["country_intel"]},
        "isp": {r["isp"]: int(r["hits"] or 0) for r in rollups["isp_intel"]},
    }


def load_proto_names(knockknock_dir):
    """knock-knock's own registry is the source of truth for proto_id -> name.
    v3.0.0 exposes `protocols.registry.DEFINITIONS`, a list of ProtocolDefinition
    dataclasses (name, proto_id, ...). Protocol modules import `protocol_api` from
    the repo root, hence the sys.path insert."""
    sys.path.insert(0, str(knockknock_dir))
    from protocols.registry import DEFINITIONS  # noqa: E402  (knock-knock module)
    return {int(d.proto_id): str(d.name) for d in DEFINITIONS}


def load_enabled_protocols(knockknock_dir, registry_names):
    """The protocols the sensor actually listens on = ENABLED_PROTOCOLS in knock-knock's
    .env (PROTO or PROTO:PORT entries, comma-separated), intersected with the registry.
    If assigned more than once, the LAST assignment wins, as with shell sourcing /
    dotenv. Unset/empty -> every registry name (dogfood confirms knock-knock's own default)."""
    env = Path(knockknock_dir) / ".env"
    names = set()
    if env.exists():
        for line in env.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("ENABLED_PROTOCOLS="):
                names = set()
                for tok in line.split("=", 1)[1].split(","):
                    name = tok.strip().split(":", 1)[0].upper()
                    if name in registry_names:
                        names.add(name)
    return sorted(names) if names else sorted(registry_names)


def knockknock_version(knockknock_dir):
    """VERSION file if the tag ships one, else `git describe --tags --always`, else 'unknown'."""
    p = Path(knockknock_dir) / "VERSION"
    if p.exists():
        return p.read_text().strip()[:32]
    # GIT_CEILING_DIRECTORIES stops upward repo discovery at knockknock_dir's own
    # parent, so a knockknock_dir that isn't itself a git checkout reports "unknown"
    # instead of accidentally describing some unrelated ancestor repository.
    env = {**os.environ, "GIT_CEILING_DIRECTORIES": str(Path(knockknock_dir).resolve().parent)}
    out = subprocess.run(["git", "-C", str(knockknock_dir), "describe", "--tags", "--always"],
                         capture_output=True, text=True, check=False, env=env).stdout.strip()
    return out[:32] or "unknown"


def _public_ip():
    out = subprocess.run(["curl", "-4", "-s", "--max-time", "5", "https://ifconfig.me"],
                         capture_output=True, text=True, check=False).stdout.strip()
    return out or socket.gethostbyname(socket.gethostname())


def _country_by_ip(geoip_db, ips):
    if not geoip_db:
        return {}
    import geoip2.database  # noqa: E402  (box only)
    out = {}
    with geoip2.database.Reader(geoip_db) as rd:
        for ip in ips:
            try:
                out[ip] = rd.country(ip).country.iso_code or ""
            except Exception:  # noqa: BLE001 — unknown IP is simply unlabelled
                continue
    return out


def _git_push(repo_dir, out_path):
    subprocess.run(["git", "-C", repo_dir, "add", Path(out_path).name], check=True)
    if subprocess.run(["git", "-C", repo_dir, "diff", "--cached", "--quiet"]).returncode == 0:
        return "unchanged"
    subprocess.run(["git", "-C", repo_dir, "commit", "-q", "-m", "picket: export"], check=True)
    subprocess.run(["git", "-C", repo_dir, "push", "-q"], check=True)
    return "pushed"


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True); ap.add_argument("--state", required=True)
    ap.add_argument("--out", required=True); ap.add_argument("--repo-dir", required=True)
    ap.add_argument("--sensor-id", required=True); ap.add_argument("--knockknock-dir", required=True)
    ap.add_argument("--geoip-db", default=None); ap.add_argument("--no-push", action="store_true")
    a = ap.parse_args(argv)

    now = datetime.now(timezone.utc)
    proto_names = load_proto_names(a.knockknock_dir)
    conn = sqlite3.connect(f"file:{a.db}?mode=ro", uri=True)
    rollups = read_rollups(conn)
    rollups["country_by_ip"] = _country_by_ip(a.geoip_db, [r["ip"] for r in rollups["ip_intel"]])

    state_path = Path(a.state)
    state = json.loads(state_path.read_text()) if state_path.exists() else new_state()
    ring_out = apply_snapshot(state, snapshot_from_rollups(rollups, proto_names), int(time.time()))
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps(state, separators=(",", ":")))

    version = knockknock_version(a.knockknock_dir)
    sensor = {"id": a.sensor_id, "public_ip_sha256": hashlib.sha256(_public_ip().encode()).hexdigest(),
              "protocols": load_enabled_protocols(a.knockknock_dir, set(proto_names.values())), "knockknock_version": version}
    if ring_out["reset"]:
        sensor["ring_reset_at"] = now.strftime("%Y-%m-%dT%H:%M:%SZ")

    export = assemble_export(rollups, ring_out["hits_7d"], ring_out["ring"], sensor, now, proto_names)
    errors = validate_export(export, SCHEMA)
    if errors:
        print("REFUSED (schema): " + errors[0], file=sys.stderr); return 2
    blob = json.dumps(export, ensure_ascii=False, separators=(",", ":"))
    if len(blob.encode("utf-8")) > MAX_EXPORT_BYTES:
        print(f"REFUSED (size): {len(blob)} > {MAX_EXPORT_BYTES}", file=sys.stderr); return 3
    Path(a.out).write_text(blob, encoding="utf-8")
    if not a.no_push:
        print(_git_push(a.repo_dir, a.out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
