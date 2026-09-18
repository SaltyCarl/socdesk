"""Rollups + ring → the raw export document (spec §4.1).

Runs on the box. Applies the credential fence, the public-IP test and the
sensor's-own-IP drop FIRST TIME (the collector applies all three a second
time — the last one by hash), joins per-IP protocol hits and ISP names,
converts knock-knock's 'YYYY-MM-DD HH:MM:SS' timestamps to ISO Z, enforces
every cap, and validates against schemas/picket_export.schema.json before
anything is written. Unknown protocol ids raise — never guessed.
"""
import json
from datetime import timedelta
from pathlib import Path

from jsonschema import Draft202012Validator

from collectors.base import clean_text, iso
from tools.picket.fence import MIN_CRED_HITS, fence_credential, is_public_ip

SCHEMA_VERSION = 1
CAP_IPS, CAP_CREDS, CAP_COUNTRIES, CAP_ISPS, CAP_PROTOS = 2000, 50, 50, 50, 16


def _ts(value):
    """'YYYY-MM-DD HH:MM:SS' / 'YYYY-MM-DDTHH:MM:SS' / None -> ISO Z or ''."""
    v = str(value or "").strip().replace(" ", "T")
    if not v:
        return ""
    return v[:19] + "Z"


def _credlist(rows, key, hits7d_kind):
    out = []
    for r in rows:
        v = fence_credential(r.get(key))
        if v is None:
            continue
        h7 = int(hits7d_kind.get(str(r.get(key)), 0))
        if h7 < MIN_CRED_HITS:
            continue
        out.append({"value": v, "hits_7d": h7, "hits_total": int(r.get("hits") or 0)})
    out.sort(key=lambda x: (-x["hits_7d"], x["value"]))
    return out[:CAP_CREDS]


def assemble_export(rollups, hits7d, ring, sensor, now, proto_names, sensor_ip=None):
    """`sensor_ip` is the box's own plaintext public address: any rollup row for it
    is dropped HERE, before the plaintext could reach the public export repo.
    knock-knock's self_redaction scrubs credential/body text only, never
    ip_intel.ip, so a knock from the box to itself does land in the rollups."""
    isp_by_asn = {int(r["asn"]): clean_text(r.get("isp") or "")[:120]
                  for r in rollups.get("isp_intel", []) if r.get("asn") is not None}
    # Per-IP, per-protocol: knock-knock's cumulative counter, published as hits_total
    # (no per-IP, per-protocol window exists upstream — R29). The parent row's
    # hits_7d says whether the IP was active this week.
    proto_by_ip = {}
    for r in rollups.get("ip_intel_proto", []):
        pid = int(r["proto"])
        if pid not in proto_names:
            raise KeyError(f"unknown knock-knock protocol id {pid}")
        proto_by_ip.setdefault(r["ip"], []).append({"proto": proto_names[pid], "hits_total": int(r.get("hits") or 0)})

    ips = []
    for r in rollups.get("ip_intel", []):
        ip = str(r.get("ip") or "").strip()
        if not is_public_ip(ip) or (sensor_ip and ip == sensor_ip):
            continue
        h7 = int(hits7d["ip"].get(ip, 0))
        row = {"ip": ip, "hits_7d": h7, "hits_total": int(r.get("hits") or 0),
               "last_seen": _ts(r.get("last_seen")),
               "protocols": sorted(proto_by_ip.get(ip, []), key=lambda p: -p["hits_total"])[:CAP_PROTOS]}
        fs = _ts(r.get("first_seen"))
        if fs:
            row["first_seen"] = fs
        cc = rollups.get("country_by_ip", {}).get(ip)
        if cc:
            row["country"] = str(cc)[:2].upper()
        if r.get("asn") is not None:
            row["asn"] = int(r["asn"])
            if int(r["asn"]) in isp_by_asn:
                row["isp"] = isp_by_asn[int(r["asn"])]
        if r.get("lat") is not None and r.get("lng") is not None:
            row["lat"], row["lng"] = float(r["lat"]), float(r["lng"])
            row["geo_precision"] = "city"
        ips.append(row)
    ips.sort(key=lambda x: (-x["hits_7d"], -x["hits_total"], x["ip"]))
    # The headline distinct-IP count comes from the RING, not from the capped
    # top_ips list (which would saturate at CAP_IPS on any busy sensor). Same
    # tests as a published row: public, and not the box's own address.
    unique_ips_7d = sum(1 for ip, h in hits7d["ip"].items()
                        if int(h) > 0 and is_public_ip(ip) and not (sensor_ip and ip == sensor_ip))

    by_proto = [{"proto": p, "hits_7d": int(hits7d["proto"].get(p, 0)),
                 "hits_total": int(t)} for p, t in _proto_totals(rollups, proto_names).items()]
    by_proto.sort(key=lambda x: -x["hits_7d"])

    countries = [{"iso": str(r["iso_code"])[:2].upper(), "name": clean_text(r.get("country") or "")[:64],
                  "hits_7d": int(hits7d["country"].get(r["iso_code"], 0)), "hits_total": int(r.get("hits") or 0)}
                 for r in rollups.get("country_intel", []) if r.get("iso_code")]
    countries.sort(key=lambda x: -x["hits_7d"])
    isps = []
    for r in rollups.get("isp_intel", []):
        name = clean_text(r.get("isp") or "")[:120]
        if not name:
            continue
        row = {"isp": name, "hits_7d": int(hits7d["isp"].get(r.get("isp"), 0)), "hits_total": int(r.get("hits") or 0)}
        if r.get("asn") is not None:            # NULL upstream is "unknown" — omitted, never 0
            row["asn"] = int(r["asn"])
        isps.append(row)
    isps.sort(key=lambda x: -x["hits_7d"])

    uptime = int(rollups.get("heartbeat_minutes") or 0)
    sensor_out = {"id": str(sensor["id"])[:32], "public_ip_sha256": sensor["public_ip_sha256"],
                  "protocols": [str(p)[:8] for p in sensor.get("protocols", [])][:CAP_PROTOS],
                  "uptime_minutes": uptime, "knockknock_version": str(sensor.get("knockknock_version", ""))[:32]}
    if sensor.get("country"):
        sensor_out["country"] = str(sensor["country"])[:2].upper()
    if sensor.get("ring_reset_at"):
        sensor_out["ring_reset_at"] = str(sensor["ring_reset_at"])[:20]

    return {
        "schema_version": SCHEMA_VERSION,
        "exported_at": iso(now),
        "sensor": sensor_out,
        "totals": {"knocks_total": int(rollups.get("knocks_total") or 0),
                   "since": iso(now - timedelta(minutes=uptime)),
                   "unique_ips_7d": unique_ips_7d},
        "ring": {"bucket_minutes": 30, "buckets": [int(x) for x in ring]},
        "by_protocol": by_proto[:CAP_PROTOS],
        "top_ips": ips[:CAP_IPS],
        "top_usernames": _credlist(rollups.get("user_intel", []), "username", hits7d["user"]),
        "top_passwords": _credlist(rollups.get("pass_intel", []), "password", hits7d["pass"]),
        "top_countries": countries[:CAP_COUNTRIES],
        "top_isps": isps[:CAP_ISPS],
    }


def _proto_totals(rollups, proto_names):
    totals = {}
    for r in rollups.get("ip_intel_proto", []):
        totals[proto_names[int(r["proto"])]] = totals.get(proto_names[int(r["proto"])], 0) + int(r.get("hits") or 0)
    return totals


def validate_export(export, schema_path):
    schema = json.loads(Path(schema_path).read_text(encoding="utf-8"))
    return [f"{e.json_path}: {e.message}" for e in Draft202012Validator(schema).iter_errors(export)][:20]
