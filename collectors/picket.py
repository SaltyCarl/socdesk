"""PICKET — SOCDesk's own honeypot sensor, via its public data-only export repo.

Keyless: a raw GitHub URL, fetched as text so the 2 MB cap applies to the
BYTES. The export is the most attacker-influenced input this pipeline has
(usernames, passwords, ISP names are chosen by whoever is attacking the
sensor), so it is re-validated against the raw schema and every string is
passed through clean_text + the credential fence AGAIN here — the box already
did both; this is the second, independent fence. Any refusal RAISES so
run_all records ok:false and publish keeps last-known-good.
"""
import hashlib
import json

from collectors.base import CollectorResult, clean_text
from tools.picket.assemble import validate_export
from tools.picket.fence import MIN_CRED_HITS, fence_credential, is_public_ip

SOURCE = "picket"
EXPORT_URL = "https://raw.githubusercontent.com/SaltyCarl/socdesk-picket-export/main/export.json"
SCHEMA = "schemas/picket_export.schema.json"
MAX_BYTES = 2_000_000


# String bounds copied from schemas/picket_export.schema.json. Every string-typed
# property the export schema allows is walked below — explicitly, path by path,
# so a reader can check the list against the schema; deliberately NOT a generic
# walk over the schema document.
_ID, _PROTO, _VERSION, _ISO, _TS, _NAME, _ISP = 32, 8, 32, 2, 20, 64, 120


def _s(value, bound):
    """Second-pass sanitiser for one attacker-influenced string."""
    return clean_text(str(value if value is not None else ""))[:bound]


def _s_opt(row, key, bound):
    if key in row:
        row[key] = _s(row[key], bound)


def _creds(rows):
    out = []
    for r in rows or []:
        v = fence_credential(r.get("value"))
        if v is None or int(r.get("hits_7d", 0)) < MIN_CRED_HITS:
            continue
        out.append({"value": v, "hits_7d": int(r["hits_7d"]), "hits_total": int(r.get("hits_total", 0))})
    return out


def _sensor(sensor):
    out = dict(sensor,
               id=_s(sensor["id"], _ID),
               protocols=[_s(p, _PROTO) for p in sensor.get("protocols", [])],
               knockknock_version=_s(sensor.get("knockknock_version"), _VERSION))
    _s_opt(out, "country", _ISO)
    _s_opt(out, "ring_reset_at", _TS)
    return out


def _ip_row(r, ip):
    row = dict(r, ip=ip,
               last_seen=_s(r.get("last_seen"), _TS),
               protocols=[dict(p, proto=_s(p.get("proto"), _PROTO)) for p in r.get("protocols", [])])
    for key, bound in (("first_seen", _TS), ("country", _ISO), ("isp", _ISP)):
        _s_opt(row, key, bound)
    return row


def normalize(export):
    errors = validate_export(export, SCHEMA)
    if errors:
        raise ValueError(f"picket export failed schema: {errors[0]}")
    sensor_hash = export["sensor"]["public_ip_sha256"]
    ips = []
    for r in export.get("top_ips", []):
        ip = str(r.get("ip", "")).strip()
        if not is_public_ip(ip) or hashlib.sha256(ip.encode()).hexdigest() == sensor_hash:
            continue
        ips.append(_ip_row(r, ip))
    by_proto = [dict(p, proto=_s(p.get("proto"), _PROTO)) for p in export.get("by_protocol", [])]
    countries = [dict(c, iso=_s(c.get("iso"), _ISO), name=_s(c.get("name"), _NAME))
                 for c in export.get("top_countries", [])]
    isps = [dict(i, isp=_s(i.get("isp"), _ISP)) for i in export.get("top_isps", [])]
    isps = [i for i in isps if i["isp"]]
    return dict(export,
                exported_at=_s(export["exported_at"], _TS),
                sensor=_sensor(export["sensor"]),
                totals=dict(export["totals"], since=_s(export["totals"].get("since"), _TS)),
                by_protocol=by_proto,
                top_ips=ips,
                top_usernames=_creds(export.get("top_usernames")),
                top_passwords=_creds(export.get("top_passwords")),
                top_countries=countries,
                top_isps=isps)


def collect(fetch, now):
    raw = fetch(EXPORT_URL, text=True)
    if len(raw.encode("utf-8")) > MAX_BYTES:
        raise ValueError(f"picket export {len(raw)} bytes exceeds {MAX_BYTES} cap")
    return CollectorResult(source=SOURCE, extra={"picket": normalize(json.loads(raw))})
