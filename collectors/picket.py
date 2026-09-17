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


def _creds(rows):
    out = []
    for r in rows or []:
        v = fence_credential(r.get("value"))
        if v is None or int(r.get("hits_7d", 0)) < MIN_CRED_HITS:
            continue
        out.append({"value": v, "hits_7d": int(r["hits_7d"]), "hits_total": int(r.get("hits_total", 0))})
    return out


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
        row = dict(r, ip=ip)
        if "isp" in row:
            row["isp"] = clean_text(row["isp"])[:120]
        ips.append(row)
    countries = [dict(c, name=clean_text(c.get("name", ""))[:64]) for c in export.get("top_countries", [])]
    isps = [dict(i, isp=clean_text(i.get("isp", ""))[:120]) for i in export.get("top_isps", [])]
    isps = [i for i in isps if i["isp"]]
    return dict(export,
                top_ips=ips,
                top_usernames=_creds(export.get("top_usernames")),
                top_passwords=_creds(export.get("top_passwords")),
                top_countries=countries,
                top_isps=isps,
                sensor=dict(export["sensor"], id=clean_text(export["sensor"]["id"])[:32]))


def collect(fetch, now):
    raw = fetch(EXPORT_URL, text=True)
    if len(raw.encode("utf-8")) > MAX_BYTES:
        raise ValueError(f"picket export {len(raw)} bytes exceeds {MAX_BYTES} cap")
    return CollectorResult(source=SOURCE, extra={"picket": normalize(json.loads(raw))})
