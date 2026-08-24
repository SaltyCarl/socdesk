import json
from functools import lru_cache
from pathlib import Path

from jsonschema import Draft202012Validator

# published filename -> schema filename
SCHEMA_FOR = {
    "feed.json": "feed.schema.json",
    "cves.json": "cves.schema.json",
    "health.json": "health.schema.json",
    "sources.json": "sources.schema.json",
    "ransomware_intel.json": "ransomware_intel.schema.json",
    "trends.json": "trends.schema.json",
    "actors.json": "actors.schema.json",
    "malware.json": "actors.schema.json",
    "relations.json": "relations.schema.json",
    "threat_ips.json": "threat_ips.schema.json",
    "community_reports.json": "community_reports.schema.json",
    "asn_leaderboard.json": "asn_leaderboard.schema.json",
}


@lru_cache(maxsize=None)
def _validator(schemas_dir, schema_name):
    schema = json.loads((Path(schemas_dir) / schema_name).read_text(encoding="utf-8"))
    return Draft202012Validator(schema)


def validate_payload(filename, payload, schemas_dir):
    v = _validator(schemas_dir, SCHEMA_FOR[filename])
    return [f"{e.json_path}: {e.message}" for e in v.iter_errors(payload)][:20]


MAX_PAYLOAD_BYTES = 8_000_000   # default hard cap: adversarial or runaway upstream data

# cves.json is the one legitimately-large payload — the full 180-day CVE window
# PLUS every KEV entry regardless of age (KEV rows accumulate indefinitely) —
# ~15k dense rows (titles are already trimmed; there is no fat to cut). It
# outgrew the default guard and silently froze the catalog at last-known-good
# once it crossed 8 MB. It is fetched lazily on the client (deferred behind an
# IntersectionObserver) and Cloudflare Pages serves files up to 25 MB, so it
# gets a higher — still bounded — cap that still catches a truly runaway NVD.
# NOTE: this buys runway, not forever; sustained catalog growth eventually needs
# a windowing/pruning strategy (e.g. cap the KEV-forever accumulation).
MAX_PAYLOAD_BYTES_FOR = {"cves.json": 16_000_000}


def cap_for(filename):
    return MAX_PAYLOAD_BYTES_FOR.get(filename, MAX_PAYLOAD_BYTES)


def gate(candidate, prior, schemas_dir):
    """Validate each candidate payload; fall back to prior snapshot on failure."""
    published, problems = {}, []
    for filename, payload in candidate.items():
        errors = validate_payload(filename, payload, schemas_dir)
        size = len(json.dumps(payload, ensure_ascii=False).encode("utf-8"))
        cap = cap_for(filename)
        if size > cap:
            errors = [f"payload {size} bytes exceeds {cap} cap"] + errors
        if not errors:
            published[filename] = payload
        elif filename in prior:
            published[filename] = prior[filename]
            problems.append(f"{filename}: invalid, kept last-known-good ({errors[0]})")
        else:
            problems.append(f"{filename}: invalid, no prior snapshot, skipped ({errors[0]})")
    return published, problems
