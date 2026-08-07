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
    "actors.json": "actors.schema.json",
    "malware.json": "actors.schema.json",
}


@lru_cache(maxsize=None)
def _validator(schemas_dir, schema_name):
    schema = json.loads((Path(schemas_dir) / schema_name).read_text(encoding="utf-8"))
    return Draft202012Validator(schema)


def validate_payload(filename, payload, schemas_dir):
    v = _validator(schemas_dir, SCHEMA_FOR[filename])
    return [f"{e.json_path}: {e.message}" for e in v.iter_errors(payload)][:20]


MAX_PAYLOAD_BYTES = 8_000_000   # hard cap: adversarial or runaway upstream data


def gate(candidate, prior, schemas_dir):
    """Validate each candidate payload; fall back to prior snapshot on failure."""
    published, problems = {}, []
    for filename, payload in candidate.items():
        errors = validate_payload(filename, payload, schemas_dir)
        size = len(json.dumps(payload, ensure_ascii=False).encode("utf-8"))
        if size > MAX_PAYLOAD_BYTES:
            errors = [f"payload {size} bytes exceeds {MAX_PAYLOAD_BYTES} cap"] + errors
        if not errors:
            published[filename] = payload
        elif filename in prior:
            published[filename] = prior[filename]
            problems.append(f"{filename}: invalid, kept last-known-good ({errors[0]})")
        else:
            problems.append(f"{filename}: invalid, no prior snapshot, skipped ({errors[0]})")
    return published, problems
