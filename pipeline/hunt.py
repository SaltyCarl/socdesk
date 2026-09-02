"""Authored hunt rules — curation, not collection (the intel-seed pattern).

SOCDesk-original hunting queries live as data/hunt/authored/*.yaml and are
re-read EVERY pipeline run (cheap local IO, no freshness gate) so an edit
appears on the next cron without any collector running. Each file must carry
the fields below; the loader composes the schema-valid published shape
(source.url = the file's own GitHub blob — the public provenance trail) and
STRIPS the review-only fields (rationale stays in the YAML for humans, never
in the payload). A malformed file is skipped and reported, never guessed at.
"""
from pathlib import Path

import yaml

AUTHORED_BLOB_BASE = "https://github.com/SaltyCarl/socdesk/blob/main/data/hunt/authored"
REQUIRED = ("id", "title", "kql", "techniques", "tables", "dialect", "tested")


def load_authored_rules(authored_dir):
    """Returns (rules, warnings). Empty dir / missing dir → ([], [])."""
    d = Path(authored_dir)
    if not d.is_dir():
        return [], []
    rules, warnings = [], []
    for f in sorted(d.glob("*.yaml")):
        try:
            doc = yaml.safe_load(f.read_text(encoding="utf-8"))
            missing = [k for k in REQUIRED if not doc.get(k)]
            if missing:
                raise ValueError(f"missing {','.join(missing)}")
            rules.append({
                "id": str(doc["id"]),
                "title": str(doc["title"])[:200],
                "kql": str(doc["kql"]).strip(),
                "techniques": [str(t) for t in doc["techniques"]],
                "tables": [str(t) for t in doc["tables"]],
                "dialect": str(doc["dialect"]),
                "tested": str(doc["tested"])[:10],
                "source": {
                    "kind": "socdesk",
                    "url": f"{AUTHORED_BLOB_BASE}/{f.name}",
                    "license": "MIT",
                    "author": "SOCDesk",
                },
            })
        except Exception as exc:  # noqa: BLE001 — skip + report, never guess
            warnings.append(f"authored {f.name}: {exc}")
    return rules, warnings


def merge_authored(hunt_payload, authored, envelope):
    """The uniform merge step (runs every cycle, fresh AND keep-prior paths):
    collector-sourced rules + authored, authored always re-read. Reassigns,
    never mutates — keep-prior payloads share structure with `state`.
    When no hunt payload exists at all but authored rules do, an
    authored-only envelope is created (no allowlist shas → the freshness
    gate stays stale, so the collectors still run next eligible cycle)."""
    if hunt_payload is not None:
        kept = [r for r in hunt_payload.get("rules", [])
                if r.get("source", {}).get("kind") != "socdesk"]
        return dict(hunt_payload, rules=kept + authored)
    if authored:
        return dict(envelope, rules=authored)
    return None
