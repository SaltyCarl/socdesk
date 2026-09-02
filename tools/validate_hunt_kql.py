"""Validate every hunt-pack KQL query against a running Kustainer.

The TESTED gate for hosted hunting queries (spec §1.5): the Kusto emulator is
the real query engine, so an unknown table/column/function is a bind-time
semantic error even with zero rows. Two modes:

  --from-allowlist   build the candidate ruleset LIVE from
                     data/hunt/sentinel_allowlist.json through the collector's
                     own parser (the CI mode — the committed hunt_packs.json is
                     stale on the very push that edits the allowlist, and the
                     cron's GITHUB_TOKEN pushes can't retrigger workflows)
  --file PATH        validate an existing hunt_packs.json-shaped file

Run discipline: validate locally against `docker run -m 4G -e ACCEPT_EULA=Y
-p 8080:8080 mcr.microsoft.com/azuredataexplorer/kustainer-linux:latest`
BEFORE pushing allowlist/DDL changes; the hunt-kql workflow is the backstop.

Plain HTTP against the emulator (it supports neither HTTPS nor Entra auth —
by design, local/CI only): POST /v1/rest/mgmt for DDL and /v1/rest/query for
the wrapped queries. Dependency-free (urllib), so the tool runs anywhere the
pipeline does.
"""
import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import os
KUSTO_URL = os.environ.get("KUSTO_URL", "http://localhost:8080")
DB = "hunt"
DDL_ROOT = Path("data/hunt/kusto_ddl")

# | render must be the LAST operator in a real query — strip it (plus any
# trailing whitespace/semicolons) before appending our own terminal operator.
_TRAILING_RENDER = re.compile(r"\|\s*render\b[^|]*$", re.IGNORECASE)


def _post(path, csl, db=None, timeout=30):
    body = {"csl": csl}
    if db:
        body["db"] = db
    req = urllib.request.Request(
        KUSTO_URL + path,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def wait_ready(attempts=60, delay=2):
    for _ in range(attempts):
        try:
            _post("/v1/rest/mgmt", ".show cluster")
            return True
        except (urllib.error.URLError, OSError):
            time.sleep(delay)
    return False


def create_db(db):
    # Emulator persist form (in-memory-only databases aren't supported).
    # One database PER DIALECT (same table names, different column sets) —
    # dropping and re-creating a persisted db at the same path 520s, so we
    # never drop; each dialect gets its own namespace.
    try:
        _post("/v1/rest/mgmt",
              f'.create database {db} persist (@"/kustodata/dbs/{db}/md", '
              f'@"/kustodata/dbs/{db}/data")')
    except urllib.error.HTTPError as e:
        if e.code != 400:  # already exists
            raise


def apply_ddl(dialect, db):
    ddl_dir = DDL_ROOT / dialect
    files = sorted(ddl_dir.glob("*.kql")) if ddl_dir.exists() else []
    for f in files:
        stmt = "\n".join(
            ln for ln in f.read_text(encoding="utf-8").splitlines()
            if not ln.strip().startswith("//"))
        _post("/v1/rest/mgmt", stmt.strip(), db=db)
    return len(files)


def wrap(kql):
    q = kql.strip().rstrip(";").strip()
    q = _TRAILING_RENDER.sub("", q).strip().rstrip("|").strip()
    # newline first: a trailing // comment must not swallow the operator
    return q + "\n| take 0"


def validate_rules(rules, db):
    failures = []
    for r in rules:
        try:
            _post("/v1/rest/query", wrap(r["kql"]), db=db)
            print(f"  PASS {r['id']} [{r['dialect']}]")
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", "replace")[:400]
            failures.append((r["id"], detail))
            print(f"  FAIL {r['id']} [{r['dialect']}]: {detail}")
    return failures


def rules_from_allowlist(path):
    # Route through the collector's own parser so CI validates exactly what
    # the pipeline will publish.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from collectors import sentinel_hunt
    from pipeline.http import http_fetch  # the real fetch the pipeline uses

    now = datetime.now(timezone.utc)
    result = sentinel_hunt.collect(http_fetch, now, allowlist_path=path)
    if result.error:
        print(f"collector warnings: {result.error}")
    return result.extra["rules"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--from-allowlist", metavar="PATH", nargs="?",
                    const="data/hunt/sentinel_allowlist.json")
    ap.add_argument("--file", metavar="PATH")
    args = ap.parse_args()

    if not wait_ready():
        print("FATAL: Kustainer not reachable at", KUSTO_URL)
        return 2

    if args.from_allowlist:
        rules = rules_from_allowlist(Path(args.from_allowlist))
    elif args.file:
        rules = json.loads(Path(args.file).read_text(encoding="utf-8"))["rules"]
    else:
        rules = json.loads(
            Path("data/state/hunt_packs.json").read_text(encoding="utf-8"))["rules"]

    by_dialect = {}
    for r in rules:
        by_dialect.setdefault(r["dialect"], []).append(r)

    failures = []
    for dialect, batch in by_dialect.items():
        db = f"{DB}_{dialect}"
        create_db(db)
        n = apply_ddl(dialect, db)
        print(f"[{dialect}] {n} DDL files applied, validating {len(batch)} rules")
        failures += validate_rules(batch, db)

    print(f"\n{len(rules) - len(failures)}/{len(rules)} rules valid")
    if failures:
        print("FAILURES:", ", ".join(f[0] for f in failures))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
