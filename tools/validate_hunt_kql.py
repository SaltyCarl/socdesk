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


_SAMPLES = {"ip": "203.0.113.7", "upn": "user@example.com", "domain": "example.com",
            "url": "https://example.com/a", "md5": "d41d8cd98f00b204e9800998ecf8427e",
            "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}


def substitute_samples(kql):
    """Replace every {{param}} placeholder with a canonical sample so a
    parameterized playbook step becomes a bindable query for the emulator."""
    for param, sample in _SAMPLES.items():
        kql = kql.replace("{{" + param + "}}", sample)
    return kql


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
    # Route through the collectors' own parsers + the authored loader so CI
    # validates EXACTLY what the pipeline will publish — all three sources.
    # (No longer urllib-only in this mode: the collectors use the pipeline's
    # httpx fetch, and the sigma lane needs pysigma installed.)
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from collectors import sentinel_hunt, sigma_hunt
    from pipeline.http import http_fetch  # the real fetch the pipeline uses
    from pipeline.hunt import load_authored_rules, load_playbooks

    now = datetime.now(timezone.utc)
    rules = []
    hunt_dir = Path(path).parent
    for mod, fname in ((sentinel_hunt, "sentinel_allowlist.json"),
                       (sigma_hunt, "sigma_allowlist.json")):
        p = hunt_dir / fname
        if not p.exists():
            continue
        result = mod.collect(http_fetch, now, allowlist_path=p)
        if result.error:
            print(f"{mod.SOURCE} warnings: {result.error}")
        rules += result.extra["rules"]
    authored, warnings = load_authored_rules(hunt_dir / "authored")
    for w in warnings:
        print(f"authored warning: {w}")
    # Fold each playbook step in as a pseudo-rule, sample-substituted. HARD-FAIL
    # on any surviving {{placeholder}}: inside a "..." literal it binds as a
    # string and would pass CI silently, shipping a step whose IOC never injects.
    playbooks, pb_warnings = load_playbooks(hunt_dir / "playbooks")
    for w in pb_warnings:
        print(f"playbook warning: {w}")
    step_rules = []
    for pb in playbooks:
        for s in pb["steps"]:
            kql = substitute_samples(s["kql"])
            if "{{" in kql:
                raise SystemExit(
                    f"playbook {pb['id']}::{s['id']}: unresolved placeholder after "
                    f"substitution — a surviving {{{{...}}}} binds as a string literal "
                    f"and would pass CI silently")
            step_rules.append({"id": f"{pb['id']}::{s['id']}",
                               "dialect": s["dialect"], "kql": kql})
    return rules + authored + step_rules


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
