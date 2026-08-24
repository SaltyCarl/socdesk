"""Provenance / staleness guard for the hand-curated ransomware seed.

Two independent drift signals. Both are SOFT — this never raises and never
hard-fails a build; drift here is a prompt for a human to re-review, not a
publish blocker.

1. Staleness: a seed group's `last_reviewed` is more than `max_age_days`
   before `reference_date` — nobody has re-checked it recently.
2. KEV drift: CISA KEV has flagged a CVE as ransomware-associated
   (`kev_ransomware=True`, see pipeline/cves.py) that does not appear in
   ANY seed group's `initial_access_cves` — the automated KEV feed knows
   about a ransomware-linked CVE the hand-curated seed hasn't caught up
   with yet. KEV's `kev_ransomware` flag says a CVE is used by ransomware
   in general; it does not say by which group, so this can only ask
   "is it in the seed anywhere", not "is it filed under the right group".

`reference_date` is passed in by the caller (never `date.today()`) so this
stays pure and deterministic — tests get reproducible output.
"""

from datetime import date


def check_intel_staleness(groups, kev_ransomware_cves, reference_date, max_age_days=180):
    warnings = []
    # The whole point of this guard is to never be the thing that breaks a
    # build. A misconfigured caller (bad env var, wrong date format, None) must
    # surface as a soft warning, not an uncaught raise.
    try:
        ref = date.fromisoformat(reference_date)
    except (ValueError, TypeError):
        return [
            f"GUARD: staleness check skipped — invalid reference_date "
            f"{reference_date!r} (expected ISO YYYY-MM-DD)"
        ]

    seed_cves = set()
    for group in groups:
        seed_cves.update(group.get("initial_access_cves") or [])

    for group in sorted(groups, key=lambda g: g.get("slug", "")):
        last_reviewed = group.get("last_reviewed")
        if not last_reviewed:
            continue
        try:
            reviewed = date.fromisoformat(last_reviewed)
        except ValueError:
            continue
        age_days = (ref - reviewed).days
        if age_days > max_age_days:
            warnings.append(
                f"STALE: seed group '{group.get('slug', '?')}' last reviewed "
                f"{last_reviewed} ({age_days} days before {reference_date}, "
                f"exceeds {max_age_days}-day threshold)"
            )

    for cve in sorted(kev_ransomware_cves):
        if cve not in seed_cves:
            warnings.append(
                f"DRIFT: {cve} is KEV-flagged ransomware-associated but does "
                f"not appear in any seed group's initial_access_cves"
            )

    return warnings
