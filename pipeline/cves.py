from datetime import timedelta

from collectors.base import iso

WINDOW_DAYS = 180
EPSS_BASE = "https://api.first.org/data/v1/epss"
BATCH = 100

# kev_due_date is intentionally NOT in the default row: it is set only on KEV
# rows (below). Defaulting it to "" on every one of the ~15k catalog rows added
# ~0.9 MB of empty strings and pushed cves.json over the publish size cap.
_EMPTY = {"cve": "", "title": "", "cvss": None, "cvss_severity": None,
          "epss": None, "epss_percentile": None, "kev": False,
          "kev_date_added": "", "kev_ransomware": False, "vendors": [],
          "products": [], "published_at": "", "last_modified": ""}


def _get_results(results, source, key):
    for r in results:
        if r.source == source and r.ok:
            return r.extra.get(key, [])
    return []


def build_cve_rows(results, prior_rows, now):
    cutoff = iso(now - timedelta(days=WINDOW_DAYS))
    merged = {}
    for row in prior_rows:
        if row.get("last_modified", "") >= cutoff or row.get("kev"):
            merged[row["cve"]] = dict(row)

    for n in _get_results(results, "nvd", "nvd"):
        row = merged.setdefault(n["cve"], dict(_EMPTY, cve=n["cve"]))
        row.update({k: n[k] for k in ("title", "cvss", "cvss_severity",
                                      "vendors", "products", "published_at",
                                      "last_modified")})

    for k in _get_results(results, "kev", "kev"):
        row = merged.setdefault(k["cve"], dict(_EMPTY, cve=k["cve"]))
        row["kev"] = True
        row["kev_date_added"] = k["kev_date_added"]
        row["kev_due_date"] = k.get("kev_due_date", "")
        row["kev_ransomware"] = k["kev_ransomware"]
        if not row["title"]:
            row["title"] = k["name"]
        if k["vendor"] and k["vendor"] not in row["vendors"]:
            row["vendors"] = row["vendors"] + [k["vendor"]]
        if not row["last_modified"]:
            row["last_modified"] = k["kev_date_added"] + "T00:00:00.000"
    return sorted(merged.values(), key=lambda r: r["cve"], reverse=True)


def epss_url(cve_ids):
    return f"{EPSS_BASE}?cve={','.join(cve_ids)}"


def build_cve_context(groups, cve_rows):
    """KEV/EPSS/CVSS context for every initial-access CVE the intel seed names.

    Joined AT PUBLISH into the ransomware_intel payload so the profile page can
    priority-order its "check whether these are exposed" chips without ever
    loading the ~10 MB catalog client-side. None/empty fields are OMITTED
    (absence renders nothing — the frontend's honesty rule); a CVE missing from
    the catalog is simply absent from the map. The committed seed file itself
    is never touched — this rides the published envelope only.
    """
    wanted = {c for g in groups for c in (g.get("initial_access_cves") or [])}
    out = {}
    for row in cve_rows:
        cve = row.get("cve")
        if cve not in wanted:
            continue
        ctx = {}
        if row.get("kev"):
            ctx["kev"] = True
        if row.get("kev_ransomware"):
            ctx["kev_ransomware"] = True
        if isinstance(row.get("epss"), (int, float)):
            ctx["epss"] = row["epss"]
        if isinstance(row.get("cvss"), (int, float)):
            ctx["cvss"] = row["cvss"]
        if row.get("kev_due_date"):
            ctx["kev_due_date"] = row["kev_due_date"]
        if ctx:
            out[cve] = ctx
    return out


def enrich_epss(fetch, rows, now):
    """Mutates rows in place; returns a health entry for the epss enrichment."""
    try:
        scores = {}
        ids = sorted(r["cve"] for r in rows)
        for i in range(0, len(ids), BATCH):
            data = fetch(epss_url(ids[i:i + BATCH]))
            for d in data.get("data", []):
                scores[d["cve"]] = (float(d["epss"]), float(d["percentile"]))
        for r in rows:
            if r["cve"] in scores:
                r["epss"], r["epss_percentile"] = scores[r["cve"]]
        return {"source": "epss", "ok": True, "error": "",
                "items": len(scores), "last_success_at": iso(now)}
    except Exception as e:  # noqa: BLE001
        return {"source": "epss", "ok": False, "error": str(e)[:300],
                "items": 0, "last_success_at": ""}
