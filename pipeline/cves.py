from datetime import timedelta

from collectors.base import iso

WINDOW_DAYS = 180
EPSS_BASE = "https://api.first.org/data/v1/epss"
BATCH = 100

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
