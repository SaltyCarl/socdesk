from datetime import timedelta

from collectors.base import CollectorResult

SOURCE = "nvd"
BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
LOOKBACK_DAYS = 2


MAX_PAGES = 5


def build_url(now, start_index=0):
    start = (now - timedelta(days=LOOKBACK_DAYS)).strftime("%Y-%m-%dT%H:%M:%S.000")
    end = now.strftime("%Y-%m-%dT%H:%M:%S.000")
    url = (f"{BASE}?lastModStartDate={start}&lastModEndDate={end}"
           f"&resultsPerPage=2000")
    return url if start_index == 0 else f"{url}&startIndex={start_index}"


def build_kev_url(start_index=0):
    """Every CVE in the CISA KEV catalogue, with full NVD detail.

    Without this the KEV/CVSS join is a fiction: KEV spans 2014-2026 but the
    recent-modified window is 2 days, so only ~2.5% of KEV rows ever received a
    CVSS score and the triage table rendered UNKNOWN for almost every row.
    """
    url = f"{BASE}?hasKev&resultsPerPage=2000"
    return url if start_index == 0 else f"{url}&startIndex={start_index}"


def _cpe_vendors_products(cve):
    vendors, products = [], []
    for cfg in cve.get("configurations", []):
        for node in cfg.get("nodes", []):
            for m in node.get("cpeMatch", []):
                parts = m.get("criteria", "").split(":")
                if len(parts) > 4:
                    if parts[3] not in vendors:
                        vendors.append(parts[3])
                    if parts[4] not in products:
                        products.append(parts[4])
    return vendors[:5], products[:5]


def _cvss(cve):
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metrics = cve.get("metrics", {}).get(key)
        if metrics:
            d = metrics[0]["cvssData"]
            return d.get("baseScore"), d.get("baseSeverity", "")
    return None, None


def _paged(fetch, url_for):
    """Fetch a paginated NVD result set, bounded by MAX_PAGES."""
    data = fetch(url_for(0))
    vulns = list(data.get("vulnerabilities", []))
    total = data.get("totalResults", len(vulns))
    pages = 1
    while len(vulns) < total and pages < MAX_PAGES:
        got = fetch(url_for(len(vulns))).get("vulnerabilities", [])
        if not got:
            break
        vulns.extend(got)
        pages += 1
    return vulns


def collect(fetch, now):
    # Two result sets: everything modified recently (fresh CVEs), plus the
    # whole KEV catalogue (so the KEV x CVSS x EPSS join is real).
    vulns = _paged(fetch, lambda i: build_url(now, i))
    seen = {e["cve"]["id"] for e in vulns if e.get("cve", {}).get("id")}
    try:
        for entry in _paged(fetch, build_kev_url):
            if entry.get("cve", {}).get("id") not in seen:
                vulns.append(entry)
    except Exception:
        pass          # KEV detail is an enrichment; never fail the collector

    rows = []
    for entry in vulns:
        cve = entry["cve"]
        score, sev = _cvss(cve)
        vendors, products = _cpe_vendors_products(cve)
        desc = next((d["value"] for d in cve.get("descriptions", [])
                     if d.get("lang") == "en"), "")
        rows.append({
            "cve": cve["id"],
            "title": desc[:200],
            "cvss": score,
            "cvss_severity": sev,
            "vendors": vendors,
            "products": products,
            "published_at": cve.get("published", ""),
            "last_modified": cve.get("lastModified", ""),
        })
    return CollectorResult(source=SOURCE, extra={"nvd": rows})
