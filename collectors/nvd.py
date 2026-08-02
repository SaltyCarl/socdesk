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


def collect(fetch, now):
    data = fetch(build_url(now))
    vulns = list(data.get("vulnerabilities", []))
    total = data.get("totalResults", len(vulns))
    pages = 1
    while len(vulns) < total and pages < MAX_PAGES:   # patch-week overflow guard
        page = fetch(build_url(now, start_index=len(vulns)))
        got = page.get("vulnerabilities", [])
        if not got:
            break
        vulns.extend(got)
        pages += 1
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
