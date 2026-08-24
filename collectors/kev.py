from datetime import timedelta

from collectors.base import CollectorResult, make_item

SOURCE = "kev"
URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
ITEM_WINDOW_DAYS = 30


def collect(fetch, now):
    data = fetch(URL)
    rows, items = [], []
    cutoff = (now - timedelta(days=ITEM_WINDOW_DAYS)).strftime("%Y-%m-%d")
    for v in data.get("vulnerabilities", []):
        ransomware = v.get("knownRansomwareCampaignUse", "").lower() == "known"
        rows.append({
            "cve": v["cveID"],
            "vendor": v.get("vendorProject", ""),
            "product": v.get("product", ""),
            "name": v.get("vulnerabilityName", ""),
            "kev_date_added": v.get("dateAdded", ""),
            "kev_due_date": v.get("dueDate", ""),
            "kev_ransomware": ransomware,
        })
        if v.get("dateAdded", "") >= cutoff:
            items.append(make_item(
                SOURCE, v["cveID"], "vulnerability",
                f"KEV: {v['cveID']} — {v.get('vulnerabilityName', '')}",
                v.get("shortDescription", ""),
                "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                "critical" if ransomware else "high",
                v.get("dateAdded", "") + "T00:00:00Z", now,
                entities={"actors": [], "malware": [],
                          "vendors": [v.get("vendorProject", "")],
                          "cves": [v["cveID"]]},
            ))
    return CollectorResult(source=SOURCE, items=items, extra={"kev": rows})
