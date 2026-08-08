from collectors import nvd
from tests.conftest import FIXED_NOW


def test_nvd_rows(fake_fetch):
    url = nvd.build_url(FIXED_NOW)
    fetch = fake_fetch({url: "nvd/recent.json"})
    r = nvd.collect(fetch, FIXED_NOW)
    assert r.ok
    row = r.extra["nvd"][0]
    assert row["cve"] == "CVE-2026-2222"
    assert row["cvss"] == 9.8
    assert row["cvss_severity"] == "CRITICAL"
    assert row["vendors"] == ["examplecorp"]
    assert row["products"] == ["exampleserver"]
    assert row["last_modified"] == "2026-07-27T10:00:00.000"


def test_nvd_also_pulls_the_whole_kev_catalogue():
    """Regression: with only the 2-day modified window, KEV entries (2014-2026)
    almost never appeared, so 97.5% of KEV rows rendered with no CVSS."""
    def entry(cve_id, score):
        return {"cve": {"id": cve_id, "published": "", "lastModified": "",
                        "descriptions": [],
                        "metrics": {"cvssMetricV31": [{"cvssData": {
                            "baseScore": score, "baseSeverity": "CRITICAL"}}]},
                        "configurations": []}}
    pages = {
        nvd.build_url(FIXED_NOW): {"totalResults": 1,
                                   "vulnerabilities": [entry("CVE-2026-0001", 7.5)]},
        nvd.build_kev_url(): {"totalResults": 2,
                              "vulnerabilities": [entry("CVE-2014-0160", 9.8),
                                                  entry("CVE-2026-0001", 7.5)]},
    }
    r = nvd.collect(lambda url, **kw: pages[url], FIXED_NOW)
    by = {row["cve"]: row for row in r.extra["nvd"]}
    assert by["CVE-2014-0160"]["cvss"] == 9.8      # old KEV entry now scored
    assert len(by) == 2                             # de-duplicated, not doubled


def test_kev_query_failure_does_not_break_the_collector():
    def fetch(url, **kw):
        if "hasKev" in url:
            raise RuntimeError("nvd 503")
        return {"totalResults": 0, "vulnerabilities": []}
    assert nvd.collect(fetch, FIXED_NOW).ok


def test_nvd_pages_when_total_exceeds_first_page():
    def entry(cve_id):
        return {"cve": {"id": cve_id, "published": "", "lastModified": "",
                        "descriptions": [], "metrics": {}, "configurations": []}}
    pages = {
        nvd.build_url(FIXED_NOW): {"totalResults": 3,
                                   "vulnerabilities": [entry("CVE-2026-0001"),
                                                       entry("CVE-2026-0002")]},
        nvd.build_url(FIXED_NOW, start_index=2): {"totalResults": 3,
                                                  "vulnerabilities": [entry("CVE-2026-0003")]},
    }
    r = nvd.collect(lambda url, **kw: pages[url], FIXED_NOW)
    assert [row["cve"] for row in r.extra["nvd"]] == [
        "CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"]
