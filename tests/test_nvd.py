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
