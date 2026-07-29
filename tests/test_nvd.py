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
