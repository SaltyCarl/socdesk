from collectors.base import CollectorResult
from pipeline import cves
from tests.conftest import FIXED_NOW

KEV_RESULT = CollectorResult(source="kev", extra={"kev": [
    {"cve": "CVE-2026-1111", "vendor": "Fortinet", "product": "FortiOS",
     "name": "FortiOS Auth Bypass", "kev_date_added": "2026-07-25",
     "kev_ransomware": True}]})
NVD_RESULT = CollectorResult(source="nvd", extra={"nvd": [
    {"cve": "CVE-2026-2222", "title": "RCE in ExampleServer.", "cvss": 9.8,
     "cvss_severity": "CRITICAL", "vendors": ["examplecorp"],
     "products": ["exampleserver"], "published_at": "2026-07-27T09:00:00.000",
     "last_modified": "2026-07-27T10:00:00.000"}]})


def test_join_merges_kev_and_nvd():
    rows = cves.build_cve_rows([KEV_RESULT, NVD_RESULT], prior_rows=[], now=FIXED_NOW)
    by_cve = {r["cve"]: r for r in rows}
    assert by_cve["CVE-2026-1111"]["kev"] is True
    assert by_cve["CVE-2026-1111"]["kev_ransomware"] is True
    assert by_cve["CVE-2026-2222"]["kev"] is False
    assert by_cve["CVE-2026-2222"]["cvss"] == 9.8


def test_join_keeps_prior_rows_within_window():
    prior = [{"cve": "CVE-2026-0001", "kev": False, "kev_date_added": "",
              "kev_ransomware": False, "cvss": 5.0, "cvss_severity": "MEDIUM",
              "title": "old", "vendors": [], "products": [], "epss": None,
              "epss_percentile": None, "published_at": "2026-06-01T00:00:00.000",
              "last_modified": "2026-06-01T00:00:00.000"}]
    rows = cves.build_cve_rows([KEV_RESULT], prior_rows=prior, now=FIXED_NOW)
    assert any(r["cve"] == "CVE-2026-0001" for r in rows)


def test_epss_enrichment(fake_fetch):
    rows = cves.build_cve_rows([KEV_RESULT, NVD_RESULT], prior_rows=[], now=FIXED_NOW)
    url = cves.epss_url(["CVE-2026-1111", "CVE-2026-2222"])
    health = cves.enrich_epss(fake_fetch({url: "epss/scores.json"}), rows, FIXED_NOW)
    by_cve = {r["cve"]: r for r in rows}
    assert by_cve["CVE-2026-1111"]["epss"] == 0.92311
    assert health["ok"] is True and health["source"] == "epss"
