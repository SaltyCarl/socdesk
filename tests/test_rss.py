from collectors import rss
from pipeline.entities import classify_category, extract_entities
from tests.conftest import FIXED_NOW, FIXTURES


def test_extract_entities():
    e = extract_entities(
        "Akira ransomware exploiting CVE-2026-1111 in Fortinet devices "
        "with Cobalt Strike", "data/entities")
    assert "Akira" in e["actors"]
    assert "Cobalt Strike" in e["malware"]
    assert "Fortinet" in e["vendors"]
    assert e["cves"] == ["CVE-2026-1111"]


def test_classify_category():
    assert classify_category("Akira ransomware hits org", {"actors": ["Akira"], "malware": [], "vendors": [], "cves": []}) == "ransomware"
    assert classify_category("Patch now", {"actors": [], "malware": [], "vendors": [], "cves": ["CVE-2026-1"]}) == "vulnerability"
    assert classify_category("New infostealer wave observed", {"actors": [], "malware": ["Vidar"], "vendors": [], "cves": []}) == "malware"
    assert classify_category("Capture the flag recap", {"actors": [], "malware": [], "vendors": [], "cves": []}) == "report"  # 'apt' must not substring-match
    assert classify_category("Quarterly trends", {"actors": [], "malware": [], "vendors": [], "cves": []}) == "report"


def test_rss_collector(fake_fetch):
    mapping = {f["url"]: "" for f in rss.FEEDS}          # unmapped feeds: empty
    mapping[rss.FEEDS[0]["url"]] = (FIXTURES / "rss/talos.xml").read_text(encoding="utf-8")
    r = rss.collect(fake_fetch(mapping), FIXED_NOW)
    assert r.ok
    hits = [i for i in r.items if "Akira" in i["title"]]
    assert hits and hits[0]["category"] == "ransomware"
    assert hits[0]["severity"] == "medium"               # entity-bearing report
    assert hits[0]["entities"]["cves"] == ["CVE-2026-1111"]
