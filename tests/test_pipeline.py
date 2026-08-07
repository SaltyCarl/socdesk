import json

from run_pipeline import run
from tests.conftest import FIXED_NOW, FIXTURES


def test_end_to_end_with_one_source_down(fake_fetch, tmp_path):
    from collectors import attack, kev, nvd, rss
    rss_xml = (FIXTURES / "rss/talos.xml").read_text(encoding="utf-8")
    mapping = {
        kev.URL: "kev/feed.json",
        nvd.build_url(FIXED_NOW): "nvd/recent.json",
        attack.URL: "attack/enterprise.json",
        # ransomwarelive.URL deliberately unmapped -> collector fails
    }
    for f in rss.FEEDS:
        mapping[f["url"]] = rss_xml if f is rss.FEEDS[0] else ""
    # EPSS URLs vary by CVE set; route any api.first.org URL to the fixture
    fetch_inner = fake_fetch(mapping)

    def fetch(url, **kw):
        if url.startswith("https://api.first.org"):
            return json.loads((FIXTURES / "epss/scores.json").read_text(encoding="utf-8"))
        return fetch_inner(url, **kw)

    out = tmp_path / "site_data"
    state = tmp_path / "state"
    run(fetch=fetch, now=FIXED_NOW, out_dir=out, state_dir=state,
        schemas_dir="schemas", sources_path="data/sources.json")

    published = {p.name for p in out.iterdir()}
    assert {"feed.json", "cves.json", "health.json", "sources.json",
            "actors.json", "malware.json"} <= published
    assert "iocs.json" not in published        # aggregator model, no corpus

    health = json.loads((out / "health.json").read_text(encoding="utf-8"))
    by_source = {s["source"]: s for s in health["sources"]}
    assert by_source["ransomwarelive"]["ok"] is False     # isolated failure
    assert by_source["kev"]["ok"] is True

    # state mirrors published payloads for next run's last-known-good
    assert (state / "feed.json").exists()

    # second run consumes state without error (idempotent)
    run(fetch=fetch, now=FIXED_NOW, out_dir=out, state_dir=state,
        schemas_dir="schemas", sources_path="data/sources.json")
