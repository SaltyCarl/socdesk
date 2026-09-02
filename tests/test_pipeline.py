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
            "actors.json", "malware.json", "ransomware_intel.json"} <= published
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


def _pipeline_fetch(fake_fetch):
    """The collector mapping test_end_to_end uses, as a reusable fetch (so the
    community wiring tests exercise a REAL run() without re-listing sources)."""
    from collectors import attack, kev, nvd, rss
    rss_xml = (FIXTURES / "rss/talos.xml").read_text(encoding="utf-8")
    mapping = {kev.URL: "kev/feed.json", nvd.build_url(FIXED_NOW): "nvd/recent.json",
               attack.URL: "attack/enterprise.json"}
    for f in rss.FEEDS:
        mapping[f["url"]] = rss_xml if f is rss.FEEDS[0] else ""
    inner = fake_fetch(mapping)

    def fetch(url, **kw):
        if url.startswith("https://api.first.org"):
            return json.loads((FIXTURES / "epss/scores.json").read_text(encoding="utf-8"))
        return inner(url, **kw)
    return fetch


def test_community_payload_published_and_env_threaded(fake_fetch, tmp_path, monkeypatch):
    import run_pipeline
    payload = {"generated_at": "seed", "schema_version": 1, "attribution": "a",
               "count": 1, "report_count": 1,
               "indicators": {"ipv4|203.0.113.4": {
                   "type": "ipv4", "value": "203.0.113.4", "reporters": 1,
                   "categories": ["ssh"], "first_reported": "2026-08-10",
                   "latest_reported": "2026-08-10"}}}
    seen = {}

    def fake_build(fetch, now, env):
        seen["env"] = env
        return payload
    monkeypatch.setattr(run_pipeline, "build_community_reports", fake_build)

    out, state = tmp_path / "o", tmp_path / "s"
    run(fetch=_pipeline_fetch(fake_fetch), now=FIXED_NOW, out_dir=out, state_dir=state,
        schemas_dir="schemas", sources_path="data/sources.json",
        env={"CLOUDFLARE_ACCOUNT_ID": "acct"})

    assert seen["env"] == {"CLOUDFLARE_ACCOUNT_ID": "acct"}   # env threaded through
    written = json.loads((state / "community_reports.json").read_text(encoding="utf-8"))
    assert written["indicators"]["ipv4|203.0.113.4"]["reporters"] == 1


def test_community_keeps_last_known_good_on_none(fake_fetch, tmp_path, monkeypatch):
    import run_pipeline
    monkeypatch.setattr(run_pipeline, "build_community_reports",
                        lambda fetch, now, env: None)
    out, state = tmp_path / "o", tmp_path / "s"
    state.mkdir(parents=True)
    prior = {"generated_at": "2020-01-01T00:00:00Z", "schema_version": 1,
             "attribution": "a", "count": 0, "report_count": 0, "indicators": {}}
    (state / "community_reports.json").write_text(json.dumps(prior), encoding="utf-8")

    run(fetch=_pipeline_fetch(fake_fetch), now=FIXED_NOW, out_dir=out, state_dir=state,
        schemas_dir="schemas", sources_path="data/sources.json", env={})

    kept = json.loads((out / "community_reports.json").read_text(encoding="utf-8"))
    assert kept["indicators"] == {}                          # prior retained (not blanked)
    assert kept["generated_at"] != prior["generated_at"]     # re-stamped this run


def test_asn_leaderboard_published_and_token_threaded(fake_fetch, tmp_path, monkeypatch):
    import run_pipeline
    payload = {"generated_at": "seed", "schema_version": 1, "attribution": "a",
               "count": 1, "total_abusive_ips": 1, "unattributed_ips": 0,
               "cap": 200, "truncated": False,
               "networks": [{"asn": "AS64500", "isp": "Example", "country": "US",
                             "ip_count": 1, "report_count": 1,
                             "categories": ["ssh"], "sources": ["community"],
                             "examples": ["1.2.3.4"]}]}
    seen = {}

    def fake_build(community, threat_ips, cache, fetch, now, token):
        seen["token"] = token
        cache["1.2.3.4"] = {"asn": "AS64500", "isp": "Example", "country": "US"}
        return payload
    monkeypatch.setattr(run_pipeline, "build_asn_leaderboard", fake_build)

    out, state = tmp_path / "o", tmp_path / "s"
    run(fetch=_pipeline_fetch(fake_fetch), now=FIXED_NOW, out_dir=out, state_dir=state,
        schemas_dir="schemas", sources_path="data/sources.json",
        env={"IPINFO_TOKEN": "tok"})

    assert seen["token"] == "tok"                     # threaded via run()'s env
    written = json.loads((out / "asn_leaderboard.json").read_text(encoding="utf-8"))
    assert written["networks"][0]["asn"] == "AS64500"
    cache = json.loads((state / "asn_cache.json").read_text(encoding="utf-8"))
    assert cache["1.2.3.4"]["asn"] == "AS64500"        # cache persisted


def test_asn_leaderboard_keeps_last_known_good_on_none(fake_fetch, tmp_path, monkeypatch):
    import run_pipeline
    monkeypatch.setattr(run_pipeline, "build_asn_leaderboard",
                        lambda community, threat_ips, cache, fetch, now, token: None)
    out, state = tmp_path / "o", tmp_path / "s"
    state.mkdir(parents=True)
    prior = {"generated_at": "2020-01-01T00:00:00Z", "schema_version": 1,
             "attribution": "a", "count": 0, "total_abusive_ips": 0,
             "unattributed_ips": 0, "cap": 200, "truncated": False, "networks": []}
    (state / "asn_leaderboard.json").write_text(json.dumps(prior), encoding="utf-8")

    run(fetch=_pipeline_fetch(fake_fetch), now=FIXED_NOW, out_dir=out, state_dir=state,
        schemas_dir="schemas", sources_path="data/sources.json", env={})

    kept = json.loads((out / "asn_leaderboard.json").read_text(encoding="utf-8"))
    assert kept["networks"] == []                      # prior retained (not blanked)
    assert kept["generated_at"] != prior["generated_at"]   # re-stamped this run


def test_attack_is_fresh_requires_derived_catalogs():
    """The freshness gate must treat attack as STALE until every derived
    catalog exists — else a catalog added after actors.json never generates
    (and, inverted, a missing-catalog bug would re-fetch the 54 MB bundle
    every cycle: the gate is the only thing standing between the two)."""
    from run_pipeline import _attack_is_fresh
    from tests.conftest import FIXED_NOW
    from collectors.base import iso
    fresh_col = {"collected_at": iso(FIXED_NOW)}
    full = {"actors.json": fresh_col, "technique_names.json": {},
            "technique_tactics.json": {}}
    assert _attack_is_fresh(full, FIXED_NOW) is True
    for missing in ("technique_names.json", "technique_tactics.json"):
        state = {k: v for k, v in full.items() if k != missing}
        assert _attack_is_fresh(state, FIXED_NOW) is False
    stale = dict(full, **{"actors.json": {"collected_at": "2020-01-01T00:00:00Z"}})
    assert _attack_is_fresh(stale, FIXED_NOW) is False
    # ⚠ the bug this gate fixes: a FRESH generated_at (keep-prior re-stamps it
    # every cycle) with an old/absent collected_at must read STALE, not fresh —
    # the ATT&CK snapshot sat frozen 35 days on the generated_at version.
    restamped = dict(full, **{"actors.json": {"generated_at": iso(FIXED_NOW)}})
    assert _attack_is_fresh(restamped, FIXED_NOW) is False
