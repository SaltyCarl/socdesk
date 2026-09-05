from pipeline.stories import build_stories, story_outlet, established_actors
from pipeline.validate import validate_payload


def item(id, source, title, entities=None, published_at="2026-09-05T00:00:00Z", severity="high"):
    return {"id": id, "source": source, "title": title,
            "entities": entities or {"actors": [], "malware": [], "vendors": [], "cves": []},
            "published_at": published_at, "severity": severity}


def cve_ents(cve):
    return {"actors": [], "malware": [], "vendors": [], "cves": [cve]}


def actor_ents(a):
    return {"actors": [a], "malware": [], "vendors": [], "cves": []}


def test_story_outlet_maps_source_and_bracket_prefix():
    assert story_outlet(item("1", "rss", "[BleepingComputer] Big breach")) == "BleepingComputer"
    assert story_outlet(item("2", "kev", "CVE-2026-1 added")) == "CISA KEV"
    assert story_outlet(item("3", "ransomwarelive", "acme leaked")) == "ransomware.live"


def test_two_outlets_one_cve_makes_a_story_with_catalog_delta():
    feed = [
        item("a", "rss", "[BleepingComputer] PAN-OS RCE", cve_ents("CVE-2026-3400")),
        item("b", "rss", "[The Hacker News] PAN-OS actively exploited", cve_ents("CVE-2026-3400")),
    ]
    cve_rows = [{"cve": "CVE-2026-3400", "kev": True, "kev_ransomware": False, "epss": 0.94}]
    trends = {"epss_movers": [{"cve": "CVE-2026-3400", "from": 0.71, "to": 0.94}]}
    out = build_stories(feed, cve_rows, trends, actors=[], intel=[])
    assert len(out["stories"]) == 1
    s = out["stories"][0]
    assert s["entity"] == "CVE-2026-3400" and s["member_count"] == 2
    assert set(s["outlets"]) == {"BleepingComputer", "The Hacker News"}
    assert s["delta"]["kev"] is True and s["delta"]["epss"] == 0.94
    assert s["delta"]["epss_from"] == 0.71 and s["delta"]["epss_to"] == 0.94
    assert s["title"] == "PAN-OS actively exploited" or s["title"] == "PAN-OS RCE"


def test_same_outlet_twice_is_not_a_story():
    feed = [
        item("a", "rss", "[BleepingComputer] part 1", cve_ents("CVE-2026-9")),
        item("b", "rss", "[BleepingComputer] part 2", cve_ents("CVE-2026-9")),
    ]
    out = build_stories(feed, cve_rows=[], trends={}, actors=[], intel=[])
    assert out["stories"] == []  # one distinct outlet -> not corroborated


def test_unestablished_actor_does_not_anchor_a_story():
    # "play" (Google Play) covered by two outlets must NOT become a story unless
    # it is a tracked ransomware actor.
    feed = [
        item("a", "rss", "[BleepingComputer] Google Play policy change", actor_ents("play")),
        item("b", "rss", "[The Hacker News] Play Store update", actor_ents("play")),
    ]
    out = build_stories(feed, cve_rows=[], trends={}, actors=[{"name": "APT29"}], intel=[])
    assert out["stories"] == []


def test_established_actor_two_outlets_makes_a_delta_less_story():
    feed = [
        item("a", "rss", "[BleepingComputer] APT29 campaign", actor_ents("APT29")),
        item("b", "rss", "[Unit 42] APT29 new tooling", actor_ents("APT29")),
    ]
    out = build_stories(feed, cve_rows=[], trends={}, actors=[{"name": "APT29"}], intel=[])
    assert len(out["stories"]) == 1
    s = out["stories"][0]
    assert s["entity_type"] == "actor" and "delta" not in s
    assert set(s["outlets"]) == {"BleepingComputer", "Unit 42"}


def test_established_actors_gate_sources():
    est = established_actors(
        actors=[{"name": "APT29", "aliases": ["Cozy Bear"]}],
        intel=[{"slug": "lockbit", "slug_aliases": ["lockbit5"]}],
        feed_items=[item("x", "ransomwarelive", "victim", actor_ents("Qilin"))])
    assert {"apt29", "cozy bear", "lockbit", "lockbit5", "qilin"} <= est


def test_built_payload_validates_against_schema():
    feed = [
        item("a", "rss", "[BleepingComputer] X", cve_ents("CVE-2026-1")),
        item("b", "rss", "[The Hacker News] X", cve_ents("CVE-2026-1")),
    ]
    out = build_stories(feed, cve_rows=[{"cve": "CVE-2026-1", "kev": True, "epss": 0.5}],
                        trends={}, actors=[], intel=[])
    payload = dict(out, generated_at="2026-09-05T00:00:00Z", schema_version=1)
    assert validate_payload("stories.json", payload, "schemas") == []
    assert validate_payload("stories.json", {"generated_at": "x", "schema_version": 1, "stories": []}, "schemas") == []
