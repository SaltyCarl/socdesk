from pipeline.relevance import apply_scores, group_repetitive, score_item

NOW = "2026-08-08T12:00:00Z"
CVES = [
    {"cve": "CVE-2026-1111", "kev": True, "epss": 0.87, "cvss": 9.8},
    {"cve": "CVE-2026-2222", "kev": False, "epss": 0.02, "cvss": 5.0},
]
IDX = {c["cve"]: c for c in CVES}


def item(**kw):
    base = {"source": "rss", "title": "t", "summary": "s", "severity": "info",
            "published_at": "2026-08-01T00:00:00Z",
            "entities": {"actors": [], "malware": [], "vendors": [], "cves": []}}
    base.update(kw)
    return base


def test_kev_reference_dominates_recency():
    old_kev = item(published_at="2026-08-01T00:00:00Z",
                   entities={"actors": [], "malware": [], "vendors": [],
                             "cves": ["CVE-2026-1111"]})
    fresh_nothing = item(published_at="2026-08-08T11:00:00Z")
    kev_score, why = score_item(old_kev, IDX, NOW)
    fresh_score, _ = score_item(fresh_nothing, IDX, NOW)
    assert kev_score > fresh_score          # an operational feed, not a newspaper
    assert "KEV-listed CVE" in why


def test_watchlist_hit_scores_and_explains():
    it = item(entities={"actors": [], "malware": [], "vendors": ["Fortinet"],
                        "cves": []})
    s, why = score_item(it, IDX, NOW, watchlist=["fortinet"])
    assert s >= 30 and any("watchlist" in w for w in why)


def test_tracked_actor_scores_and_names():
    it = item(entities={"actors": ["Sandworm"], "malware": [], "vendors": [],
                        "cves": []})
    s, why = score_item(it, IDX, NOW, tracked_actors={"sandworm"})
    assert s == 8
    assert "actor: Sandworm" in why


def test_untracked_leak_site_group_does_not_score_as_actor():
    """A ransomware.live group not in the curated dictionary must NOT earn the
    'tracked adversary' bonus — auto-tagging every group inflated ~half the feed
    by 8 and mislabelled unknown groups as tracked."""
    it = item(source="ransomwarelive",
              entities={"actors": ["ObscureLeakGroup"], "malware": [],
                        "vendors": [], "cves": []})
    s, why = score_item(it, IDX, NOW, tracked_actors={"sandworm", "akira"})
    assert s == 0
    assert not any(w.startswith("actor:") for w in why)


def test_tracked_ransomware_group_still_scores():
    """A leak-site group that IS in the dictionary (e.g. Akira) keeps the bonus."""
    it = item(entities={"actors": ["akira"], "malware": [], "vendors": [],
                        "cves": []})
    s, _ = score_item(it, IDX, NOW, tracked_actors={"akira"})
    assert s == 8


def test_score_is_capped_and_explained():
    it = item(severity="critical",
              published_at="2026-08-08T11:30:00Z",
              entities={"actors": ["Akira"], "malware": ["Cobalt Strike"],
                        "vendors": ["Fortinet"], "cves": ["CVE-2026-1111"]})
    s, why = score_item(it, IDX, NOW, watchlist=["fortinet"],
                        tracked_actors={"akira"})
    assert s == 100                          # capped
    assert len(why) >= 4


def test_apply_scores_annotates_every_item():
    items = [item(), item(entities={"actors": [], "malware": [], "vendors": [],
                                    "cves": ["CVE-2026-1111"]})]
    apply_scores(items, CVES, NOW)
    assert all("score" in i and "why" in i for i in items)
    assert len(items[1]["why"]) <= 4


def test_repetitive_claims_are_grouped_not_dropped():
    """~55% of the feed was near-identical victim-claim stubs; grouped they
    inform, individually they drown everything else."""
    sectors = ["Manufacturing", "Retail", "Manufacturing", "Healthcare",
               "Retail", "Manufacturing"]
    claims = [item(source="ransomwarelive", title=f"akira claim {n}",
                   summary=(f"Unverified claim by akira, per its leak site. "
                            f"Sector: {sectors[n]} — Country: US."),
                   published_at=f"2026-08-0{n + 1}T00:00:00Z",
                   victim=f"Victim {n}", domain=f"victim{n}.example",
                   url=f"http://abcxyz.onion/claim-{n}",
                   entities={"actors": ["akira"], "malware": [], "vendors": [],
                             "cves": []}) for n in range(6)]
    news = [item(title="real story")]
    out = group_repetitive(claims + news, "ransomwarelive",
                           lambda i: i["entities"]["actors"][0])
    by_title = {o["title"]: o for o in out}
    assert "akira posted 6 victim claims" in by_title
    assert "real story" in by_title
    assert len(out) == 2                     # 6 stubs collapsed to 1
    # digest names the distinct sectors, NOT the leading attribution prose
    digest = by_title["akira posted 6 victim claims"]
    assert digest["summary"] == "Grouped: Healthcare, Manufacturing, Retail"
    # the digest CARRIES its collapsed victims (Finding #1) — none are lost —
    # newest-first by published_at, and does NOT inherit a misleading scalar
    # victim/domain from group[0].
    assert "victim" not in digest
    assert "domain" not in digest
    claim_victims = [c["victim"] for c in digest["claims"]]
    assert claim_victims == ["Victim 5", "Victim 4", "Victim 3",
                              "Victim 2", "Victim 1", "Victim 0"]
    assert digest["claims"][0] == {
        "victim": "Victim 5", "domain": "victim5.example",
        "date": "2026-08-06T00:00:00Z", "url": "http://abcxyz.onion/claim-5",
    }


def test_small_groups_are_left_alone():
    claims = [item(source="ransomwarelive", title=f"c{n}",
                   entities={"actors": ["play"], "malware": [], "vendors": [],
                             "cves": []}) for n in range(2)]
    out = group_repetitive(claims, "ransomwarelive",
                           lambda i: i["entities"]["actors"][0])
    assert len(out) == 2                     # below threshold, untouched
