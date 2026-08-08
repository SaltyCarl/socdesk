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


def test_score_is_capped_and_explained():
    it = item(severity="critical",
              published_at="2026-08-08T11:30:00Z",
              entities={"actors": ["Akira"], "malware": ["Cobalt Strike"],
                        "vendors": ["Fortinet"], "cves": ["CVE-2026-1111"]})
    s, why = score_item(it, IDX, NOW, watchlist=["fortinet"])
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
    claims = [item(source="ransomwarelive", title=f"akira claim {n}",
                   summary="Sector: Manufacturing — Country: US",
                   entities={"actors": ["akira"], "malware": [], "vendors": [],
                             "cves": []}) for n in range(6)]
    news = [item(title="real story")]
    out = group_repetitive(claims + news, "ransomwarelive",
                           lambda i: i["entities"]["actors"][0])
    titles = [o["title"] for o in out]
    assert "akira posted 6 victim claims" in titles
    assert "real story" in titles
    assert len(out) == 2                     # 6 stubs collapsed to 1


def test_small_groups_are_left_alone():
    claims = [item(source="ransomwarelive", title=f"c{n}",
                   entities={"actors": ["play"], "malware": [], "vendors": [],
                             "cves": []}) for n in range(2)]
    out = group_repetitive(claims, "ransomwarelive",
                           lambda i: i["entities"]["actors"][0])
    assert len(out) == 2                     # below threshold, untouched
