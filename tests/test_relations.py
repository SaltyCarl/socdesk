"""Relationship index: every edge provable, noise pruned, output deterministic."""
import json
import random

from pipeline.relations import FANOUT_CAP, MIN_COOCCUR_SUPPORT, build_relations


def feed_item(n, **entities):
    base = {"actors": [], "malware": [], "vendors": [], "cves": []}
    base.update(entities)
    return {"id": f"{n:040x}", "entities": base}


def edges_of(rel, etype=None):
    return [e for e in rel["edges"] if etype is None or e["type"] == etype]


# --- evidence: no edge without proof ---------------------------------------

def test_every_edge_carries_evidence():
    rel = build_relations(
        feed_items=[feed_item(1, actors=["FIN7"], malware=["Carbanak"]),
                    feed_item(2, actors=["FIN7"], malware=["Carbanak"])],
        cve_rows=[{"cve": "CVE-2026-0001", "kev": True,
                   "vendors": ["Acme"], "products": ["Widget"]}],
        actor_profiles=[{"name": "FIN7", "aliases": [],
                         "techniques": ["T1059"], "software": ["Carbanak"]}])
    assert rel["edges"] and all(e["evidence"] for e in rel["edges"])
    cooc = edges_of(rel, "cooccurs")
    assert cooc and cooc[0]["evidence"] == [f"{1:040x}", f"{2:040x}"]
    assert cooc[0]["weight"] == 2            # weight == distinct supporting items
    assert all(e["evidence"] == ["attack"]
               for e in edges_of(rel, "uses_technique"))
    assert all(e["evidence"] == ["cve-db"]
               for e in edges_of(rel, "affects_vendor"))


# --- pruning: single-support noise out, KEV pairs survive -------------------

def test_single_support_cooccurrence_is_pruned():
    rel = build_relations(
        feed_items=[feed_item(1, actors=["FIN7"], vendors=["Acme"])])
    assert edges_of(rel, "cooccurs") == []


def test_single_support_survives_when_cve_is_kev():
    rel = build_relations(
        feed_items=[feed_item(1, actors=["FIN7"], cves=["CVE-2026-0001"]),
                    feed_item(2, actors=["FIN7"], cves=["CVE-2026-0002"])],
        cve_rows=[{"cve": "CVE-2026-0001", "kev": True},
                  {"cve": "CVE-2026-0002", "kev": False}])
    pairs = {(e["src"], e["dst"]) for e in edges_of(rel, "cooccurs")}
    assert ("actor:FIN7", "cve:CVE-2026-0001") in pairs   # KEV: kept at w=1
    assert ("actor:FIN7", "cve:CVE-2026-0002") not in pairs


def test_multi_support_survives_without_kev():
    items = [feed_item(n, actors=["Akira"], vendors=["SonicWall"])
             for n in range(MIN_COOCCUR_SUPPORT)]
    rel = build_relations(feed_items=items)
    assert len(edges_of(rel, "cooccurs")) == 1


def test_cve_vendor_edges_scoped_to_kev_or_feed():
    rel = build_relations(
        feed_items=[feed_item(1, cves=["CVE-2026-0002"], vendors=["Beta"]),
                    feed_item(2, cves=["CVE-2026-0002"], vendors=["Beta"])],
        cve_rows=[{"cve": "CVE-2026-0001", "kev": True, "vendors": ["Acme"]},
                  {"cve": "CVE-2026-0002", "kev": False, "vendors": ["Beta"]},
                  {"cve": "CVE-2026-0003", "kev": False, "vendors": ["Gamma"]}])
    srcs = {e["src"] for e in edges_of(rel, "affects_vendor")}
    assert srcs == {"cve:CVE-2026-0001", "cve:CVE-2026-0002"}  # no 0003


# --- fan-out cap ------------------------------------------------------------

def test_fanout_is_capped_per_node():
    profile = {"name": "Busy", "aliases": [],
               "techniques": [f"T1{n:03d}" for n in range(FANOUT_CAP + 25)],
               "software": []}
    rel = build_relations(actor_profiles=[profile])
    assert len(rel["edges"]) == FANOUT_CAP
    busy = next(n for n in rel["nodes"] if n["id"] == "actor:Busy")
    assert busy["degree"] == FANOUT_CAP


def test_degree_reflects_surviving_edges_only():
    rel = build_relations(actor_profiles=[
        {"name": "A", "techniques": [f"T1{n:03d}" for n in range(5)]}])
    assert all(n["degree"] >= 1 for n in rel["nodes"])
    assert sum(n["degree"] for n in rel["nodes"]) == 2 * len(rel["edges"])


# --- determinism ------------------------------------------------------------

def test_output_is_deterministic_under_input_shuffle():
    items = [feed_item(n, actors=["FIN7", "Akira"], vendors=["Acme", "Beta"],
                       cves=[f"CVE-2026-{n % 3:04d}"]) for n in range(12)]
    rows = [{"cve": f"CVE-2026-{n:04d}", "kev": n == 0,
             "vendors": ["Acme"], "products": ["Widget"]} for n in range(3)]
    profiles = [{"name": "FIN7", "aliases": ["Carbon Spider"],
                 "techniques": ["T1059", "T1003"], "software": ["Carbanak"]}]
    a = build_relations(items, rows, profiles)
    shuffled = list(items)
    random.Random(7).shuffle(shuffled)
    b = build_relations(shuffled, list(reversed(rows)), profiles)
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
    assert a["nodes"] == sorted(a["nodes"], key=lambda n: n["id"])
    assert a["edges"] == sorted(a["edges"],
                                key=lambda e: (e["type"], e["src"], e["dst"]))


def test_feed_alias_resolves_to_canonical_actor():
    """'akira' in the feed and 'Akira' in ATT&CK must be ONE node."""
    rel = build_relations(
        feed_items=[feed_item(n, actors=["akira"], vendors=["SonicWall"])
                    for n in range(2)],
        actor_profiles=[{"name": "Akira", "aliases": ["akira"],
                         "techniques": ["T1486"], "software": []}])
    ids = {n["id"] for n in rel["nodes"]}
    assert "actor:Akira" in ids and "actor:akira" not in ids


# --- resilience -------------------------------------------------------------

def test_empty_and_missing_inputs_do_not_explode():
    assert build_relations() == {"nodes": [], "edges": []}
    assert build_relations([], [], [], []) == {"nodes": [], "edges": []}
    rel = build_relations(
        feed_items=[{"id": "x" * 40}, {"id": "y" * 40, "entities": {}}],
        cve_rows=[{"cve": "CVE-2026-0001", "kev": True}])   # no vendors key
    assert rel["edges"] == []
