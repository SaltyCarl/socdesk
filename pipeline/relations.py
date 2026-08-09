"""Entity relationship index — every edge provable, nothing inferred.

Derived only from data the pipeline already owns:

- ATT&CK structure:   actor -> technique, actor -> software  (evidence "attack")
- Feed co-occurrence: cross-type entity pairs named in the same feed item,
  weighted by how many DISTINCT items support the pair, carrying those item
  ids as evidence so every edge is auditable against the published feed
- CVE metadata:       cve -> vendor / product from the CVE table (evidence
  "cve-db"), scoped to KEV-listed or feed-referenced CVEs

We hold no passive DNS / WHOIS / certificates / IP resolution (COMPLIANCE.md,
aggregator model): infrastructure pivots are out of scope and never faked.

Noise control: single-item co-occurrence edges are dropped unless one endpoint
is a KEV-listed CVE; per-node fan-out is capped, keeping the highest-weight
(KEV-preferred) edges. Output ordering is fully deterministic.
"""

MIN_COOCCUR_SUPPORT = 2   # distinct items required, unless a KEV CVE endpoint
FANOUT_CAP = 40           # max edges per node; an edge must fit BOTH endpoints
MAX_EVIDENCE = 8          # evidence ids per edge (weight keeps the true count)

_KIND_ORDER = {"actor": 0, "malware": 1, "cve": 2, "vendor": 3,
               "product": 4, "technique": 5}
# cross-type co-occurrence pairs we index (unordered), per the product spec
_COOCCUR_KINDS = {("actor", "malware"), ("actor", "cve"), ("actor", "vendor"),
                  ("malware", "vendor"), ("cve", "vendor")}


def _canon_map(profiles):
    """lowercased name/alias -> canonical ATT&CK name (first profile wins)."""
    canon = {}
    for p in sorted(profiles, key=lambda p: p.get("name", "")):
        for label in [p.get("name", "")] + list(p.get("aliases") or []):
            canon.setdefault(label.lower(), p["name"])
    return canon


class _Names:
    """Case-insensitive identity with a deterministic display spelling."""

    def __init__(self, canon=None):
        self.canon = canon or {}
        self.seen = {}                      # (kind, lower) -> sorted-min spelling

    def key(self, kind, raw):
        raw = (raw or "").strip()[:96]
        if not raw:
            return None
        name = self.canon.get(raw.lower(), raw)
        k = (kind, name.lower())
        if k not in self.seen or name < self.seen[k]:
            self.seen[k] = name
        return k

    def display(self, k):
        return self.seen[k]


def _item_entities(item, actors, malwares, vendors, cves):
    e = item.get("entities") or {}
    return {
        "actor": {actors.key("actor", a) for a in e.get("actors") or []},
        "malware": {malwares.key("malware", m) for m in e.get("malware") or []},
        "vendor": {vendors.key("vendor", v) for v in e.get("vendors") or []},
        "cve": {cves.key("cve", c.upper()) for c in e.get("cves") or []},
    }


def build_relations(feed_items=None, cve_rows=None,
                    actor_profiles=None, malware_profiles=None):
    """Return {"nodes": [...], "edges": [...]} — pure, deterministic."""
    feed_items = feed_items or []
    cve_rows = cve_rows or []
    actor_profiles = actor_profiles or []
    malware_profiles = malware_profiles or []

    actors = _Names(_canon_map(actor_profiles))
    malwares = _Names(_canon_map(malware_profiles))
    vendors, cves, plain = _Names(), _Names(), _Names()
    kev = {r["cve"].upper() for r in cve_rows if r.get("kev")}

    edges = {}                              # (type, src_key, dst_key) -> edge

    def add(etype, ka, kb, weight, evidence):
        if not ka or not kb or ka == kb:
            return
        if (_KIND_ORDER[ka[0]], ka) > (_KIND_ORDER[kb[0]], kb):
            ka, kb = kb, ka
        edges[(etype, ka, kb)] = {"type": etype, "src": ka, "dst": kb,
                                  "weight": weight, "evidence": evidence}

    # --- ATT&CK structural edges -------------------------------------------
    for p in sorted(actor_profiles, key=lambda p: p.get("name", "")):
        ka = actors.key("actor", p.get("name"))
        for t in sorted(set(p.get("techniques") or [])):
            add("uses_technique", ka, plain.key("technique", t), 1, ["attack"])
        for s in sorted(set(p.get("software") or [])):
            add("uses_software", ka, malwares.key("malware", s), 1, ["attack"])

    # --- feed co-occurrence -------------------------------------------------
    support = {}                            # (kind-pair keys) -> set(item ids)
    for item in feed_items:
        ents = _item_entities(item, actors, malwares, vendors, cves)
        iid = item.get("id", "")
        for kind_a, kind_b in sorted(_COOCCUR_KINDS):
            for ka in ents[kind_a]:
                for kb in ents[kind_b]:
                    if ka and kb:
                        support.setdefault((ka, kb), set()).add(iid)
    for (ka, kb), ids in sorted(support.items()):
        kev_endpoint = any(k[0] == "cve" and k[1].upper() in kev
                           for k in (ka, kb))
        if len(ids) >= MIN_COOCCUR_SUPPORT or kev_endpoint:
            add("cooccurs", ka, kb, len(ids), sorted(ids)[:MAX_EVIDENCE])

    # --- CVE -> vendor / product (KEV-listed or feed-referenced only) ------
    feed_cves = {k[1].upper() for k in cves.seen}
    for row in sorted(cve_rows, key=lambda r: r["cve"]):
        cid = row["cve"].upper()
        if not (row.get("kev") or cid in feed_cves):
            continue
        kc = cves.key("cve", cid)
        for v in sorted(set(row.get("vendors") or [])):
            add("affects_vendor", kc, vendors.key("vendor", v), 1, ["cve-db"])
        for pr in sorted(set(row.get("products") or [])):
            add("affects_product", kc, plain.key("product", pr), 1, ["cve-db"])

    # --- fan-out cap: an edge survives only inside BOTH endpoints' caps ----
    ordered = sorted(edges.items())
    incident = {}
    for i, ((_, ka, kb), e) in enumerate(ordered):
        for mine, other in ((ka, kb), (kb, ka)):
            rank = (-e["weight"],
                    0 if other[0] == "cve" and other[1].upper() in kev else 1,
                    e["type"], other)
            incident.setdefault(mine, []).append((rank, i))
    kept_per_node = {k: {i for _, i in sorted(v)[:FANOUT_CAP]}
                     for k, v in incident.items()}
    kept = [e for i, ((_, ka, kb), e) in enumerate(ordered)
            if i in kept_per_node[ka] and i in kept_per_node[kb]]

    # --- materialize node ids, compute degree ------------------------------
    def node_id(k):
        names = {"actor": actors, "malware": malwares, "vendor": vendors,
                 "cve": cves}.get(k[0], plain)
        return f"{k[0]}:{names.display(k)}"

    degree = {}
    for e in kept:
        e["src"], e["dst"] = node_id(e["src"]), node_id(e["dst"])
        degree[e["src"]] = degree.get(e["src"], 0) + 1
        degree[e["dst"]] = degree.get(e["dst"], 0) + 1
    nodes = [{"id": nid, "type": nid.split(":", 1)[0],
              "name": nid.split(":", 1)[1], "degree": deg}
             for nid, deg in sorted(degree.items())]
    for n in nodes:
        if n["type"] == "cve":
            n["kev"] = n["name"].upper() in kev
    kept.sort(key=lambda e: (e["type"], e["src"], e["dst"]))
    return {"nodes": nodes, "edges": kept}
