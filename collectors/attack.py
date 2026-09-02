from collectors.base import CollectorResult

SOURCE = "attack"
URL = ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
       "master/enterprise-attack/enterprise-attack.json")
CACHE_DAYS = 7  # pipeline skips this collector when state is fresher than this


def _attack_id(obj):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id", "")
    return ""


def _clip(text, cap=800):
    """Cap a description at a WORD boundary, never mid-word/mid-token.

    A blind [:800] cut shipped dangling markdown tails ("...the [SolarWinds
    Compromise](https://attack.mitre.org/campaigns/C") that leaked raw into the
    UI. Cutting at the last whitespace <= cap removes most of those shapes at
    the source; the frontend's cleanDescription remains the backstop for the
    ones a word cut can still produce (link ALIAS text itself contains spaces).
    """
    t = text or ""
    if len(t) <= cap:
        return t
    cut = t[:cap]
    ws = cut.rfind(" ")
    return cut[:ws] if ws > 0 else cut


def collect(fetch, now):
    bundle = fetch(URL)
    objs = bundle.get("objects", [])
    by_id, rels, tactics, matrices = {}, [], {}, []
    for o in objs:
        if o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        if o["type"] in ("intrusion-set", "malware", "tool", "attack-pattern"):
            by_id[o["id"]] = o
        elif o["type"] == "relationship" and o.get("relationship_type") == "uses":
            rels.append(o)
        elif o["type"] == "x-mitre-tactic":
            tactics[o["id"]] = o
        elif o["type"] == "x-mitre-matrix":
            matrices.append(o)

    uses = {}
    for r in rels:
        uses.setdefault(r["source_ref"], []).append(r["target_ref"])

    actors, malware = [], []
    for o in by_id.values():
        if o["type"] == "intrusion-set":
            techniques, software = [], []
            for tgt in uses.get(o["id"], []):
                t = by_id.get(tgt)
                if not t:
                    continue
                if t["type"] == "attack-pattern":
                    techniques.append(_attack_id(t))
                elif t["type"] in ("malware", "tool"):
                    software.append(t["name"])
            actors.append({
                "name": o["name"], "attack_id": _attack_id(o),
                "aliases": o.get("aliases", []),
                "description": _clip(o.get("description")),
                "techniques": sorted(t for t in techniques if t),
                "software": sorted(software),
            })
        elif o["type"] in ("malware", "tool"):
            # A malware/tool's own `uses` rels target attack-patterns — the
            # same map the actor branch consumes; hardcoding [] here left 825
            # profiles techniqueless while the data sat already-parsed.
            # sorted(set(...)): real bundles carry duplicate rels. software
            # stays [] — malware→malware uses rels don't exist in the bundle.
            mw_techniques = {
                _attack_id(by_id[tgt])
                for tgt in uses.get(o["id"], [])
                if tgt in by_id and by_id[tgt]["type"] == "attack-pattern"
            }
            malware.append({
                "name": o["name"], "attack_id": _attack_id(o),
                "aliases": o.get("x_mitre_aliases", []),
                "description": _clip(o.get("description")),
                "techniques": sorted(t for t in mw_techniques if t), "software": [],
            })
    actors.sort(key=lambda a: a["attack_id"])
    malware.sort(key=lambda m: m["attack_id"])
    # id -> human name for every technique, so the frontend can label the bare
    # T-ids an actor's fingerprint carries (the name is right here in the STIX;
    # the per-actor `techniques` list stays id-only — relations.py consumes it as
    # strings — and the names ride a separate committed catalog).
    technique_names = {
        aid: o["name"]
        for o in by_id.values()
        if o["type"] == "attack-pattern" and (aid := _attack_id(o))
    }
    # Technique -> tactic slugs (mitre-attack kill chain only), plus the
    # matrix's OWN tactic order + display names. NEVER hardcode a tactic list
    # client-side: the live matrix has drifted from the classic 14 (e.g.
    # defense-evasion no longer exists — stealth + defense-impairment do), so
    # the order ships from the bundle itself via x-mitre-matrix.tactic_refs.
    technique_tactics = {}
    for o in by_id.values():
        if o["type"] != "attack-pattern":
            continue
        aid = _attack_id(o)
        if not aid:
            continue
        phases = sorted({
            p.get("phase_name", "")
            for p in o.get("kill_chain_phases", [])
            if p.get("kill_chain_name") == "mitre-attack" and p.get("phase_name")
        })
        if phases:
            technique_tactics[aid] = phases
    tactic_order = [
        {"slug": t["x_mitre_shortname"], "name": t["name"]}
        for m in matrices
        for ref in m.get("tactic_refs", [])
        if (t := tactics.get(ref)) and t.get("x_mitre_shortname") and t.get("name")
    ]
    return CollectorResult(
        source=SOURCE,
        extra={
            "actors": actors, "malware": malware,
            "technique_names": technique_names,
            "technique_tactics": {"tactics": technique_tactics, "order": tactic_order},
        },
    )
