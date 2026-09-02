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
    by_id, rels = {}, []
    for o in objs:
        if o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        if o["type"] in ("intrusion-set", "malware", "tool", "attack-pattern"):
            by_id[o["id"]] = o
        elif o["type"] == "relationship" and o.get("relationship_type") == "uses":
            rels.append(o)

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
            malware.append({
                "name": o["name"], "attack_id": _attack_id(o),
                "aliases": o.get("x_mitre_aliases", []),
                "description": _clip(o.get("description")),
                "techniques": [], "software": [],
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
    return CollectorResult(
        source=SOURCE,
        extra={"actors": actors, "malware": malware, "technique_names": technique_names},
    )
