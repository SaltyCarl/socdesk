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
                "description": (o.get("description") or "")[:800],
                "techniques": sorted(t for t in techniques if t),
                "software": sorted(software),
            })
        elif o["type"] in ("malware", "tool"):
            malware.append({
                "name": o["name"], "attack_id": _attack_id(o),
                "aliases": o.get("x_mitre_aliases", []),
                "description": (o.get("description") or "")[:800],
                "techniques": [], "software": [],
            })
    actors.sort(key=lambda a: a["attack_id"])
    malware.sort(key=lambda m: m["attack_id"])
    return CollectorResult(source=SOURCE, extra={"actors": actors, "malware": malware})
