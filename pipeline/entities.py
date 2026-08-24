import json
import re
from functools import lru_cache
from pathlib import Path

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


@lru_cache(maxsize=None)
def _dictionaries(entities_dir):
    d = Path(entities_dir)
    return {
        "actors": json.loads((d / "actors.json").read_text(encoding="utf-8")),
        "malware": json.loads((d / "malware.json").read_text(encoding="utf-8")),
        "vendors": json.loads((d / "vendors.json").read_text(encoding="utf-8")),
    }


def extract_entities(text, entities_dir="data/entities"):
    dicts = _dictionaries(entities_dir)
    lower = text.lower()
    found = {"actors": [], "malware": [], "vendors": [], "cves": []}
    for kind in ("actors", "malware", "vendors"):
        for name in dicts[kind]:
            if re.search(rf"\b{re.escape(name.lower())}\b", lower):
                found[kind].append(name)
    found["cves"] = sorted({m.upper() for m in CVE_RE.findall(text)})
    return found


def tracked_actor_set(entities_dir="data/entities"):
    """Lowercased set of curated tracked-adversary names — the authority for the
    relevance scorer's "names a tracked adversary" signal. Only a name in this
    dictionary earns the bonus; a raw leak-site group injected into an item's
    actors (ransomware.live) does not, unless it is independently tracked here."""
    return frozenset(a.lower() for a in _dictionaries(entities_dir)["actors"])


RANSOM_ACTORS = {"akira", "lockbit", "alphv", "blackcat", "play", "cl0p",
                 "black basta", "ransomhub", "medusa", "rhysida", "qilin",
                 "8base", "conti", "royal"}


def classify_category(title, entities):
    tl = title.lower()
    if "ransom" in tl or any(a.lower() in RANSOM_ACTORS for a in entities["actors"]):
        return "ransomware"
    if entities["cves"] or "vulnerab" in tl or "patch" in tl or "zero-day" in tl:
        return "vulnerability"
    if re.search(r"\bapt\d*\b", tl) or (entities["actors"] and not entities["malware"]):
        return "apt"
    if "campaign" in tl or "phishing" in tl:
        return "campaign"
    if entities["malware"]:
        return "malware"
    return "report"
