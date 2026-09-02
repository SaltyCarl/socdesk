from collectors import attack
from tests.conftest import FIXED_NOW


def test_attack_profiles(fake_fetch):
    r = attack.collect(fake_fetch({attack.URL: "attack/enterprise.json"}), FIXED_NOW)
    assert r.ok
    actors = r.extra["actors"]
    assert len(actors) == 1                      # revoked object dropped
    a = actors[0]
    assert a["name"] == "APT9999" and a["attack_id"] == "G9999"
    assert a["techniques"] == ["T1566"]
    assert a["software"] == ["TestRAT"]
    malware = r.extra["malware"]
    assert malware[0]["attack_id"] == "S9999"
    # id -> name catalog for the frontend to label the bare technique ids
    assert r.extra["technique_names"] == {"T1566": "Phishing"}


def test_clip_cuts_at_word_boundary_never_mid_token():
    long = ("word " * 200).strip()          # 999 chars of clean words
    out = attack._clip(long, cap=800)
    assert len(out) <= 800
    assert not out.endswith(" ") and out.endswith("word")  # whole final word
    # short text passes through untouched
    assert attack._clip("short text.", cap=800) == "short text."
    # a single 900-char token can't word-cut — falls back to the hard cap
    assert len(attack._clip("x" * 900, cap=800)) == 800
