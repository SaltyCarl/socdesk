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
