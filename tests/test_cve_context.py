from pipeline.cves import build_cve_context

GROUPS = [
    {"slug": "akira", "name": "Akira",
     "initial_access_cves": ["CVE-2023-20269", "CVE-2020-3259"]},
    {"slug": "nocve", "name": "NoCve"},
]
ROWS = [
    {"cve": "CVE-2023-20269", "kev": True, "kev_ransomware": True,
     "epss": 0.94, "cvss": 9.1, "kev_due_date": "2023-09-27"},
    # sparse row: no due-date key, None epss/cvss, not ransomware-flagged
    {"cve": "CVE-2020-3259", "kev": True, "kev_ransomware": False,
     "epss": None, "cvss": None},
    {"cve": "CVE-2099-1111", "kev": True, "epss": 0.5},  # named by no seed group
]


def test_build_cve_context_joins_and_omits_empties():
    ctx = build_cve_context(GROUPS, ROWS)
    assert ctx["CVE-2023-20269"] == {
        "kev": True, "kev_ransomware": True, "epss": 0.94, "cvss": 9.1,
        "kev_due_date": "2023-09-27"}
    # None/absent/false fields are OMITTED, never emitted as null/false noise
    assert ctx["CVE-2020-3259"] == {"kev": True}
    # a CVE no seed group names never rides along
    assert "CVE-2099-1111" not in ctx


def test_build_cve_context_empty_inputs_yield_empty_map():
    assert build_cve_context([], ROWS) == {}
    assert build_cve_context(GROUPS, []) == {}


def test_schema_accepts_context_and_empty_map():
    from pipeline.validate import validate_payload
    base = {"generated_at": "x", "schema_version": 1, "groups": [
        {"slug": "akira", "name": "Akira"}]}
    good = dict(base, cve_context={"CVE-2023-20269": {"kev": True, "epss": 0.94}})
    assert validate_payload("ransomware_intel.json", good, "schemas") == []
    empty = dict(base, cve_context={})
    assert validate_payload("ransomware_intel.json", empty, "schemas") == []


def test_schema_rejects_bad_context_shapes():
    from pipeline.validate import validate_payload
    base = {"generated_at": "x", "schema_version": 1, "groups": [
        {"slug": "akira", "name": "Akira"}]}
    bad_key = dict(base, cve_context={"NOTACVE": {"kev": True}})
    assert validate_payload("ransomware_intel.json", bad_key, "schemas") != []
    bad_epss = dict(base, cve_context={"CVE-2023-20269": {"epss": 1.5}})
    assert validate_payload("ransomware_intel.json", bad_epss, "schemas") != []
    extra_field = dict(base, cve_context={"CVE-2023-20269": {"verdict": "bad"}})
    assert validate_payload("ransomware_intel.json", extra_field, "schemas") != []
