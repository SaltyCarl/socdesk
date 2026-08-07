from collectors.base import CollectorResult, iso, make_item, run_all
from tests.conftest import FIXED_NOW


def test_make_item_shape():
    item = make_item("rss", "native-1", "report", "Title", "Summary",
                     "https://x.test/a", "info", "2026-07-28T10:00:00Z", FIXED_NOW)
    assert len(item["id"]) == 40
    assert item["collected_at"] == "2026-07-28T12:00:00Z"
    assert item["entities"] == {"actors": [], "malware": [], "vendors": [], "cves": []}
    assert item["iocs"] == []


def test_make_item_sanitizes_upstream_markup():
    item = make_item("rss", "n2", "report",
                     "Breaking <img src=x onerror=alert(1)> &amp; more",
                     "<p>Body with <script>evil()</script> tags</p>",
                     "javascript:alert(1)", "info", "p", FIXED_NOW)
    assert item["title"] == "Breaking  & more"
    assert item["summary"] == "Body with evil() tags"
    assert item["url"] == ""                      # non-http scheme rejected
    ok = make_item("rss", "n3", "report", "T", "S",
                   "https://x.test/a", "info", "p", FIXED_NOW)
    assert ok["url"] == "https://x.test/a"


def test_unterminated_tag_cannot_borrow_a_closing_bracket():
    """Regression: `<[^>]*>` leaves an unterminated tag intact, which then
    borrows the `>` from surrounding template markup and executes."""
    item = make_item("rss", "x1", "report",
                     "Breaking <img src=x onerror=alert(1)//", "s",
                     "https://x.test/a", "info", "p", FIXED_NOW)
    assert "<" not in item["title"] and ">" not in item["title"]
    assert "onerror" in item["title"]      # kept as inert literal text


def test_entity_encoded_markup_does_not_survive_stripping():
    item = make_item("rss", "x2", "report",
                     "&lt;script&gt;alert(1)&lt;/script&gt; hi", "s",
                     "https://x.test/a", "info", "p", FIXED_NOW)
    assert "<" not in item["title"] and ">" not in item["title"]


def test_url_attribute_breakout_is_rejected():
    """Regression: a scheme-prefix check passes `http://x/" onmouseover=…`,
    which escapes the href attribute."""
    bad = make_item("rss", "x3", "report", "T", "s",
                    'http://x.test/" onmouseover="alert(1)', "info", "p", FIXED_NOW)
    assert bad["url"] == ""
    for u in ("javascript:alert(1)", "http://x.test/a b", "https://", "//evil.test"):
        assert make_item("rss", u, "report", "T", "s", u, "info", "p",
                         FIXED_NOW)["url"] == ""
    ok = make_item("rss", "x4", "report", "T", "s",
                   "https://x.test/a?b=1&c=2", "info", "p", FIXED_NOW)
    assert ok["url"] == "https://x.test/a?b=1&c=2"


def test_make_item_id_is_stable():
    a = make_item("rss", "native-1", "report", "T", "S", "u", "info", "p", FIXED_NOW)
    b = make_item("rss", "native-1", "report", "T2", "S2", "u2", "low", "p2", FIXED_NOW)
    assert a["id"] == b["id"]


class _Good:
    SOURCE = "good"
    @staticmethod
    def collect(fetch, now):
        return CollectorResult(source="good", items=[{"x": 1}], extra={"iocs": [1, 2]})


class _Boom:
    SOURCE = "boom"
    @staticmethod
    def collect(fetch, now):
        raise RuntimeError("upstream 500")


def test_run_all_isolates_failures():
    results, health = run_all([_Good, _Boom], fetch=None, now=FIXED_NOW)
    by_source = {r.source: r for r in results}
    assert by_source["good"].ok and not by_source["boom"].ok
    assert "upstream 500" in by_source["boom"].error
    h = {e["source"]: e for e in health}
    assert h["good"]["items"] == 3          # 1 item + 2 extra rows
    assert h["good"]["last_success_at"] == iso(FIXED_NOW)
    assert h["boom"]["ok"] is False and h["boom"]["last_success_at"] == ""
