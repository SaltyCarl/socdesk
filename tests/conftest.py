import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"
FIXED_NOW = datetime(2026, 7, 28, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def now():
    return FIXED_NOW


@pytest.fixture
def fake_fetch():
    """fake_fetch({"https://url": payload_or_fixture_relpath}) -> fetch callable."""
    def _make(mapping):
        def fetch(url, *, method="GET", json=None, headers=None, text=False):
            if url not in mapping:
                raise RuntimeError(f"unexpected URL in test: {url}")
            val = mapping[url]
            if isinstance(val, str) and val.endswith(".json"):
                raw = (FIXTURES / val).read_text(encoding="utf-8")
                return raw if text else __import__("json").loads(raw)
            if isinstance(val, str):
                return val  # raw text (RSS xml)
            return val
        return fetch
    return _make
