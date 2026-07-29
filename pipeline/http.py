import httpx

HEADERS = {"User-Agent": "VIGIL-collector/0.1 (+https://github.com/SaltyCarl)"}


def http_fetch(url, *, method="GET", json=None, headers=None, text=False):
    merged = dict(HEADERS, **(headers or {}))
    with httpx.Client(timeout=30, follow_redirects=True) as client:
        resp = client.request(method, url, json=json, headers=merged)
        resp.raise_for_status()
        return resp.text if text else resp.json()
