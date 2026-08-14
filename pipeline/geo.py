import hashlib
import json
import math
from functools import lru_cache
from pathlib import Path

CENTROIDS_PATH = (Path(__file__).resolve().parent.parent
                  / "data" / "geo" / "country_centroids.json")

# Radius (degrees) of the deterministic scatter applied to every IP that shares
# a country in the CENTROID FALLBACK path. Many C2s live in a handful of hosting
# countries, so plotting each on the raw centroid stacks them into one dot; a
# per-IP offset spreads them into a readable cloud. The offset is a pure
# function of the IP, so it is byte-identical on every run — no unseeded
# randomness reaches the payload. City-precision IPinfo coordinates are used
# as-is and get no jitter.
JITTER_RADIUS_DEG = 2.4

IPINFO_URL = "https://ipinfo.io/{ip}/json?token={token}"


@lru_cache(maxsize=1)
def _centroids():
    return json.loads(CENTROIDS_PATH.read_text(encoding="utf-8"))


def _disc_offset(ip):
    """Deterministic (dlat, dlng) inside a disc of JITTER_RADIUS_DEG.

    Seeded from the IP so the same address always lands on the same spot.
    Radius is sqrt-scaled so points spread evenly across the disc instead of
    clustering at the centre.
    """
    h = int(hashlib.sha256(ip.encode("utf-8")).hexdigest(), 16)
    angle = (h % 1_000_000) / 1_000_000 * 2 * math.pi
    radius = math.sqrt(((h >> 32) % 1_000_000) / 1_000_000) * JITTER_RADIUS_DEG
    return radius * math.sin(angle), radius * math.cos(angle)


def locate(ip, source_country):
    """Country-centroid fallback. Returns ``(lat, lng, country, "country")`` or
    ``None`` when the IP has no usable country — an unplaceable IP is dropped,
    never given a fabricated coordinate. Coordinates are the country centroid
    plus the deterministic per-IP jitter.
    """
    country = (source_country or "").strip().upper()
    if not country:
        return None
    base = _centroids().get(country)
    if base is None:
        return None
    dlat, dlng = _disc_offset(ip)
    lat = max(-85.0, min(85.0, base[0] + dlat))
    # Widen the longitude offset toward the poles so the disc keeps its shape;
    # then wrap into the valid [-180, 180] range.
    lng = base[1] + dlng / max(math.cos(math.radians(base[0])), 0.25)
    lng = ((lng + 180.0) % 360.0) - 180.0
    return round(lat, 4), round(lng, 4), country, "country"


def _ipinfo(ip, fetch, token):
    """Look one IP up via the IPinfo API. Returns a cache record
    ``{lat, lng, country, city, precision:"city"}`` or ``None``. Any failure
    (network, bogon/private IP with no ``loc``, malformed body) yields ``None``
    so the caller falls back to the centroid path — a lookup is never fatal.
    """
    try:
        data = fetch(IPINFO_URL.format(ip=ip, token=token))
    except Exception:                          # noqa: BLE001 — never fatal
        return None
    if not isinstance(data, dict):
        return None
    loc = data.get("loc") or ""
    country = (data.get("country") or "").strip().upper()
    if "," not in loc or not country:
        return None
    try:
        lat_s, lng_s = loc.split(",", 1)
        lat, lng = round(float(lat_s), 4), round(float(lng_s), 4)
    except ValueError:
        return None
    if not (-90.0 <= lat <= 90.0 and -180.0 <= lng <= 180.0):
        return None
    return {"lat": lat, "lng": lng, "country": country,
            "city": (data.get("city") or "").strip() or None,
            "precision": "city"}


def resolve(ip, source_country, cache, fetch=None, token=None):
    """Place an IP, preferring accuracy while staying inside the API quota.

    Order: (1) the persistent per-IP cache — a hit means IPinfo already resolved
    this IP on an earlier run, so no call is made; (2) a live IPinfo lookup when
    a token and fetch are available, whose result is written back to ``cache``;
    (3) the country-centroid fallback on the source's own country. Returns
    ``(lat, lng, country, city_or_None, precision)`` or ``None``.

    Only city-precision IPinfo results are cached; centroid fallbacks are
    recomputed each run (they are deterministic and free), so an IP placed by
    fallback today is transparently upgraded to city precision once a token is
    present.
    """
    hit = cache.get(ip)
    if isinstance(hit, dict) and "lat" in hit and "lng" in hit and hit.get("country"):
        return (hit["lat"], hit["lng"], hit["country"],
                hit.get("city"), hit.get("precision", "city"))

    if fetch is not None and token:
        got = _ipinfo(ip, fetch, token)
        if got:
            cache[ip] = got
            return (got["lat"], got["lng"], got["country"],
                    got["city"], got["precision"])

    placed = locate(ip, source_country)
    if placed is None:
        return None
    lat, lng, country, precision = placed
    return lat, lng, country, None, precision
