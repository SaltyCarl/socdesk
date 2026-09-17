"""Credential PII fence — applied ON THE BOX (exporter) and AGAIN in the pipeline
(collector). Attackers replay credential-stuffing lists that can contain real
people's emails and passwords; a honeypot must never republish those.

Invariant: only aggregate top-N credential VALUES leave here, never pairs, never
singletons (MIN_CRED_HITS), never anything that looks like an identity.
"""
import ipaddress
import re

from collectors.base import clean_text

MAX_CRED_LEN = 32
MIN_CRED_HITS = 3

_EMAIL_RE = re.compile(r"[^\s@]+@[^\s@]+\.[^\s@]+")
# Account-like: pure alphanumeric words separated by @, e.g., "bob@corp"
_ACCOUNT_RE = re.compile(r"^[a-z0-9]+@[a-z0-9]+$", re.IGNORECASE)
# 9+ digits allowing separators: phone numbers, card numbers, SSNs, IDs.
_LONG_DIGITS_RE = re.compile(r"\d[\d\-\s.]{7,}\d")


def fence_credential(value):
    """Return the inert value, or None if it must not be published."""
    v = clean_text(str(value or ""))
    if not v or len(v) > MAX_CRED_LEN:
        return None
    if _EMAIL_RE.search(v) or _ACCOUNT_RE.search(v):
        return None
    digits = re.sub(r"[^\d]", "", v)
    if len(digits) >= 9 and _LONG_DIGITS_RE.search(v):
        return None
    return v


def is_public_ip(ip):
    """True only for a routable public unicast IPv4/IPv6 literal (never CIDR)."""
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_multicast or addr.is_reserved or addr.is_unspecified)
