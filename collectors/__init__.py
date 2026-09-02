from collectors import (attack, feodotracker, kev, nvd, ransomwarelive,
                        ransomwarelive_groups, rss, sentinel_hunt, sigma_hunt,
                        threatfox)

# Aggregator model (see COMPLIANCE.md): SOCDESK holds only data it may clearly
# redistribute — CISA KEV (CC0), NVD (US-Gov public domain), FIRST EPSS
# (free with attribution), MITRE ATT&CK (permission notice in README) and
# headline+link RSS. Reputation *corpora* (MalwareBazaar/ThreatFox lookups,
# AbuseIPDB, VirusTotal) are reached by user-clicked deep links at render
# time, never mirrored here. Ransomware.live FACTS are republished under the
# R3 boundary (attributed + framed unverified): victim/domain on claim items
# (ransomwarelive) and bare group NAMES for directory coverage
# (ransomwarelive_groups) — its editorial (descriptions, screenshots,
# locations, ttps) is never mirrored.
#
# The abuse.ch C2/blocklist IPs (feodotracker, threatfox ip:port) are a
# deliberate exception: these are indicators published expressly to be blocked,
# so the IP itself is the useful, redistributable datum. They power the
# geolocated threat-surface payload (threat_ips.json), attributed to abuse.ch.
COLLECTORS = [kev, nvd, ransomwarelive, rss, feodotracker, threatfox]
# run only when their committed state is stale (each module's CACHE_DAYS) —
# run_pipeline appends each one individually per its own freshness check.
CACHED_COLLECTORS = [attack]
GROUPS_COLLECTOR = ransomwarelive_groups
HUNT_COLLECTOR = sentinel_hunt
SIGMA_COLLECTOR = sigma_hunt
