from collectors import (attack, feodotracker, kev, nvd, ransomwarelive, rss,
                        threatfox)

# Aggregator model (see COMPLIANCE.md): SOCDESK holds only data it may clearly
# redistribute — CISA KEV (CC0), NVD (US-Gov public domain), FIRST EPSS
# (free with attribution), MITRE ATT&CK (permission notice in README) and
# headline+link RSS. Reputation *corpora* (MalwareBazaar/ThreatFox lookups,
# AbuseIPDB, VirusTotal, Ransomware.live victim detail) are reached by
# user-clicked deep links at render time, never mirrored here.
#
# The abuse.ch C2/blocklist IPs (feodotracker, threatfox ip:port) are a
# deliberate exception: these are indicators published expressly to be blocked,
# so the IP itself is the useful, redistributable datum. They power the
# geolocated threat-surface payload (threat_ips.json), attributed to abuse.ch.
COLLECTORS = [kev, nvd, ransomwarelive, rss, feodotracker, threatfox]
CACHED_COLLECTORS = [attack]   # run only when state is stale (attack.CACHE_DAYS)
