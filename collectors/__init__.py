from collectors import attack, kev, nvd, ransomwarelive, rss

# Aggregator model (see COMPLIANCE.md): VIGIL holds only data it may clearly
# redistribute — CISA KEV (CC0), NVD (US-Gov public domain), FIRST EPSS
# (free with attribution), MITRE ATT&CK (permission notice in README) and
# headline+link RSS. Reputation corpora (abuse.ch, AbuseIPDB, VirusTotal,
# Ransomware.live victim detail) are reached by user-clicked deep links at
# render time, never mirrored here.
COLLECTORS = [kev, nvd, ransomwarelive, rss]
CACHED_COLLECTORS = [attack]   # run only when state is stale (attack.CACHE_DAYS)
