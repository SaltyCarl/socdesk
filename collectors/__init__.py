from collectors import (attack, kev, malwarebazaar, nvd, ransomwarelive, rss,
                        threatfox, urlhaus)

COLLECTORS = [kev, nvd, threatfox, urlhaus, malwarebazaar, ransomwarelive, rss]
CACHED_COLLECTORS = [attack]   # run only when state is stale (attack.CACHE_DAYS)
