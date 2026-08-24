// enrich.js — one indicator in, every source's answer out.
//
// Scoped deliberately to the observed workflow: an L1/L2 grabs an IP or a hash
// out of an alert, checks reputation, and decides whether to escalate. IPs and
// hashes are ~99% of lookups, so those are what the sources here cover. Domain
// and URL ride along only because VirusTotal answers them for free.
//
// Pure logic, no Cloudflare bindings — `fetchImpl` is injected so this is
// testable offline, the same contract the Python collectors use.
//
// THREE RULES, each learned expensively:
//
//  1. NEVER fetch the indicator itself. Attacker-controlled values are passed
//     to third-party APIs as parameters, never requested by us. This is not an
//     open proxy for outbound HTTP.
//  2. A failing source is a NAMED ERROR inside a 200, never a 500. One dead
//     upstream must not take the verdict down.
//  3. Never launder someone else's assessment into ours. Every row keeps the
//     source's own numbers, its own wording, and a link back so the person
//     receiving the escalation can verify it at source. That link is a hard
//     requirement, not a nicety — it is what makes the evidence card credible.

const UPSTREAM_TIMEOUT_MS = 4500;
// RDAP bootstraps through rdap.org then follows a redirect to the authoritative
// registry — two sequential round-trips. It is CONTEXT (the registration-age
// tell, never a verdict) but it sits in the BLOCKING response, so its budget is
// part of the card's latency floor. Capped tight so a slow registry can't gate a
// domain lookup — the age fills only when RDAP answers fast.
// (Proper fix: pull context sources out of the blocking path — see the TODO at
// the response assembler.)
const RDAP_TIMEOUT_MS = 1500;
// OTX throttles datacenter/Cloudflare egress (fast from a residential IP, slow
// from the Worker). It is CONTEXT and also sits in the blocking response, so a
// slow OTX made every uncached lookup take ~9s. Capped tight so it can never
// gate the loop; it contributes only when it answers fast.
const OTX_TIMEOUT_MS = 1500;

/* ---------- indicator validation ---------------------------------------- */
// Server-side, because the client's claim about what it sent is not evidence.
const RE = {
  ipv4: /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/,
  // Comprehensive IPv6 (full, ::-compressed, %zone, IPv4-mapped). Kept identical
  // to shared/indicators.ts IPV6_RE.
  ipv6: /^(([0-9a-f]{1,4}:){7,7}[0-9a-f]{1,4}|([0-9a-f]{1,4}:){1,7}:|([0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}|([0-9a-f]{1,4}:){1,5}(:[0-9a-f]{1,4}){1,2}|([0-9a-f]{1,4}:){1,4}(:[0-9a-f]{1,4}){1,3}|([0-9a-f]{1,4}:){1,3}(:[0-9a-f]{1,4}){1,4}|([0-9a-f]{1,4}:){1,2}(:[0-9a-f]{1,4}){1,5}|[0-9a-f]{1,4}:((:[0-9a-f]{1,4}){1,6})|:((:[0-9a-f]{1,4}){1,7}|:)|fe80:(:[0-9a-f]{0,4}){0,4}%[0-9a-z]+|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-f]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/i,
  domain: /^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(?:\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/i,
  md5: /^[a-f0-9]{32}$/i,
  sha1: /^[a-f0-9]{40}$/i,
  sha256: /^[a-f0-9]{64}$/i,
};

/** Private/reserved space. Enriching these leaks internal addressing upstream
 *  and tells the analyst nothing — refuse rather than forward. */
export function isPrivateIp(ip) {
  const p = ip.split(".").map(Number);
  return p[0] === 10 || p[0] === 127 || p[0] === 0 ||
         (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
         (p[0] === 192 && p[1] === 168) ||
         (p[0] === 169 && p[1] === 254) ||
         (p[0] === 100 && p[1] >= 64 && p[1] <= 127) ||
         p[0] >= 224;
}

/** Reserved/private IPv6: loopback ::1, unspecified ::, unique-local fc00::/7,
 *  link-local fe80::/10, and multicast ff00::/8. Prefix checks on the leading
 *  hextet are compression-safe — these ranges are defined by the first hextet,
 *  which `::` shortening never elides. */
export function isPrivateIp6(ip) {
  const s = String(ip).toLowerCase();
  if (s === "::1" || s === "::") return true;   // loopback / unspecified
  if (/^f[cd]/.test(s)) return true;            // fc00::/7 unique-local
  if (/^fe[89ab]/.test(s)) return true;         // fe80::/10 link-local
  if (/^ff/.test(s)) return true;               // ff00::/8 multicast
  return false;
}

export function validate(type, q) {
  const v = String(q ?? "").trim();
  if (!v) return { ok: false, reason: "empty indicator" };
  if (v.length > 2048) return { ok: false, reason: "indicator too long" };

  if (type === "url") {
    let u;
    try { u = new URL(v); } catch { return { ok: false, reason: "unparseable URL" }; }
    if (u.protocol !== "http:" && u.protocol !== "https:")
      return { ok: false, reason: "only http and https URLs" };
    return { ok: true, value: u.href };
  }
  if (!RE[type]) return { ok: false, reason: `unsupported type: ${type}` };
  if (!RE[type].test(v)) return { ok: false, reason: `not a valid ${type}` };
  if (type === "ipv4" && isPrivateIp(v))
    return { ok: false, reason: "private or reserved address — not enriched" };
  if (type === "ipv6" && isPrivateIp6(v))
    return { ok: false, reason: "private or reserved address — not enriched" };
  return { ok: true, value: type === "domain" || type === "ipv6" ? v.toLowerCase() : v };
}

/* ---------- community-report key (shared with the Python export) ---------
 * The export key and the enrich lookup MUST be byte-identical, so this is the
 * one normalizer both sides call. `validate()` already lowercases domain/ipv6
 * and canonicalizes URLs, but does NOT lowercase hashes (line 94) — so a hash
 * reported as AAAA… and looked up as aaaa… would miss. Close that gap here.
 * `value` is assumed already validate()-normalized on both sides. */
const HASH_TYPES = new Set(["md5", "sha1", "sha256"]);
export function communityKey(type, value) {
  const v = HASH_TYPES.has(type) ? String(value).toLowerCase() : String(value);
  return `${type}|${v}`;
}

/* ---------- upstream helpers -------------------------------------------- */

async function getJson(fetchImpl, url, headers = {}, timeoutMs = UPSTREAM_TIMEOUT_MS) {
  const res = await fetchImpl(url, {
    headers: { accept: "application/json", ...headers },
    signal: AbortSignal.timeout(timeoutMs),
  });
  // 404 is "nothing on record" for several of these APIs — a finding, not an
  // outage, and it must never surface as a failed source.
  if (res.status === 404) return { missing: true };
  if (res.status === 401 || res.status === 403)
    throw new Error("rejected the API key");
  if (res.status === 429) throw new Error("rate limit reached");
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return { data: await res.json() };
}

const pct = (n, d) => (d > 0 ? Math.round((n / d) * 100) : 0);
const day = s => (s ? String(s).slice(0, 10) : "—");
const epoch = t => (t ? new Date(t * 1000).toISOString().slice(0, 10) : "—");

function b64url(s) {
  const bytes = new TextEncoder().encode(s);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/* ---------- sources ------------------------------------------------------
 * Each returns: { name, verdict, headline, facts, url }
 *   verdict  malicious | suspicious | benign | unknown
 *   headline the one line that goes on the evidence card
 *   facts    ordered [label, value] pairs, rendered verbatim — the source
 *            speaking, not us
 *   url      where the recipient verifies it. Always present.
 * -------------------------------------------------------------------- */

// AbuseIPDB report-category IDs → human names (docs: abuseipdb.com/categories).
// Surfaced so "35% abuse" also answers "abuse of WHAT KIND" — the actual triage
// question. `verbose` is what returns the per-report `categories` array.
const AIPDB_CATEGORY = {
  1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders", 4: "DDoS", 5: "FTP Brute-Force",
  6: "Ping of Death", 7: "Phishing", 8: "Fraud VoIP", 9: "Open Proxy", 10: "Web Spam",
  11: "Email Spam", 12: "Blog Spam", 13: "VPN IP", 14: "Port Scan", 15: "Hacking",
  16: "SQL Injection", 17: "Spoofing", 18: "Brute-Force", 19: "Bad Web Bot", 20: "Exploited Host",
  21: "Web App Attack", 22: "SSH", 23: "IoT Targeted",
};

/** The most-reported abuse categories across a verbose AbuseIPDB report set,
 *  most-frequent first, named. Empty when nothing was reported. */
function topAbuseCategories(reports, limit = 4) {
  const counts = new Map();
  for (const r of reports ?? [])
    for (const id of r?.categories ?? []) counts.set(id, (counts.get(id) ?? 0) + 1);
  return [...counts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, limit)
    .map(([id]) => AIPDB_CATEGORY[id] ?? `category ${id}`);
}

const ABUSEIPDB = {
  name: "AbuseIPDB",
  types: ["ipv4", "ipv6"],
  key: "ABUSEIPDB_API_KEY",
  link: v => `https://www.abuseipdb.com/check/${v}`,
  async run(fetchImpl, ind, key) {
    const { data } = await getJson(fetchImpl,
      `https://api.abuseipdb.com/api/v2/check?ipAddress=${ind.value}&maxAgeInDays=90&verbose`,
      { Key: key });
    const d = data?.data ?? {};
    const score = Number(d.abuseConfidenceScore ?? 0);
    const categories = topAbuseCategories(d.reports);
    return {
      name: ABUSEIPDB.name,
      verdict: score >= 50 ? "malicious" : score >= 25 ? "suspicious" : "benign",
      // Categories ride the headline (the one line the card renders) so "35% abuse"
      // also says of WHAT KIND — the triage question — but only when reported.
      headline: `${score}% abuse confidence · ${d.totalReports ?? 0} reports in 90 days` +
        (categories.length ? ` · ${categories.slice(0, 3).join(", ")}` : ""),
      facts: [
        ["Abuse confidence", `${score}%`],
        ["Reports (90 days)", String(d.totalReports ?? 0)],
        ["Abuse categories", categories.length ? categories.join(", ") : "—"],
        ["Distinct reporters", String(d.numDistinctUsers ?? 0)],
        ["Last reported", d.lastReportedAt ? day(d.lastReportedAt) : "never"],
        ["ISP", d.isp ?? "—"],
        ["Usage type", d.usageType ?? "—"],
        ["Country", d.countryCode ?? "—"],
        ["Tor exit node", d.isTor ? "yes" : "no"],
      ],
      url: ABUSEIPDB.link(ind.value),
    };
  },
};

const VIRUSTOTAL = {
  name: "VirusTotal",
  types: ["ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256"],
  key: "VT_API_KEY",
  link: (v, t) => ({
    ipv4: `https://www.virustotal.com/gui/ip-address/${v}`,
    ipv6: `https://www.virustotal.com/gui/ip-address/${v}`,
    domain: `https://www.virustotal.com/gui/domain/${v}`,
    url: `https://www.virustotal.com/gui/url/${b64url(v)}`,
  }[t] ?? `https://www.virustotal.com/gui/file/${v}`),
  async run(fetchImpl, ind, key) {
    const path = {
      ipv4: `ip_addresses/${ind.value}`,
      ipv6: `ip_addresses/${ind.value}`,
      domain: `domains/${ind.value}`,
      url: `urls/${b64url(ind.value)}`,          // VT keys URLs by base64url
    }[ind.type] ?? `files/${ind.value}`;
    const pivot = VIRUSTOTAL.link(ind.value, ind.type);

    const { missing, data } = await getJson(fetchImpl,
      `https://www.virustotal.com/api/v3/${path}`, { "x-apikey": key });
    if (missing) return {
      name: VIRUSTOTAL.name, verdict: "unknown",
      headline: "Not present in VirusTotal — nobody has submitted this",
      facts: [], url: pivot,
    };

    const a = data?.data?.attributes ?? {};
    const s = a.last_analysis_stats ?? {};
    const mal = Number(s.malicious ?? 0), sus = Number(s.suspicious ?? 0);
    const total = mal + sus + Number(s.harmless ?? 0) + Number(s.undetected ?? 0);
    const named = Object.entries(a.last_analysis_results ?? {})
      .filter(([, r]) => r.category === "malicious" && r.result)
      .slice(0, 4).map(([eng, r]) => `${eng}: ${r.result}`);

    return {
      name: VIRUSTOTAL.name,
      verdict: mal >= 3 ? "malicious" : mal + sus > 0 ? "suspicious"
             : total ? "benign" : "unknown",
      headline: total ? `${mal}/${total} engines flag this as malicious`
                      : "Present, but not yet analysed",
      facts: [
        ["Detections", total ? `${mal} malicious · ${sus} suspicious · of ${total}` : "none"],
        ["Reputation", String(a.reputation ?? "—")],
        ["File type", a.type_description ?? "—"],
        ["First seen", epoch(a.first_submission_date ?? a.creation_date)],
        ["Last analysed", epoch(a.last_analysis_date ?? a.last_modification_date)],
        ...(named.length ? [["Sample detections", named.join(" · ")]] : []),
      ],
      url: pivot,
    };
  },
};

const GREYNOISE = {
  name: "GreyNoise",
  types: ["ipv4"],
  key: "GREYNOISE_API_KEY",
  optionalKey: true,          // usable unauthenticated, at ~10 lookups/day
  link: v => `https://viz.greynoise.io/ip/${v}`,
  async run(fetchImpl, ind, key) {
    const { missing, data } = await getJson(fetchImpl,
      `https://api.greynoise.io/v3/community/${ind.value}`, key ? { key } : {});
    if (missing) return {
      name: GREYNOISE.name, verdict: "unknown",
      // Said carefully on purpose: absence of scanning is not evidence of
      // safety, and this line ends up in front of a client.
      headline: "Not observed scanning the internet — this is not a safety verdict",
      facts: [], url: GREYNOISE.link(ind.value),
    };
    const c = data?.classification ?? "unknown";
    return {
      name: GREYNOISE.name,
      verdict: c === "malicious" ? "malicious" : c === "benign" ? "benign" : "unknown",
      // GreyNoise SAW this IP (mass-scanner noise or a known-good RIOT service) —
      // a real observation, not a blank. Marks it so an unclassified-but-observed
      // scanner never counts as a "no record" coverage gap on the card.
      observed: !!(data?.noise || data?.riot),
      // The signal that actually closes alerts: is this aimed at us, or is it
      // background radiation hitting everyone on the internet equally?
      headline: data?.noise
        ? "Opportunistic internet scanner — mass activity, not targeted"
        : `Classified ${c}, not internet background noise`,
      facts: [
        ["Classification", c],
        ["Actor", data?.name ?? "—"],
        ["Internet noise", data?.noise ? "yes" : "no"],
        ["Known-good service (RIOT)", data?.riot ? "yes" : "no"],
        ["Last seen", day(data?.last_seen)],
      ],
      url: data?.link ?? GREYNOISE.link(ind.value),
    };
  },
};

const MALWAREBAZAAR = {
  name: "MalwareBazaar",
  types: ["md5", "sha1", "sha256"],
  key: "ABUSECH_API_KEY",
  link: v => `https://bazaar.abuse.ch/sample/${v}/`,
  async run(fetchImpl, ind, key) {
    // Per-sample lookup, not a corpus pull. POST form-encoded; abuse.ch answers
    // 200 with query_status even when the hash is unknown.
    const res = await fetchImpl("https://mb-api.abuse.ch/api/v1/", {
      method: "POST",
      headers: {
        "Auth-Key": key,
        "content-type": "application/x-www-form-urlencoded",
      },
      body: `query=get_info&hash=${encodeURIComponent(ind.value)}`,
      signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS),
    });
    if (res.status === 401 || res.status === 403) throw new Error("rejected the API key");
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();

    if (data?.query_status !== "ok" || !data?.data?.length) return {
      name: MALWAREBAZAAR.name, verdict: "unknown",
      headline: "No sample on record",
      facts: [], url: `https://bazaar.abuse.ch/browse.php?search=${ind.value}`,
    };
    const d = data.data[0];
    return {
      name: MALWAREBAZAAR.name,
      // Presence in MalwareBazaar means somebody collected it as malware. That
      // is a stronger statement than a reputation score, so it is stated flatly.
      verdict: "malicious",
      headline: d.signature
        ? `Known sample — family ${d.signature}`
        : "Known malware sample",
      facts: [
        ["Family", d.signature ?? "unclassified"],
        ["File name", d.file_name ?? "—"],
        ["File type", d.file_type ?? "—"],
        ["File size", d.file_size ? `${d.file_size} bytes` : "—"],
        ["First seen", day(d.first_seen)],
        ["Tags", (d.tags ?? []).join(", ") || "none"],
      ],
      url: MALWAREBAZAAR.link(d.sha256_hash ?? ind.value),
    };
  },
};

const IPINFO = {
  name: "ipinfo",
  types: ["ipv4", "ipv6"],
  key: "IPINFO_TOKEN",
  optionalKey: true,        // works unauthenticated; a free token raises the cap
  // CONTEXT, NOT AN ASSESSMENT. Where an address is hosted is not a claim about
  // whether it is hostile, and the card must not imply we asked ipinfo for a
  // verdict and got a shrug. `kind` keeps it out of the roll-up entirely.
  kind: "context",
  link: v => `https://ipinfo.io/${v}`,
  async run(fetchImpl, ind, token) {
    const url = `https://ipinfo.io/${ind.value}/json` + (token ? `?token=${token}` : "");
    const { missing, data } = await getJson(fetchImpl, url);
    if (missing) return {
      name: IPINFO.name, kind: "context", verdict: "unknown",
      headline: "No geolocation record", facts: [], url: IPINFO.link(ind.value),
    };
    // `org` arrives as "AS60729 Stiftung Erneuerbare Freiheit" — split it so the
    // ASN is its own field, because that is what gets quoted in an escalation.
    const org = String(data?.org ?? "");
    const m = org.match(/^(AS\d+)\s+(.*)$/);
    const where = [data?.city, data?.region, data?.country].filter(Boolean).join(", ");
    return {
      name: IPINFO.name,
      kind: "context",
      verdict: "unknown",
      headline: where ? `${where}${m ? ` · ${m[1]}` : ""}` : "Location unknown",
      facts: [
        ["Location", where || "—"],
        // ipinfo returns "lat,lng"; surfaced so the escalation card can plot the
        // locator pin at the real coordinates. Context only — never a verdict.
        ["Coordinates", data?.loc ?? "—"],
        ["ASN", m ? m[1] : "—"],
        ["Organisation", m ? m[2] : org || "—"],
        ["Reverse hostname", data?.hostname ?? "—"],
        ["Timezone", data?.timezone ?? "—"],
      ],
      url: IPINFO.link(ind.value),
    };
  },
};

const URLSCAN = {
  name: "urlscan",
  types: ["url", "domain"],
  key: "URLSCAN_API_KEY",
  optionalKey: true,        // the search API works unauthenticated (rate-limited);
                            // a free key raises the cap
  link: (v, t) => t === "domain"
    ? `https://urlscan.io/domain/${v}`
    : `https://urlscan.io/search/#${encodeURIComponent(v)}`,
  async run(fetchImpl, ind, key) {
    // EXISTING SCANS ONLY. We search for scans other people already ran and
    // read the completed result; we never call /api/v1/scan, because submitting
    // would fetch the attacker's URL from urlscan on our behalf — and a public
    // scan can also tip off the operator. Inspecting a finished scan discloses
    // nothing new.
    const headers = key ? { "API-Key": key } : {};
    const q = ind.type === "domain"
      // page.domain (a scan OF this domain), not the broad `domain:` (ANY scan
      // that merely contacted it — for a common domain that's a random page).
      ? `page.domain:${ind.value}`
      : `page.url:"${ind.value.replace(/"/g, "")}"`;
    const search = await getJson(fetchImpl,
      `https://urlscan.io/api/v1/search/?q=${encodeURIComponent(q)}&size=1`, headers);
    const hit = search.data?.results?.[0];
    if (!hit || !hit._id) return {
      name: URLSCAN.name, verdict: "unknown",
      headline: "No existing scan — nobody has scanned this yet",
      facts: [], url: URLSCAN.link(ind.value, ind.type),
    };

    // Build the result URL from the id ourselves — never fetch a URL handed to
    // us by the upstream response (defence in depth against an SSRF via a
    // poisoned `result` field).
    const id = encodeURIComponent(hit._id);
    const { data: r } = await getJson(fetchImpl,
      `https://urlscan.io/api/v1/result/${id}/`, headers);
    const v = r?.verdicts?.overall ?? {};
    const score = Number(v.score ?? 0);
    // Only surface a screenshot that lives on urlscan's own origin.
    const shot = /^https:\/\/urlscan\.io\//.test(hit.screenshot || "") ? hit.screenshot : "";
    return {
      name: URLSCAN.name,
      verdict: v.malicious ? "malicious" : score > 0 ? "suspicious" : "benign",
      headline: v.malicious ? `Flagged malicious — score ${score}`
              : score > 0 ? `Suspicious signals — score ${score}`
              : "Scanned, no malicious verdict",
      facts: [
        ["Overall score", String(score)],
        ["Malicious", v.malicious ? "yes" : "no"],
        ["Page IP", r?.page?.ip ?? "—"],
        ["Server", r?.page?.server ?? "—"],
        ["Country", r?.page?.country ?? "—"],
        ["Scanned", day(hit.task?.time)],
      ],
      screenshot: shot,     // the preview an analyst drops into the escalation
      url: `https://urlscan.io/result/${id}/`,
    };
  },
};

const RDAP = {
  name: "RDAP",
  types: ["domain"],
  optionalKey: true,        // keyless registry data (Registration Data Access Protocol)
  kind: "context",          // registration is CONTEXT, never a verdict — excluded from the tally
  blocking: false,          // scheduling axis (Track B1): rides along only if already
                            // resolved by verdict-settle; never gates the response.
  link: v => `https://rdap.org/domain/${v}`,
  async run(fetchImpl, ind) {
    // rdap.org bootstraps to the authoritative registry RDAP server (fetch follows
    // the redirect). 404 = not registered / no record — a finding, not an outage.
    // It 403s a request with NO User-Agent (the Workers runtime sends none); any
    // UA satisfies it, so set one explicitly.
    const { missing, data } = await getJson(fetchImpl, `https://rdap.org/domain/${ind.value}`,
      { "User-Agent": "SOCDesk/1.0 (+https://socdesk.io)" }, RDAP_TIMEOUT_MS);
    if (missing || !data) return {
      name: RDAP.name, kind: "context", verdict: "unknown",
      headline: "No registration record", facts: [], url: RDAP.link(ind.value),
    };
    const ev = Object.fromEntries((data.events ?? []).map(e => [e.eventAction, e.eventDate]));
    const registrar = (data.entities ?? [])
      .filter(e => (e.roles ?? []).includes("registrar"))
      .map(e => (e.vcardArray?.[1] ?? []).find(x => x[0] === "fn")?.[3])
      .find(Boolean) ?? "—";
    const iso = s => (s ? String(s).slice(0, 10) : "—");
    return {
      name: RDAP.name,
      kind: "context",
      verdict: "unknown",
      headline: ev.registration
        ? `Registered ${iso(ev.registration)}${registrar !== "—" ? ` · ${registrar}` : ""}`
        : "Registration record found",
      facts: [
        ["Registered", iso(ev.registration)],
        ["Registrar", registrar],
        ["Expires", iso(ev.expiration)],
        ["Last changed", iso(ev["last changed"])],
      ],
      url: RDAP.link(ind.value),
    };
  },
};

const OTX = {
  name: "AlienVault OTX",
  types: ["ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256"],
  key: "OTX_API_KEY",
  // CONTEXT, NOT A VERDICT. OTX pulses are community-submitted; a benign but
  // popular indicator turns up in reference pulses too, so a raw pulse count is
  // campaign/actor ATTRIBUTION, not a malicious/benign call. `kind` keeps it out
  // of the consensus tally (anti-cry-wolf) — it informs, it does not pronounce.
  kind: "context",
  blocking: false,          // scheduling axis (Track B1): rides along only if already
                            // resolved by verdict-settle; never gates the response.
  link: (v, t) => {
    const seg = { ipv4: "ip", ipv6: "ip", domain: "domain", url: "url" }[t] ?? "file";
    return `https://otx.alienvault.com/indicator/${seg}/${encodeURIComponent(v)}`;
  },
  async run(fetchImpl, ind, key) {
    // API section names differ from the web-UI path segments (IPv4 vs ip).
    const section = { ipv4: "IPv4", ipv6: "IPv6", domain: "domain", url: "url" }[ind.type] ?? "file";
    const pivot = OTX.link(ind.value, ind.type);
    const { missing, data } = await getJson(fetchImpl,
      `https://otx.alienvault.com/api/v1/indicators/${section}/${encodeURIComponent(ind.value)}/general`,
      { "X-OTX-API-KEY": key }, OTX_TIMEOUT_MS);
    if (missing || !data) return {
      name: OTX.name, kind: "context", verdict: "unknown",
      headline: "No OTX record", facts: [], url: pivot,
    };
    const pulses = Array.isArray(data.pulse_info?.pulses) ? data.pulse_info.pulses : [];
    const count = Number(data.pulse_info?.count ?? pulses.length ?? 0);
    // Aggregate the community's attribution across the referencing pulses — the
    // distinctive OTX signal the other sources don't carry.
    const collect = fn => {
      const set = new Set();
      for (const p of pulses) for (const x of fn(p)) if (x) set.add(String(x));
      return [...set];
    };
    const tags = collect(p => p.tags ?? []);
    const attribution = collect(p => [
      p.adversary,
      ...(p.malware_families ?? []).map(m => m?.display_name ?? m),
    ]);
    return {
      name: OTX.name,
      kind: "context",
      verdict: "unknown",   // never votes in the tally
      headline: count > 0
        ? `${count} pulse${count === 1 ? "" : "s"} reference this` +
          (attribution.length ? ` · ${attribution.slice(0, 3).join(", ")}` : "")
        : "No community pulses reference this",
      facts: [
        ["Pulses", String(count)],
        ["Adversary / malware", attribution.length ? attribution.slice(0, 5).join(", ") : "—"],
        ["Tags", tags.length ? tags.slice(0, 8).join(", ") : "—"],
        ["Top pulse", pulses[0]?.name ?? "—"],
      ],
      url: pivot,
    };
  },
};

/* SOCDesk Community — owner-moderated crowdsourced abuse reports, published as
 * a committed dataset (Phase 3). CONTEXT, never a verdict: it states an
 * attributed distinct-CONTRIBUTOR count, out of the tally/band. No network, no
 * D1 — a synchronous lookup in the injected map. `key` names the env slot the
 * Function fills with the parsed dataset (not a secret); `optionalKey` keeps it
 * dispatched even when absent, and run() returns undefined so slots.filter
 * drops it on the ~all clean lookups (no "not configured" clutter). BLOCKING
 * (default) but pure-synchronous, so it adds zero fan-out latency. */
const SOCDESK_COMMUNITY = {
  name: "SOCDesk Community",
  types: ["ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256"],
  key: "SOCDESK_COMMUNITY_DATA",   // env slot carries the injected parsed map, not a secret
  optionalKey: true,               // usable even when absent → then it no-ops
  kind: "context",                 // excluded from the tally + band (enrich.mjs:560, map.ts:127)
  link: "https://socdesk.io/about#community-reports",
  async run(_fetchImpl, ind, data) {
    const map = data && data.indicators;           // injected dataset (Task 6)
    if (!map) return undefined;                    // dataset absent → omit, never an error
    const hit = map[communityKey(ind.type, ind.value)];
    if (!hit) return undefined;                    // no report for this indicator → omit
    const cats = (hit.categories ?? []).join(", ");
    const n = hit.reporters ?? 0;
    return {
      name: SOCDESK_COMMUNITY.name,
      kind: "context",
      verdict: "unknown",                          // context — never votes
      headline:
        `Reported by ${n} contributor${n === 1 ? "" : "s"} (owner-moderated)` +
        (cats ? ` · ${cats}` : "") +
        (hit.latest_reported ? ` · latest ${hit.latest_reported}` : ""),
      facts: [
        ["Contributors", String(n)],
        ["Reported for", cats || "—"],
        ["First reported", hit.first_reported ?? "—"],
        ["Latest reported", hit.latest_reported ?? "—"],
        ["Source", "SOCDesk contributors · owner-moderated"],
      ],
      url: SOCDESK_COMMUNITY.link,
    };
  },
};

const SOURCES = [ABUSEIPDB, VIRUSTOTAL, GREYNOISE, MALWAREBAZAAR, IPINFO, URLSCAN, RDAP, OTX, SOCDESK_COMMUNITY];

/* ---------- consensus tally ---------------------------------------------- */

/** The source-consensus tally (docs/VERDICT-LANGUAGE.md §1–§2). SOCDesk emits
 *  no verdict word of its own — it counts what independent public sources
 *  reported, VirusTotal-style ("N of M sources flagged this"), across services.
 *
 *  Given the per-source rows this returns:
 *    consulted (M) — non-context sources that returned a response. Errors are
 *                    already absent from `rows` (they live in a separate list);
 *                    context rows (ipinfo geolocation) carry no adverse/benign
 *                    signal and are excluded. Benign and no-data DO count in M.
 *    flagged   (N) — of those, the ones whose own verdict is malicious|suspicious.
 *    tone          — from the ratio alone, never a hidden weighting:
 *                    grey  M = 0        nothing consulted returned
 *                    green N = 0        no adverse findings — NOT a clearance
 *                    red   N ≥ M/2      majority flagged
 *                    amber 0 < N < M/2  minority flagged
 */
export function consensus(rows) {
  const scored = (rows ?? []).filter(r => r.kind !== "context");
  const consulted = scored.length;
  const flagged = scored.filter(
    r => r.verdict === "malicious" || r.verdict === "suspicious").length;
  // `flagged * 2 >= consulted` is `N >= M/2` without floating point.
  const tone = consulted === 0 ? "grey"
             : flagged === 0 ? "green"
             : flagged * 2 >= consulted ? "red"
             : "amber";
  return { consulted, flagged, tone };
}

/* ---- phase 1: plan (pure, no I/O) ----------------------------------------
 * Partitions the applicable sources for this indicator `type` into the
 * BLOCKING set (awaited before the response can return) and the NON-BLOCKING
 * set (OTX, RDAP — ride along only if already resolved; see Track B1 plan).
 * `blocking` here is a SCHEDULING axis, orthogonal to the semantic `kind`
 * axis (context vs verdict-bearing): ipinfo is `kind:"context"` but stays
 * BLOCKING because it feeds the globe-pin coordinates. Not-configured skips
 * are tagged with their blocking-ness too, so later phases can decide which
 * skips count toward `partial` without re-deriving it. */
export function planSources(type, env = {}, budgetBlocked = new Set()) {
  const applicable = SOURCES.filter(s => s.types.includes(type));
  const configured = applicable.filter(s => s.optionalKey || env[s.key]);
  const usable = configured.filter(s => !budgetBlocked.has(s.key));
  const blocking = usable.filter(s => s.blocking !== false);
  const nonBlocking = usable.filter(s => s.blocking === false);
  const notConfigured = applicable
    .filter(s => !s.optionalKey && !env[s.key])
    .map(s => ({ source: s.name, reason: "not configured", blocking: s.blocking !== false }));
  // A budget-blocked source degrades to a NON-blocking named skip (§4.2): it
  // lands in errors[] for honesty but never sets `partial`, so the degraded
  // answer stays cacheable and we do not re-run the other sources uncached.
  // A spent budget is a deliberate, stable degradation (like being
  // unconfigured), not a transient failure — and `partial` exists only to keep
  // transient failures out of the edge cache (enrich.js:60-62).
  const budgetSkipped = configured
    .filter(s => budgetBlocked.has(s.key))
    .map(s => ({ source: s.name, reason: "daily budget reached", blocking: false }));
  const skipped = [...notConfigured, ...budgetSkipped];
  return { usable, blocking, nonBlocking, skipped };
}

// Track B1: grace-race scaffolding. GRACE_MS=0 and skipped_context land in
// Tasks 3–4 — this task (Task 2) only introduces the terminal-handling
// helpers so a non-blocking source promise NEVER surfaces an unhandled
// rejection once dispatched; collectResults still awaits every context
// result fully (no race yet), so behavior is byte-for-byte unchanged.
const GRACE_MS = 0;

const PENDING = Symbol("pending");

/** Terminal-handle a non-blocking source promise so it NEVER rejects. A
 *  dropped source that later rejects (its AbortSignal.timeout firing after
 *  we've moved on) must not surface as an unhandled rejection in the Worker. */
function tagContext(source, promise) {
  return promise.then(
    value => ({ source, ok: true, value }),
    err => ({ source, ok: false, reason: String(err?.message ?? err).slice(0, 120) }),
  );
}

/** Race an already terminal-handled context result against a grace timer.
 *  Deterministic by event-loop semantics: an already-microtask-ready `tagged`
 *  always beats even setTimeout(0) (the microtask queue drains before any
 *  timer fires), so a zero-delay mock rides along and a real-network laggard
 *  drops. Unused until Task 3 wires it into collectResults. */
function settleWithin(tagged, ms) {
  let t;
  const timer = new Promise(res => { t = setTimeout(() => res(PENDING), ms); });
  return Promise.race([tagged, timer]).finally(() => clearTimeout(t));
}

/* ---- phase 2: dispatch (starts ALL I/O in one tick) ----------------------
 * Fires every applicable source's run() NOW — blocking and non-blocking
 * alike, identical fan-out timing to the pre-extraction assembler — and
 * terminal-handles each non-blocking promise immediately via `tagContext`.
 * The grace TIMER (Task 3) is started later, in collectResults, so the grace
 * window is measured from verdict-settle (collect-anchored), not dispatch. */
export function dispatchSources(fetchImpl, ind, env, plan) {
  const blocking = plan.blocking.map(s => ({ source: s, promise: s.run(fetchImpl, ind, env[s.key]) }));
  const context = plan.nonBlocking.map(s => ({ source: s, tagged: tagContext(s, s.run(fetchImpl, ind, env[s.key])) }));
  return { blocking, context };
}

/* ---- phase 3: collect (await blocking, then grace-race context) ----------
 * Track B1 Task 4: await ONLY the blocking set, then start the grace timer
 * (collect-anchored — measured from verdict-settle, not dispatch) and race
 * each terminal-handled context result via `settleWithin`. A non-blocking
 * result that is not already microtask-ready by verdict-settle resolves to
 * PENDING and is OMITTED from `sources` (the response returns at verdict
 * speed, never waiting on the OTX/RDAP floor). The two dropped outcomes now
 * split three ways:
 *   - PENDING (genuinely slow)        → additive `skipped_context` (silent +
 *                                       observable); NOT `errors`, NOT partial.
 *   - in-grace `ok:false` (FAST fail, → `errors` (honest, named); NOT partial
 *     e.g. a bad key → quick 401)       (mirrors the not-configured case).
 *   - fulfilled                       → rides along in `sources`.
 * `partial` is recomputed from the BLOCKING axis alone — blocking rejections
 * plus blocking not-configured skips — so a dropped/errored/not-configured
 * CONTEXT source can never poison the edge cache, while a real BLOCKING-source
 * failure still sets `partial:true`. */
export async function collectResults(dispatched, plan, grace = GRACE_MS) {
  const blockingSettled = await Promise.allSettled(dispatched.blocking.map(b => b.promise));
  // Grace starts HERE — after the blocking set settled (collect-anchored).
  const contextResults = await Promise.all(dispatched.context.map(c => settleWithin(c.tagged, grace)));

  const slots = new Array(plan.usable.length).fill(null); // order-preserving assembly
  const errors = [];
  let blockingFailures = 0;

  // not-configured skips: ALL named in `errors` (honesty); only blocking ones
  // count toward `partial`.
  for (const sk of plan.skipped) {
    errors.push({ source: sk.source, reason: sk.reason });
    if (sk.blocking) blockingFailures++;
  }

  dispatched.blocking.forEach((b, i) => {
    const r = blockingSettled[i];
    const idx = plan.usable.indexOf(b.source);
    if (r.status === "fulfilled") slots[idx] = r.value;
    else {
      errors.push({ source: b.source.name, reason: String(r.reason?.message ?? r.reason).slice(0, 120) });
      blockingFailures++;
    }
  });

  const skipped_context = [];
  dispatched.context.forEach((c, i) => {
    const r = contextResults[i];
    const idx = plan.usable.indexOf(c.source);
    if (r === PENDING) skipped_context.push(c.source.name);         // slow drop — silent + observable
    else if (r.ok) slots[idx] = r.value;                            // rides along
    else errors.push({ source: r.source.name, reason: r.reason });  // FAST fail — honest, NOT partial
  });

  return { sources: slots.filter(Boolean), errors, partial: blockingFailures > 0, skipped_context };
}

/* ---- phase 4: assemble (shape unchanged + additive skipped_context) ------ */
export function assemble(ind, type, now, collected) {
  const { consulted, flagged, tone } = consensus(collected.sources);
  return {
    indicator: ind.value,
    type,
    checked_at: now.toISOString(),
    // The tally replaces the old single-word `verdict`. Per-source `verdict`
    // stays on each row (it is what "flagged" counts); SOCDesk itself no longer
    // pronounces one. (docs/VERDICT-LANGUAGE.md §7.)
    consulted,
    flagged,
    tone,
    sources: collected.sources,
    partial: collected.partial,
    errors: collected.errors,
    // Additive: non-blocking context sources dropped for slowness (PENDING past
    // grace). Never touches `errors`/`partial`; the client ignores unknown
    // fields (shared/verdict/map.ts reads only sources/errors/partial).
    skipped_context: collected.skipped_context,
  };
}

/**
 * Enrich one indicator across every source that applies and is configured.
 * Never throws for upstream reasons — failures come back named, in `errors`.
 *
 * @param {(url: string, init?: object) => Promise<Response>} fetchImpl
 * @param {string} type  ipv4 | ipv6 | domain | url | md5 | sha1 | sha256
 * @param {string} q     the indicator
 * @param {Record<string,string>} env  API keys; a missing key skips its source
 */
export async function enrich(fetchImpl, type, q, env = {}, now = new Date(), budgetBlocked = new Set()) {
  const check = validate(type, q);
  if (!check.ok) return { error: check.reason, status: 400 };

  const ind = { type, value: check.value };
  const plan = planSources(type, env, budgetBlocked);
  const dispatched = dispatchSources(fetchImpl, ind, env, plan);
  const collected = await collectResults(dispatched, plan);
  return assemble(ind, type, now, collected);
}

export const _internals = {
  SOURCES, b64url, GRACE_MS, PENDING,
  planSources, dispatchSources, collectResults, assemble, tagContext, settleWithin,
};
