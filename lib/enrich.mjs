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

/* ---------- indicator validation ---------------------------------------- */
// Server-side, because the client's claim about what it sent is not evidence.
const RE = {
  ipv4: /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/,
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
  return { ok: true, value: type === "domain" ? v.toLowerCase() : v };
}

/* ---------- upstream helpers -------------------------------------------- */

async function getJson(fetchImpl, url, headers = {}) {
  const res = await fetchImpl(url, {
    headers: { accept: "application/json", ...headers },
    signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS),
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

const ABUSEIPDB = {
  name: "AbuseIPDB",
  types: ["ipv4"],
  key: "ABUSEIPDB_API_KEY",
  link: v => `https://www.abuseipdb.com/check/${v}`,
  async run(fetchImpl, ind, key) {
    const { data } = await getJson(fetchImpl,
      `https://api.abuseipdb.com/api/v2/check?ipAddress=${ind.value}&maxAgeInDays=90`,
      { Key: key });
    const d = data?.data ?? {};
    const score = Number(d.abuseConfidenceScore ?? 0);
    return {
      name: ABUSEIPDB.name,
      verdict: score >= 50 ? "malicious" : score >= 25 ? "suspicious" : "benign",
      headline: `${score}% abuse confidence · ${d.totalReports ?? 0} reports in 90 days`,
      facts: [
        ["Abuse confidence", `${score}%`],
        ["Reports (90 days)", String(d.totalReports ?? 0)],
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
  types: ["ipv4", "domain", "url", "md5", "sha1", "sha256"],
  key: "VT_API_KEY",
  link: (v, t) => ({
    ipv4: `https://www.virustotal.com/gui/ip-address/${v}`,
    domain: `https://www.virustotal.com/gui/domain/${v}`,
    url: `https://www.virustotal.com/gui/url/${b64url(v)}`,
  }[t] ?? `https://www.virustotal.com/gui/file/${v}`),
  async run(fetchImpl, ind, key) {
    const path = {
      ipv4: `ip_addresses/${ind.value}`,
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
  types: ["ipv4"],
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
      ? `domain:${ind.value}`
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

const SOURCES = [ABUSEIPDB, VIRUSTOTAL, GREYNOISE, MALWAREBAZAAR, IPINFO, URLSCAN];

/* ---------- roll-up ------------------------------------------------------ */

/** One headline from many rows. The worst credible answer wins — an analyst
 *  deciding whether to escalate needs the ceiling, not an average.
 *  Context rows (geolocation) carry no assessment and are excluded. */
export function overall(allRows) {
  const rows = allRows.filter(r => r.kind !== "context");
  const any = v => rows.some(r => r.verdict === v);
  if (any("malicious")) return "malicious";
  if (any("suspicious")) return "suspicious";
  if (any("benign")) return "benign";
  return "unknown";
}

/**
 * Enrich one indicator across every source that applies and is configured.
 * Never throws for upstream reasons — failures come back named, in `errors`.
 *
 * @param {(url: string, init?: object) => Promise<Response>} fetchImpl
 * @param {string} type  ipv4 | domain | url | md5 | sha1 | sha256
 * @param {string} q     the indicator
 * @param {Record<string,string>} env  API keys; a missing key skips its source
 */
export async function enrich(fetchImpl, type, q, env = {}, now = new Date()) {
  const check = validate(type, q);
  if (!check.ok) return { error: check.reason, status: 400 };

  const ind = { type, value: check.value };
  const applicable = SOURCES.filter(s => s.types.includes(type));

  // A source without its key is SKIPPED, not failed — and it still appears in
  // `errors` so the UI can say which sources were not consulted. Silence about
  // an unconsulted source is how an evidence card starts lying by omission.
  const usable = applicable.filter(s => s.optionalKey || env[s.key]);
  const skipped = applicable.filter(s => !s.optionalKey && !env[s.key])
    .map(s => ({ source: s.name, reason: "not configured" }));

  const settled = await Promise.allSettled(
    usable.map(s => s.run(fetchImpl, ind, env[s.key])));

  const sources = [], errors = [...skipped];
  settled.forEach((r, i) => {
    if (r.status === "fulfilled") sources.push(r.value);
    else errors.push({
      source: usable[i].name,
      reason: String(r.reason?.message ?? r.reason).slice(0, 120),
    });
  });

  return {
    indicator: ind.value,
    type,
    checked_at: now.toISOString(),
    verdict: overall(sources),
    sources,
    partial: errors.length > 0,
    errors,
  };
}

export const _internals = { SOURCES, b64url };
