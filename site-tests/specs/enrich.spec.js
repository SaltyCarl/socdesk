// enrich.spec.js — the enrichment layer is the product. These run against the
// real module with a fake fetch, so they need no API keys and no network.
//
// What they defend, in order of importance:
//   1. Every row carries a verifiable link. The evidence card's credibility
//      rests on the recipient being able to check each figure at source.
//   2. A missing key or a dead upstream degrades to a named gap — never a 500,
//      never a silently shorter card. An evidence card that omits a source it
//      failed to reach is lying by omission.
//   3. "Nothing on record" is a finding, not an error.
const { test, expect } = require("@playwright/test");

let E;
// .mjs so Node treats it as ESM without a package.json "type" declaration that
// would change how every other file in the repo is interpreted.
test.beforeAll(async () => { E = await import("../../lib/enrich.mjs"); });

/** A fetch stand-in: routes by URL substring, returns canned JSON. */
function fakeFetch(routes) {
  return async (url, init = {}) => {
    const key = Object.keys(routes).find(k => String(url).includes(k));
    if (!key) throw new Error(`unrouted fetch: ${url}`);
    const r = typeof routes[key] === "function" ? routes[key](url, init) : routes[key];
    if (r instanceof Error) throw r;
    return {
      ok: (r.status ?? 200) < 400,
      status: r.status ?? 200,
      json: async () => r.body,
    };
  };
}

const KEYS = {
  ABUSEIPDB_API_KEY: "k", VT_API_KEY: "k",
  GREYNOISE_API_KEY: "k", ABUSECH_API_KEY: "k",
};

const ABUSE_OK = { body: { data: {
  abuseConfidenceScore: 100, totalReports: 412, numDistinctUsers: 89,
  lastReportedAt: "2026-08-08T11:00:00+00:00", isp: "Example Hosting",
  usageType: "Data Center/Web Hosting/Transit", countryCode: "NL", isTor: false } } };

const VT_IP_OK = { body: { data: { attributes: {
  last_analysis_stats: { malicious: 12, suspicious: 2, harmless: 60, undetected: 20 },
  reputation: -41, last_analysis_date: 1770000000,
  last_analysis_results: { Fortinet: { category: "malicious", result: "Malware" } } } } } };

const IPINFO_OK = { body: {
  ip: "185.220.101.42", hostname: "tor-exit-42.for-privacy.net", city: "Berlin",
  region: "State of Berlin", country: "DE", loc: "52.5244,13.4105",
  org: "AS60729 Stiftung Erneuerbare Freiheit", timezone: "Europe/Berlin" } };

const GN_OK = { body: {
  ip: "185.220.101.42", noise: true, riot: false, classification: "malicious",
  name: "Tor Exit Node", last_seen: "2026-08-08", link: "https://viz.greynoise.io/ip/x" } };

// A benign 8.8.8.8-shape: every consulted source returns a non-adverse verdict.
const ABUSE_CLEAN = { body: { data: {
  abuseConfidenceScore: 0, totalReports: 0, numDistinctUsers: 0,
  isp: "Google LLC", usageType: "Content Delivery Network", countryCode: "US" } } };
const VT_IP_CLEAN = { body: { data: { attributes: {
  last_analysis_stats: { malicious: 0, suspicious: 0, harmless: 70, undetected: 24 },
  reputation: 0, last_analysis_date: 1770000000 } } } };
const GN_CLEAN = { body: {
  ip: "8.8.8.8", noise: false, riot: true, classification: "benign",
  name: "Google Public DNS", last_seen: "2026-08-08" } };
const IPINFO_CLEAN = { body: {
  ip: "8.8.8.8", hostname: "dns.google", city: "Mountain View",
  region: "California", country: "US", org: "AS15169 Google LLC",
  timezone: "America/Los_Angeles" } };

test.describe("enrichment", () => {
  test("every row carries a link the recipient can verify", async () => {
    // The product decision this enforces: the evidence card is a composite, and
    // it is only credible because each figure can be checked at its source.
    const r = await E.enrich(fakeFetch({
      "abuseipdb.com": ABUSE_OK,
      "virustotal.com": VT_IP_OK,
      "greynoise.io": GN_OK,
    }), "ipv4", "185.220.101.42", KEYS);

    expect(r.sources.length).toBe(3);
    for (const s of r.sources) {
      expect(s.url, `${s.name} must link back`).toMatch(/^https:\/\//);
      expect(s.headline, `${s.name} must have a headline`).toBeTruthy();
      expect(s.name).toBeTruthy();
    }
  });

  test("the headline is a source-consensus tally, not a single verdict word", async () => {
    // Three sources call this IP adverse; ipinfo answers too but is context and
    // must not enter the tally. So: 3 of 3 consulted flagged it — red.
    const r = await E.enrich(fakeFetch({
      "abuseipdb.com": ABUSE_OK,           // malicious
      "virustotal.com": VT_IP_OK,          // malicious
      "greynoise.io": GN_OK,               // malicious
      "ipinfo.io": IPINFO_OK,              // context — excluded from the tally
    }), "ipv4", "185.220.101.42", KEYS);

    // The single-word verdict is gone; the tally replaces it (§7).
    expect(r.verdict).toBeUndefined();
    expect(r.flagged).toBe(3);
    expect(r.consulted).toBe(3);           // ipinfo context excluded, not counted
    expect(r.tone).toBe("red");
    // per-source verdicts are retained — they are what "flagged" counts
    expect(r.sources.find(s => s.name === "AbuseIPDB").verdict).toBe("malicious");
  });

  test("a benign indicator is 0 of M — green, and never a clearance", async () => {
    const r = await E.enrich(fakeFetch({
      "abuseipdb.com": ABUSE_CLEAN,        // benign (0%)
      "virustotal.com": VT_IP_CLEAN,       // benign (0/94)
      "greynoise.io": GN_CLEAN,            // benign (RIOT known-good)
      "ipinfo.io": IPINFO_CLEAN,           // context
    }), "ipv4", "8.8.8.8", KEYS);
    expect(r.flagged).toBe(0);
    expect(r.consulted).toBe(3);           // benign still counts in M, not N
    expect(r.tone).toBe("green");
  });

  test("consensus() is the whole rule — context out, ratio decides tone", async () => {
    // context rows never enter M or N
    expect(E.consensus([{ verdict: "malicious" },
                        { kind: "context", verdict: "malicious" }]))
      .toEqual({ consulted: 1, flagged: 1, tone: "red" });
    // benign and no-data count in M, not N
    expect(E.consensus([{ verdict: "benign" }, { verdict: "unknown" }]))
      .toEqual({ consulted: 2, flagged: 0, tone: "green" });
    // N ≥ M/2 is red; below is amber
    expect(E.consensus([{ verdict: "suspicious" }, { verdict: "benign" }]))
      .toEqual({ consulted: 2, flagged: 1, tone: "red" });
    expect(E.consensus([{ verdict: "suspicious" }, { verdict: "benign" },
                        { verdict: "benign" }]))
      .toEqual({ consulted: 3, flagged: 1, tone: "amber" });
    // nothing consulted returned → grey (never green — absence is not safety)
    expect(E.consensus([])).toEqual({ consulted: 0, flagged: 0, tone: "grey" });
    expect(E.consensus([{ kind: "context", verdict: "benign" }]))
      .toEqual({ consulted: 0, flagged: 0, tone: "grey" });
  });

  test("nothing consulted returns → M = 0, grey, never a manufactured verdict", async () => {
    // sha256 with no keys: VT and MalwareBazaar are both key-gated, so both are
    // named as unconsulted and no source returns → the tally is empty (grey).
    const r = await E.enrich(fakeFetch({}), "sha256", "a".repeat(64), {});
    expect(r.sources).toEqual([]);
    expect(r.consulted).toBe(0);
    expect(r.flagged).toBe(0);
    expect(r.tone).toBe("grey");
    expect(r.errors.map(e => e.source).sort()).toEqual(["MalwareBazaar", "VirusTotal"]);
    expect(r.partial).toBe(true);
  });

  test("a source with no key is reported as unconsulted, not omitted", async () => {
    // Silence about a source we never asked is how an evidence card misleads.
    const r = await E.enrich(fakeFetch({ "greynoise.io": GN_OK, "ipinfo.io": IPINFO_OK }),
      "ipv4", "185.220.101.42", {});      // no keys at all

    // GreyNoise and ipinfo both work unauthenticated, so they still answer.
    expect(r.sources.map(s => s.name).sort()).toEqual(["GreyNoise", "ipinfo"]);
    expect(r.errors).toEqual(expect.arrayContaining([
      { source: "AbuseIPDB", reason: "not configured" },
      { source: "VirusTotal", reason: "not configured" },
    ]));
    expect(r.partial).toBe(true);
  });

  test("geolocation is context and never moves the verdict", async () => {
    // ipinfo answers every IP. If it counted as an assessment, a benign-looking
    // "unknown" would sit alongside real verdicts and imply we checked
    // something we did not.
    const r = await E.enrich(fakeFetch({ "ipinfo.io": IPINFO_OK }),
      "ipv4", "185.220.101.42", {});
    const geo = r.sources.find(s => s.name === "ipinfo");
    expect(geo.kind).toBe("context");
    expect(geo.facts).toEqual(expect.arrayContaining([
      ["ASN", "AS60729"],
      ["Reverse hostname", "tor-exit-42.for-privacy.net"],
    ]));
    expect(geo.headline).toContain("Berlin");

    // ipinfo answered, but as the only source it leaves the tally empty (grey) —
    // context alone never manufactures a consulted count.
    expect(r.consulted).toBe(0);
    expect(r.flagged).toBe(0);
    expect(r.tone).toBe("grey");
  });

  test("one dead upstream never takes the verdict down", async () => {
    const r = await E.enrich(fakeFetch({
      "abuseipdb.com": ABUSE_OK,
      "virustotal.com": { status: 500, body: {} },
      "greynoise.io": GN_OK,
    }), "ipv4", "185.220.101.42", KEYS);

    expect(r.sources.map(s => s.name).sort()).toEqual(["AbuseIPDB", "GreyNoise"]);
    expect(r.errors.find(e => e.source === "VirusTotal").reason).toContain("500");
    expect(r.flagged).toBe(2);                  // still tallies from the survivors
    expect(r.consulted).toBe(2);
    expect(r.tone).toBe("red");
    expect(r.partial).toBe(true);
  });

  test("a rejected key says so instead of looking like an outage", async () => {
    const r = await E.enrich(fakeFetch({
      "abuseipdb.com": { status: 401, body: {} },
      "virustotal.com": VT_IP_OK,
      "greynoise.io": GN_OK,
    }), "ipv4", "1.2.3.4", KEYS);
    expect(r.errors.find(e => e.source === "AbuseIPDB").reason).toContain("API key");
  });

  test("'nothing on record' is a finding, not a failure", async () => {
    const r = await E.enrich(fakeFetch({
      "virustotal.com": { status: 404, body: {} },
      "mb-api.abuse.ch": { body: { query_status: "hash_not_found" } },
    }), "sha256", "a".repeat(64), KEYS);

    expect(r.errors).toEqual([]);                      // no source failed
    expect(r.sources.length).toBe(2);
    // "no data on record" is consulted (counts in M) but never flagged (N):
    // 0 of 2 → green, and the green headline states it is not a clearance.
    expect(r.flagged).toBe(0);
    expect(r.consulted).toBe(2);
    expect(r.tone).toBe("green");
    expect(r.sources.find(s => s.name === "VirusTotal").headline).toMatch(/not present/i);
    expect(r.sources.find(s => s.name === "MalwareBazaar").headline).toMatch(/no sample/i);
  });

  test("a known sample is stated flatly, with its family", async () => {
    const r = await E.enrich(fakeFetch({
      "virustotal.com": { status: 404, body: {} },
      "mb-api.abuse.ch": { body: { query_status: "ok", data: [{
        signature: "AgentTesla", file_name: "invoice.exe", file_type: "exe",
        file_size: 481280, first_seen: "2026-07-02 08:11:00",
        tags: ["exe", "AgentTesla"], sha256_hash: "b".repeat(64) }] } },
    }), "sha256", "b".repeat(64), KEYS);

    const mb = r.sources.find(s => s.name === "MalwareBazaar");
    expect(mb.verdict).toBe("malicious");              // per-source verdict retained
    expect(mb.headline).toContain("AgentTesla");
    // MalwareBazaar flags it, VT has nothing on record: 1 of 2 → red (N ≥ M/2).
    expect(r.flagged).toBe(1);
    expect(r.consulted).toBe(2);
    expect(r.tone).toBe("red");
  });

  test("hash lookups never consult the IP-only sources", async () => {
    const r = await E.enrich(fakeFetch({
      "virustotal.com": { status: 404, body: {} },
      "mb-api.abuse.ch": { body: { query_status: "hash_not_found" } },
    }), "md5", "c".repeat(32), KEYS);
    const consulted = [...r.sources.map(s => s.name), ...r.errors.map(e => e.source)];
    expect(consulted).not.toContain("AbuseIPDB");
    expect(consulted).not.toContain("GreyNoise");
  });

  const URLSCAN_SEARCH_HIT = { body: { total: 1, results: [{
    _id: "0198abcd-1234", task: { url: "http://evil.example/x", time: "2026-08-09T10:00:00Z" },
    page: { url: "http://evil.example/x", domain: "evil.example" },
    screenshot: "https://urlscan.io/screenshots/0198abcd-1234.png" }] } };
  const URLSCAN_RESULT_MAL = { body: { verdicts: { overall: { score: 80, malicious: true } },
    page: { ip: "1.2.3.4", server: "nginx", country: "RU" } } };

  test("a URL with an existing urlscan gets a reputation verdict and a screenshot", async () => {
    const r = await E.enrich(fakeFetch({
      "virustotal.com": { status: 404, body: {} },       // not submitted to VT
      "urlscan.io/api/v1/search": URLSCAN_SEARCH_HIT,
      "urlscan.io/api/v1/result": URLSCAN_RESULT_MAL,
    }), "url", "http://evil.example/x", { VT_API_KEY: "k" });

    const us = r.sources.find(s => s.name === "urlscan");
    expect(us, "urlscan must answer for URLs").toBeTruthy();
    expect(us.verdict).toBe("malicious");
    expect(us.headline.toLowerCase()).toContain("malicious");
    // the screenshot the analyst pastes into the email, on urlscan's own origin
    expect(us.screenshot).toBe("https://urlscan.io/screenshots/0198abcd-1234.png");
    expect(us.url).toMatch(/^https:\/\/urlscan\.io\/result\//);
    // urlscan flags it, VT has nothing on record: 1 of 2 → red.
    expect(r.flagged).toBe(1);
    expect(r.consulted).toBe(2);
    expect(r.tone).toBe("red");
  });

  test("a URL nobody has scanned is a finding, not a failure — and never submitted", async () => {
    const seen = [];
    const spy = async (url, init) => {
      seen.push(String(url));
      if (String(url).includes("urlscan.io/api/v1/search"))
        return { ok: true, status: 200, json: async () => ({ total: 0, results: [] }) };
      return { ok: true, status: 404, json: async () => ({}) };  // VT 404
    };
    const r = await E.enrich(spy, "url", "http://never-scanned.example/y", { VT_API_KEY: "k" });
    const us = r.sources.find(s => s.name === "urlscan");
    expect(us.verdict).toBe("unknown");
    expect(us.headline.toLowerCase()).toMatch(/no existing scan|not scanned/);
    // never a submit/scan POST — inspecting existing scans only
    for (const u of seen)
      expect(/\/api\/v1\/scan/.test(u), `must not submit a scan: ${u}`).toBe(false);
  });

  test("urlscan only ever fetches urlscan.io, never the indicator", async () => {
    const seen = [];
    const spy = async (url) => {
      seen.push(String(url));
      if (String(url).includes("search")) return { ok: true, status: 200,
        json: async () => URLSCAN_SEARCH_HIT.body };
      return { ok: true, status: 200, json: async () => URLSCAN_RESULT_MAL.body };
    };
    await E.enrich(spy, "url", "http://evil.example/x", {});   // urlscan is keyless-capable
    // The indicator may appear as a query PARAMETER — that is how it is passed
    // to the API. What must never happen is an outbound request TO the
    // indicator's host. Check the fetched hostname, not the string.
    expect(seen.length).toBeGreaterThan(0);
    for (const u of seen) {
      expect(new URL(u).hostname).toBe("urlscan.io");
      expect(new URL(u).hostname).not.toBe("evil.example");
    }
  });

  test("private and malformed indicators are refused before any request", async () => {
    const never = fakeFetch({});               // any call throws "unrouted"
    for (const ip of ["10.0.0.5", "192.168.1.1", "127.0.0.1", "172.16.4.4", "169.254.1.1"])
      expect((await E.enrich(never, "ipv4", ip, KEYS)).error).toMatch(/private|reserved/i);

    expect((await E.enrich(never, "ipv4", "999.1.1.1", KEYS)).error).toMatch(/not a valid/);
    expect((await E.enrich(never, "sha256", "nothex", KEYS)).error).toMatch(/not a valid/);
    expect((await E.enrich(never, "url", "javascript:alert(1)", KEYS)).error).toMatch(/http/i);
    expect((await E.enrich(never, "wat", "x", KEYS)).error).toMatch(/unsupported/);
    expect((await E.enrich(never, "ipv4", "", KEYS)).error).toMatch(/empty/);
  });

  test("the indicator is passed to upstreams, never fetched itself", async () => {
    // An attacker-supplied URL must never become an outbound request of ours.
    const seen = [];
    const spy = async (url, init) => {
      seen.push(String(url));
      return { ok: true, status: 200, json: async () => ({ data: { attributes: {} } }) };
    };
    await E.enrich(spy, "url", "http://evil.example/payload.exe", { VT_API_KEY: "k" });
    // URLs are enriched by VirusTotal AND urlscan; both are legitimate upstream
    // hosts. The invariant is that we never fetch the indicator's own host.
    const UPSTREAMS = new Set(["www.virustotal.com", "urlscan.io"]);
    for (const u of seen) {
      const h = new URL(u).hostname;
      expect(h, `must not fetch the indicator host: ${u}`).not.toBe("evil.example");
      expect(UPSTREAMS.has(h), `unexpected outbound host: ${u}`).toBe(true);
    }
  });
});
