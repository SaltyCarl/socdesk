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

  test("the headline verdict takes the worst credible answer", async () => {
    const r = await E.enrich(fakeFetch({
      "abuseipdb.com": ABUSE_OK,           // malicious
      "virustotal.com": VT_IP_OK,          // malicious
      "greynoise.io": GN_OK,               // malicious
    }), "ipv4", "185.220.101.42", KEYS);
    expect(r.verdict).toBe("malicious");

    // An analyst deciding whether to escalate needs the ceiling, not an average.
    expect(E.overall([{ verdict: "benign" }, { verdict: "suspicious" }])).toBe("suspicious");
    expect(E.overall([{ verdict: "unknown" }, { verdict: "benign" }])).toBe("benign");
    expect(E.overall([])).toBe("unknown");
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

    // Context alone must not manufacture a verdict.
    expect(E.overall([{ kind: "context", verdict: "unknown" }])).toBe("unknown");
    expect(E.overall([{ kind: "context", verdict: "benign" },
                      { verdict: "malicious" }])).toBe("malicious");
  });

  test("one dead upstream never takes the verdict down", async () => {
    const r = await E.enrich(fakeFetch({
      "abuseipdb.com": ABUSE_OK,
      "virustotal.com": { status: 500, body: {} },
      "greynoise.io": GN_OK,
    }), "ipv4", "185.220.101.42", KEYS);

    expect(r.sources.map(s => s.name).sort()).toEqual(["AbuseIPDB", "GreyNoise"]);
    expect(r.errors.find(e => e.source === "VirusTotal").reason).toContain("500");
    expect(r.verdict).toBe("malicious");        // still answers
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
    expect(r.verdict).toBe("unknown");
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
    expect(mb.verdict).toBe("malicious");
    expect(mb.headline).toContain("AgentTesla");
    expect(r.verdict).toBe("malicious");
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
    for (const u of seen)
      expect(u.startsWith("https://www.virustotal.com/"), `unexpected outbound: ${u}`).toBe(true);
  });
});
