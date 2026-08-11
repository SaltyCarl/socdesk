// evidence.spec.js — the "Copy card" is the artifact that leaves the tool and
// goes in front of a client. What it SAYS has to be right before what it looks
// like matters, so the content model is asserted separately from the pixels.
//
// The renderer is shared byte-for-byte by the site and the extension; the last
// test proves the two copies have not drifted.
const { test, expect } = require("@playwright/test");
const fs = require("fs");
const path = require("path");

// A realistic malicious IP, one source deliberately unreachable so the card has
// to admit it. AbuseIPDB tags it a Tor exit node (a dual-use qualifier).
const RESULT = {
  indicator: "185.220.101.42", type: "ipv4",
  checked_at: "2026-08-09T04:12:00.000Z",
  // The consensus tally: 3 of 3 consulted reputation sources flagged it
  // (ipinfo is context, not consulted).
  flagged: 3, consulted: 3, tone: "red",
  sources: [
    { name: "AbuseIPDB", verdict: "malicious",
      headline: "100% abuse confidence · 412 reports in 90 days",
      facts: [["Abuse confidence", "100%"], ["Reports (90 days)", "412"],
              ["Distinct reporters", "89"], ["Last reported", "2026-08-08"],
              ["ISP", "Example Hosting BV"],
              ["Usage type", "Data Center/Web Hosting/Transit"],
              ["Country", "DE"], ["Tor exit node", "yes"]],
      url: "https://www.abuseipdb.com/check/185.220.101.42" },
    { name: "VirusTotal", verdict: "malicious",
      headline: "12/94 engines flag this as malicious",
      facts: [["Detections", "12 malicious · 2 suspicious · of 94"],
              ["Reputation", "-41"], ["Last analysed", "2026-08-08"],
              ["Sample detections", "Fortinet: Malicious · ESET: Tor.Exit"]],
      url: "https://www.virustotal.com/gui/ip-address/185.220.101.42" },
    { name: "GreyNoise", verdict: "malicious",
      headline: "Opportunistic internet scanner — mass activity, not targeted",
      facts: [["Classification", "malicious"], ["Actor", "Tor Exit Node"],
              ["Internet noise", "yes"], ["Last seen", "2026-08-08"]],
      url: "https://viz.greynoise.io/ip/185.220.101.42" },
  ],
  partial: true,
  errors: [{ source: "MalwareBazaar", reason: "not configured" }],
};

// The same result with the ipinfo geolocation context row present, including the
// precise lat/long ipinfo now surfaces as "Coordinates" (§ enrich contract).
const WITH_GEO = { ...RESULT, sources: [
  ...RESULT.sources,
  { name: "ipinfo", kind: "context", verdict: "unknown",
    headline: "Frankfurt, Hesse, DE · AS3209",
    facts: [["Location", "Frankfurt, Hesse, DE"], ["Coordinates", "50.1109,8.6821"],
            ["ASN", "AS3209"], ["Organisation", "Vodafone GmbH"],
            ["Reverse hostname", "tor-exit-42.for-privacy.net"],
            ["Timezone", "Europe/Berlin"]],
    url: "https://ipinfo.io/185.220.101.42" },
] };

// ipinfo without a coordinate (older / partial response) — the card must still
// render, falling back to the country centroid.
const GEO_NO_LOC = { ...RESULT, sources: [
  ...RESULT.sources,
  { name: "ipinfo", kind: "context", verdict: "unknown",
    headline: "Frankfurt, Hesse, DE · AS3209",
    facts: [["Location", "Frankfurt, Hesse, DE"], ["Coordinates", "—"],
            ["ASN", "AS3209"], ["Organisation", "Vodafone GmbH"]],
    url: "https://ipinfo.io/185.220.101.42" },
] };

async function load(page) {
  await page.goto("/index.html");
  await page.evaluate(() => document.fonts.ready);
}

const model = (page, result) => page.evaluate(async r => {
  const { evidenceModel } = await import("./js/evidence.js");
  return evidenceModel(r);
}, result);

test.describe("escalation Copy card", () => {
  test.beforeEach(async ({ page }) => { await load(page); });

  test("geolocation is a separate context block, never counted in the tally", async ({ page }) => {
    // Where an address is hosted says nothing about whether it is hostile. It is
    // context — excluded from N and M, drawn in its own hero, labelled so.
    const m = await model(page, WITH_GEO);

    expect(m.geo).not.toBeNull();
    expect(m.geo.countryCode).toBe("DE");
    expect(m.geo.countryName).toBe("Germany");
    expect(m.geo.asn).toBe("AS3209");
    // ipinfo never appears among the counted reputation rows
    expect(m.sources.some(s => s.name === "ipinfo")).toBe(false);
    // and the tally is unaffected by the presence of context
    expect(m.tallyNum).toBe("3 / 3");
    expect(m.tone).toBe("red");
    expect(m.consulted).toBe(3);
  });

  test("the locator uses ipinfo's real lat/long when present, and the city", async ({ page }) => {
    // ipinfo now surfaces "Coordinates" (lat,lng). The pin is plotted from those
    // real numbers and the "country-level" fallback label is dropped.
    const m = await model(page, WITH_GEO);
    expect(m.geo.precise).toBe(true);
    expect(m.geo.lat).toBeCloseTo(50.1109, 3);
    expect(m.geo.lon).toBeCloseTo(8.6821, 3);
    expect(m.geo.city).toBe("Frankfurt");
  });

  test("the locator falls back to the country centroid when no coordinate is present", async ({ page }) => {
    // An older / partial ipinfo response has no "Coordinates" — the card must
    // still render honestly, at the country centroid, marked country-level.
    const m = await model(page, GEO_NO_LOC);
    expect(m.geo).not.toBeNull();
    expect(m.geo.precise).toBe(false);
    expect(m.geo.countryCode).toBe("DE");
    // centroid for DE, not a precise per-host coordinate
    expect(m.geo.lat).toBeCloseTo(51.2, 1);
  });

  test("the copied card carries NO branding — neutral timestamp provenance only", async ({ page }) => {
    // Finalized decision + VERDICT-LANGUAGE §4: the name/mark live in the app
    // UI, never in the copied artifact. The card's only provenance is a pair of
    // timestamps; the artifact rides inside the analyst's own MSSP email.
    const m = await model(page, WITH_GEO);
    expect(JSON.stringify(m).toLowerCase()).not.toContain("socdesk");
    expect(m.provenance.generated).toMatch(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC$/);
    expect(m.provenance.queried).toBe("2026-08-09 04:12 UTC");
  });

  test("a dual-use / mitigating qualifier is surfaced (promoted under the tally)", async ({ page }) => {
    // So "3 of 3 flagged" is never read as 3 independent confirmations: the
    // Tor-exit note tempers it, and it is carried in the model's mitigations
    // (drawn directly beneath the tally), not buried at the bottom.
    const m = await model(page, RESULT);
    expect(m.mitigations.length).toBeGreaterThan(0);
    expect(m.mitigations.join(" ")).toContain("Tor exit node");
  });

  test("analyst jargon is glossed for a client-facing reader", async ({ page }) => {
    const m = await model(page, { ...RESULT, sources: [{
      name: "ThreatFox", verdict: "malicious",
      headline: "records 2 IOCs; threat type: botnet C2",
      facts: [], url: "https://threatfox.abuse.ch/browse/" }] });
    const finding = m.sources[0].finding;
    expect(finding).toContain("indicators of compromise");
    expect(finding).toContain("command-and-control");
  });

  test("every source on the card carries its own verifiable link", async ({ page }) => {
    // The card is our composite of other people's data. Without the link back,
    // the recipient has to take our retyping on faith.
    const m = await model(page, RESULT);
    expect(m.sources).toHaveLength(3);
    for (const s of m.sources) {
      expect(s.url, `${s.name} must link back`).toMatch(/^https:\/\//);
      expect(s.url).toContain("185.220.101.42");
      expect(s.finding.length).toBeGreaterThan(0);
    }
  });

  test("clean / negative sources are kept on the card, part of the N of M denominator", async ({ page }) => {
    // Dropping a disconfirming source (e.g. Spamhaus "not listed") would make a
    // "5 of 6" read like a unanimous "5 of 5". Every source that returned a real
    // finding stays — only NOT-CONSULTED sources come off (and are no longer
    // drawn as a line at all).
    const withClean = { ...RESULT, flagged: 3, consulted: 4, tone: "red", sources: [
      ...RESULT.sources,
      { name: "Spamhaus", verdict: "benign", headline: "not listed", facts: [],
        url: "https://check.spamhaus.org/" },
    ] };
    const m = await model(page, withClean);
    expect(m.sources.map(s => s.name)).toContain("Spamhaus");
    expect(m.sources).toHaveLength(4);
    expect(m.counts).toEqual({ malicious: 3, suspicious: 0, notFlagged: 1 });
    expect(m.caption.right).toBe("1 not flagged");
  });

  test("the caveat is the §4 wording, baked into the card", async ({ page }) => {
    const m = await model(page, RESULT);
    expect(m.caveat).toContain("Reflects third-party reputation gathered at the time shown");
    expect(m.caveat).toContain("has not been independently confirmed");
  });

  test("the headline is the ratio, in words a recipient can act on", async ({ page }) => {
    const m = await model(page, RESULT);
    expect(m.tallyNum).toBe("3 / 3");
    expect(m.headline).toContain("3 of 3 public reputation sources flagged this as adverse");
    expect(m.typeLabel).toBe("IPv4");
    expect(m.counts).toEqual({ malicious: 3, suspicious: 0, notFlagged: 0 });

    // 0 of M must never render as a clean bill of health.
    const clean = await model(page, { ...RESULT, flagged: 0, consulted: 3, tone: "green",
      sources: RESULT.sources.map(s => ({ ...s, verdict: "benign" })), errors: [] });
    expect(clean.tallyNum).toBe("0 / 3");
    expect(clean.headline).toContain("no adverse findings");
    expect(clean.headline).toContain("Not a clearance");
    // nothing consulted → grey, and it is not evidence of safety
    const nothing = await model(page, { ...RESULT, flagged: 0, consulted: 0, tone: "grey",
      sources: [], errors: [] });
    expect(nothing.tallyNum).toBe("0 / 0");
    expect(nothing.headline).toContain("Not evidence of safety");
  });

  test("one gauge segment per consulted source, coloured by its finding", async ({ page }) => {
    const m = await model(page, { ...RESULT, flagged: 2, consulted: 3, tone: "red", sources: [
      { ...RESULT.sources[0], verdict: "malicious" },
      { ...RESULT.sources[1], verdict: "suspicious" },
      { ...RESULT.sources[2], verdict: "benign" },
    ] });
    expect(m.segments.map(s => s.verdict)).toEqual(["malicious", "suspicious", "benign"]);
    expect(m.caption.left).toBe("1 malicious · 1 suspicious");
    expect(m.caption.right).toBe("1 not flagged");
  });

  test("it renders a card at print resolution in BOTH themes", async ({ page }) => {
    const probe = (theme) => page.evaluate(async ({ r, theme }) => {
      const { renderEvidence } = await import("./js/evidence.js");
      const c = renderEvidence(r, { theme });
      const ctx = c.getContext("2d");
      const { data } = ctx.getImageData(0, 0, c.width, c.height);
      let sum = 0, n = 0;
      for (let i = 0; i < data.length; i += 40) {        // sample every 10th px
        if (data[i + 3] < 10) continue;                  // skip transparent corners
        sum += 0.2126 * data[i] + 0.7152 * data[i + 1] + 0.0722 * data[i + 2];
        n++;
      }
      return { w: c.width, h: c.height, mean: sum / n };
    }, { r: WITH_GEO, theme });

    const light = await probe("light");
    const dark = await probe("dark");

    expect(light.w).toBe(880);                    // 440 CSS px at 2x
    expect(dark.w).toBe(880);
    expect(light.h).toBeGreaterThan(900);         // tally + geo hero + 3 sources
    expect(dark.h).toBe(light.h);                 // same content ⇒ same height
    // warm-paper light is bright; espresso dark is dark — clearly separated.
    expect(light.mean).toBeGreaterThan(150);
    expect(dark.mean).toBeLessThan(110);
  });

  test("the rendered card is a real PNG of non-trivial size", async ({ page }) => {
    const bytes = await page.evaluate(async r => {
      const { renderEvidence, toBlob } = await import("./js/evidence.js");
      const blob = await toBlob(renderEvidence(r, { theme: "dark" }));
      return { type: blob.type, size: blob.size };
    }, WITH_GEO);
    expect(bytes.type).toBe("image/png");
    expect(bytes.size).toBeGreaterThan(10_000);
  });

  test("a blocked clipboard reports failure instead of claiming success", async ({ page }) => {
    // The project has already shipped a button that said COPIED while the
    // clipboard rejected the write. Never again.
    const ok = await page.evaluate(async r => {
      const { renderEvidence, copyEvidence } = await import("./js/evidence.js");
      navigator.clipboard.write = () => Promise.reject(new Error("denied"));
      return copyEvidence(renderEvidence(r, { theme: "dark" }));
    }, RESULT);
    expect(ok).toBe(false);
  });

  test("the ClipboardItem image/png write path executes on a permissive clipboard", async ({ page }) => {
    // Prove the happy path runs without throwing and actually calls write() with
    // an image/png ClipboardItem — the feature the whole card exists to deliver.
    const res = await page.evaluate(async r => {
      const { renderEvidence, copyEvidence } = await import("./js/evidence.js");
      let wroteType = null;
      navigator.clipboard.write = async (items) => {
        wroteType = items[0] && [...(items[0].types || [])][0];
      };
      const ok = await copyEvidence(renderEvidence(r, { theme: "light" }));
      return { ok, wroteType };
    }, RESULT);
    expect(res.ok).toBe(true);
    expect(res.wroteType).toBe("image/png");
  });

  test("long unbroken values wrap instead of running off the card", async ({ page }) => {
    // A SHA-256 has no spaces. Naive word wrapping silently clips it, and a
    // truncated hash on an escalation is worse than no hash.
    const h = await page.evaluate(async () => {
      const { renderEvidence } = await import("./js/evidence.js");
      const long = { indicator: "d".repeat(64), type: "sha256",
        checked_at: "2026-08-09T04:12:00.000Z", flagged: 1, consulted: 1, tone: "red",
        sources: [{ name: "VirusTotal", verdict: "malicious",
          headline: "60/72 engines flag this as malicious",
          facts: [["Sample detections", "A".repeat(300)]],
          url: "https://www.virustotal.com/gui/file/" + "d".repeat(64) }],
        errors: [] };
      return renderEvidence(long, { theme: "dark" }).height;
    });
    expect(h).toBeGreaterThan(400);      // grew to fit rather than clipping
  });

  test("the shared renderer is byte-identical in the site and the extension", async () => {
    // The site and the extension MUST emit the same card. The only guarantee of
    // that is that they run the same bytes. site-tests/lib/real.js resolves SITE
    // as <repo>/site, so the repo root is one level up.
    const siteFile = path.join(__dirname, "..", "..", "site", "js", "evidence.js");
    const extFile = path.join(__dirname, "..", "..", "extension", "lib", "evidence.js");
    const a = fs.readFileSync(siteFile);
    const b = fs.readFileSync(extFile);
    expect(b.equals(a), "extension/lib/evidence.js must be a byte-identical copy of site/js/evidence.js").toBe(true);
  });
});
