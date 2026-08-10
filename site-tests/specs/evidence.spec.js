// evidence.spec.js — the card is the artifact that leaves the tool and goes in
// front of a client. What it says has to be right before what it looks like
// matters, so the content model is asserted separately from the pixels.
const { test, expect } = require("@playwright/test");

// A realistic malicious IP, one source deliberately unreachable so the card has
// to admit it.
const RESULT = {
  indicator: "185.220.101.42", type: "ipv4",
  checked_at: "2026-08-09T04:12:00.000Z",
  // The consensus tally replaces the old single-word verdict: 3 of 3 consulted
  // reputation sources flagged it (ipinfo is context, not consulted).
  flagged: 3, consulted: 3, tone: "red",
  sources: [
    { name: "AbuseIPDB", verdict: "malicious",
      headline: "100% abuse confidence · 412 reports in 90 days",
      facts: [["Abuse confidence", "100%"], ["Reports (90 days)", "412"],
              ["Distinct reporters", "89"], ["Last reported", "2026-08-08"],
              ["ISP", "Example Hosting BV"],
              ["Usage type", "Data Center/Web Hosting/Transit"],
              ["Country", "NL"], ["Tor exit node", "yes"]],
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

async function load(page) {
  await page.goto("/index.html");
  await page.evaluate(() => document.fonts.ready);
}

const model = (page, result) => page.evaluate(async r => {
  const { evidenceModel } = await import("./js/evidence.js");
  return evidenceModel(r);
}, result);

test.describe("escalation evidence card", () => {
  test.beforeEach(async ({ page }) => { await load(page); });

  test("geolocation is labelled context, never counted in the tally", async ({ page }) => {
    // Where an address is hosted says nothing about whether it is hostile. It is
    // context — excluded from N and M — and it must sit last, after the findings.
    const m = await model(page, { ...RESULT, sources: [
      ...RESULT.sources,
      { name: "ipinfo", kind: "context", verdict: "unknown",
        headline: "Berlin, State of Berlin, DE · AS60729",
        facts: [["ASN", "AS60729"], ["Reverse hostname", "tor-exit-42.for-privacy.net"]],
        url: "https://ipinfo.io/185.220.101.42" },
    ] });

    const geo = m.blocks.find(b => b.name === "ipinfo");
    expect(geo.kind).toBe("context");
    expect(m.blocks[m.blocks.length - 1].name).toBe("ipinfo");   // context last
    // the tally is unaffected by adding context
    expect(m.tallyNum).toBe("3 / 3");
    expect(m.tone).toBe("red");
  });

  test("the card says what produced it", async ({ page }) => {
    // The recipient is handed a composite by a tool they may not know. The
    // card's credibility is provenance, so it names itself.
    const m = await model(page, RESULT);
    expect(m.origin).toContain("socdesk.io");
  });

  test("every source on the card carries its own verifiable link", async ({ page }) => {
    // The card is our composite of other people's data. Without the link back,
    // the recipient has to take our retyping on faith — which is exactly why
    // analysts screenshot the original page instead.
    const m = await model(page, RESULT);
    expect(m.blocks).toHaveLength(3);
    for (const b of m.blocks) {
      expect(b.url, `${b.name} must link back`).toMatch(/^https:\/\//);
      expect(b.url).toContain("185.220.101.42");
      expect(b.headline.length).toBeGreaterThan(0);
    }
  });

  test("a source that was not consulted is named on the card", async ({ page }) => {
    // Omitting it would imply the card is complete when it is not.
    const m = await model(page, RESULT);
    expect(m.notConsulted).toEqual(["MalwareBazaar (not configured)"]);
  });

  test("the headline is the ratio, in words a recipient can act on", async ({ page }) => {
    const m = await model(page, RESULT);
    expect(m.tallyNum).toBe("3 / 3");
    expect(m.headline).toContain("3 of 3 consulted sources flagged this as adverse");
    expect(m.checkedAt).toBe("2026-08-09 04:12 UTC");
    expect(m.typeLabel).toBe("IP ADDRESS");

    // 0 of M must never render as a clean bill of health — the sources we asked
    // found nothing, which is not the same as the indicator being safe.
    const clean = await model(page, { ...RESULT, flagged: 0, consulted: 3, tone: "green", errors: [] });
    expect(clean.tallyNum).toBe("0 / 3");
    expect(clean.headline).toContain("no adverse findings");
    expect(clean.headline).toContain("Not a clearance");
    // nothing consulted → grey, and it is not evidence of safety
    const nothing = await model(page, { ...RESULT, flagged: 0, consulted: 0, tone: "grey", errors: [] });
    expect(nothing.tallyNum).toBe("0 / 0");
    expect(nothing.headline).toContain("Not evidence of safety");
  });

  test("empty facts are dropped rather than printed as em dashes", async ({ page }) => {
    const m = await model(page, { ...RESULT, sources: [{
      name: "VirusTotal", verdict: "unknown", headline: "Not present",
      facts: [["Detections", "none"], ["Reputation", "—"], ["File type", ""]],
      url: "https://www.virustotal.com/gui/file/x" }] });
    expect(m.blocks[0].facts).toEqual([["Detections", "none"]]);
  });

  test("it renders a light card at print resolution", async ({ page }) => {
    const info = await page.evaluate(async r => {
      const { renderEvidence } = await import("./js/evidence.js");
      const c = renderEvidence(r);
      const ctx = c.getContext("2d");
      const corner = ctx.getImageData(20, 20, 1, 1).data;   // inside the card
      return { w: c.width, h: c.height, corner: [...corner].slice(0, 3) };
    }, RESULT);

    expect(info.w).toBe(1520);                       // 760 CSS px at 2x
    expect(info.h).toBeGreaterThan(900);             // three sources of content
    // Light background is a hard requirement: this lands in an email body.
    expect(info.corner.every(v => v > 240)).toBe(true);
  });

  test("the rendered card is a real PNG of non-trivial size", async ({ page }) => {
    const bytes = await page.evaluate(async r => {
      const { renderEvidence, toBlob } = await import("./js/evidence.js");
      const blob = await toBlob(renderEvidence(r));
      return { type: blob.type, size: blob.size };
    }, RESULT);
    expect(bytes.type).toBe("image/png");
    expect(bytes.size).toBeGreaterThan(10_000);
  });

  test("a blocked clipboard reports failure instead of claiming success", async ({ page }) => {
    // The project has already shipped a button that said COPIED while the
    // clipboard rejected the write. Never again.
    const ok = await page.evaluate(async r => {
      const { renderEvidence, copyEvidence } = await import("./js/evidence.js");
      navigator.clipboard.write = () => Promise.reject(new Error("denied"));
      return copyEvidence(renderEvidence(r));
    }, RESULT);
    expect(ok).toBe(false);
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
      return renderEvidence(long).height;
    });
    expect(h).toBeGreaterThan(600);      // grew to fit rather than clipping
  });
});
