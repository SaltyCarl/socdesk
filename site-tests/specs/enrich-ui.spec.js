// enrich-ui.spec.js — the front-end wiring of the live reputation lookup.
//
// Pages Functions do not run under the static QA server, so `/api/enrich` is
// stubbed with a fixture and the RENDER is asserted deterministically. The
// module itself (lib/enrich.mjs) is proven offline in enrich.spec.js; the live
// endpoint is verified by hand against socdesk.io. This file proves the third
// leg: that a resolved verdict actually reaches the console, replaces the
// "NOT IN CORPUS" placeholder, shows every source honestly, and never blanks or
// crashes when the endpoint is down.
const { test, expect } = require("@playwright/test");
const R = require("../lib/real");

// The enrich fetch fires on user action, by which point the service worker is
// active and would proxy it past page.route (SW-initiated requests are not
// intercepted). Block the SW so the stub route is authoritative; the SW's own
// hands-off treatment of /api/* is a separate, production concern.
test.use({ serviceWorkers: "block" });

const IP = "185.220.101.42";

// Shape per lib/enrich.mjs: 3 of 3 consulted reputation sources flagged it, one
// context row (ipinfo, excluded from the tally), one source named-but-
// unconsulted (MalwareBazaar), partial:true.
const MAL = {
  indicator: IP, type: "ipv4", checked_at: "2026-08-10T04:12:00.000Z",
  flagged: 3, consulted: 3, tone: "red",
  sources: [
    { name: "AbuseIPDB", verdict: "malicious",
      headline: "100% abuse confidence · 412 reports in 90 days",
      facts: [["Abuse confidence", "100%"], ["Reports (90 days)", "412"], ["Country", "NL"]],
      url: "https://www.abuseipdb.com/check/" + IP },
    { name: "VirusTotal", verdict: "malicious",
      headline: "12/94 engines flag this as malicious",
      facts: [["Detections", "12 malicious · 2 suspicious · of 94"], ["Reputation", "-41"]],
      url: "https://www.virustotal.com/gui/ip-address/" + IP },
    { name: "GreyNoise", verdict: "malicious",
      headline: "Opportunistic internet scanner — mass activity, not targeted",
      facts: [["Classification", "malicious"], ["Internet noise", "yes"]],
      url: "https://viz.greynoise.io/ip/" + IP },
    { name: "ipinfo", kind: "context", verdict: "unknown",
      headline: "Berlin, State of Berlin, DE · AS60729",
      facts: [["ASN", "AS60729"], ["Reverse hostname", "tor-exit-42.for-privacy.net"]],
      url: "https://ipinfo.io/" + IP },
  ],
  partial: true,
  errors: [{ source: "MalwareBazaar", reason: "not configured" }],
};

const stub = (body, { status = 200, delay = 0 } = {}) => async route => {
  if (delay) await new Promise(r => setTimeout(r, delay));
  route.fulfill({ status, contentType: "application/json", body: JSON.stringify(body) });
};

async function lookup(page, q) { await page.fill("#q", q); await page.press("#q", "Enter"); }

test.describe("live enrichment wiring", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/index.html");
    await page.waitForFunction(() => document.querySelectorAll("#feedRows .row").length > 0);
  });

  test("a loading state shows, then the consensus tally replaces NOT IN CORPUS", async ({ page }) => {
    await page.route("**/api/enrich*", stub(MAL, { delay: 800 }));

    await lookup(page, IP);

    // The live panel announces itself while it waits (the static router verdict
    // is what sits above it, decoding in place).
    await expect(page.locator("#liveEnrich .live-status")).toContainText("Checking", { timeout: 4000 });

    // Then the tally arrives: N / M, colored by the ratio, with the §2 headline.
    await expect(page.locator("#liveEnrich .tally .tally-num"))
      .toHaveText("3 / 3", { timeout: 8000 });
    await expect(page.locator("#liveEnrich .tally .tally-num")).toHaveClass(/tone-red/);
    await expect(page.locator("#liveEnrich .tally-headline"))
      .toContainText("3 of 3 consulted sources flagged this as adverse");
    // SOCDesk never says a verdict word of its own for a live indicator
    await expect(page.locator("#liveEnrich")).not.toContainText(/\bMALICIOUS\b/);

    // the static placeholder is REPLACED, not left contradicting the live answer
    await expect(page.locator("#vword")).toHaveText("3 / 3", { timeout: 8000 });
    await expect(page.locator("#vword")).toHaveClass(/tone-red/);
    await expect(page.locator("#console .vc-head .caps").first()).toContainText("Live reputation");
    // the on-screen escalation docket is rebuilt to the ratio-led §4 card
    await expect(page.locator("#escBody")).toContainText("ASSESSMENT: 3 of 3 public reputation sources flagged this as adverse");
    await expect(page.locator("#escBody")).toContainText("CAVEAT:");
    await expect(page.locator("#escBody")).not.toContainText("NOT IN CORPUS");
  });

  test("every source is an attributed finding, with facts and a verifiable link", async ({ page }) => {
    await page.route("**/api/enrich*", stub(MAL));
    await lookup(page, IP);
    await expect(page.locator("#liveEnrich .src-block")).toHaveCount(4, { timeout: 8000 });

    const names = (await page.locator("#liveEnrich .src-name").allInnerTexts())
      .map(s => s.toLowerCase());
    expect(names.sort()).toEqual(["abuseipdb", "greynoise", "ipinfo", "virustotal"]);

    // each line attributes: the source name + its RAW finding, stated as fact
    const abuse = page.locator("#liveEnrich .src-block", { hasText: "AbuseIPDB" });
    await expect(abuse.locator(".src-headline")).toContainText("100% abuse confidence");

    // geolocation is CONTEXT, explicitly not a verdict
    const geo = page.locator("#liveEnrich .src-block", { hasText: "ipinfo" });
    await expect(geo.locator(".tag")).toContainText("context — not a verdict");

    // every source links back, https only
    const hrefs = await page.locator("#liveEnrich .src-verify").evaluateAll(as => as.map(a => a.href));
    expect(hrefs.length).toBeGreaterThanOrEqual(4);
    for (const h of hrefs) expect(h).toMatch(/^https:\/\//);
  });

  test("a source that was not consulted is named, never hidden", async ({ page }) => {
    await page.route("**/api/enrich*", stub(MAL));
    await lookup(page, IP);
    await expect(page.locator("#liveEnrich .live-partial")).toBeVisible({ timeout: 8000 });
    await expect(page.locator("#liveEnrich .live-gaps")).toContainText("MalwareBazaar");
    await expect(page.locator("#liveEnrich .live-gaps")).toContainText("not configured");
  });

  test("the ready-to-paste evidence card renders on a light ground", async ({ page }) => {
    await page.route("**/api/enrich*", stub(MAL));
    await lookup(page, IP);
    const canvas = page.locator("#liveEnrich canvas.evcard-canvas");
    await expect(canvas).toHaveCount(1, { timeout: 8000 });
    const corner = await canvas.evaluate(c => {
      const d = c.getContext("2d").getImageData(20, 20, 1, 1).data;
      return [d[0], d[1], d[2]];
    });
    expect(corner.every(v => v > 240), "the escalation card is a light artifact").toBe(true);
  });

  test("a dead endpoint degrades to the static verdict and pivots, never a blank or a crash", async ({ page }) => {
    // a failed API load logs a benign resource error in the console; a CRASH
    // (pageerror) is what must never happen
    const crashes = [];
    page.on("pageerror", e => crashes.push(e.message));
    const errs = R.watchConsole(page, [/status of 503/i]);
    await page.route("**/api/enrich*", stub({ down: true }, { status: 503 }));
    await lookup(page, IP);

    await expect(page.locator("#liveEnrich")).toContainText("unavailable", { timeout: 8000 });
    // the static verdict and its pivots are untouched
    await expect(page.locator("#vword")).toHaveText("NOT IN CORPUS");
    await expect(page.locator("#console .pivots a.pivot").first()).toBeVisible();
    await expect(page.locator("#liveEnrich canvas")).toHaveCount(0);
    expect(crashes, "the degrade path must not throw").toEqual([]);
    expect(errs()).toEqual([]);
  });

  test("a refused indicator says so honestly instead of failing silently", async ({ page }) => {
    // /api/enrich answers a private IP with a 400 + reason.
    await page.route("**/api/enrich*",
      stub({ error: "private or reserved address — not enriched" }, { status: 400 }));
    // 8.8.8.8 detects as ipv4 and is enrichable; the stub decides the outcome.
    await lookup(page, "8.8.8.8");
    await expect(page.locator("#liveEnrich")).toContainText("declined", { timeout: 8000 });
    await expect(page.locator("#liveEnrich .live-note")).toContainText("private or reserved");
  });

  test("hostile upstream text is escaped, not executed", async ({ page }) => {
    const hostile = {
      ...MAL,
      sources: [{ name: "VirusTotal", verdict: "malicious",
        headline: `</span><img src=x onerror="window.__pwned=1"><script>window.__pwned=1</script>`,
        facts: [["Note", `"><b>x</b>`]],
        url: "https://www.virustotal.com/gui/ip-address/" + IP }],
      errors: [],
    };
    await page.route("**/api/enrich*", stub(hostile));
    await lookup(page, IP);
    await expect(page.locator("#liveEnrich .src-headline")).toBeVisible({ timeout: 8000 });
    expect(await page.evaluate(() => window.__pwned)).toBeUndefined();
    // the markup survived as literal text
    await expect(page.locator("#liveEnrich .src-headline")).toContainText("<script>");
  });

  test("non-enrichable types never call /api/enrich; an IP always does", async ({ page }) => {
    const seen = [];
    await page.route("**/api/enrich*", route => { seen.push(route.request().url()); return stub(MAL)(route); });

    await lookup(page, R.topKevCve().cve);              // CVE — authoritative, not enriched
    await page.waitForTimeout(300);
    await lookup(page, "analyst@example.com");           // email — pivot-only
    await page.waitForTimeout(300);
    expect(seen, "CVE and email must not hit the endpoint").toEqual([]);

    await lookup(page, IP);
    await expect(page.locator("#liveEnrich .src-block").first()).toBeVisible({ timeout: 8000 });
    expect(seen.length).toBe(1);
    expect(seen[0]).toContain("type=ipv4");
    expect(seen[0]).toContain(encodeURIComponent(IP));
  });
});
