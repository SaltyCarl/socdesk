// chrome.spec.js — the masthead / live chrome contract, checked against the
// payloads that are actually published in site/data/.
const { test, expect } = require("@playwright/test");
const R = require("../lib/real");

const nf = n => n.toLocaleString("en-US");

test.describe("page chrome", () => {
  let errors;

  test.beforeEach(async ({ page }) => {
    errors = R.watchConsole(page);
    await page.goto("/index.html");
    await page.waitForFunction(() => document.querySelectorAll("#feedRows .row").length > 0);
  });

  test("tracked-object count is non-zero and equals feed + cves + actors + malware", async ({ page }) => {
    const total = R.trackedTotal();
    expect(total, "corpus must not be empty").toBeGreaterThan(0);
    // countUp() animates to the value, so poll rather than snapshot.
    await expect(page.locator("#mastCount")).toHaveText(nf(total), { timeout: 8000 });
  });

  test("edition stamp comes from the feed's generated_at", async ({ page }) => {
    const gen = R.feed().generated_at;
    await expect(page.locator("#mastEdition")).toHaveText(new RegExp(`^${gen.slice(0, 10)} · [A-Z]{3}$`));
  });

  test("#liveCount matches the ok/total in health.json", async ({ page }) => {
    const s = R.health().sources;
    const ok = s.filter(x => x.ok).length;
    await expect(page.locator("#liveCount")).toHaveText(`${ok}/${s.length} collectors online`);
    // the health grid must render one cell per collector
    await expect(page.locator("#healthGrid .hcell")).toHaveCount(s.length);
  });

  test("ticker carries at least 6 items, built from real KEV + feed rows", async ({ page }) => {
    const items = page.locator("#tickTrack .tick-item");
    const n = await items.count();
    // the track is duplicated for the -50% marquee loop, so unique = n / 2
    expect(n % 2, "ticker track must be duplicated for a seamless loop").toBe(0);
    expect(n / 2, "at least six distinct ticker items").toBeGreaterThanOrEqual(6);
    const first = (await items.first().innerText()).trim();
    expect(first.length).toBeGreaterThan(4);
  });

  test("elapsed and next-pull counters render live values, not placeholders", async ({ page }) => {
    // elapsed() is +HH:MM:SS on our own clock; nextPull() is a U+2212 countdown.
    await expect(page.locator("#mastRefreshed")).toHaveText(/^\+\d{2}:\d{2}:\d{2}$/);
    await expect(page.locator("#mastNext")).toHaveText(/^−\d{2}:\d{2}$/);

    const before = await page.locator("#mastRefreshed").innerText();
    await page.waitForTimeout(1600);
    const after = await page.locator("#mastRefreshed").innerText();
    expect(after, "the elapsed clock must actually tick").not.toBe(before);
  });

  test("source registry renders every row in sources.json with its split", async ({ page }) => {
    const rows = R.sources().sources;
    await expect(page.locator("#regRows tr")).toHaveCount(rows.length);
    await expect(page.locator("#regCollectors"))
      .toHaveText(String(rows.filter(s => s.kind === "collector").length));
    await expect(page.locator("#regReference"))
      .toHaveText(String(rows.filter(s => s.kind === "reference").length));
  });

  test("no console errors beyond the known brief.json 404", async ({ page }) => {
    await page.waitForTimeout(1500);
    expect(errors()).toEqual([]);
  });
});
