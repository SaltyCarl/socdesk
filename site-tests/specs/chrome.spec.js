// chrome.spec.js — the live chrome contract (stat band, live count,
// registry), checked against the payloads actually published in site/data/.
// The broadsheet masthead was cut in the re-layout; its edition/tracked-object/
// ingest plate no longer exists, so liveness is asserted on the surfaces that
// replaced it: the stat band count and the topbar live count.
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

  test("the stat band's daily-intelligence count equals the feed payload", async ({ page }) => {
    const n = R.feed().items.length;
    expect(n, "the feed must not be empty").toBeGreaterThan(0);
    // countUp() animates to the value, so poll rather than snapshot.
    await expect(page.locator('#band button[data-cat="all"] b')).toHaveText(nf(n), { timeout: 8000 });
  });

  test("#liveCount matches the ok/total in health.json", async ({ page }) => {
    const s = R.health().sources;
    const ok = s.filter(x => x.ok).length;
    await expect(page.locator("#liveCount")).toHaveText(`${ok}/${s.length} collectors online`);
    // the health grid must render one cell per collector
    await expect(page.locator("#healthGrid .hcell")).toHaveCount(s.length);
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
