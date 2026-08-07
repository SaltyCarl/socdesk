// feed.spec.js — the operations feed: completeness, filtering, search,
// per-analyst review state, and the JSON export an analyst hands to a ticket.
const { test, expect } = require("@playwright/test");
const fs = require("fs");
const R = require("../lib/real");

test.describe("threat operations feed", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/index.html");
    await page.waitForFunction(() => document.querySelectorAll("#feedRows .row").length > 0);
  });

  test("renders every item in feed.json — nothing silently truncated", async ({ page }) => {
    const n = R.feed().items.length;
    expect(n).toBeGreaterThan(0);
    await expect(page.locator("#feedRows .row")).toHaveCount(n);
    await expect(page.locator("#fhCount"))
      .toHaveText(`Showing ${n.toLocaleString("en-US")} of ${n.toLocaleString("en-US")}`);
  });

  test("every category chip filters to exactly the count printed on that chip", async ({ page }) => {
    const chips = page.locator("#filters .fchip");
    const count = await chips.count();
    expect(count, "one chip per category plus 'all'").toBe(R.categoryCounts().size);

    for (let i = 0; i < count; i++) {
      const chip = chips.nth(i);
      const cat = await chip.getAttribute("data-f");
      const printed = Number((await chip.locator("b").innerText()).replace(/[^\d]/g, ""));
      // the chip's own number is the site's claim; the rendered rows are the truth
      expect(printed, `chip ${cat} claims a count matching the payload`)
        .toBe(R.categoryCounts().get(cat));
      await chip.click();
      await expect(page.locator("#feedRows .row")).toHaveCount(printed, { timeout: 8000 });
      await expect(page.locator("#fhCat")).toHaveText(cat);
    }
  });

  test("the search box narrows results and the chip agrees with the DOM", async ({ page }) => {
    const total = R.feed().items.length;
    // a term computed from the live payload: present in some items, not all
    const { term, expected } = R.narrowingTerm();
    expect(expected).toBeGreaterThan(0);
    expect(expected).toBeLessThan(total);

    await page.fill("#q2", term);
    await expect(page.locator("#resChip"))
      .toHaveText(`${expected.toLocaleString("en-US")} results`, { timeout: 8000 });
    await expect(page.locator("#feedRows .row")).toHaveCount(expected, { timeout: 8000 });

    await page.fill("#q2", "zzz-no-such-token-zzz");
    await expect(page.locator("#feedRows .row")).toHaveCount(0, { timeout: 8000 });

    await page.fill("#q2", "");
    await expect(page.locator("#feedRows .row")).toHaveCount(total, { timeout: 8000 });
  });

  test("the reviewed toggle survives a reload", async ({ page }) => {
    const row = page.locator("#feedRows .row").nth(2);
    const id = await row.getAttribute("data-id");
    await expect(row).not.toHaveClass(/reviewed/);
    await row.locator("[data-act=review]").click();
    await expect(row).toHaveClass(/reviewed/);

    await page.reload();
    await page.waitForFunction(() => document.querySelectorAll("#feedRows .row").length > 0);
    await expect(page.locator(`#feedRows .row[data-id="${id}"]`)).toHaveClass(/reviewed/);

    // and un-review persists too, so the flag is state and not a one-way latch
    await page.locator(`#feedRows .row[data-id="${id}"] [data-act=review]`).click();
    await page.reload();
    await page.waitForFunction(() => document.querySelectorAll("#feedRows .row").length > 0);
    await expect(page.locator(`#feedRows .row[data-id="${id}"]`)).not.toHaveClass(/reviewed/);
  });

  test("the JSON export downloads and parses to the visible rows", async ({ page }) => {
    const cat = "vulnerability";
    await page.locator(`#filters .fchip[data-f="${cat}"]`).click();
    const expected = R.categoryCounts().get(cat);
    await expect(page.locator("#feedRows .row")).toHaveCount(expected, { timeout: 8000 });

    const [dl] = await Promise.all([
      page.waitForEvent("download"),
      page.click("#exportBtn"),
    ]);
    expect(dl.suggestedFilename()).toMatch(/^vigil-feed-\d{4}-\d{2}-\d{2}\.json$/);
    const parsed = JSON.parse(fs.readFileSync(await dl.path(), "utf8"));
    expect(Array.isArray(parsed)).toBe(true);
    expect(parsed).toHaveLength(expected);
    expect(parsed.every(i => i.category === cat)).toBe(true);
    expect(parsed[0]).toHaveProperty("id");
    expect(parsed[0]).toHaveProperty("url");
  });

  test("selecting a row renders it in the rail with a safe source link", async ({ page }) => {
    await page.locator("#feedRows .row").nth(1).click();
    await expect(page.locator("#rail .rail-title")).toBeVisible();
    const link = page.locator("#rail .rail-title a");
    if (await link.count()) {
      expect(await link.getAttribute("href")).toMatch(/^https?:\/\//);
      expect(await link.getAttribute("rel")).toContain("noopener");
    }
  });
});
