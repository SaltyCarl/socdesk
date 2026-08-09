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

  test("work queue: priority-first, capped render, load-more reaches every item", async ({ page }) => {
    const n = R.feed().items.length;
    expect(n).toBeGreaterThan(0);
    const first = Math.min(25, n);

    // capped initial render, honestly labelled
    await expect(page.locator("#feedRows .row")).toHaveCount(first);
    await expect(page.locator("#fhCount"))
      .toHaveText(`Showing ${first.toLocaleString("en-US")} of ${n.toLocaleString("en-US")}`);

    // default order is the pipeline's relevance score, descending
    const scores = await page.locator("#feedRows .pscore")
      .evaluateAll(els => els.map(e => e.textContent === "—" ? -1 : Number(e.textContent)));
    const sorted = [...scores].sort((a, b) => b - a);
    expect(scores, "priority order = score descending").toEqual(sorted);

    // the Newest toggle flips to chronology
    const byTime = [...R.feed().items]
      .sort((a, b) => String(b.published_at).localeCompare(String(a.published_at)))
      .slice(0, first).map(i => i.id);
    await page.click("#sortNewest");
    // the re-render rides a View Transition — poll for the new head of queue
    await expect(page.locator("#feedRows .row").first())
      .toHaveAttribute("data-id", byTime[0], { timeout: 8000 });
    const times = await page.locator("#feedRows .row")
      .evaluateAll(els => els.map(e => e.dataset.id));
    expect(times).toEqual(byTime);
    await page.click("#sortPriority");
    await expect(page.locator("#feedRows .pscore").first()).toHaveText(String(
      Math.max(...R.feed().items.map(i => i.score ?? -1))), { timeout: 8000 });

    // load more walks the full payload — nothing silently truncated
    let guard = 0;
    while (await page.locator("#feedMore").isVisible() && guard++ < 30)
      await page.click("#feedMore");
    await expect(page.locator("#feedRows .row")).toHaveCount(n);
    await expect(page.locator("#feedMore")).toBeHidden();
  });

  test("scored rows print their score and why, grouped rows read as digests", async ({ page }) => {
    const items = R.feed().items;
    const scored = items.filter(i => i.score != null && (i.why ?? []).length);
    test.skip(!scored.length, "no scored items in the published feed");

    // the top-priority row is on screen by construction
    const top = [...items].sort((a, b) => (b.score ?? -1) - (a.score ?? -1))[0];
    const row = page.locator(`#feedRows .row[data-id="${top.id}"]`);
    await expect(row.locator(".pscore")).toHaveText(String(top.score));
    if ((top.why ?? []).length)
      await expect(row.locator(".wq span:not(.grp)").first()).toHaveText(top.why[0]);

    const grouped = items.filter(i => i.grouped)
      .sort((a, b) => (b.score ?? -1) - (a.score ?? -1))[0];
    if (grouped) {
      await page.fill("#q2", grouped.title.slice(0, 30));
      const grow = page.locator(`#feedRows .row[data-id="${grouped.id}"]`);
      await expect(grow).toHaveClass(/digest/, { timeout: 8000 });
      await expect(grow.locator(".wq .grp"))
        .toContainText(`${grouped.grouped.toLocaleString("en-US")} reports`);
    }
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
      // the DOM renders the capped queue; the res chip carries the full claim
      await expect(page.locator("#feedRows .row"))
        .toHaveCount(Math.min(25, printed), { timeout: 8000 });
      await expect(page.locator("#resChip"))
        .toHaveText(`${printed.toLocaleString("en-US")} results`);
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
    await expect(page.locator("#feedRows .row"))
      .toHaveCount(Math.min(25, expected), { timeout: 8000 });

    await page.fill("#q2", "zzz-no-such-token-zzz");
    await expect(page.locator("#feedRows .row")).toHaveCount(0, { timeout: 8000 });

    await page.fill("#q2", "");
    await expect(page.locator("#feedRows .row"))
      .toHaveCount(Math.min(25, total), { timeout: 8000 });
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
    // the export must carry EVERY filtered item, not just the rendered cap
    await expect(page.locator("#feedRows .row"))
      .toHaveCount(Math.min(25, expected), { timeout: 8000 });

    const [dl] = await Promise.all([
      page.waitForEvent("download"),
      page.click("#exportBtn"),
    ]);
    expect(dl.suggestedFilename()).toMatch(/^socdesk-feed-\d{4}-\d{2}-\d{2}\.json$/);
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
