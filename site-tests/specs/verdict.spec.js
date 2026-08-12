// verdict.spec.js — the escalation card is the artifact that travels into a
// ticket, so its honesty is the product. Two failure modes are checked hardest:
// a KEV CVE that fails to say ACTIVELY EXPLOITED, and an unknown indicator that
// looks cleared.
const { test, expect } = require("@playwright/test");
const fs = require("fs");
const R = require("../lib/real");

async function lookup(page, q) {
  await page.fill("#q", q);
  await page.press("#q", "Enter");
}

test.describe("indicator verdicts", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/index.html");
    await page.waitForFunction(() => document.querySelectorAll("#feedRows .row").length > 0);
  });

  test("the highest-EPSS KEV CVE is called ACTIVELY EXPLOITED with real evidence", async ({ page }) => {
    const c = R.topKevCve();
    expect(c, "the corpus must contain at least one KEV row").toBeTruthy();

    await lookup(page, c.cve);
    // decode() scrambles the word into place when GSAP is live — poll for it.
    await expect(page.locator("#vword")).toHaveText("ACTIVELY EXPLOITED", { timeout: 8000 });
    await expect(page.locator("#vword")).toHaveClass(/tone-red/);
    await expect(page.locator("#console #vq")).toHaveText(c.cve);

    // THE LAYOUT CONTRACT: paste + Enter renders the verdict console in place,
    // with no scroll jump, and the lookup is shareable via the #q= hash.
    expect(await page.evaluate(() => window.scrollY), "no scroll jump on paste").toBe(0);
    expect(await page.evaluate(() => location.hash)).toBe(`#q=${c.cve}`);
    // the verdict never rents the feed-detail rail
    await expect(page.locator("#rail #vword")).toHaveCount(0);

    // verdict radar (the decided graphic), built from the real CVE signals; its
    // centre number is the score verdict.js computes (the EPSS percentage)
    const radar = page.locator("#console svg.radar");
    await expect(radar).toHaveCount(1);
    await expect(radar.locator(".r2-poly")).toHaveCount(1);       // the 5-axis profile
    await expect(page.locator("#console .r2-corenum"))
      .toContainText(String(Math.round(c.epss * 100)), { timeout: 8000 });  // count-up settles here

    // Public data now lives ONLY in the escalation docket (the duplicated
    // full-width block was removed in the re-layout); it must still be
    // substantive — Type/Assessment/Basis plus the CVE evidence rows.
    await expect(page.locator("#escBody .dk-row").first()).toBeVisible();
    expect(await page.locator("#escBody .dk-row").count()).toBeGreaterThanOrEqual(3);

    // the escalation summary is a FORMATTED docket, not raw markdown in a <pre>
    expect(await page.locator("#escBody pre").count()).toBe(0);
    const esc = await page.locator("#escBody").innerText();
    expect(esc.length, "the escalation summary must be substantive").toBeGreaterThan(400);
    expect(esc).not.toMatch(/\*\*|^## /m);          // no literal markdown syntax
    expect(esc).toContain("INDICATOR REVIEW");
    expect(esc).toContain("ACTIVELY EXPLOITED");
    expect(esc).toContain("Suggested next steps");
    expect(esc).toContain("CISA KEV");

    // Escape returns to browse mode and drops the hash
    await page.keyboard.press("Escape");
    await expect(page.locator("#console")).toBeHidden();
    expect(await page.evaluate(() => location.hash)).toBe("");
  });

  test("a #q= deep link restores the lookup on load", async ({ page }) => {
    const c = R.topKevCve();
    await page.goto(`/index.html#q=${c.cve}`);
    await expect(page.locator("#vword")).toHaveText("ACTIVELY EXPLOITED", { timeout: 8000 });
    await expect(page.locator("#console #vq")).toHaveText(c.cve);
    await expect(page.locator("#q")).toHaveValue(c.cve);
  });

  test("every pivot link is https and carries rel=noopener", async ({ page }) => {
    for (const q of [R.topKevCve().cve, "185.220.101.42", "example-not-real-domain.com",
                     "d41d8cd98f00b204e9800998ecf8427e"]) {
      await lookup(page, q);
      await expect(page.locator("#console .pivots a.pivot").first()).toBeVisible({ timeout: 8000 });
      const links = page.locator("#console .pivots a.pivot");
      const n = await links.count();
      expect(n, `pivots offered for ${q}`).toBeGreaterThan(0);
      for (let i = 0; i < n; i++) {
        const href = await links.nth(i).getAttribute("href");
        const rel = await links.nth(i).getAttribute("rel");
        expect(href, `${q} pivot ${i} must be https`).toMatch(/^https:\/\//);
        expect(rel, `${q} pivot ${i} rel`).toContain("noopener");
        expect(await links.nth(i).getAttribute("target")).toBe("_blank");
      }
    }
  });

  test("pivots are the T1 workflow set — no fluff vendors", async ({ page }) => {
    // The product decision (2026-08-10): 99% of the workflow is IP/hash into
    // AbuseIPDB/VirusTotal and URL into a safe viewer. Pivot rows carry exactly
    // that; Shodan/Censys/Spamhaus-class vendors must not reappear.
    const want = {
      "185.220.101.42": ["virustotal", "abuseipdb", "greynoise"],
      "d41d8cd98f00b204e9800998ecf8427e": ["virustotal", "malwarebazaar"],
      "https://evil-updates.example/payload": ["virustotal", "urlscan", "browserling"],
    };
    for (const [q, expected] of Object.entries(want)) {
      await lookup(page, q);
      await expect(page.locator("#console .pivots a.pivot").first()).toBeVisible({ timeout: 8000 });
      const names = (await page.locator("#console .pivots a.pivot").allInnerTexts())
        .map(t => t.replace(/[⚠↗\s]/g, "").toLowerCase());
      expect(names.sort()).toEqual(expected.sort());
    }
  });

  test("an unknown domain is NOT IN CORPUS and is never dressed as safe", async ({ page }) => {
    const rnd = `zq${Date.now().toString(36)}${Math.random().toString(36).slice(2, 8)}.example.com`;
    await lookup(page, rnd);
    await expect(page.locator("#vword")).toHaveText("NOT IN CORPUS", { timeout: 8000 });

    // absence of a corpus hit must not read as clearance
    await expect(page.locator("#vword")).toHaveClass(/tone-muted/);
    await expect(page.locator("#vword")).not.toHaveClass(/tone-green/);
    await expect(page.locator("#console")).not.toHaveText(/\b(CLEAN|SAFE|BENIGN|NO THREAT)\b/);
    await expect(page.locator("#console .vc-basis")).toContainText("Absence here is not clearance");
    // no CVE signals means no radar — a scored graphic would imply a measurement we lack
    await expect(page.locator("#console svg.radar")).toHaveCount(0);
  });

  test("an email routes to credential-exposure pivots including HIBP", async ({ page }) => {
    await lookup(page, "analyst.test@example.com");
    await expect(page.locator("#vword")).toHaveText("NOT IN CORPUS", { timeout: 8000 });
    // pivot labels are text-transform:uppercase in CSS — compare case-insensitively
    const names = (await page.locator("#console .pivots a.pivot").allInnerTexts()).join(" ");
    expect(names.toLowerCase()).toContain("have i been pwned");
    const hrefs = await page.locator("#console .pivots a.pivot").evaluateAll(
      as => as.map(a => a.href));
    expect(hrefs.some(h => h.startsWith("https://haveibeenpwned.com/account/"))).toBe(true);
    // an email must not be shipped to file/URL reputation services
    expect(names.toLowerCase()).not.toContain("virustotal");
  });

  test("three pasted indicators produce a 3-row bulk table with working exports", async ({ page }) => {
    const trio = `8.8.8.8, ${R.topKevCve().cve}, d41d8cd98f00b204e9800998ecf8427e`;
    await lookup(page, trio);

    await expect(page.locator("#console .vc-head")).toContainText("Bulk lookup", { timeout: 8000 });
    await expect(page.locator("#console .vc-head")).toContainText("3 indicators");
    await expect(page.locator("#console .ev .ev-row")).toHaveCount(3);

    // .ev-row .k is text-transform:uppercase — the DOM text is the real value
    const cells = await page.locator("#console .ev .ev-row .k")
      .evaluateAll(els => els.map(e => e.textContent.trim()));
    expect(cells.sort())
      .toEqual(["8.8.8.8", R.topKevCve().cve, "d41d8cd98f00b204e9800998ecf8427e"].sort());

    const cases = [
      ["csv", /\.csv$/, t => {
        expect(t.split("\n")).toHaveLength(4);              // header + 3
        expect(t.split("\n")[0]).toBe("indicator,type,assessment,score");
        expect(t).toContain("ACTIVELY EXPLOITED");
      }],
      ["json", /\.json$/, t => {
        const rows = JSON.parse(t);
        expect(rows).toHaveLength(3);
        expect(rows.every(r => r.q && r.type && r.word)).toBe(true);
      }],
      ["txt", /\.txt$/, t => {
        const lines = t.split("\n");
        expect(lines).toHaveLength(3);
        expect(lines.join("\n")).toContain("8[.]8[.]8[.]8");   // fully defanged
      }],
    ];
    for (const [mode, name, check] of cases) {
      const [dl] = await Promise.all([
        page.waitForEvent("download"),
        page.click(`#console [data-bulk="${mode}"]`),
      ]);
      expect(dl.suggestedFilename()).toMatch(name);
      check(fs.readFileSync(await dl.path(), "utf8"));
    }
  });

  test("a CVE outside the window is an honest miss, not a fabricated verdict", async ({ page }) => {
    await lookup(page, "CVE-1999-0001");
    await expect(page.locator("#vword")).toHaveText("NOT IN CORPUS", { timeout: 8000 });
    await expect(page.locator("#console .vc-basis")).toContainText("Check NVD directly");
  });

  test("an actor/malware name resolves to its ATT&CK profile", async ({ page }) => {
    const p = (R.actors()?.profiles ?? []).find(x => x.attack_id && x.name);
    test.skip(!p, "no actor profiles published");
    await lookup(page, p.name);
    await expect(page.locator("#console .vc-head")).toContainText(p.attack_id, { timeout: 8000 });
    const href = await page.locator("#console .pivots a.pivot").last().getAttribute("href");
    expect(href).toBe(`https://attack.mitre.org/groups/${encodeURIComponent(p.attack_id)}/`);
  });
});
