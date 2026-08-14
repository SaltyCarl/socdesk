#!/usr/bin/env node
// verify-deploy.mjs — post-deploy validation for the web/ flip.
//
// Runs every check from the pre-flip QA against a live URL and exits non-zero
// if any fails. Use it against a Cloudflare PREVIEW url before flipping, and
// against https://socdesk.io after.
//
//   node tools/verify-deploy.mjs https://preview-flip.socdesk.pages.dev
//   node tools/verify-deploy.mjs https://socdesk.io
//   node tools/verify-deploy.mjs http://localhost:4319 --local   (build sanity;
//       skips the Function + header checks, which only exist on Cloudflare)
//
// Checks: app shell · hashed assets serve JS/CSS (NOT rewritten to index.html —
// the H2 gate) · data payloads serve JSON · /api/enrich answers (Functions
// co-deploy) · SPA deep-links resolve · strict security headers present.

const base = process.argv[2];
const local = process.argv.includes('--local');
if (!base || base.startsWith('--')) {
  console.error('usage: node tools/verify-deploy.mjs <base-url> [--local]');
  process.exit(2);
}
const B = base.replace(/\/+$/, '');

let failed = 0;
const g = (s) => `\x1b[32m${s}\x1b[0m`;
const r = (s) => `\x1b[31m${s}\x1b[0m`;
const y = (s) => `\x1b[33m${s}\x1b[0m`;
const pass = (m) => console.log(`  ${g('PASS')}  ${m}`);
const fail = (m) => { console.log(`  ${r('FAIL')}  ${m}`); failed++; };
const skip = (m) => console.log(`  ${y('SKIP')}  ${m}`);

async function get(path) {
  try {
    const res = await fetch(B + path, { redirect: 'follow' });
    const text = await res.text();
    return { res, text, ct: res.headers.get('content-type') || '', ok: res.ok };
  } catch (e) {
    return { res: null, text: '', ct: '', ok: false, err: String(e.message || e) };
  }
}
const isHtml = (t) => /<!doctype html/i.test(t) || /<div id="?root"?/.test(t);

console.log(`\nVerifying ${B}${local ? '  (local build-sanity mode)' : ''}\n`);

// 1 — app shell
const home = await get('/');
if (home.ok && isHtml(home.text) && /\/assets\//.test(home.text)) pass(`/ serves the app shell (${home.res.status})`);
else fail(`/ did not serve the app shell (${home.res?.status ?? home.err})`);

// 2 — hashed assets must serve their real content, NOT be rewritten to index.html
const jsRef = home.text.match(/\/assets\/[A-Za-z0-9._-]+\.js/);
if (jsRef) {
  const a = await get(jsRef[0]);
  if (a.ok && /javascript|ecmascript/.test(a.ct) && !isHtml(a.text)) pass(`asset ${jsRef[0]} serves JS (${a.ct})`);
  else fail(`asset ${jsRef[0]} did NOT serve JS (ct=${a.ct || a.err}) — a _redirects catch-all may be hijacking static assets`);
} else fail('no /assets/*.js referenced in the shell');
const cssRef = home.text.match(/\/assets\/[A-Za-z0-9._-]+\.css/);
if (cssRef) {
  const c = await get(cssRef[0]);
  if (c.ok && /css/.test(c.ct) && !isHtml(c.text)) pass(`asset ${cssRef[0]} serves CSS`);
  else fail(`asset ${cssRef[0]} did NOT serve CSS (ct=${c.ct || c.err})`);
}

// 3 — data payloads serve JSON
for (const p of ['/data/state/feed.json', '/data/state/threat_ips.json']) {
  const d = await get(p);
  if (d.ok && /json/.test(d.ct) && !isHtml(d.text) && d.text.includes('generated_at')) pass(`${p} serves JSON`);
  else fail(`${p} did NOT serve JSON (ct=${d.ct || d.err})`);
}

// 4 — /api/enrich Function (Cloudflare only)
if (local) {
  skip('/api/enrich — no Function on a local static build');
} else {
  const e = await get('/api/enrich?type=ipv4&q=8.8.8.8');
  if (e.ok && /json/.test(e.ct) && /"consulted"|"tone"|"sources"/.test(e.text)) pass('/api/enrich answers JSON (Functions co-deploy OK)');
  else fail(`/api/enrich did NOT answer (${e.res?.status ?? e.err}) — repo-root functions/ not co-deployed`);
}

// 5 — SPA deep-links resolve to the app
for (const p of ['/desk', '/actor', '/lookup']) {
  const s = await get(p);
  if (s.ok && isHtml(s.text)) pass(`${p} deep-link resolves to the app (SPA fallback)`);
  else fail(`${p} deep-link did not resolve (${s.res?.status ?? s.err})`);
}

// 6 — strict security headers (Cloudflare only)
if (local) {
  skip('security headers — _headers apply on Cloudflare Pages, not the dev server');
} else {
  const csp = home.res?.headers.get('content-security-policy') || '';
  if (csp.includes("default-src 'none'") && csp.includes("frame-ancestors 'none'")) pass('strict CSP present (default-src none + frame-ancestors none)');
  else fail(`CSP missing/weak: "${csp.slice(0, 70)}"`);
  home.res?.headers.get('x-frame-options') ? pass('X-Frame-Options present') : fail('X-Frame-Options missing');
  /same-origin/.test(home.res?.headers.get('cross-origin-opener-policy') || '') ? pass('COOP present') : fail('COOP missing');
}

console.log(failed ? `\n${r(`✗ ${failed} check(s) FAILED — do NOT flip`)}` : `\n${g('✓ all checks passed')}`);
process.exit(failed ? 1 : 0);
