# SOCDesk — Indicator Lookup (browser extension)

A thin Manifest V3 client for Chrome/Edge that puts a **live multi-source
reputation verdict** where an analyst already is. It calls your SOCDesk
instance's `/api/enrich` endpoint — the same endpoint the site uses — and
renders a compact verdict card. It holds no data of its own and ships no
reputation corpus.

**v1 is core-only, on purpose.** Minimal permissions = an easy Web Store review
and an easy IT approval. No content script, no page reading, no `<all_urls>`.
Inline page annotation is deliberately deferred to v2.

---

## What it does

1. **Right-click a selection → "Check in SOCDesk"**
   Refangs (`evil[.]com` → `evil.com`, `hxxp` → `http`) and type-detects the
   selected text. If it's an enrichable indicator (IPv4 / domain / URL / MD5 /
   SHA-1 / SHA-256) it opens the toolbar popup pre-loaded with the live verdict.
   If it's a CVE, an email, or anything else, it opens the full SOCDesk report
   in a new tab (`https://<origin>/#q=<indicator>`).

2. **Toolbar popup** — paste an indicator, press Enter. It classifies the input,
   calls `GET https://<origin>/api/enrich?type=<t>&q=<indicator>`, and shows the
   **source-consensus tally** — `N / M flagged` (status-colored by the ratio)
   and the headline "N of M consulted sources flagged this as adverse" — then one
   **attributed** line per source (name · its own raw finding · a `verify ↗`
   link), with `ipinfo` tagged "context — not a verdict" and an honest "not
   consulted" line for any sources without a key. Beneath it is a ratio-led
   **escalation card** with a **COPY** button that copies the §4 assessment
   block straight into an email. That copy-out wording is finalized to
   `docs/VERDICT-LANGUAGE.md` §4 (consensus tally, no recommended action,
   reworded caveat, neutral provenance) and is byte-identical to the site's
   `site/js/verdict.js`. SOCDesk never prints a verdict word of its own — only
   the count and each source's attribution. An **Open full report ↗** button
   jumps to the full SOCDesk report for the same indicator.

3. **Options** — set the SOCDesk origin (default `https://socdesk.io`), stored
   in `chrome.storage.sync`. Every fetch and every link uses this origin, so a
   self-hosted instance can be targeted without editing code.

The indicator in the full-report deep link rides in the URL **fragment**
(`#q=`), which browsers never send to the server — the same privacy property the
site's bookmarklet has.

---

## File tree

```
extension/
├─ manifest.json          MV3 manifest
├─ background.js          service worker: context menu + click routing
├─ popup.html/.css/.js    toolbar popup — search + live verdict card
├─ options.html/.css/.js  set the SOCDesk origin (chrome.storage.sync)
├─ lib/
│  └─ indicators.js       refang, detectType, safeUrl, origin/URL helpers
├─ icons/
│  ├─ icon16.png
│  ├─ icon48.png
│  └─ icon128.png         final coffee-mug mark (warm/periwinkle brand system)
├─ README.md
└─ PRIVACY.md
```

> **Icons are final.** The pixel coffee-mug mark — coffee-brown liquid
> (`#A6612F`), golden crema (`#E0B36A`), cream rim, periwinkle steam
> (`#7C8AFF`) — cut from the locked warm/periwinkle brand system
> (`design/mockups/palette-warm-v2.html`) and set on a rounded dark warm tile
> so it reads on both light and dark toolbars. Pixels land on integer
> boundaries at 16/48/128 (crisp, no blur); the coffee-brown band carries the
> "coffee" read at 16px where the steam collapses.

---

## Load it unpacked (Chrome or Edge)

1. Go to `chrome://extensions` (or `edge://extensions`).
2. Turn on **Developer mode** (top-right).
3. Click **Load unpacked** and select this `extension/` folder.
4. Pin the SOCDesk icon to the toolbar.

### Test it

- **Popup, benign:** click the toolbar icon, paste `8.8.8.8`, press Enter →
  expect a green `0 / M` tally ("0 of M consulted sources flagged this — no
  adverse findings. Not a clearance.") with per-source rows.
- **Popup, hostile:** paste `185.220.101.42` (a well-known Tor exit) → expect a
  red `N / M` tally with multiple attributed sources and an escalation card you
  can copy into a ticket with **COPY**.
- **Refang:** paste `evil[.]com` → it normalizes to `evil.com` (domain) before
  the lookup.
- **Context menu:** select `1.1.1.1` on any page → right-click →
  **Check in SOCDesk** → the popup opens with the verdict. (If your browser
  build can't open the popup programmatically, it falls back to opening the full
  report tab, which shows the same live verdict.)
- **Non-enrichable routing:** select `CVE-2024-3400` → right-click → it opens
  the full report tab instead of the popup (CVE and email are not enriched).
- **Options:** open **Options**, change the origin to a `*.pages.dev` preview
  deployment, Save, and confirm lookups hit that host.

---

## Permissions — and why each one is here

| Declared | Why it's the minimum |
|---|---|
| `contextMenus` | Adds the "Check in SOCDesk" item and receives the selected text. This is how the extension reads a selection **without** a content script. |
| `storage` | Persists the configured origin (`sync`) and the one-shot pending lookup handed from the context menu to the popup (`session`, trusted-contexts only). |
| `host_permissions: https://socdesk.io/*` | The enrich fetch target. Required so the popup can `fetch()` the verdict cross-origin. |
| `host_permissions: https://socdesk.pages.dev/*` | The Cloudflare Pages deploy alias (used for testing / while the custom domain propagates). Two specific origins — no wildcards. |

**Deliberately NOT requested:** `<all_urls>`, `tabs`, `scripting`,
`content_scripts`, `activeTab`. v1 never injects into or reads page content;
the two host grants are specific origins, never a wildcard.

### Custom origins on other domains

Host access is fixed at pack time. If a self-hoster sets an Options origin that
is **not** covered by `host_permissions` (i.e. not `socdesk.io` and not
`socdesk.pages.dev`), live `fetch()` calls to it will be blocked and the popup
will show "Live reputation unavailable". Two ways to support it:

- **Simple (documented reinstall):** add the host to `host_permissions` in
  `manifest.json`, then reload the unpacked extension / repack.
- **Cleaner (a v1.x follow-up):** move custom hosts to
  `optional_host_permissions` and request them at runtime from the Options page
  with `chrome.permissions.request(...)`. Not wired in this build to keep the
  permission prompt minimal for the first review.

---

## Shipping checklist

- [x] Replace placeholder `icons/*.png` with final 16/48/128 art. **Done** — the
      coffee-mug brand mark, rendered crisp at all three sizes.
- [x] Finalize the escalation copy-out wording to `docs/VERDICT-LANGUAGE.md` §4
      (kept byte-identical to the site's `site/js/verdict.js`).
- [ ] Confirm `host_permissions` lists exactly the origins you support (drop
      `socdesk.pages.dev` for an apex-domain-only build).
- [ ] Register a **Chrome Web Store developer account** (one-time **US $5** fee).
- [ ] Zip the **contents** of `extension/` (the files at the root of the zip,
      not a nested `extension/` folder).
- [ ] Chrome Web Store Developer Dashboard → **New item** → upload the zip →
      fill store listing → attach `PRIVACY.md` as the **privacy policy**
      (a URL is required; host this file or paste its text).
- [ ] Set visibility:
      - **Unlisted** — recommended for an internal SOC tool: installable by link,
        not surfaced in search. Fastest to approve, no public discovery.
      - **Public** — listed in the store; expect a stricter review of the
        permission justifications and privacy disclosure.
- [ ] **Microsoft Edge Add-ons** (optional): separate submission at
      Partner Center (**free**, no dev fee). Same zip; Edge accepts MV3.
- [ ] **IT force-install (managed deployment):** after approval, note the
      extension's **ID** (shown on the store listing and in `chrome://extensions`
      with Developer mode on). IT pushes it via the
      `ExtensionInstallForcelist` policy (Chrome) /
      `ExtensionInstallForcelist` (Edge) using
      `<extension-id>;https://clients2.google.com/service/update2/crx` (Chrome
      Web Store) or the Edge equivalent update URL. Unlisted + force-install is
      the usual pairing for an internal analyst tool.

---

## Security notes for reviewers

- **No remote code.** All HTML/CSS/JS is local; nothing is `eval`'d or fetched
  as script. Fonts are system stacks (no remote font loads).
- **Untrusted response data.** Every string in the `/api/enrich` response is
  treated as attacker-influenced (it echoes upstream reputation vendors). The
  popup builds DOM with `createElement` + `textContent` only — no `innerHTML`
  with response data — and every link href is validated to `http(s)` via
  `safeUrl()` before it becomes a live link.
- **Scope.** The only network destination is the configured SOCDesk origin.
