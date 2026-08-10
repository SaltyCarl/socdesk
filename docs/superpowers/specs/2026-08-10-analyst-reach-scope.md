# Analyst Reach — Scope & Checklist

**Date:** 2026-08-10 · **Status:** Scoped, not started · **Governs:** P1 "reach"
work, after Cloudflare/enrichment is live.

The goal, in the owner's words: emulate the useful part of the Recorded Future
browser extension — **get a verdict in front of the analyst without a
copy-paste** — while staying installable on a locked-down SOC workstation.
Three deliverables, ordered by value-per-effort. Paste-a-blob was explicitly
declined and is out of scope.

The backend is already done: all three call the existing `/api/enrich`
function. This is front-end reach only. **Nothing here matters until
`/api/enrich` is live** (Cloudflare project + keys) — that is the hard
predecessor for every item.

---

## R1 — Bookmarklet selection-capture (the 95% move)

Upgrade the shipped bookmarklet from "look up the current page" to "look up
what I selected." Drag-to-install, no extension store, survives corporate
extension bans — which is often the actual SOC environment. This is the
Recorded Future extension for 95% of daily value at ~5% of the cost.

**Files:** `site/js/bookmarklet.js` (generator), the install card in
`site/index.html`, `site-tests/specs/bookmarklet.spec.js`.

- [ ] Read the current bookmarklet: how it builds the `javascript:` payload and
      what the install card renders.
- [ ] Payload change: on click, read `window.getSelection().toString()`; if
      non-empty, refang + `detectType` it. If it is a known indicator, open
      `https://socdesk.io/#q=<indicator>` in a new tab (the hash deep-link the
      site already restores). If the selection is empty or not an indicator,
      fall back to today's behaviour (open SOCDesk).
- [ ] Multi-indicator selection → open the site with the bulk-lookup hash the
      existing bulk path already understands.
- [ ] Keep the payload CSP-proof on the HOST page: it runs in the analyst's
      page context, so no eval, no remote script — a single self-contained
      `javascript:` string. Test that it is inert if the selection contains
      HTML/quotes (no breakout).
- [ ] Update the install card copy: "select an indicator on any page, then
      click SOCDesk."
- [ ] Bump `site/sw.js` VERSION.
- [ ] Playwright: given a page with a selected IP, clicking the generated
      payload navigates to the correct `#q=` URL; a selected non-indicator
      falls back; a selection with quotes cannot break the payload.

**Acceptance:** an analyst on any alert page selects an IP, clicks the
bookmark, lands on a SOCDesk verdict — zero typing, zero paste.

**Effort:** small (half a day). **Predecessor:** enrichment live.

---

## R2 — Right-click context menu (needs R3's extension shell)

"Select indicator → right-click → Check in SOCDesk." More ergonomic than the
bookmarklet, but a context-menu entry requires an installed extension — so this
is not independent; it ships as a feature of R3, not before it. Do not scope it
as its own project.

- [ ] `chrome.contextMenus.create` on `contexts: ["selection"]`.
- [ ] Handler refangs + type-detects the selection, opens the `#q=` tab (or, if
      R3 has a popup, renders the verdict in the popup).
- [ ] Reuse R1's detect/refang logic — factor it into a shared module both the
      bookmarklet build and the extension import, so the rules cannot drift.

**Effort:** trivial once R3 exists. **Predecessor:** R3.

---

## R3 — MV3 browser extension (only on real demand)

The only thing that delivers true *inline annotation* (indicators highlighted
in place on the SIEM page, hover-for-verdict). Highest fidelity to Recorded
Future; also the highest cost and the one with a non-technical blocker.

**Build only after** R1 is in real use AND the team explicitly asks for inline
mode AND MSSP IT will approve a sideloaded/store extension. Any one of those
missing = do not start.

- [ ] Decide distribution first (this gates everything): Chrome Web Store
      listing vs. enterprise sideload via group policy. This is an IT/political
      question, not an engineering one — answer it before writing code.
- [ ] Manifest V3 skeleton: `manifest.json`, service worker, `host_permissions`
      minimal, `content_script` for annotation, optional popup.
- [ ] Content script: scan visible text for IP/hash/CVE/URL patterns (reuse the
      shared detect module from R1/R2), wrap matches, attach hover cards that
      call `/api/enrich` on `https://socdesk.io`.
- [ ] Rate/scope guard: annotate on demand or on a keystroke, not a full-page
      sweep on every DOM mutation (performance + not hammering the API).
- [ ] The endpoint already sets `cache-control: public, max-age=900`; lean on it
      so repeated hovers do not re-hit upstreams.
- [ ] Options page: let the analyst point at a self-hosted origin if the team
      ever runs its own instance.
- [ ] Privacy note in the listing: indicators the analyst hovers are sent to
      SOCDesk's origin (their own tool), and from there to the reputation
      services — same disclosure model as the site.

**Acceptance:** on the team's SIEM, indicators are highlighted inline and a
hover shows the SOCDesk verdict with no click.

**Effort:** medium-large + ongoing MV3 maintenance + an approval process
outside our control. **Predecessor:** R1 proven, team demand, IT sign-off.

---

## Shared prerequisite to extract now (cheap, do with R1)

Factor `detectType` + `refang` (currently in `site/js/data.js`) into a tiny
dependency-free module both the bookmarklet generator and any future extension
import. One source of truth for "what is an indicator and how do we normalise
it" prevents the bookmarklet and the extension from disagreeing later.
