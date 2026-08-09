// bookmarklet.js — the in-context lookup shim.
//
// The gap between SOCDesk and a commercial extension is delivery, not data: an
// extension puts a verdict where the analyst already is, while a site makes
// them switch tabs and paste. This closes most of that distance with no
// install, no store review, and no permissions — a bookmark that carries the
// selected text to the console.
//
// TWO DESIGN POINTS WORTH KEEPING:
//
//  1. The indicator travels in the URL *fragment*. Fragments are never placed
//     in an HTTP request, so the host never sees the value — the same privacy
//     property the toolbelt has, preserved across the hop. Do not "improve"
//     this into a query string.
//
//  2. The base URL is read from wherever the page is being served rather than
//     hardcoded, so a bookmark installed from the GitHub Pages URL keeps
//     working, and one installed from socdesk.io after the DNS cut-over points
//     at the apex. No build step, nothing to update twice.

/**
 * The bookmarklet body. Serialised with Function.prototype.toString(), so this
 * is the only copy of the source — there is no minified twin to drift from it.
 *
 * Constraints, because this is stringified rather than executed here:
 *   * NO `//` comments inside the function — whitespace is collapsed to one
 *     line and a line comment would swallow the remainder.
 *   * ES5 only. It runs inside whatever page the analyst is on, which may be
 *     an ancient SIEM console.
 *   * `__BASE__` is substituted at install time.
 */
function socdeskLookup() {
  var BASE = "__BASE__";
  var LIMIT = 1500;

  /* window.getSelection() returns "" for text selected inside an <input> or
     <textarea> in Chrome and Safari — and a SIEM query bar is exactly that,
     which makes this the single most common case, not an edge case. */
  function fromField(el) {
    if (!el || typeof el.selectionStart !== "number") return "";
    if (el.selectionStart === el.selectionEnd) return "";
    return String(el.value || "").slice(el.selectionStart, el.selectionEnd);
  }

  /* Consoles render results into nested frames. A same-origin frame is
     readable; a cross-origin one throws on access and is skipped. */
  function fromFrames(win, depth) {
    var text = "";
    try {
      text = String(win.getSelection() || "");
      for (var i = 0; !text && depth < 3 && i < win.frames.length; i++) {
        text = fromFrames(win.frames[i], depth + 1);
      }
    } catch (err) { }
    return text;
  }

  var q = (fromField(document.activeElement) || fromFrames(window, 0)).trim();
  if (q.length > LIMIT) q = q.slice(0, LIMIT);
  window.open(q ? BASE + "#q=" + encodeURIComponent(q) : BASE, "_blank", "noopener");
}

/** Collapse the function source to a single line. */
function compact(fn) {
  return String(fn)
    .replace(/\/\*[\s\S]*?\*\//g, " ")     // block comments
    .replace(/\s*\n\s*/g, " ")
    .replace(/\s{2,}/g, " ")
    .trim();
}

/**
 * The URL SOCDesk is being served from, minus any filename, hash or query.
 * Works for an apex domain and for a GitHub Pages project path alike.
 */
export function siteBase(loc = location) {
  return loc.origin + loc.pathname.replace(/[^/]*$/, "");
}

/**
 * Build the installable `javascript:` URL.
 *
 * The body is percent-encoded because it contains `#` — unencoded, the browser
 * would treat everything from `"#q="` onward as a fragment and silently
 * truncate the bookmark to a program that does nothing.
 */
export function bookmarkletHref(base = siteBase()) {
  const body = compact(socdeskLookup).replace("__BASE__", base);
  return "javascript:" + encodeURIComponent("(" + body + ")()");
}

/**
 * Wire the install card.
 *
 * The anchor's href is assigned here rather than in index.html so the shipped
 * HTML contains no `javascript:` URL, and so the bookmark encodes the origin it
 * was dragged from. Clicking is intercepted: our own CSP forbids `javascript:`
 * navigation, so an un-prevented click would fire a policy violation and appear
 * broken. Dragging is unaffected — it copies the href without navigating.
 *
 * @param {{link: HTMLAnchorElement, hint: HTMLElement, copy: HTMLElement,
 *          copyText: (t: string) => Promise<boolean>}} els
 */
export function initBookmarklet({ link, hint, copy, copyText } = {}) {
  if (!link) return;
  const href = bookmarkletHref();
  link.href = href;
  link.draggable = true;

  link.addEventListener("click", e => {
    e.preventDefault();
    if (hint) hint.textContent =
      "Drag this button to your bookmarks bar — clicking it here does nothing.";
  });

  if (copy && typeof copyText === "function") {
    copy.addEventListener("click", async () => {
      const was = copy.textContent;
      copy.textContent = (await copyText(href)) ? "COPIED ✓" : "COPY BLOCKED";
      if (hint) hint.textContent =
        "Create a bookmark by hand and paste this as the URL.";
      setTimeout(() => { copy.textContent = was; }, 1400);
    });
  }
}
