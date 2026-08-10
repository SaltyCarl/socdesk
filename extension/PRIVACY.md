# Privacy Policy — SOCDesk Indicator Lookup

_Last updated: 2026-08-10 · Draft for store submission_

## What this extension does with your data

The extension exists to look up the reputation of a security indicator (an IP
address, domain, URL, or file hash) that **you** select on a page or paste into
its popup.

When you run a lookup, the extension sends **only that indicator** to the
SOCDesk origin you have configured (default `https://socdesk.io`) at its
`/api/enrich` endpoint. That SOCDesk server forwards the indicator to
third-party reputation services (for example AbuseIPDB, VirusTotal, GreyNoise,
ipinfo, MalwareBazaar, urlscan) to obtain a verdict, and returns the combined
result to the extension for display.

That is the extent of the data flow. The indicator you look up leaves your
browser **only** to reach the SOCDesk origin you configured, and only when you
actively trigger a lookup.

## What the extension does NOT do

- It does **not** collect, store, or transmit your browsing history, page
  contents, form data, cookies, credentials, or any personal information.
- It does **not** read the pages you visit. There is no content script; the only
  page text it ever sees is text you explicitly select and send via the
  right-click "Check in SOCDesk" action.
- It does **not** run analytics, tracking, advertising, or fingerprinting.
- It does **not** send data to the extension's authors or to any destination
  other than the SOCDesk origin you configure.
- It does **not** sell or share data with anyone. (There is no data to sell.)

## Data stored locally

The extension stores exactly one setting — your configured SOCDesk origin —
using the browser's extension storage (`chrome.storage.sync`), so it can persist
across your signed-in browsers. It also briefly holds a single pending indicator
in session storage to pass a right-click selection to the popup; this is cleared
as soon as the popup reads it and never leaves your browser.

## Third parties

The reputation verdict is produced by the SOCDesk server you point the extension
at, which in turn queries third-party reputation providers. Those providers
receive the indicator you looked up as part of normal reputation queries. Their
handling of that data is governed by their own privacy policies and by the
policy of the SOCDesk instance you use. The extension itself has no direct
relationship with those providers and sends them nothing directly.

## Changes

If this policy changes, the "Last updated" date above will change and the
updated policy will accompany the extension's store listing.

## Contact

Questions about this policy: file an issue on the SOCDesk repository or contact
the operator of the SOCDesk instance you use.
