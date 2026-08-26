import { useState } from 'react'
import { faviconSrc, monogram } from './logo'

/**
 * A victim org's favicon via the same-origin proxy, falling back to a brand-
 * coloured monogram on any load error (or an absent/invalid domain). The proxy
 * (/api/favicon, functions/api/favicon.js) is what keeps the page CSP at
 * `img-src 'self'` and the victim domain off any third-party icon CDN — the
 * analyst's browser never reveals which victim they are viewing.
 *
 * Shared by the Intel claimed-victims ledger (ActorProfile) and the Desk feed's
 * ransomware-claim rows (FeedView) — one logo treatment, one CSP story.
 */
export function VictimLogo({ domain, name }: { domain?: string; name: string }) {
  const src = faviconSrc(domain)
  const [failed, setFailed] = useState(false)
  const monoBox =
    'flex h-7 w-7 shrink-0 items-center justify-center rounded-sm border border-[var(--edge-accent)] bg-[var(--tint-accent)] font-mono text-micro font-semibold text-accent'

  if (!src || failed) {
    return (
      <span aria-hidden="true" className={monoBox}>
        {monogram(name)}
      </span>
    )
  }
  return (
    <img
      src={src}
      alt=""
      width={28}
      height={28}
      loading="lazy"
      onError={() => setFailed(true)}
      // The proxy answers "no icon" with a 1×1 transparent PNG (a SUCCESSFUL
      // load, so onError never fires) — detect that sentinel on load and fall
      // back to the monogram, else the row shows an empty square.
      onLoad={(e) => {
        if (e.currentTarget.naturalWidth <= 1) setFailed(true)
      }}
      className="h-7 w-7 shrink-0 rounded-sm border border-line bg-panel-soft object-contain"
    />
  )
}
