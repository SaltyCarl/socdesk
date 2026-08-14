// LookupStates — the honest non-ok renderings for a resolved lookup, shared by
// the /lookup triptych and the landing inline card so the wording is identical
// on both surfaces (checking / declined / unavailable / unsupported).
//
// The `ok` arm is intentionally NOT handled here: each surface renders a result
// differently (the dense triptych vs. the landing's card + copy-card), so it
// owns that branch and delegates every other state to <LookupStatus/>.

import type { ReactNode } from 'react'
import { cx } from '@socdesk/shared/lib/cx'
import { MicroLabel } from '../ui'
import type { LookupState } from './useLookup'

/** The in-flight spinner + honest "Checking <indicator>…" line. */
export function Checking({ indicator }: { indicator: string }) {
  return (
    <div
      className="flex items-center gap-3 rounded-lg border border-line bg-panel p-5"
      role="status"
      aria-live="polite"
    >
      <span
        aria-hidden="true"
        className="size-4 shrink-0 rounded-full border-2 border-line-bright border-t-accent motion-safe:animate-spin"
      />
      <span className="break-all font-mono text-xs text-muted">Checking {indicator}…</span>
    </div>
  )
}

/** A framed honest message (no fabricated verdict). Amber tone for a declined
 *  indicator; muted for an unavailable/unsupported one. */
export function Notice({
  tone = 'muted',
  eyebrow,
  title,
  children,
}: {
  tone?: 'muted' | 'amber'
  eyebrow: string
  title: string
  children: ReactNode
}) {
  return (
    <div
      className={cx(
        'flex flex-col gap-2 rounded-lg border bg-panel p-5',
        tone === 'amber' ? 'border-[var(--edge-gold)]' : 'border-line',
      )}
      role="status"
    >
      <MicroLabel tone="faint">{eyebrow}</MicroLabel>
      <p
        className={cx(
          'font-display text-base font-bold leading-snug',
          tone === 'amber' ? 'text-verdict-amber' : 'text-paper',
        )}
      >
        {title}
      </p>
      <p className="text-xs leading-relaxed text-muted">{children}</p>
    </div>
  )
}

/**
 * Render every non-ok resolved state honestly. Returns null for `idle` and `ok`
 * — the caller renders the result (and, on the landing, decides whether a zone
 * shows at all). One place owns the wording so /lookup and the landing agree.
 */
export function LookupStatus({ state }: { state: LookupState }) {
  switch (state.kind) {
    case 'checking':
      return <Checking indicator={state.indicator} />

    case 'declined':
      return (
        <Notice
          tone="amber"
          eyebrow="Indicator declined"
          title="The enrichment endpoint declined this indicator"
        >
          {state.reason}
        </Notice>
      )

    case 'unavailable':
      return state.source === 'catalog' ? (
        <Notice eyebrow="Catalog unavailable" title="The vulnerability catalog could not be loaded">
          {state.reason}.
        </Notice>
      ) : (
        <Notice eyebrow="Lookup unavailable" title="Live lookup is unavailable">
          {state.reason}. The enrichment endpoint is a Cloudflare Pages Function — it answers on the
          deployed site, not in local preview. Nothing is fabricated when it can&rsquo;t be reached.
        </Notice>
      )

    case 'unsupported':
      if (state.variant === 'cve-missing') {
        return (
          <Notice
            eyebrow="Not in snapshot"
            title={`${state.indicator} is not in the current KEV/EPSS snapshot`}
          >
            This CVE isn&rsquo;t in the committed catalog. It may be newer than the last snapshot,
            below the tracked risk threshold, or a mistyped id.
          </Notice>
        )
      }
      if (state.variant === 'email') {
        return (
          <Notice eyebrow="Unsupported type" title="Email addresses aren't enriched here">
            The live lookup covers IPs, domains, URLs, file hashes and CVEs. An email address
            carries no third-party reputation to attribute.
          </Notice>
        )
      }
      return (
        <Notice
          eyebrow="Unrecognised"
          title={`"${state.indicator}" isn't a recognised indicator type`}
        >
          Enter an IPv4 address, a domain, a URL, an MD5 / SHA-1 / SHA-256 hash, or a CVE id
          (CVE-YYYY-NNNN). Defanged input (evil[.]com, hxxp://) is accepted.
        </Notice>
      )

    default:
      return null // idle / ok — the caller renders these
  }
}
