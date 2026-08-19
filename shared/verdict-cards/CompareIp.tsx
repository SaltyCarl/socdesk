// CompareIp.tsx — the inline "compare to a previous IP" triage helper on the IP
// escalation card. The analyst enters a PREVIOUS sign-in IP (and, optionally,
// the minutes between the two sign-ins) and gets the great-circle separation in
// MILES and — when a time gap is given — the implied speed with an honest
// impossible-travel read, plus a copyable client one-liner.
//
// HONESTY IS THE WHOLE FEATURE (do not soften):
//   * IP geolocation is city-level and routinely distorted by VPNs, proxies,
//     mobile carriers, and CGNAT — this is a TRIAGE LEAD, never proof. A caveat
//     to that effect ALWAYS rides on the result.
//   * A distance is computed ONLY from two REAL coordinates (geoModel.precise on
//     BOTH IPs). A country-centroid distance is meaningless and is refused.
//   * Reserved-colour law: amber (Chip variant="suspicious") marks ONLY the
//     implausible/impossible bands (a genuine caution). "plausible" is neutral —
//     NEVER green, which would imply a clearance — and nothing here is ever red.

import { useEffect, useRef, useState } from 'react'
import { geoModel, type GeoModel } from '../card/geo'
import { haversineMiles, travelAssessment, travelSummary, type TravelAssessment } from '../card/travel'
import { detectType, refang } from '../indicators'
import { fetchEnrich, type VerdictData } from '../verdict'
import { Button, Chip, MicroLabel } from '../ui'
import { cx } from '../lib/cx'

/** "City, CC" when we have it, else the country name, else an em dash. */
const label = (g: GeoModel): string =>
  [g.city, g.countryCode].filter(Boolean).join(', ') || g.countryName || '—'

/** The successful-compare payload lifted to the card: the resolved second
 *  location + the travel read. The escalation card threads this to the SVG hero
 *  (arc + second pin) and the copy-card PNG so all three registers agree. */
export interface CompareResult {
  /** The primary (looked-up) IP's location — the arc's origin. */
  first: GeoModel
  second: GeoModel
  assessment: TravelAssessment
}

const INPUT_CLS =
  'rounded-md border border-line bg-field px-2.5 py-1.5 font-mono text-xs text-paper ' +
  'outline-offset-2 placeholder:text-faint focus-visible:outline-2 focus-visible:outline-accent'

export function CompareIp({
  data,
  baseUrl,
  onResult,
}: {
  data: VerdictData
  baseUrl?: string
  /** Lifts the compare state to the card so the SVG hero + copy-card PNG can draw
   *  the arc/second pin. Fired with the payload on success, and with `null` on
   *  clear / re-run / collapse / any error, so the arc never lingers stale. */
  onResult?: (r: CompareResult | null) => void
}) {
  const [open, setOpen] = useState(false)
  const [secondIp, setSecondIp] = useState('')
  const [minutes, setMinutes] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<CompareResult | null>(null)
  const [copied, setCopied] = useState(false)
  const copyTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  // Latest `onResult` behind a ref so the unmount cleanup can clear the arc
  // without re-subscribing whenever the parent hands a fresh callback identity.
  const onResultRef = useRef(onResult)
  onResultRef.current = onResult

  useEffect(
    () => () => {
      if (copyTimer.current) clearTimeout(copyTimer.current)
    },
    [],
  )

  // Clear the lifted arc when this helper unmounts (e.g. the card switches to a
  // non-IP indicator and CompareIp is no longer rendered).
  useEffect(() => () => onResultRef.current?.(null), [])

  // A new primary indicator resets the panel + the lifted arc, so a prior IP's
  // route can never linger on a freshly looked-up IP's map.
  useEffect(() => {
    setResult(null)
    setError(null)
    setSecondIp('')
    setMinutes('')
    onResultRef.current?.(null)
  }, [data.indicator])

  // Only a REAL coordinate for THIS IP makes a comparison meaningful — with just
  // a country centroid a distance would be misleading, so the panel is absent.
  const first = geoModel(data.context, data.sources)
  if (!first || !first.precise) return null

  const compare = async () => {
    const q = refang(secondIp)
    const type = detectType(q)
    if (type !== 'ipv4' && type !== 'ipv6') {
      setResult(null)
      onResult?.(null)
      setError('Enter a valid IPv4 or IPv6 address.')
      return
    }
    setError(null)
    setResult(null)
    onResult?.(null) // drop any prior arc while the new lookup resolves
    setLoading(true)
    try {
      const out = await fetchEnrich(type, q, baseUrl ? { baseUrl } : {})
      if (out.status !== 'ok') {
        setError(
          out.status === 'unavailable'
            ? 'Live lookup is unavailable here (works on the deployed site).'
            : "Couldn't resolve that IP.",
        )
        return
      }
      const second = geoModel(out.data.context, out.data.sources)
      if (!second || !second.precise) {
        setError('That IP has only country-level geolocation — a distance would be misleading.')
        return
      }
      const mins = minutes.trim() === '' ? null : Number(minutes)
      const gap = mins != null && Number.isFinite(mins) && mins > 0 ? mins : null
      const miles = haversineMiles(first.lat, first.lon, second.lat, second.lon)
      const assessment = travelAssessment(miles, gap)
      setResult({ first, second, assessment })
      onResult?.({ first, second, assessment })
    } finally {
      setLoading(false)
    }
  }

  // Collapsing the panel drops the panel state AND the lifted arc together, so
  // the map and the panel never disagree about whether a compare is active.
  const toggle = () => {
    if (open) {
      setResult(null)
      setError(null)
      onResult?.(null)
    }
    setOpen((v) => !v)
  }

  const copy = async (text: string) => {
    if (typeof navigator === 'undefined' || !navigator.clipboard) return
    try {
      await navigator.clipboard.writeText(text)
      setCopied(true)
      if (copyTimer.current) clearTimeout(copyTimer.current)
      copyTimer.current = setTimeout(() => setCopied(false), 2000)
    } catch {
      /* clipboard blocked — leave the text on screen to copy by hand */
    }
  }

  const summary = result ? travelSummary(label(first), label(result.second), result.assessment) : ''

  return (
    <div className="flex flex-col gap-2.5">
      <button
        type="button"
        onClick={toggle}
        aria-expanded={open}
        className="inline-flex w-fit items-center gap-1 font-mono text-xs font-semibold text-accent underline-offset-2 outline-offset-2 hover:underline focus-visible:outline-2 focus-visible:outline-accent"
      >
        Compare to a previous IP {open ? '▾' : '→'}
      </button>

      {open && (
        <div className="flex flex-col gap-2.5">
          <div className="flex flex-col gap-2">
            <input
              type="text"
              inputMode="text"
              autoComplete="off"
              spellCheck={false}
              value={secondIp}
              onChange={(e) => setSecondIp(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') {
                  e.preventDefault()
                  void compare()
                }
              }}
              aria-label="Previous IP address"
              placeholder="previous sign-in IP"
              className={cx('w-full', INPUT_CLS)}
            />
            <div className="flex flex-wrap items-center gap-2">
              <input
                type="number"
                inputMode="numeric"
                min={0}
                value={minutes}
                onChange={(e) => setMinutes(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    e.preventDefault()
                    void compare()
                  }
                }}
                aria-label="Minutes between sign-ins"
                placeholder="mins (optional)"
                className={cx('w-40 max-w-full', INPUT_CLS)}
              />
              <Button variant="primary" size="sm" onClick={() => void compare()} disabled={loading}>
                Compare
              </Button>
            </div>
          </div>

          {loading ? (
            <p className="font-mono text-xs text-muted">Resolving…</p>
          ) : error ? (
            <p className="font-mono text-xs text-muted">{error}</p>
          ) : result ? (
            <div className="flex flex-col gap-2.5 rounded-md border border-line bg-field p-3">
              <MicroLabel tone="muted">Geographic separation — approximate, context only</MicroLabel>

              <p className="font-mono text-xs text-muted">
                <span className="text-paper">{label(first)}</span>
                <span aria-hidden="true" className="px-2 text-faint">
                  ↔
                </span>
                <span className="text-paper">{label(result.second)}</span>
              </p>

              <div className="flex flex-wrap items-baseline gap-2">
                <span className="font-display text-xl font-bold text-paper">{result.assessment.milesLabel}</span>
                {result.assessment.band === 'plausible' && <Chip variant="neutral">consistent with travel</Chip>}
                {result.assessment.band === 'implausible' && <Chip variant="suspicious">implausible travel</Chip>}
                {result.assessment.band === 'impossible' && <Chip variant="suspicious">impossible travel</Chip>}
              </div>

              <p className="text-xs leading-relaxed text-muted">{result.assessment.read}</p>

              <div className="flex items-start gap-2 rounded-md border border-line bg-panel px-2.5 py-2">
                <p className="min-w-0 flex-1 font-mono text-micro leading-relaxed text-muted">{summary}</p>
                <button
                  type="button"
                  onClick={() => void copy(summary)}
                  className={cx(
                    'shrink-0 rounded-md border px-2.5 py-1 font-mono text-micro font-semibold uppercase tracking-label',
                    'outline-offset-2 transition-colors duration-150 ease-brand focus-visible:outline-2 focus-visible:outline-accent',
                    copied
                      ? 'border-[var(--edge-accent)] bg-[var(--tint-accent)] text-accent'
                      : 'border-line text-muted hover:border-line-bright hover:text-paper',
                  )}
                >
                  {copied ? 'Copied' : 'Copy'}
                </button>
              </div>
            </div>
          ) : null}
        </div>
      )}
    </div>
  )
}
