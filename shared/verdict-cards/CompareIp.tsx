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

interface Result {
  second: GeoModel
  t: TravelAssessment
}

const INPUT_CLS =
  'rounded-md border border-line bg-field px-2.5 py-1.5 font-mono text-xs text-paper ' +
  'outline-offset-2 placeholder:text-faint focus-visible:outline-2 focus-visible:outline-accent'

export function CompareIp({ data }: { data: VerdictData }) {
  const [open, setOpen] = useState(false)
  const [secondIp, setSecondIp] = useState('')
  const [minutes, setMinutes] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<Result | null>(null)
  const [copied, setCopied] = useState(false)
  const copyTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(
    () => () => {
      if (copyTimer.current) clearTimeout(copyTimer.current)
    },
    [],
  )

  // Only a REAL coordinate for THIS IP makes a comparison meaningful — with just
  // a country centroid a distance would be misleading, so the panel is absent.
  const first = geoModel(data.context, data.sources)
  if (!first || !first.precise) return null

  const compare = async () => {
    const q = refang(secondIp)
    const type = detectType(q)
    if (type !== 'ipv4' && type !== 'ipv6') {
      setResult(null)
      setError('Enter a valid IPv4 or IPv6 address.')
      return
    }
    setError(null)
    setResult(null)
    setLoading(true)
    try {
      const out = await fetchEnrich(type, q)
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
      setResult({ second, t: travelAssessment(miles, gap) })
    } finally {
      setLoading(false)
    }
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

  const summary = result ? travelSummary(label(first), label(result.second), result.t) : ''

  return (
    <div className="flex flex-col gap-2.5">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
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
                <span className="font-display text-xl font-bold text-paper">{result.t.milesLabel}</span>
                {result.t.band === 'plausible' && <Chip variant="neutral">consistent with travel</Chip>}
                {result.t.band === 'implausible' && <Chip variant="suspicious">implausible travel</Chip>}
                {result.t.band === 'impossible' && <Chip variant="suspicious">impossible travel</Chip>}
              </div>

              <p className="text-xs leading-relaxed text-muted">{result.t.read}</p>

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
