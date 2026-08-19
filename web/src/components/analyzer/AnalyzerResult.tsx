import { Chip } from '@socdesk/shared/ui'
import type { AnalysisResult } from '@socdesk/shared/analyzer'
import { DecodeLadder } from './DecodeLadder'
import { IocTable } from './IocTable'
import { TechniqueTally } from './TechniqueTally'

/** The analyzer's result composition — flag chips + the technique tally +
 *  the decode ladder + the extracted-IOC table. Extracted from
 *  PowerShellAnalyzer.tsx (the `/analyzer` route) so the cockpit's
 *  ResultRegion can render the exact same surface for a `command`-classified
 *  submission (design spec §3.4). Prop-driven, no local state — both callers
 *  own their own `usePsAnalysis` hook and pass down only the resolved
 *  `AnalysisResult`. `onLookup` forwards straight to `IocTable` — see there
 *  for the in-place cockpit pivot vs. standalone-route fallback. */
export function AnalyzerResult({
  result,
  onLookup,
}: {
  result: AnalysisResult
  onLookup?: (raw: string) => void
}) {
  return (
    <div className="flex flex-col gap-4">
      {result.flags.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {result.flags.map((f) => (
            <Chip key={f.flag} variant="neutral">{f.flag}</Chip>
          ))}
        </div>
      )}
      <TechniqueTally signals={result.signals} characterization={result.characterization} />
      <DecodeLadder layers={result.layers} />
      <IocTable iocs={result.iocs} onLookup={onLookup} />
    </div>
  )
}
