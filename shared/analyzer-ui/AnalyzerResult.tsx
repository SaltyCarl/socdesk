import { Chip } from '@socdesk/shared/ui'
import type { AnalysisResult } from '@socdesk/shared/analyzer'
import { ActionBullets } from './ActionBullets'
import { DecodeLadder } from './DecodeLadder'
import { IocTable } from './IocTable'
import { PartialDecodeNotice } from './PartialDecodeNotice'
import { TechniqueTally } from './TechniqueTally'

/** The analyzer's result composition — flag chips + the technique tally +
 *  the decode ladder + the extracted-IOC table. Extracted from
 *  PowerShellAnalyzer.tsx (the `/analyzer` route) so the cockpit's
 *  ResultRegion can render the exact same surface for a `command`-classified
 *  submission (design spec §3.4). Prop-driven, no local state — both callers
 *  own their own `usePsAnalysis` hook and pass down only the resolved
 *  `AnalysisResult`. `IocTable` owns its own inline-expand lookup per row —
 *  nothing here navigates or replaces this result. */
export function AnalyzerResult({ result, baseUrl }: { result: AnalysisResult; baseUrl?: string }) {
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
      <PartialDecodeNotice state={result.confidence.state} />
      <ActionBullets bullets={result.bullets} />
      <DecodeLadder layers={result.layers} />
      <IocTable iocs={result.iocs} baseUrl={baseUrl} />
    </div>
  )
}
