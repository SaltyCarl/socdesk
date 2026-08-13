import { MicroLabel } from '../components/ui'
import { ViewHeader } from '../components/views/ViewFrame'
import { AsyncGate, SkeletonRows } from '../components/views/states'
import { VulnsView } from '../components/views/VulnsView'
import { useStateData } from '../components/views/useStateData'
import { rel } from '../components/views/format'
import type { CvePayload } from '../components/views/types'

/**
 * /vulnerabilities — KEV + CVSS + EPSS, risk-sorted. The catalog is large
 * (~10k CVEs), so it only fetches when this route mounts.
 */
export function VulnsRoute() {
  const { status, data, error } = useStateData<CvePayload>('cves')
  const cves = data?.cves ?? []

  return (
    <div className="flex flex-col gap-6">
      <ViewHeader
        eyebrow="Exposure"
        title="Vulnerabilities"
        intro="Risk-sorted: CISA KEV membership first (actively exploited outranks all), then EPSS exploitation probability. CVSS is shown but never the default order — a high score nobody exploits sits below a modest one on the KEV list."
        aside={
          status === 'ready' && data ? (
            <MicroLabel tone="faint">updated {rel(data.generated_at)}</MicroLabel>
          ) : null
        }
      />
      <AsyncGate
        status={status}
        label="the vulnerability catalog"
        detail={error}
        skeleton={<SkeletonRows rows={10} />}
      >
        <VulnsView cves={cves} />
      </AsyncGate>
    </div>
  )
}
