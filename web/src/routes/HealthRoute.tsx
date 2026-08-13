import { MicroLabel } from '../components/ui'
import { ViewHeader } from '../components/views/ViewFrame'
import { AsyncGate, SkeletonRows } from '../components/views/states'
import { HealthView } from '../components/views/HealthView'
import { useStateData } from '../components/views/useStateData'
import { rel } from '../components/views/format'
import type { HealthPayload } from '../components/views/types'

/**
 * /health — collection status. One cell per source: item count, last-success
 * recency, and an online/down status dot.
 */
export function HealthRoute() {
  const { status, data, error } = useStateData<HealthPayload>('health')

  return (
    <div className="flex flex-col gap-6">
      <ViewHeader
        eyebrow="Pipeline"
        title="Collection health"
        intro="Is the pipeline actually collecting? Each collector reports its item count and last successful run. A degraded source shows its error verbatim — no green light over a silent failure."
        aside={
          status === 'ready' && data ? (
            <MicroLabel tone="faint">updated {rel(data.generated_at)}</MicroLabel>
          ) : null
        }
      />
      <AsyncGate
        status={status}
        label="collector health"
        detail={error}
        skeleton={<SkeletonRows rows={6} />}
      >
        {data ? <HealthView health={data} /> : null}
      </AsyncGate>
    </div>
  )
}
