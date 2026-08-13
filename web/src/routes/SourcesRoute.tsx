import { MicroLabel } from '../components/ui'
import { ViewHeader } from '../components/views/ViewFrame'
import { AsyncGate, SkeletonRows } from '../components/views/states'
import { SourcesView } from '../components/views/SourcesView'
import { useStateData } from '../components/views/useStateData'
import { rel } from '../components/views/format'
import type { RegistryPayload } from '../components/views/types'

/**
 * /sources — the collector + reference registry. Every source the desk draws
 * on, named openly, with a verification link.
 */
export function SourcesRoute() {
  const { status, data, error } = useStateData<RegistryPayload>('sources')

  return (
    <div className="flex flex-col gap-6">
      <ViewHeader
        eyebrow="Provenance"
        title="Sources"
        intro="The registry of every collector feeding the pipeline and every reference source used for verification. Nothing is consulted that isn't listed here."
        aside={
          status === 'ready' && data ? (
            <MicroLabel tone="faint">updated {rel(data.generated_at)}</MicroLabel>
          ) : null
        }
      />
      <AsyncGate
        status={status}
        label="the source registry"
        detail={error}
        skeleton={<SkeletonRows rows={6} />}
      >
        {data ? <SourcesView registry={data} /> : null}
      </AsyncGate>
    </div>
  )
}
