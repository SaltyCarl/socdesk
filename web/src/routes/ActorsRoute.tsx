import { MicroLabel } from '../components/ui'
import { ViewHeader } from '../components/views/ViewFrame'
import { AsyncGate, SkeletonRows } from '../components/views/states'
import { ActorsView } from '../components/views/ActorsView'
import { useStateData, type AsyncStatus } from '../components/views/useStateData'
import { rel } from '../components/views/format'
import type { ProfilePayload, RelationsPayload } from '../components/views/types'

/**
 * /actors — ATT&CK actor + malware profiles with the related-entity panel.
 * Merges two profile files; relations.json is fetched alongside but NOT gated
 * on (the RELATED panel fills in when it lands, the profiles show immediately).
 */
export function ActorsRoute() {
  const actors = useStateData<ProfilePayload>('actors')
  const malware = useStateData<ProfilePayload>('malware')
  const relations = useStateData<RelationsPayload>('relations')

  const loading = actors.status === 'loading' || malware.status === 'loading'
  const errored = actors.status === 'error' && malware.status === 'error'
  const status: AsyncStatus = loading ? 'loading' : errored ? 'error' : 'ready'

  return (
    <div className="flex flex-col gap-6">
      <ViewHeader
        eyebrow="Adversaries"
        title="Actors & malware"
        intro="ATT&CK profiles with a ranked related-entity panel — live feed co-occurrence before encyclopedia structure. Pivot between linked actors and malware; techniques deep-link to ATT&CK."
        aside={
          actors.status === 'ready' && actors.data ? (
            <MicroLabel tone="faint">updated {rel(actors.data.generated_at)}</MicroLabel>
          ) : null
        }
      />
      <AsyncGate
        status={status}
        label="the ATT&CK profiles"
        detail={actors.error ?? malware.error}
        skeleton={<SkeletonRows rows={8} />}
      >
        <ActorsView
          actors={actors.data?.profiles ?? []}
          malware={malware.data?.profiles ?? []}
          relations={relations.data}
        />
      </AsyncGate>
    </div>
  )
}
