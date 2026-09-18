import { MicroLabel } from '../components/ui'
import { ViewHeader } from '../components/views/ViewFrame'
import { AsyncGate, SkeletonRows } from '../components/views/states'
import { PicketView } from '../components/views/PicketView'
import { useStateData } from '../components/views/useStateData'
import { rel } from '../components/views/format'
import type { PicketPayload } from '../components/views/types'

/** /desk#picket — reads the committed picket.json snapshot (no API, no account). */
export function PicketRoute() {
  const { status, data, error } = useStateData<PicketPayload>('picket')
  return (
    <div className="flex flex-col gap-6">
      <ViewHeader
        eyebrow="SOCDESK · PICKET"
        title="Picket"
        intro="Telemetry from SOCDesk's own internet-facing honeypot: what automated bots try against an unsolicited sensor. Context, never a verdict on any network or operator."
        aside={status === 'ready' && data ? <MicroLabel tone="faint">updated {rel(data.generated_at)}</MicroLabel> : null}
      />
      <AsyncGate status={status} label="the sensor telemetry" detail={error} skeleton={<SkeletonRows rows={8} />}>
        <PicketView payload={data} />
      </AsyncGate>
    </div>
  )
}
