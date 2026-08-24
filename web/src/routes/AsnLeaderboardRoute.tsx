import { MicroLabel } from '../components/ui'
import { ViewHeader } from '../components/views/ViewFrame'
import { AsyncGate, SkeletonRows } from '../components/views/states'
import { AsnLeaderboardView } from '../components/views/AsnLeaderboardView'
import { useStateData } from '../components/views/useStateData'
import { rel } from '../components/views/format'
import { CountUp } from '../components/views/CountUp'
import type { AsnLeaderboardPayload } from '../components/views/types'

/**
 * /desk#networks — the abuse-by-network leaderboard. Reads the committed
 * asn_leaderboard.json snapshot (no D1, no API, no account) and hands it to
 * AsnLeaderboardView, gating on loading/error with an honest skeleton +
 * fallback.
 */
export function AsnLeaderboardRoute() {
  const { status, data, error } = useStateData<AsnLeaderboardPayload>('asn_leaderboard')
  const networks = data?.networks ?? []

  return (
    <div className="flex flex-col gap-6">
      <ViewHeader
        eyebrow="Abuse by network"
        title="Networks"
        intro="Autonomous systems ranked by the volume of abusive IPs reported to SOCDesk and published on the abuse.ch blocklists. Reported volume hosted on a network — not a verdict on the network or its operator."
        aside={
          status === 'ready' && data ? (
            <MicroLabel tone="faint">
              <CountUp value={networks.length} /> networks · updated {rel(data.generated_at)}
            </MicroLabel>
          ) : null
        }
      />
      <AsyncGate
        status={status}
        label="the leaderboard"
        detail={error}
        skeleton={<SkeletonRows rows={8} />}
      >
        <AsnLeaderboardView payload={data} />
      </AsyncGate>
    </div>
  )
}
