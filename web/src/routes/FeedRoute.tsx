import { MicroLabel } from '../components/ui'
import { ViewHeader } from '../components/views/ViewFrame'
import { AsyncGate, SkeletonRows } from '../components/views/states'
import { FeedView } from '../components/views/FeedView'
import { useStateData } from '../components/views/useStateData'
import { num, rel } from '../components/views/format'
import type { FeedPayload } from '../components/views/types'

/**
 * /feed — the score-sorted work queue. Fetches the committed feed snapshot,
 * hands the items to FeedView, and gates on loading/error with an honest
 * skeleton + fallback.
 */
export function FeedRoute() {
  const { status, data, error } = useStateData<FeedPayload>('feed')
  const items = data?.items ?? []

  return (
    <div className="flex flex-col gap-6">
      <ViewHeader
        eyebrow="Work queue"
        title="Feed"
        intro="Every collected report, ranked by the pipeline's 0–100 relevance score. The why-rationale rides each row, so the order explains itself. Triage from the keyboard: j / k to move, r to review, ⏎ to open."
        aside={
          status === 'ready' && data ? (
            <MicroLabel tone="faint">
              {num(items.length)} items · updated {rel(data.generated_at)}
            </MicroLabel>
          ) : null
        }
      />
      <AsyncGate
        status={status}
        label="the feed"
        detail={error}
        skeleton={<SkeletonRows rows={8} />}
      >
        <FeedView items={items} />
      </AsyncGate>
    </div>
  )
}
