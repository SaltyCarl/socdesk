import { MicroLabel } from '../components/ui'
import { ViewHeader } from '../components/views/ViewFrame'
import { AsyncGate, SkeletonRows } from '../components/views/states'
import { FeedView } from '../components/views/FeedView'
import { useStateData } from '../components/views/useStateData'
import { rel } from '../components/views/format'
import { CountUp } from '../components/views/CountUp'
import type { FeedPayload, StoriesPayload } from '../components/views/types'

/**
 * /feed — "The Brief". Fetches the committed feed snapshot and hands the items
 * to FeedView, which presents them as a dated briefing (one featured lead, then
 * category-grouped sections), and gates on loading/error with an honest
 * skeleton + fallback.
 */
export function FeedRoute() {
  const { status, data, error } = useStateData<FeedPayload>('feed')
  const items = data?.items ?? []
  // Corroborated stories are additive: fetched separately so a missing/loading
  // stories payload never blocks the feed (§3). The briefing renders exactly as
  // before when there are none.
  const stories = useStateData<StoriesPayload>('stories').data?.stories ?? []

  return (
    <div className="flex flex-col gap-6">
      <ViewHeader
        eyebrow="Security briefing"
        title="Feed"
        intro="What's landed in the latest collection window — one lead story, then the reports ranked by the pipeline's relevance score. Every source attributed."
        aside={
          status === 'ready' && data ? (
            <MicroLabel tone="faint">
              <CountUp value={items.length} /> reports · updated{' '}
              {rel(data.generated_at)}
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
        <FeedView items={items} generatedAt={data?.generated_at} stories={stories} />
      </AsyncGate>
    </div>
  )
}
