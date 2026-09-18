import { num } from '../views/format'
import type { PicketPayload } from '../views/types'
import { BoardPanel, DeskLink, PanelEmpty, SourceStamp } from './board-ui'
import { Sparkline } from './Sparkline'
import { histogramPoints, statusCopy } from '../views/picketModel'

/**
 * Compact landing teaser for /desk#picket. Same honesty rules as the tab:
 * periwinkle volume only, a silent sensor stated as "no export".
 */
export function PicketTeaser({ payload }: { payload: PicketPayload | null }) {
  return (
    <BoardPanel
      eyebrow="SOCDESK · PICKET"
      title="Picket — telemetry from my own sensor"
      aside={<SourceStamp label="knock-knock · GeoLite2" />}
      footer={
        <>
          <span className="font-mono text-micro uppercase tracking-label text-faint">
            {payload ? `${num(payload.totals.knocks_7d)} knocks · ${num(payload.totals.unique_ips_7d)} IPs · 7 d` : 'no export yet'}
          </span>
          <DeskLink tab="picket">Picket</DeskLink>
        </>
      }
    >
      {!payload ? (
        <PanelEmpty>No sensor telemetry yet.</PanelEmpty>
      ) : (
        <div className="flex flex-col gap-3">
          <p className="text-xs text-muted">{statusCopy(payload.sensor)}</p>
          <div className="flex items-end justify-between gap-4">
            <div>
              <div className="font-display text-3xl font-extrabold tracking-tight text-paper">{num(payload.totals.knocks_24h)}</div>
              <div className="font-mono text-micro uppercase tracking-label text-faint">knocks · 24 h</div>
            </div>
            <Sparkline points={histogramPoints(payload.histogram_7d, payload.generated_at)} label="knocks per day, last 7 days" />
          </div>
          {payload.top_countries[0] && (
            <p className="font-mono text-micro text-faint">most from {payload.top_countries[0].name || payload.top_countries[0].iso} · {payload.sensor.protocols.join(' · ')}</p>
          )}
        </div>
      )}
    </BoardPanel>
  )
}
