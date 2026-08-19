import type { DecodedLayer } from '@socdesk/shared/analyzer'
import { MicroLabel } from '@socdesk/shared/ui'

export function DecodeLadder({ layers }: { layers: DecodedLayer[] }) {
  if (!layers.length) return null
  return (
    <div className="flex flex-col gap-2">
      <MicroLabel tone="muted">Decode layers</MicroLabel>
      <div className="flex flex-col gap-2">
        {layers.map((l) => (
          <div key={l.index} className="rounded-md border border-line bg-panel p-3">
            <div className="flex items-center gap-2">
              <span className="font-mono text-micro text-faint">{l.index + 1}.</span>
              <span className="font-mono text-micro uppercase tracking-label text-muted">{l.transform}</span>
              <span className="ml-auto font-mono text-micro uppercase tracking-label text-faint">{l.state}</span>
            </div>
            {l.text != null && (
              <pre className="mt-2 overflow-x-auto whitespace-pre-wrap break-all font-mono text-micro text-paper">{l.text}</pre>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}
