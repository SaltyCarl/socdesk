import type { ReactNode } from 'react'
import { MicroLabel } from '../ui'

/**
 * Toolbelt — a deliberate stub. The analyst micro-tools (defang/refang,
 * base64, hash typing) live in the lookup engine's doctrine layer; this
 * surface will host their standalone forms. Listed honestly as planned, not
 * dressed up as working buttons.
 */

const PLANNED: Array<{ name: string; blurb: string }> = [
  { name: 'Defang / refang', blurb: 'Toggle evil[.]com ⇄ evil.com, hxxp ⇄ http for safe paste.' },
  { name: 'Base64 decode', blurb: 'Decode encoded command lines and payload blobs, in place.' },
  { name: 'Indicator typing', blurb: 'Classify a pasted string (ipv4 / domain / url / hash / CVE).' },
]

function ToolCard({ name, children }: { name: string; children: ReactNode }) {
  return (
    <div className="flex flex-col gap-2 rounded-lg border border-line bg-panel p-4">
      <div className="flex items-center justify-between gap-2">
        <span className="font-display text-base font-bold tracking-tight text-paper">
          {name}
        </span>
        <MicroLabel tone="faint">planned</MicroLabel>
      </div>
      <p className="text-xs text-muted">{children}</p>
    </div>
  )
}

export function ToolbeltView() {
  return (
    <div className="flex flex-col gap-5">
      <div
        role="status"
        className="rounded-lg border border-line bg-panel px-5 py-6"
      >
        <MicroLabel tone="accent">Stub</MicroLabel>
        <p className="mt-2 max-w-2xl text-base text-muted">
          The toolbelt is scaffolded, not yet wired. The micro-tools below draw
          on the same deterministic helpers as the lookup engine; their
          standalone forms land in a later pass. Nothing here fakes a working
          control.
        </p>
      </div>
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {PLANNED.map((t) => (
          <ToolCard key={t.name} name={t.name}>
            {t.blurb}
          </ToolCard>
        ))}
      </div>
    </div>
  )
}
