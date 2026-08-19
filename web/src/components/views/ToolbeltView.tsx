import type { ReactNode } from 'react'
import { MicroLabel } from '../ui'
import { navigate } from '../palette/commands'

/**
 * Toolbelt — a deliberate stub. The analyst micro-tools (defang/refang,
 * hash typing) live in the lookup engine's doctrine layer; this surface will
 * host their standalone forms. Listed honestly as planned, not dressed up as
 * working buttons. Base64 decode is live — it grew into the full PowerShell
 * analyzer, so its card links out to that route instead.
 */

const PLANNED: Array<{ name: string; blurb: string; href?: string }> = [
  { name: 'Defang / refang', blurb: 'Toggle evil[.]com ⇄ evil.com, hxxp ⇄ http for safe paste.' },
  {
    name: 'Base64 decode',
    blurb: 'Decode encoded command lines and payload blobs, in place.',
    href: '/analyzer',
  },
  { name: 'Indicator typing', blurb: 'Classify a pasted string (ipv4 / domain / url / hash / CVE).' },
]

function ToolCard({
  name,
  href,
  children,
}: {
  name: string
  href?: string
  children: ReactNode
}) {
  const body = (
    <>
      <div className="flex items-center justify-between gap-2">
        <span className="font-display text-base font-bold tracking-tight text-paper">
          {name}
        </span>
        {href ? (
          <MicroLabel tone="accent" tick>
            live
          </MicroLabel>
        ) : (
          <MicroLabel tone="faint">planned</MicroLabel>
        )}
      </div>
      <p className="text-xs text-muted">{children}</p>
    </>
  )

  if (href) {
    return (
      <a
        href={href}
        onClick={(e) => {
          if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || e.button !== 0) return
          e.preventDefault()
          navigate(href)
        }}
        className="flex flex-col gap-2 rounded-lg border border-line bg-panel p-4 outline-offset-2 transition-colors duration-150 ease-brand hover:border-accent focus-visible:outline-2 focus-visible:outline-accent"
      >
        {body}
      </a>
    )
  }

  return (
    <div className="flex flex-col gap-2 rounded-lg border border-line bg-panel p-4">
      {body}
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
          <ToolCard key={t.name} name={t.name} href={t.href}>
            {t.blurb}
          </ToolCard>
        ))}
      </div>
    </div>
  )
}
