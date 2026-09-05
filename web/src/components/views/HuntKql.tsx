import { useState } from 'react'

/** Truth-returning clipboard write — this project has shipped a button that
 *  claimed success while the clipboard silently rejected the write
 *  (shared/verdict-cards/copy.ts lesson); never claim what didn't happen.
 *  Module-local (only CopyKqlButton uses it) so this file exports components
 *  only — clean under react-refresh/only-export-components. */
async function copyPlain(text: string): Promise<boolean> {
  try {
    if (!navigator.clipboard?.writeText) return false
    await navigator.clipboard.writeText(text)
    return true
  } catch {
    return false
  }
}

/** Truth-returning copy button — shows "Copied" / "Clipboard blocked" honestly
 *  (never claims a write that the clipboard rejected). Generic over any text so
 *  the hunt-pack row, a playbook step, and "copy whole playbook" share it. */
export function CopyButton({ text, label = 'Copy' }: { text: string; label?: string }) {
  const [state, setState] = useState<'idle' | 'copied' | 'blocked'>('idle')
  const shown = state === 'copied' ? 'Copied' : state === 'blocked' ? 'Clipboard blocked' : label
  return (
    <button
      type="button"
      onClick={() => {
        void copyPlain(text).then((ok) => {
          setState(ok ? 'copied' : 'blocked')
          setTimeout(() => setState('idle'), 2000)
        })
      }}
      className="inline-flex items-center rounded-md border border-line bg-panel px-2.5 py-1 font-mono text-micro font-semibold text-muted transition-colors duration-150 ease-brand hover:border-line-bright hover:text-paper focus-visible:outline-2 focus-visible:outline-accent"
    >
      {shown}
    </button>
  )
}

export function CopyKqlButton({ kql }: { kql: string }) {
  return <CopyButton text={kql} label="Copy KQL" />
}

/** The shared "View KQL" disclosure + scrollable code block + copy button — used
 *  by the Adversaries hunt-pack row AND the enrichment playbook step, so the
 *  affordance never drifts. whitespace-pre + overflow-x-auto (not wrap/break) so
 *  KQL identifiers never split mid-token. */
export function KqlBlock({ kql, label = 'View KQL' }: { kql: string; label?: string }) {
  return (
    <details>
      <summary className="cursor-pointer select-none font-mono text-micro font-semibold uppercase tracking-label text-accent">
        {label}
      </summary>
      <pre className="mt-2 overflow-x-auto whitespace-pre rounded-md border border-line bg-panel p-3 font-mono text-micro text-paper">
        {kql}
      </pre>
      <div className="mt-2">
        <CopyKqlButton kql={kql} />
      </div>
    </details>
  )
}
