import { useEffect, useState } from 'react'
import { AnalyzerResult, usePsAnalysis } from '@socdesk/shared/analyzer-ui'
import { readLookupQuery } from './lookupModel'

export function PowerShellAnalyzer() {
  // Lazy-init from the `#q=` deep link so a command routed here from the
  // palette/`/lookup` (commands.ts::submitLookup, Lookup.tsx) arrives
  // prefilled and auto-analyzes for free — `input` already drives
  // `usePsAnalysis` reactively, so no separate trigger is needed.
  const [input, setInput] = useState(readLookupQuery)
  const state = usePsAnalysis(input)

  useEffect(() => {
    // hashchange covers a same-route hash edit/resubmit; popstate covers
    // commands.ts's cross-route pushState + synthetic-popstate navigation,
    // which does NOT fire hashchange. Mirrors Lookup.tsx's sync effect.
    const sync = () => setInput(readLookupQuery())
    window.addEventListener('hashchange', sync)
    window.addEventListener('popstate', sync)
    return () => {
      window.removeEventListener('hashchange', sync)
      window.removeEventListener('popstate', sync)
    }
  }, [])
  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-col gap-1">
        <span className="font-mono text-micro uppercase tracking-label text-faint">PowerShell analyzer</span>
        <h1 className="font-display text-xl font-bold text-paper">Paste a PowerShell command</h1>
        <p className="text-xs text-muted">Deterministic, client-side, never executed. Decodes it and extracts IOCs you can look up.</p>
      </div>
      <textarea
        value={input}
        onChange={(e) => setInput(e.target.value)}
        spellCheck={false}
        placeholder="powershell -nop -w hidden -enc …"
        aria-label="PowerShell command"
        className="min-h-28 w-full rounded-md border border-line bg-field p-3 font-mono text-xs text-paper placeholder:text-faint focus-visible:border-line-bright"
      />
      {state.kind === 'analyzing' && <p className="font-mono text-micro text-faint">Analyzing…</p>}
      {state.kind === 'error' && <p className="font-mono text-xs text-muted">Could not analyze: {state.message}</p>}
      {state.kind === 'ok' && <AnalyzerResult result={state.result} />}
    </div>
  )
}
