import { useState } from 'react'
import { usePsAnalysis } from '../components/analyzer/usePsAnalysis'

export function PowerShellAnalyzer() {
  const [input, setInput] = useState('')
  const state = usePsAnalysis(input)
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
        className="min-h-28 w-full rounded-md border border-line bg-field p-3 font-mono text-xs text-paper placeholder:text-faint focus-visible:border-line-bright"
      />
      {state.kind === 'analyzing' && <p className="font-mono text-micro text-faint">Analyzing…</p>}
      {state.kind === 'error' && <p className="font-mono text-xs text-muted">Could not analyze: {state.message}</p>}
      {state.kind === 'ok' && (
        <pre className="overflow-x-auto rounded-md border border-line bg-panel p-3 font-mono text-micro text-muted">
          {JSON.stringify(state.result, null, 2)}
        </pre>
      )}
    </div>
  )
}
