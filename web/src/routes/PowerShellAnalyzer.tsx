import { useState } from 'react'
import { Chip } from '@socdesk/shared/ui'
import { DecodeLadder } from '../components/analyzer/DecodeLadder'
import { IocTable } from '../components/analyzer/IocTable'
import { TechniqueTally } from '../components/analyzer/TechniqueTally'
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
        aria-label="PowerShell command"
        className="min-h-28 w-full rounded-md border border-line bg-field p-3 font-mono text-xs text-paper placeholder:text-faint focus-visible:border-line-bright"
      />
      {state.kind === 'analyzing' && <p className="font-mono text-micro text-faint">Analyzing…</p>}
      {state.kind === 'error' && <p className="font-mono text-xs text-muted">Could not analyze: {state.message}</p>}
      {state.kind === 'ok' && (
        <div className="flex flex-col gap-4">
          {state.result.flags.length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {state.result.flags.map((f) => (
                <Chip key={f.flag} variant="neutral">{f.flag}</Chip>
              ))}
            </div>
          )}
          <TechniqueTally signals={state.result.signals} characterization={state.result.characterization} />
          <DecodeLadder layers={state.result.layers} />
          <IocTable iocs={state.result.iocs} />
        </div>
      )}
    </div>
  )
}
