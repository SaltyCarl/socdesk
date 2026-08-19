// shared/analyzer/extract.ts
import type { ExtractedIoc } from './types'
import { detectType, refang } from '../indicators'
import { defang } from '../verdict/doctrine'

// Candidate substrings that might be indicators; detectType is the arbiter.
const CANDIDATE_RE = /\bhttps?:\/\/[^\s'"()<>]+|\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b|\b[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9-]+)+\b|\b[a-fA-F0-9]{32,64}\b/gi

// Binary/script filenames (cmd.exe, kernel32.dll, amsi.dll, a dropped payload.vbs)
// are mis-typed as domains by the shared detectType — a bare lowercase filename
// with a dotted extension satisfies the TLD-agnostic domain regex. Real domains
// don't carry these extensions; URL hosts arrive via the URL branch, unaffected
// by this guard (it only fires on type === 'domain').
const BINARY_EXT_DENYLIST = /\.(?:exe|dll|sys|bat|cmd|scr|ocx|cpl|msi|vbs|ps1|js|hta)$/i

/** Harvest IOCs from every decoded layer, deduped by raw value (first layer
 *  wins), typed by the app's own detectType so it agrees with /lookup. */
export function extractIocs(layers: { index: number; text: string | null }[]): ExtractedIoc[] {
  const seen = new Set<string>()
  const out: ExtractedIoc[] = []
  for (const layer of layers) {
    if (!layer.text) continue
    const matches = layer.text.match(CANDIDATE_RE) ?? []
    for (const m of matches) {
      const raw = refang(m).trim()
      if (!raw || seen.has(raw)) continue
      const type = detectType(raw)
      if (!type) continue
      // .NET member-access tokens (Net.WebClient, IO.MemoryStream, wc.DownloadString)
      // are mis-typed as domains by the shared detectType. They're PascalCase; real
      // domains are conventionally lowercase and URL hosts arrive via the URL branch.
      if (type === 'domain' && /[A-Z]/.test(raw)) continue
      if (type === 'domain' && BINARY_EXT_DENYLIST.test(raw)) continue
      seen.add(raw)
      out.push({ raw, defanged: defang(raw), type, layerIndex: layer.index })
    }
  }
  return out
}
