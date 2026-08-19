import type { EvasionFlag, RuleContext, Signal, Specificity } from './types'
import { tokenize } from './lex'
import { matchLolbin } from './lolbins'

export interface RuleHit {
  hit: boolean
  trigger?: string
  techniqueIds?: string[]  // overrides the rule's static ids when a rule is data-driven (LOLBins)
  label?: string           // overrides the rule's static label (LOLBins name the binary)
}

export interface SignatureRule {
  id: string
  label: string
  techniqueIds: string[]
  baseSpecificity: Specificity
  upgradesWith: string[]   // companion rule ids: if any co-fires, bump this rule one tier
  test(ctx: RuleContext): RuleHit
}

/** Build the read-only match context once per analysis. `words` are lowercased
 *  bareword/string token values (backtick obfuscation already stripped by the
 *  lexer); `lower` is the whole-text fallback for multi-word phrases. */
export function buildContext(text: string, flags: EvasionFlag[]): RuleContext {
  const tokens = tokenize(text)
  const words = tokens
    .filter((t) => t.type === 'bareword' || t.type === 'string')
    .map((t) => t.value.toLowerCase())
  return { text, lower: text.toLowerCase(), tokens, words, flags }
}

// ---- match helpers (all case-insensitive; token-value first, whole-text fallback) ----

function present(ctx: RuleContext, needle: string): boolean {
  const k = needle.toLowerCase()
  return ctx.words.some((w) => w.includes(k)) || ctx.lower.includes(k)
}
function hasAll(ctx: RuleContext, needles: string[]): boolean {
  return needles.every((n) => present(ctx, n))
}
function hasAny(ctx: RuleContext, needles: string[]): boolean {
  return needles.some((n) => present(ctx, n))
}
function flagSet(ctx: RuleContext): Set<string> {
  return new Set(ctx.flags.map((f) => f.flag))
}
/** First token whose value contains any needle → its raw slice (audit trigger). */
function triggerFor(ctx: RuleContext, needles: string[]): string {
  for (const n of needles) {
    const k = n.toLowerCase()
    const tok = ctx.tokens.find(
      (t) => (t.type === 'bareword' || t.type === 'string') && t.value.toLowerCase().includes(k),
    )
    if (tok) return tok.raw.slice(0, 80)
  }
  return needles[0]
}

// Shared vocab.
const FETCH = ['downloadstring', 'downloaddata', 'downloadfile', 'invoke-webrequest', 'iwr', 'invoke-restmethod', 'irm', 'net.webclient', 'start-bitstransfer', 'httpclient', 'system.net.webrequest', 'wget', 'curl']
const OUTFILE = ['-outfile', '-out ', 'convertfrom-json', 'set-content', 'out-file']

/** IEX / Invoke-Expression / '&' call-operator sink present. `&` is a bareword
 *  to the lexer (not a punct), so it lands in `words`. */
function hasIexSink(ctx: RuleContext): boolean {
  return hasAny(ctx, ['iex', 'invoke-expression', '.invoke(']) || ctx.words.includes('&')
}

// ---- the rule table (extended by Tasks 3–5) ----

export const RULES: SignatureRule[] = [
  {
    id: 'download-cradle',
    label: 'download cradle',
    techniqueIds: ['T1059.001', 'T1105'],
    baseSpecificity: 'strong',
    upgradesWith: ['amsi-reflection', 'clickfix', 'evasion-cluster'],
    test(ctx) {
      const fetches = hasAny(ctx, FETCH)
      // Discriminator: fetched content must flow into an interpreter, not a file.
      if (fetches && hasIexSink(ctx)) return { hit: true, trigger: triggerFor(ctx, FETCH) }
      return { hit: false }
    },
  },
  {
    id: 'evasion-cluster',
    label: 'evasion flag cluster',
    techniqueIds: ['T1059.001', 'T1564.003', 'T1027'],
    baseSpecificity: 'weak',
    upgradesWith: ['download-cradle', 'amsi-reflection', 'clickfix'],
    test(ctx) {
      const flags = flagSet(ctx)
      const cluster = ['-enc', '-nop', '-w', '-ep', '-noni', '-sta'].filter((f) => flags.has(f)).length
      // Discriminator: a cluster is only suspicious with -enc or an inline fetch;
      // the same flags running a LOCAL -File automation are benign.
      const localFile = /-file\b/i.test(ctx.text) || present(ctx, '-file')
      const payload = flags.has('-enc') || hasAny(ctx, FETCH) || hasIexSink(ctx)
      if (cluster >= 3 && payload && !localFile) {
        return { hit: true, trigger: ctx.flags.map((f) => f.flag).join(' ') }
      }
      return { hit: false }
    },
  },
]

/** Run every rule once; emit one Signal per hit, in table order (deterministic).
 *  A rule's test may override label/techniqueIds (LOLBins are data-driven). */
export function runRules(ctx: RuleContext): Signal[] {
  const out: Signal[] = []
  for (const rule of RULES) {
    const r = rule.test(ctx)
    if (!r.hit) continue
    out.push({
      id: rule.id,
      label: r.label ?? rule.label,
      techniqueIds: r.techniqueIds ?? rule.techniqueIds,
      specificity: rule.baseSpecificity,
      trigger: r.trigger ?? rule.label,
    })
  }
  return out
}

const ORDER: Specificity[] = ['weak', 'strong', 'near-dispositive']
function bump(s: Specificity): Specificity {
  return ORDER[Math.min(ORDER.indexOf(s) + 1, ORDER.length - 1)]
}

/** Signals + co-occurrence upgrade: a rule whose `upgradesWith` names a
 *  companion that also fired is raised one specificity tier (capped at
 *  near-dispositive). Every single token has a benign twin — company is the
 *  accuracy mechanism. */
export function classify(ctx: RuleContext): Signal[] {
  const signals = runRules(ctx)
  const fired = new Set(signals.map((s) => s.id))
  const byId = new Map(RULES.map((r) => [r.id, r]))
  return signals.map((s) => {
    const rule = byId.get(s.id)
    if (rule && rule.upgradesWith.some((id) => fired.has(id))) {
      return { ...s, specificity: bump(s.specificity) }
    }
    return s
  })
}

// Re-exported so later rules (Tasks 3–5) and their tests can reuse the vocab/helpers.
export { hasAll, hasAny, present, flagSet, triggerFor, hasIexSink, FETCH, OUTFILE, matchLolbin }
