import { tokenize, type Token } from './lex'

const isPlus = (t: Token | undefined): boolean => t?.type === 'bareword' && t?.value === '+'
const isVar = (t: Token | undefined): boolean => !!t && t.type === 'bareword' && /^\$[A-Za-z_][\w]*$/.test(t.value)
const isEq = (t: Token | undefined): boolean => !!t && t.type === 'punct' && t.value === '='

/** Serialize one token back to source-ish text: strings become single-quoted
 *  (their resolved value re-quoted), everything else keeps its original `raw`.
 *  Bare words starting with '+' followed by other chars are split (e.g. '+$x' → '+ $x').
 *  Embedded single quotes in strings are escaped by doubling. */
function emit(t: Token): string {
  if (t.type === 'string') {
    return `'${t.value.replace(/'/g, "''")}'`
  }
  // Bareword starting with '+' followed by other chars: split into operator + operand
  if (t.type === 'bareword' && t.value.startsWith('+') && t.value.length > 1) {
    return '+ ' + t.value.slice(1)
  }
  return t.raw
}

/** Collapse `'a'+'b'+…` runs of string literals into one string token. Only
 *  folds when BOTH sides of every `+` are string literals — a non-literal
 *  operand (a variable, a call) stops the run and is left untouched. */
export function foldConcat(text: string): string {
  const toks = tokenize(text)
  const out: string[] = []
  let i = 0
  while (i < toks.length) {
    if (toks[i].type === 'string' && isPlus(toks[i + 1]) && toks[i + 2]?.type === 'string') {
      let value = toks[i].value
      let j = i + 1
      while (isPlus(toks[j]) && toks[j + 1]?.type === 'string') {
        value += toks[j + 1].value
        j += 2
      }
      out.push(`'${value.replace(/'/g, "''")}'`)
      i = j
    } else {
      out.push(emit(toks[i]))
      i++
    }
  }
  return out.join(' ')
}

/** Substitute single-assignment `$var = '<literal>'` bindings, and report the
 *  set of variable names that could NOT be resolved to a literal: assigned
 *  more than once, assigned to a non-literal, referenced before assignment,
 *  or never bound at all. `resolveVars` (below) is the pre-existing
 *  string-only call shape, kept byte-identical for every current call site —
 *  this is its internals, exposed so `resolveWithFacts` can see the poisoned
 *  set instead of discarding it (bullets design D4). */
export function resolveVarsWithFacts(text: string): { text: string; poisoned: string[] } {
  const toks = tokenize(text)
  // Pass 1: collect single-assignment bindings + the token index of the assignment.
  const bound = new Map<string, { value: string; at: number }>()
  const poisoned = new Set<string>()
  for (let i = 0; i < toks.length; i++) {
    if (isVar(toks[i]) && isEq(toks[i + 1])) {
      const name = toks[i].value
      if (toks[i + 2]?.type === 'string' && !isPlus(toks[i + 3])) {
        if (bound.has(name) || poisoned.has(name)) { bound.delete(name); poisoned.add(name) }
        else bound.set(name, { value: toks[i + 2].value, at: i })
      } else {
        bound.delete(name); poisoned.add(name) // assigned to a non-literal → ambiguous
      }
    }
  }
  // Pass 2: substitute a bound var ONLY at a use site AFTER its assignment (never
  // the LHS, never a use-before-def), escaping quotes so it round-trips. A
  // reference that's still a bare $var here — never bound, or used before its
  // one assignment — is an unresolved operand too, even though pass 1 never
  // poisoned it (pass 1 only poisons "bound then invalidated").
  const out: string[] = []
  for (let i = 0; i < toks.length; i++) {
    const t = toks[i]
    const isAssignLhs = isVar(t) && isEq(toks[i + 1])
    const b = isVar(t) && !isAssignLhs ? bound.get(t.value) : undefined
    if (b && i > b.at) {
      out.push(`'${b.value.replace(/'/g, "''")}'`)
    } else {
      if (isVar(t) && !isAssignLhs && !b) poisoned.add(t.value)
      out.push(emit(t))
    }
  }
  return { text: out.join(' '), poisoned: [...poisoned].sort() }
}

/** The pre-existing string-only call shape — unchanged for every current call site. */
export function resolveVars(text: string): string {
  return resolveVarsWithFacts(text).text
}

/** Re-emit the token stream with no folding or substitution — the whitespace/
 *  quote baseline that separates real deobfuscation from mere reformatting.
 *  resolve(x) === normalize(x) exactly when nothing was folded or substituted. */
export function normalize(text: string): string {
  return tokenize(text).map(emit).join(' ')
}

/** Fold concatenations and substitute single-assignment vars to a fixpoint.
 *  Capped so hostile input can never spin. Note: a var built FROM a concat
 *  (`$c = $a + $b`) resolves over successive passes — substitute the vars, then
 *  the next foldConcat collapses the now-literal `'x' + 'y'`. */
export function resolve(text: string): string {
  const MAX_OUTPUT = 1 << 20 // 1 MiB — bail past this; return the last bounded form
  let cur = text
  for (let i = 0; i < 12; i++) {
    const next = foldConcat(resolveVars(cur))
    if (next.length > MAX_OUTPUT) return cur
    if (next === cur) return next
    cur = next
  }
  return cur
}

/** Same fixpoint loop as resolve(), but also reports whether the converged
 *  (final) pass still saw a variable reference that never resolved to a
 *  literal. Backs the bullets 'inferred' confidence tier (D3/D4 of the
 *  bullets design): an object built from an unresolved operand is a real,
 *  honest distinction from one built entirely from literals. Deliberately
 *  reflects only the LAST pass, not an OR across every intermediate pass —
 *  a var assigned from other vars (e.g. `$u = $a + $b`) is transiently
 *  "poisoned" mid-fixpoint (its RHS isn't literal YET) but resolves fully
 *  once $a/$b substitute in on a later pass; only the final state should
 *  count as truly unresolved. */
export function resolveWithFacts(text: string): { text: string; hadUnresolvedOperand: boolean } {
  const MAX_OUTPUT = 1 << 20
  let cur = text
  let hadUnresolvedOperand = false
  for (let i = 0; i < 12; i++) {
    const { text: varsResolved, poisoned } = resolveVarsWithFacts(cur)
    hadUnresolvedOperand = poisoned.length > 0
    const next = foldConcat(varsResolved)
    if (next.length > MAX_OUTPUT) return { text: cur, hadUnresolvedOperand }
    if (next === cur) return { text: next, hadUnresolvedOperand }
    cur = next
  }
  return { text: cur, hadUnresolvedOperand }
}
