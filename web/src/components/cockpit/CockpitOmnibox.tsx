import { useEffect, useLayoutEffect, useRef, useState } from 'react'
import type { ChangeEvent, KeyboardEvent } from 'react'
import { cx } from '@socdesk/shared/lib/cx'
import { classifyCockpitInput } from '@socdesk/shared/intent'
import { ModeChip } from './ModeChip'

const FIELD_CLS =
  'w-full rounded-md border border-line bg-field px-3 py-2 font-mono text-base text-paper outline-offset-2 placeholder:text-faint focus-visible:outline-2 focus-visible:outline-accent'

const SUBMIT_BTN_CLS =
  'shrink-0 rounded-md border border-line bg-panel px-3 py-2 font-mono text-sm text-muted transition-colors duration-150 ease-brand hover:border-line-bright hover:text-paper focus-visible:outline-2 focus-visible:outline-accent'

export interface CockpitOmniboxProps {
  value: string
  onChange: (value: string) => void
  /** Fires on Enter or the arrow button. `kindOverride` carries a corrected
   *  ModeChip toggle (null when auto-detection is in force). */
  onSubmit: (value: string, kindOverride: 'indicator' | 'command' | null) => void
}

/**
 * The cockpit's single input control (design spec §3.7) — a one-line
 * `<input>` by default, morphing to a multi-line, auto-growing, monospace
 * `<textarea>` once the LIVE value is command-shaped (`classifyCockpitInput`
 * === 'command'). Both elements are fully CONTROLLED off the same `value`
 * prop, so the swap never loses what was typed/pasted — only the DOM node
 * identity changes (input and textarea are different element types, so React
 * always remounts the leaf on the swap). Focus follows the morph in BOTH
 * directions: forward into the textarea when the value becomes command-shaped
 * (e.g. mid-paste), and back into the input when it stops being command-shaped
 * (e.g. backspacing a command below the detection threshold) — tracked via
 * `prevCommandShapedRef` so only an actual transition refocuses, never the
 * component's initial mount. The textarea's height is synced to its content
 * in a `useLayoutEffect` keyed on `[value, isCommandShaped]`, so a paste that
 * morphs the box straight into multi-line text is sized correctly on that
 * same paint — not clipped at the floor height until the next keystroke.
 */
export function CockpitOmnibox({ value, onChange, onSubmit }: CockpitOmniboxProps) {
  const [override, setOverride] = useState<'indicator' | 'command' | null>(null)
  const textareaRef = useRef<HTMLTextAreaElement>(null)
  const inputRef = useRef<HTMLInputElement>(null)
  const isCommandShaped = classifyCockpitInput(value) === 'command'
  const prevCommandShapedRef = useRef(isCommandShaped)

  // A change to `value` for ANY reason — typed, pasted, or demo-populated —
  // invalidates a stale ModeChip correction (it was a correction for a
  // DIFFERENT string). Clicking the chip itself does not change `value`, so
  // "click chip -> submit the same value" still carries the override through.
  useEffect(() => {
    setOverride(null)
  }, [value])

  useEffect(() => {
    const wasCommandShaped = prevCommandShapedRef.current
    if (isCommandShaped && !wasCommandShaped) {
      textareaRef.current?.focus()
    } else if (!isCommandShaped && wasCommandShaped) {
      inputRef.current?.focus()
    }
    prevCommandShapedRef.current = isCommandShaped
  }, [isCommandShaped])

  useLayoutEffect(() => {
    const el = textareaRef.current
    if (!el) return
    el.style.height = 'auto'
    el.style.height = `${el.scrollHeight}px`
  }, [value, isCommandShaped])

  const fire = () => {
    onSubmit(value, override)
    setOverride(null)
  }
  const onKeyDown = (e: KeyboardEvent<HTMLInputElement | HTMLTextAreaElement>) => {
    if (e.key === 'Enter') {
      e.preventDefault()
      fire()
    }
  }
  const onInputChange = (e: ChangeEvent<HTMLInputElement>) => {
    onChange(e.target.value)
  }
  const onTextareaChange = (e: ChangeEvent<HTMLTextAreaElement>) => {
    onChange(e.target.value)
  }
  const toggleOverride = () => {
    const autoKind = classifyCockpitInput(value)
    const current = override ?? autoKind
    setOverride(current === 'command' ? 'indicator' : 'command')
  }

  return (
    <div className="flex w-full flex-col gap-2">
      <div className="flex items-start gap-2">
        {isCommandShaped ? (
          <textarea
            ref={textareaRef}
            value={value}
            onChange={onTextareaChange}
            onKeyDown={onKeyDown}
            spellCheck={false}
            rows={3}
            aria-label="Paste an indicator or a PowerShell command — get its escalation card or decode inline"
            placeholder="powershell -nop -w hidden -enc … or 185.220.101.34"
            className={cx(FIELD_CLS, 'min-h-24 resize-none overflow-hidden')}
          />
        ) : (
          <input
            ref={inputRef}
            type="text"
            inputMode="text"
            autoComplete="off"
            spellCheck={false}
            value={value}
            onChange={onInputChange}
            onKeyDown={onKeyDown}
            aria-label="Paste an indicator or a PowerShell command — get its escalation card or decode inline"
            placeholder="Enrich an IP / domain / hash, or paste a command — 185.220.101.34"
            className={FIELD_CLS}
          />
        )}
        <button type="button" onClick={fire} aria-label="Submit" className={SUBMIT_BTN_CLS}>
          →
        </button>
      </div>
      <ModeChip value={value} override={override} onToggle={toggleOverride} />
    </div>
  )
}
