import { Chip } from '@socdesk/shared/ui'
import { classifyCockpitInput } from '@socdesk/shared/intent'
import { classifyIndicator, INDICATOR_LABEL } from '../palette/classify'

/** The live-detected input kind, shown beside the omnibox — a FACT about the
 *  pasted text, never a verdict (periwinkle/`catalog`, design spec §8 — NOT
 *  `neutral`, which renders identically to Chip's gray `unknown` VERDICT
 *  badge and would misread as a severity state).
 *  Correctable: clicking toggles a manual override that wins over
 *  auto-detection for the next submit (spec §3.7, §7 — the misclassification
 *  mitigation). `override` is null when auto-detection is in force. */
export function ModeChip({
  value,
  override,
  onToggle,
}: {
  value: string
  override: 'indicator' | 'command' | null
  onToggle: () => void
}) {
  const autoKind = classifyCockpitInput(value)
  // The override is monotonic (`resolveKind`, useCockpitInput.ts, design spec
  // §2.1): it may escalate a missed indicator/unclassified value TO
  // 'command', but can never pull an auto-detected 'command' away from
  // 'command'. So an auto-detected command ignores any override entirely —
  // offering the correction there would advertise a click that silently does
  // nothing — and the true empty box has nothing to correct either.
  const isEmpty = value.trim() === ''
  const correctable = !isEmpty && autoKind !== 'command'
  const kind = autoKind === 'command' ? 'command' : (override ?? autoKind)
  const label =
    kind === 'unclassified'
      ? '—'
      : kind === 'command'
        ? 'PowerShell'
        : INDICATOR_LABEL[classifyIndicator(value)]
  return (
    <button
      type="button"
      onClick={correctable ? onToggle : undefined}
      disabled={!correctable}
      aria-label={
        correctable
          ? `Detected as ${label} — click to switch to ${kind === 'command' ? 'indicator' : 'command'}`
          : isEmpty
            ? 'No indicator or command detected yet'
            : `Detected as ${label}`
      }
      className="shrink-0 disabled:cursor-default"
    >
      <Chip variant="catalog">{label}</Chip>
    </button>
  )
}
