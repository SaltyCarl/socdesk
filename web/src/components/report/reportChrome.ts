// reportChrome — reserved-colour class strings for the report confirmation.
// A report CONFIRMATION is UI chrome, not a verdict: success is the accent-
// stroked checkmark + paper text, NEVER text-verdict-green (green already means
// "a source found nothing adverse"; reusing it would let a user misread "queued"
// as "this IOC is clean"). Exported so the reserved-colour guard test can assert
// no verdict hue leaks in.

export const SUCCESS_ICON_CLASS = 'size-4 shrink-0 stroke-[var(--accent)]'
export const SUCCESS_TEXT_CLASS = 'text-paper'
