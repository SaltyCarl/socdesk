import { describe, expect, it } from 'vitest'
import { SUCCESS_ICON_CLASS, SUCCESS_TEXT_CLASS } from './reportChrome'

describe('report success chrome is accent, never a verdict hue', () => {
  it('carries no verdict-* class (green = "a source found nothing adverse")', () => {
    expect(SUCCESS_ICON_CLASS).not.toMatch(/verdict/)
    expect(SUCCESS_TEXT_CLASS).not.toMatch(/verdict/)
  })
  it('success is the accent-stroked check + paper text', () => {
    expect(SUCCESS_ICON_CLASS).toContain('stroke-[var(--accent)]')
    expect(SUCCESS_TEXT_CLASS).toContain('text-paper')
  })
})
