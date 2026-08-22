import { describe, expect, it } from 'vitest'
import { buttonClasses } from './buttonClasses'

describe('buttonClasses — tertiary variant (discoverable, not competing)', () => {
  it('is borderless-until-hover, muted ink, revealing paper on hover', () => {
    const c = buttonClasses('tertiary', 'sm')
    expect(c).toContain('border-transparent')
    expect(c).toContain('text-muted')
    expect(c).toContain('hover:border-line')
    expect(c).toContain('hover:bg-panel-soft')
    expect(c).toContain('hover:text-paper')
  })
  it('shares the sm box with its row-mates (h-8 / px-3 / text-xs)', () => {
    const c = buttonClasses('tertiary', 'sm')
    expect(c).toContain('h-8')
    expect(c).toContain('px-3')
    expect(c).toContain('text-xs')
  })
  it('carries NO verdict/severity colour (reserved-colour law)', () => {
    expect(buttonClasses('tertiary', 'sm')).not.toMatch(/verdict-|--red|--gold|--green/)
  })
})
