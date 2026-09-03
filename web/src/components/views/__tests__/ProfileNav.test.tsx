import { describe, expect, it } from 'vitest'
import { renderToStaticMarkup } from 'react-dom/server'
import { ProfileNav } from '../ProfileNav'
import type { NavSection } from '../useProfileNav'

const sections: NavSection[] = [
  { id: 'overview', label: 'Overview' },
  { id: 'activity', label: 'Activity' },
  { id: 'huntpack', label: 'Hunt pack' },
]

describe('ProfileNav', () => {
  it('renders a landmark button per section (hash-safe — the app is hash-routed)', () => {
    const html = renderToStaticMarkup(<ProfileNav sections={sections} activeId="" />)
    // buttons, NOT #id anchors (which would wipe the g=<slug> route)
    expect(html).not.toContain('href="#')
    expect(html).toContain('<button')
    expect(html).toContain('Overview')
    expect(html).toContain('Activity')
    expect(html).toContain('Hunt pack')
  })

  it('marks the active section with aria-current', () => {
    const html = renderToStaticMarkup(<ProfileNav sections={sections} activeId="activity" />)
    expect(html).toMatch(/aria-current="true"[^>]*>Activity<|>Activity<[^<]*aria-current/)
    // exactly one active per render context (desktop bar) — Overview is not active
    expect(html).not.toMatch(/aria-current="true"[^>]*>Overview</)
  })

  it('renders nothing when there is only the Overview landmark (nothing to orient)', () => {
    const html = renderToStaticMarkup(<ProfileNav sections={[{ id: 'overview', label: 'Overview' }]} activeId="" />)
    expect(html).toBe('')
  })

  it('includes a mobile "Jump to" disclosure', () => {
    const html = renderToStaticMarkup(<ProfileNav sections={sections} activeId="" />)
    expect(html).toContain('Jump to')
    expect(html).toContain('<details')
  })
})
