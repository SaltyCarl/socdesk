import { describe, expect, it } from 'vitest'
import { injectIoc, playbooksForType, PARAM_FOR_TYPE } from '../playbooks'
import type { Playbook } from '../types'

const pb = (id: string, ioc_types: string[]): Playbook => ({
  id, title: id, ioc_types, techniques: [], source: { kind: 'socdesk', url: 'x', license: 'MIT' }, steps: [],
})

describe('playbooksForType', () => {
  it('keeps playbooks whose ioc_types include the enriched type', () => {
    const all = [pb('a', ['ipv4', 'ipv6']), pb('b', ['domain'])]
    expect(playbooksForType(all, 'ipv4').map((p) => p.id)).toEqual(['a'])
    expect(playbooksForType(all, 'domain').map((p) => p.id)).toEqual(['b'])
    expect(playbooksForType(all, 'sha256')).toEqual([])
  })
})

describe('injectIoc', () => {
  it('substitutes when the param family matches the IOC type (ipv4 -> ip)', () => {
    expect(injectIoc('where IPAddress == "{{ip}}"', 'ip', 'ipv4', '203.0.113.7')).toBe(
      'where IPAddress == "203.0.113.7"',
    )
  })

  it('replaces every occurrence of the placeholder', () => {
    expect(injectIoc('a "{{ip}}" b "{{ip}}"', 'ip', 'ipv6', '::1')).toBe('a "::1" b "::1"')
  })

  it('leaves a non-matching (follow-on) placeholder visible', () => {
    expect(injectIoc('where UserPrincipalName == "{{upn}}"', 'upn', 'ipv4', '203.0.113.7')).toBe(
      'where UserPrincipalName == "{{upn}}"',
    )
  })

  it('escapes quotes/backslashes so the IOC cannot break the string literal', () => {
    // input value is a, quote, backslash, b  ->  a, backslash-quote, backslash-backslash, b
    expect(injectIoc('== "{{domain}}"', 'domain', 'domain', 'a"\\b')).toBe('== "a\\"\\\\b"')
  })

  it('preserves hyphens/dots in domains (does not strip them)', () => {
    expect(injectIoc('== "{{domain}}"', 'domain', 'domain', 'my-site.example.com')).toBe(
      '== "my-site.example.com"',
    )
  })

  it('maps both IP families to the ip param', () => {
    expect(PARAM_FOR_TYPE.ipv4).toBe('ip')
    expect(PARAM_FOR_TYPE.ipv6).toBe('ip')
  })
})
