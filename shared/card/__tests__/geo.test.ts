import { describe, expect, it } from 'vitest';
import { coordLabel, geoModel, project } from '../geo';
import { STUBS } from '../../verdict-cards/stubs';

const dataFor = (id: string) => STUBS.find((s) => s.id === id)!.data;

describe('project (equirectangular pin placement)', () => {
  it('maps the origin to the centre and clamps inside the frame', () => {
    expect(project(0, 0)).toEqual({ fx: 0.5, fy: 0.5 });
    const p = project(50.11, 8.68);
    expect(p.fx).toBeGreaterThan(0);
    expect(p.fx).toBeLessThan(1);
    expect(p.fy).toBeGreaterThan(0);
    expect(p.fy).toBeLessThan(1);
  });
});

describe('geoModel (derived from the STUBS fixtures, deterministic)', () => {
  it('resolves a precise IP location with flag + coordinate readout', () => {
    const ip = dataFor('ip');
    const g = geoModel(ip.context, ip.sources);
    expect(g).not.toBeNull();
    expect(g!.countryCode).toBe('DE');
    expect(g!.countryName).toBe('Germany');
    expect(g!.city).toBe('Frankfurt');
    expect(g!.precise).toBe(true);
    expect(g!.flag).not.toBeNull();
    expect(coordLabel(g!)).toMatch(/°N/);
    expect(coordLabel(g!)).toMatch(/°E/);
  });

  it('resolves a country-level domain location (no wire coordinate)', () => {
    const dom = dataFor('domain');
    const g = geoModel(dom.context, dom.sources);
    expect(g).not.toBeNull();
    expect(g!.countryCode).toBe('US');
    expect(g!.precise).toBe(false);
    expect(coordLabel(g!)).toBe('country-level');
  });

  it('returns null when nothing carries a location (a hash)', () => {
    const hash = dataFor('hash');
    expect(geoModel(hash.context, hash.sources)).toBeNull();
  });

  it('is deterministic — same input, identical output', () => {
    const ip = dataFor('ip');
    expect(geoModel(ip.context, ip.sources)).toEqual(geoModel(ip.context, ip.sources));
  });
});
