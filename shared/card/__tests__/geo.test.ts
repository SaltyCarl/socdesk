import { describe, expect, it } from 'vitest';
import { coordLabel, geoModel, greatCircleArc, project } from '../geo';
import { STUBS } from '../../verdict-cards/stubs';

const dataFor = (id: string) => STUBS.find((s) => s.id === id)!.data;

describe('greatCircleArc', () => {
  it('starts at A and ends at B (projected)', () => {
    const segs = greatCircleArc(37.77, -122.42, 52.52, 13.4); // SF → Berlin
    const first = segs[0][0];
    const last = segs[segs.length - 1][segs[segs.length - 1].length - 1];
    expect(first.fx).toBeCloseTo(project(37.77, -122.42).fx, 2);
    expect(last.fx).toBeCloseTo(project(52.52, 13.4).fx, 2);
  });
  it('is a single segment when it does not cross the antimeridian', () => {
    expect(greatCircleArc(40.71, -74.0, 51.5, -0.12)).toHaveLength(1); // NYC → London
  });
  it('splits into 2 segments across the antimeridian', () => {
    // Tokyo → LA: the shortest great circle crosses the 180° line.
    expect(greatCircleArc(35.68, 139.65, 34.05, -118.24).length).toBeGreaterThan(1);
  });
  it('every projected point stays inside the [0,1] frame', () => {
    for (const seg of greatCircleArc(-33.87, 151.21, 55.75, 37.62)) {
      for (const p of seg) {
        expect(p.fx).toBeGreaterThanOrEqual(0);
        expect(p.fx).toBeLessThanOrEqual(1);
        expect(p.fy).toBeGreaterThanOrEqual(0);
        expect(p.fy).toBeLessThanOrEqual(1);
      }
    }
  });
});

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
