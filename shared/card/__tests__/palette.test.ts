import { describe, expect, it } from 'vitest';
import { THEMES } from '../palette';

// The copy-card PNG paints from literal hexes (a <canvas> can't read CSS vars),
// so these MUST stay byte-identical to the app tokens in shared/tokens.css. This
// pins the cool-slate scheme the app moved to (2026-08-14) so a silent drift
// back to the legacy warm-espresso palette — or any divergence from tokens.css —
// fails CI rather than shipping a copy-card that clashes with the app it's from.

describe('copy-card canvas palette (slate — mirrors shared/tokens.css)', () => {
  it('dark theme matches the tokens.css dark block (§B/§C)', () => {
    expect(THEMES.dark).toEqual({
      bg: '#0E121A', // --ink
      panel: '#161C27', // --panel
      panel2: '#212936', // --panel-soft
      field: '#0A0E15', // --field
      border: '#29323F', // --line
      border2: '#3A4557', // --line-bright
      border3: '#4E5C72', // --line-strong
      text: '#E9EDF4', // --paper
      textDim: '#98A3B4', // --muted
      textFaint: '#697486', // --faint
      accent: '#7C8AFF', // --accent
      accent2: '#ADB6FF', // --accent-dim
      vRed: '#F5566B', // --red
      vAmber: '#F2A81E', // --gold
      vGreen: '#4FC97A', // --green
    });
  });

  it('light theme matches the tokens.css light block (§A)', () => {
    expect(THEMES.light).toEqual({
      bg: '#EDF1F6', // --ink
      panel: '#F8FAFC', // --panel
      panel2: '#E8EDF3', // --panel-soft
      field: '#FFFFFF', // --field
      border: '#D6DCE5', // --line
      border2: '#C2CAD6', // --line-bright
      border3: '#A2AEBE', // --line-strong
      text: '#131A24', // --paper
      textDim: '#55606F', // --muted
      textFaint: '#8996A6', // --faint
      accent: '#4A4FD0', // --accent
      accent2: '#6E74E0', // --accent-dim
      vRed: '#D33A50', // --red
      vAmber: '#B4740C', // --gold
      vGreen: '#1E9E57', // --green
    });
  });

  it('is a cool-slate ground, not the legacy warm espresso', () => {
    // A guard on intent: the dark ground must be blue-dominant (B ≥ R), the
    // opposite of the old warm espresso (#15100A, R > B).
    const [r, , b] = [1, 3, 5].map((i) => parseInt(THEMES.dark.bg.slice(i, i + 2), 16));
    expect(b).toBeGreaterThanOrEqual(r);
  });
});
