/* ============================================================
   SOCDESK — Brand HYBRID renderer.
   ONE source of geometry for the "bar-chart-in-mug" mark, rendered flat in
   two brand tones — coffee (mug) + periwinkle (bars). No glow, no gradient,
   no gloss: paints are solid, the SVG is crisp vector.

   Paints ride CSS classes (.m-wall / .m-rim / .m-handle / .m-bar / .m-wisp),
   never var() in a presentation attribute (SVG can't) and never inline style
   (the CSP forbids it) — the same discipline site/css/chrome.css uses for the
   shipping .cup. The canvas magnifier is the exception: it needs a standalone
   data-URI SVG, so those strings bake resolved hexes.
   ============================================================ */
(function () {
  'use strict';

  var NS = 'http://www.w3.org/2000/svg';

  /* ---- resolved hexes (mirror tokens.css) for the data-URI / canvas path ---- */
  var HEX = {
    dark:  { cup: '#A6612F', bar: '#7C8AFF', ink: '#15100A' },
    light: { cup: '#A6612F', bar: '#4A4FD0', ink: '#F2E6D0' }
  };

  /* ============================================================
     DETAILED MARK — master, viewBox 0 0 32 32.
     Coffee cup (open rim + D-handle) holding 3 ascending periwinkle bars.
     Reads at topbar / app-icon / hero scale (>= ~24px).
     ============================================================ */
  var WALL   = 'M8.4 9 L9.8 22 Q10.05 22.4 12.3 22.4 L19.7 22.4 Q21.95 22.4 22.2 22 L23.6 9';
  var RIM    = 'M8.4 9 L23.6 9';
  var HANDLE = 'M23.8 11.6 C28.4 11.2 29 15 29 16.6 C29 18.2 28.4 21.4 23.8 21';
  var BARS   = [           /* x, y, w, h  — common base y = 22.4, rounded tops */
    [11.80, 17.2, 2.4, 5.2],
    [15.15, 13.6, 2.4, 8.8],
    [18.50, 10.6, 2.4, 11.8]
  ];

  function detailInner() {
    var s = '';
    s += '<path class="m-wall" stroke-width="2.6" d="' + WALL + '"/>';
    s += '<path class="m-rim" stroke-width="2.6" d="' + RIM + '"/>';
    s += '<path class="m-handle" stroke-width="2.5" d="' + HANDLE + '"/>';
    BARS.forEach(function (b) {
      s += '<rect class="m-bar" x="' + b[0] + '" y="' + b[1] + '" width="' + b[2] +
           '" height="' + b[3] + '" rx="1"/>';
    });
    return s;
  }
  function detailMark(size) {
    return '<svg viewBox="0 0 32 32" width="' + size + '" height="' + size +
      '" fill="none" aria-hidden="true" xmlns="' + NS + '">' + detailInner() + '</svg>';
  }

  /* ============================================================
     16px CUTS — viewBox 0 0 16 16. Four candidates for the make-or-break.
       bars3 : direct scale of the master (3 slim bars)   — the smudge risk
       bars2 : reduced to 2 bolder contained bars
       rise  : 2 bars, the tall one BREAKS THE RIM (signal escaping the cup)
       steam : the shipped-equity move — mug + periwinkle steam, no bars
     Cup walls are thicker here (1.7) so the vessel survives the tab.
     ============================================================ */
  var F_WALL   = 'M4.2 5 L4.9 11.2 Q5.05 12.6 6.3 12.6 L9.7 12.6 Q10.95 12.6 11.1 11.2 L11.8 5';
  var F_RIM    = 'M4.2 5 L11.8 5';
  var F_HANDLE = 'M11.9 6.5 C14 6.2 14.3 7.8 14.3 8.5 C14.3 9.2 14 10.9 11.9 10.6';

  function favCup(withRim) {
    var s = '';
    s += '<path class="m-wall" stroke-width="1.7" d="' + F_WALL + '"/>';
    if (withRim) s += '<path class="m-rim" stroke-width="1.7" d="' + F_RIM + '"/>';
    s += '<path class="m-handle" stroke-width="1.6" d="' + F_HANDLE + '"/>';
    return s;
  }
  function favBarsInner(variant) {
    if (variant === 'bars3') {
      return favCup(true) +
        '<rect class="m-bar" x="5.70" y="9.0" width="1.3" height="2.6" rx="0.4"/>' +
        '<rect class="m-bar" x="7.35" y="7.6" width="1.3" height="4.0" rx="0.4"/>' +
        '<rect class="m-bar" x="9.00" y="6.4" width="1.3" height="5.2" rx="0.4"/>';
    }
    if (variant === 'bars2') {
      return favCup(true) +
        '<rect class="m-bar" x="5.9" y="8.6" width="2.1" height="3.0" rx="0.6"/>' +
        '<rect class="m-bar" x="8.3" y="6.4" width="2.1" height="5.2" rx="0.6"/>';
    }
    if (variant === 'steam') {
      // shipped-equity: mug + three periwinkle wavy wisps (no bars)
      return favCup(true) +
        '<path class="m-wisp" stroke-width="1.35" d="M5.4 4.4 C4.3 3.3 6.5 2.4 5.4 1"/>' +
        '<path class="m-wisp" stroke-width="1.35" d="M8 4.7 C6.9 3.5 9.1 2.4 8 0.7"/>' +
        '<path class="m-wisp" stroke-width="1.35" d="M10.6 4.4 C9.5 3.3 11.7 2.4 10.6 1"/>';
    }
    // 'rise' (default) — rim drawn first, tall bar drawn over it so it escapes the cup
    return favCup(true) +
      '<rect class="m-bar" x="5.95" y="8.4" width="2.1" height="3.2" rx="0.6"/>' +
      '<rect class="m-bar" x="8.30" y="3.4" width="2.1" height="8.2" rx="0.7"/>';
  }
  function favMark(size, variant) {
    return '<svg viewBox="0 0 16 16" width="' + size + '" height="' + size +
      '" fill="none" aria-hidden="true" xmlns="' + NS + '">' + favBarsInner(variant) + '</svg>';
  }

  /* ---- hex-baked variants for the data-URI magnifier ---- */
  function favBarsInnerHex(variant, cup, bar) {
    var wall = '<path fill="none" stroke="' + cup + '" stroke-linecap="round" stroke-linejoin="round" stroke-width="1.7" d="' + F_WALL + '"/>' +
               '<path fill="none" stroke="' + cup + '" stroke-linecap="round" stroke-width="1.7" d="' + F_RIM + '"/>' +
               '<path fill="none" stroke="' + cup + '" stroke-linecap="round" stroke-width="1.6" d="' + F_HANDLE + '"/>';
    function b(x, y, w, h, r) { return '<rect fill="' + bar + '" x="' + x + '" y="' + y + '" width="' + w + '" height="' + h + '" rx="' + r + '"/>'; }
    if (variant === 'bars3') return wall + b(5.70, 9.0, 1.3, 2.6, 0.4) + b(7.35, 7.6, 1.3, 4.0, 0.4) + b(9.0, 6.4, 1.3, 5.2, 0.4);
    if (variant === 'bars2') return wall + b(5.9, 8.6, 2.1, 3.0, 0.6) + b(8.3, 6.4, 2.1, 5.2, 0.6);
    if (variant === 'steam') return wall +
      '<path fill="none" stroke="' + bar + '" stroke-linecap="round" stroke-width="1.35" d="M5.4 4.4 C4.3 3.3 6.5 2.4 5.4 1"/>' +
      '<path fill="none" stroke="' + bar + '" stroke-linecap="round" stroke-width="1.35" d="M8 4.7 C6.9 3.5 9.1 2.4 8 0.7"/>' +
      '<path fill="none" stroke="' + bar + '" stroke-linecap="round" stroke-width="1.35" d="M10.6 4.4 C9.5 3.3 11.7 2.4 10.6 1"/>';
    return wall + b(5.95, 8.4, 2.1, 3.2, 0.6) + b(8.30, 3.4, 2.1, 8.2, 0.7);
  }
  function favMarkHex(variant, cup, bar) {
    return '<svg viewBox="0 0 16 16" width="16" height="16" fill="none" xmlns="' + NS + '">' +
      favBarsInnerHex(variant, cup, bar) + '</svg>';
  }

  /* ============================================================
     POPULATE — every .mk slot: data-kind (detail|fav), data-size, data-var
     ============================================================ */
  document.querySelectorAll('.mk').forEach(function (el) {
    var size = parseFloat(el.getAttribute('data-size')) || 32;
    var kind = el.getAttribute('data-kind') || 'detail';
    el.innerHTML = (kind === 'fav')
      ? favMark(size, el.getAttribute('data-var') || 'rise')
      : detailMark(size);
  });

  /* ============================================================
     TRUE-PIXEL MAGNIFIER — rasterise a cut at 16x16, then blit it up
     nearest-neighbour so the actual favicon pixels are visible. This is the
     honest 16px legibility proof (vector upscaling would hide the smudge).
     ============================================================ */
  document.querySelectorAll('canvas.mag').forEach(function (cv) {
    var variant = cv.getAttribute('data-var') || 'rise';
    var theme = cv.getAttribute('data-theme') || 'dark';
    var hx = HEX[theme];
    var scale = cv.width / 16;                    // 128 / 16 = 8x
    var ctx = cv.getContext('2d');
    ctx.imageSmoothingEnabled = false;
    ctx.fillStyle = hx.ink;                        // simulate the tab/ground
    ctx.fillRect(0, 0, cv.width, cv.height);

    var off = document.createElement('canvas');
    off.width = 16; off.height = 16;
    var octx = off.getContext('2d');
    octx.imageSmoothingEnabled = true;             // let the browser antialias INTO 16px (real favicon render)

    var svg = favMarkHex(variant, hx.cup, hx.bar);
    var img = new Image();
    img.onload = function () {
      octx.clearRect(0, 0, 16, 16);
      octx.drawImage(img, 0, 0, 16, 16);
      ctx.imageSmoothingEnabled = false;
      ctx.drawImage(off, 0, 0, 16, 16, 0, 0, cv.width, cv.height);
      // faint pixel grid so the raster is legible as pixels
      ctx.strokeStyle = 'rgba(128,128,128,0.14)';
      ctx.lineWidth = 1;
      for (var i = 1; i < 16; i++) {
        ctx.beginPath(); ctx.moveTo(i * scale + 0.5, 0); ctx.lineTo(i * scale + 0.5, cv.height); ctx.stroke();
        ctx.beginPath(); ctx.moveTo(0, i * scale + 0.5); ctx.lineTo(cv.width, i * scale + 0.5); ctx.stroke();
      }
    };
    img.src = 'data:image/svg+xml;utf8,' + encodeURIComponent(svg);
  });

  /* ============================================================
     BUILD-READY CODE — drop into <pre> via textContent (no HTML injection).
     ============================================================ */
  function setCode(id, txt) { var n = document.getElementById(id); if (n) n.textContent = txt; }

  setCode('code-mark',
'<!-- SOCDESK mark — flat coffee mug + periwinkle bars. Paints ride classes\n' +
'     (chrome.css supplies --m-cup:var(--coffee) and --m-bar:var(--accent)). -->\n' +
'<svg class="cup" viewBox="0 0 32 32" fill="none" aria-hidden="true">\n' +
'  <path class="m-wall"   stroke-width="2.6" d="' + WALL + '"/>\n' +
'  <path class="m-rim"    stroke-width="2.6" d="' + RIM + '"/>\n' +
'  <path class="m-handle" stroke-width="2.5" d="' + HANDLE + '"/>\n' +
'  <rect class="m-bar" x="11.80" y="17.2" width="2.4" height="5.2"  rx="1"/>\n' +
'  <rect class="m-bar" x="15.15" y="13.6" width="2.4" height="8.8"  rx="1"/>\n' +
'  <rect class="m-bar" x="18.50" y="10.6" width="2.4" height="11.8" rx="1"/>\n' +
'</svg>');

  setCode('code-css',
'/* chrome.css — the mark paints. Coffee is mark-only; periwinkle is the\n' +
'   product accent and flips with the theme. No glow, no gradient. */\n' +
'.cup .m-wall,\n' +
'.cup .m-rim,\n' +
'.cup .m-handle { stroke: var(--coffee); fill: none;\n' +
'                 stroke-linecap: round; stroke-linejoin: round; }\n' +
'.cup .m-bar    { fill: var(--accent); }        /* periwinkle, retunes per theme */');

  setCode('code-favicon',
'<!-- favicon.svg — the 16px "rise" cut. Standalone doc, so hexes are baked\n' +
'     and the periwinkle flips via prefers-color-scheme. Zero external refs. -->\n' +
'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" fill="none">\n' +
'  <style>\n' +
'    .cup { stroke:#A6612F }               /* coffee — same on every tab */\n' +
'    .bar { fill:#7C8AFF }                 /* periwinkle — dark tab */\n' +
'    @media (prefers-color-scheme: light){ .bar { fill:#4A4FD0 } }\n' +
'  </style>\n' +
'  <path class="cup" stroke-linecap="round" stroke-linejoin="round" stroke-width="1.7" d="' + F_WALL + '"/>\n' +
'  <path class="cup" stroke-linecap="round" stroke-width="1.7" d="' + F_RIM + '"/>\n' +
'  <path class="cup" stroke-linecap="round" stroke-width="1.6" d="' + F_HANDLE + '"/>\n' +
'  <rect class="bar" x="5.95" y="8.4" width="2.1" height="3.2" rx="0.6"/>\n' +
'  <rect class="bar" x="8.30" y="3.4" width="2.1" height="8.2" rx="0.7"/>\n' +
'</svg>');
})();
