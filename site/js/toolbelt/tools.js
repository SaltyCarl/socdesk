// tools.js — client-side analyst utilities for the SOCDESK toolbelt.
//
// SNAPSHOT PORT from CARL (`CARL/src/carl-tools.js`, taken 2026-08-07).
// Public-data utilities ONLY: IOC extraction, defang/refang, Base64 decoding,
// PowerShell command-line parsing, and the LOLBin reference table. Nothing
// client-aware, tenant-aware, or employer-specific was carried over, and this
// is a COPY — SOCDESK does not depend on CARL and CARL does not depend on this.
//
// This module MUST stay dependency-free: no imports, no build step, no network
// access. Everything below runs entirely in the browser on text the user pasted.

// ─────────────────────────────────────────────────────────────────────────
// IOC EXTRACTION
// ─────────────────────────────────────────────────────────────────────────

/** Regex patterns for IOC extraction. Exported so they can be tested directly. */
export const patterns = {
  ipv4:   /\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b/g,
  md5:    /\b[a-fA-F0-9]{32}\b/g,
  sha1:   /\b[a-fA-F0-9]{40}\b/g,
  sha256: /\b[a-fA-F0-9]{64}\b/g,
  email:  /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g,
  url:    /\bhttps?:\/\/[^\s<>"')\]]+/gi,
  // SOCDESK addition (not in the CARL original): CVE IDs are the spine of this
  // product's corpus, so the extractor surfaces them alongside the other IOCs.
  cve:    /\bCVE-\d{4}-\d{4,7}\b/gi,
  // Domain: word chars + dots + TLD, excluding IPs and pure numbers
  domain: /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+(?:com|net|org|io|gov|edu|mil|co|uk|de|fr|ru|cn|br|in|au|ca|nl|it|es|ch|se|no|fi|jp|kr|za|mx|ar|info|biz|us|tv|me|xyz|top|club|online|site|store|tech|dev|app|cloud|security)\b/gi
};

/**
 * Extract all IOC types from freeform text.
 * @param {string} text - raw text to scan
 * @returns {Object} { ips:[], domains:[], md5s:[], sha1s:[], sha256s:[], urls:[], emails:[], cves:[] }
 */
export function extractIOCs(text) {
  if (!text || typeof text !== 'string') {
    return { ips: [], domains: [], md5s: [], sha1s: [], sha256s: [], urls: [], emails: [], cves: [] };
  }

  var result = {
    ips:     [],
    domains: [],
    md5s:    [],
    sha1s:   [],
    sha256s: [],
    urls:    [],
    emails:  [],
    cves:    []
  };

  // Helper: deduplicated match collection
  function collect(pattern, arr) {
    var m;
    // Reset lastIndex for global regex
    pattern.lastIndex = 0;
    var seen = {};
    while ((m = pattern.exec(text)) !== null) {
      var val = m[0].toLowerCase();
      if (!seen[val]) {
        seen[val] = true;
        arr.push(m[0]);
      }
    }
  }

  // Order matters: extract longer hashes first so sha256 matches
  // are not partially consumed by sha1/md5
  collect(patterns.sha256, result.sha256s);
  collect(patterns.sha1, result.sha1s);
  collect(patterns.md5, result.md5s);

  // Remove sha1 values that are substrings of sha256, md5 substrings of sha1
  var sha256Lower = result.sha256s.map(function(h) { return h.toLowerCase(); });
  var sha1Lower = result.sha1s.map(function(h) { return h.toLowerCase(); });

  result.sha1s = result.sha1s.filter(function(h) {
    var low = h.toLowerCase();
    for (var i = 0; i < sha256Lower.length; i++) {
      if (sha256Lower[i].indexOf(low) !== -1) return false;
    }
    return true;
  });

  result.md5s = result.md5s.filter(function(h) {
    var low = h.toLowerCase();
    for (var i = 0; i < sha256Lower.length; i++) {
      if (sha256Lower[i].indexOf(low) !== -1) return false;
    }
    for (var j = 0; j < sha1Lower.length; j++) {
      if (sha1Lower[j].indexOf(low) !== -1) return false;
    }
    return true;
  });

  collect(patterns.ipv4, result.ips);
  collect(patterns.url, result.urls);
  collect(patterns.email, result.emails);
  collect(patterns.cve, result.cves);

  // Domains: extract and exclude IPs, emails' domain parts already covered
  collect(patterns.domain, result.domains);

  // Filter domains that are just IP addresses or part of already-extracted URLs
  var ipSet = {};
  for (var i = 0; i < result.ips.length; i++) { ipSet[result.ips[i]] = true; }
  result.domains = result.domains.filter(function(d) { return !ipSet[d]; });

  // Deduplicate domains (case-insensitive)
  var domainSeen = {};
  result.domains = result.domains.filter(function(d) {
    var low = d.toLowerCase();
    if (domainSeen[low]) return false;
    domainSeen[low] = true;
    return true;
  });

  return result;
}

// ─────────────────────────────────────────────────────────────────────────
// DEFANG / REFANG — safe-format IOCs for sharing in tickets, email, chat.
// ─────────────────────────────────────────────────────────────────────────

/**
 * Defang text: make IOCs safe for sharing (non-clickable).
 * IP:    1.1.1.1       -> 1.1.1[.]1
 * URL:   https://evil  -> hxxps[://]evil[.]com
 * Email: a@b.com       -> a[@]b[.]com
 * @param {string} text
 * @returns {string} defanged text
 */
export function defang(text) {
  if (!text || typeof text !== 'string') return '';

  // Defang URLs: http(s):// -> hxxp(s)://
  var result = text.replace(/https?:\/\//gi, function(match) {
    return match.replace(/http/i, function(h) {
      return h.charAt(0) + 'xx' + h.charAt(3);
    }).replace(':\/\/', '[://]');
  });

  // Defang email addresses: user@domain.com -> user[@]domain[.]com
  result = result.replace(/([A-Za-z0-9._%+\-]+)@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})/g, function(match, local, domain) {
    return local + '[@]' + domain.replace(/\./g, '[.]');
  });

  // Defang remaining IPs: 1.1.1.1 -> 1.1.1[.]1 (replace last dot)
  result = result.replace(/\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b/g, function(match, a, b, c, d) {
    // Validate it's a plausible IP
    var parts = [parseInt(a), parseInt(b), parseInt(c), parseInt(d)];
    for (var i = 0; i < 4; i++) {
      if (parts[i] > 255) return match; // not a valid IP, leave as-is
    }
    return a + '.' + b + '.' + c + '[.]' + d;
  });

  // Defang remaining bare domains (common TLDs)
  result = result.replace(/\b([a-zA-Z0-9\-]+)\.(com|net|org|io|gov|edu|co\.uk|ru|cn)\b/gi, function(match, name, tld) {
    // Don't double-defang if already has [.]
    if (match.indexOf('[.]') !== -1) return match;
    return name + '[.]' + tld;
  });

  return result;
}

/**
 * Refang text: restore defanged IOCs to their original form.
 * Reverses defang() transformations.
 * @param {string} text
 * @returns {string} refanged text
 */
export function refang(text) {
  if (!text || typeof text !== 'string') return '';

  var result = text;

  // Restore hxxp(s) -> http(s)
  result = result.replace(/hxxps?/gi, function(match) {
    return match.replace(/xx/i, 'tt');
  });

  // Restore [://] -> ://
  result = result.replace(/\[:\/\/\]/g, '://');

  // Restore [@] -> @
  result = result.replace(/\[@\]/g, '@');

  // Restore [.] -> .
  result = result.replace(/\[\.\]/g, '.');

  return result;
}

// ─────────────────────────────────────────────────────────────────────────
// POWERSHELL / LOLBIN DEOBFUSCATOR
// Command-line parser, flag resolver, risk scorer, UTF-16LE Base64 decoder,
// and the LOLBin reference table.
// ─────────────────────────────────────────────────────────────────────────

/**
 * PowerShell.exe parameter alias map — normalizes short/alternate flags
 * to their canonical form for consistent risk scoring.
 */
export const PS_FLAG_MAP = {
  '-enc':'-EncodedCommand','-encodedcommand':'-EncodedCommand','-ec':'-EncodedCommand','-e':'-EncodedCommand',
  '-ep':'-ExecutionPolicy','-executionpolicy':'-ExecutionPolicy',
  '-nop':'-NoProfile','-noprofile':'-NoProfile',
  '-noni':'-NonInteractive','-noninteractive':'-NonInteractive',
  '-nol':'-NoLogo','-nologo':'-NoLogo',
  '-noe':'-NoExit','-noexit':'-NoExit',
  '-w':'-WindowStyle','-windowstyle':'-WindowStyle',
  '-sta':'-Sta',
  '-c':'-Command','-command':'-Command',
  '-f':'-File','-file':'-File'
};

/**
 * Risk-scored PowerShell flags — each resolved flag is looked up here
 * to determine if it contributes to overall command risk.
 */
export const PS_RISK_FLAGS = {
  '-EncodedCommand':{risk:'HIGH',desc:'Executes Base64-encoded command — commonly used to bypass logging and obfuscate payloads'},
  '-ExecutionPolicy Bypass':{risk:'HIGH',desc:'Bypasses script execution restrictions'},
  '-ExecutionPolicy Unrestricted':{risk:'HIGH',desc:'Allows all scripts to run without restriction'},
  '-WindowStyle Hidden':{risk:'HIGH',desc:'Hides the PowerShell window — strong indicator of malicious automation'},
  '-NoProfile':{risk:'MEDIUM',desc:'Skips loading user profile scripts — reduces execution footprint'},
  '-NonInteractive':{risk:'MEDIUM',desc:'Suppresses prompts — script runs without user interaction'},
  '-NoLogo':{risk:'LOW',desc:'Hides startup banner — minor evasion indicator'},
  '-Sta':{risk:'LOW',desc:'Single-threaded apartment — sometimes used with COM objects'},
  '-NoExit':{risk:'LOW',desc:'Keeps shell open after execution — can indicate persistence'}
};

/**
 * LOLBin risk database — 33 Living-off-the-Land binaries with MITRE mapping,
 * risk level, known suspicious flags, and descriptions.
 * (The CARL original's comment says 34; the table has always held 33. Entries
 * are copied byte-for-byte and verified deep-equal against the source.)
 */
export const LOLBIN_DB = {
  'regsvr32':{risk:'HIGH',mitre:'T1218.010',desc:'Signed Binary Proxy Execution via regsvr32. Can load remote scriptlets (.sct) to bypass AppLocker.',flags:{'/s':'Silent mode','/n':'Do not call DllRegisterServer','/u':'Unregister','/i':'Install — accepts URL for remote scriptlet loading'}},
  'mshta':{risk:'HIGH',mitre:'T1218.005',desc:'Executes .HTA files or inline JavaScript/VBScript. Trusted Microsoft binary that bypasses application control.',flags:{}},
  'certutil':{risk:'HIGH',mitre:'T1140',desc:'Certificate utility abused for downloading files and Base64 decoding.',flags:{'-urlcache':'Download file from URL','-split':'Write downloaded content to disk','-decode':'Base64 decode a file','-encode':'Base64 encode a file','-f':'Force overwrite'}},
  'rundll32':{risk:'MEDIUM',mitre:'T1218.011',desc:'Loads and executes DLL export functions. Abused to proxy execution via legitimate DLLs.',flags:{}},
  'msbuild':{risk:'HIGH',mitre:'T1127.001',desc:'Builds and executes C#/VB project files. Can compile and run inline code, bypassing application control.',flags:{}},
  'bitsadmin':{risk:'MEDIUM',mitre:'T1197',desc:'Background Intelligent Transfer Service — abused to download files stealthily.',flags:{'/transfer':'Start a file transfer','/create':'Create a download job','/addfile':'Add file URL to job','/resume':'Resume a paused job','/complete':'Finalize a job'}},
  'cmstp':{risk:'HIGH',mitre:'T1218.003',desc:'Connection Manager Profile Installer — can be abused to execute arbitrary commands via .inf files.',flags:{'/s':'Silent install','/ns':'No silent','/au':'Auto install'}},
  'wmic':{risk:'MEDIUM',mitre:'T1047',desc:'Windows Management Instrumentation command-line. Can execute processes, query system info, and interact with remote hosts.',flags:{'process call create':'Execute a new process','os get':'Get OS information','/node:':'Target remote host'}},
  'cscript':{risk:'MEDIUM',mitre:'T1059.005',desc:'Command-line script host for VBScript/JScript execution.',flags:{'//b':'Batch mode (no alerts)','/nologo':'Suppress logo'}},
  'wscript':{risk:'MEDIUM',mitre:'T1059.005',desc:'Windows-based script host for VBScript/JScript execution.',flags:{'//b':'Batch mode','/nologo':'Suppress logo'}},
  'installutil':{risk:'HIGH',mitre:'T1218.004',desc:'.NET Installation utility — can execute code via custom installer classes, bypassing application control.',flags:{'/logfile=':'Specify log file','/LogToConsole=false':'Suppress console output'}},
  'schtasks':{risk:'MEDIUM',mitre:'T1053.005',desc:'Schedule tasks for persistence or execution.',flags:{'/create':'Create new task','/sc':'Schedule frequency','/tn':'Task name','/tr':'Command to run','/ru':'Run-as user','/rl':'Run level (HIGHEST)'}},
  'powershell':{risk:'MEDIUM',mitre:'T1059.001',desc:'PowerShell interpreter — risk depends on flags and payload.',flags:{}},
  'pwsh':{risk:'MEDIUM',mitre:'T1059.001',desc:'PowerShell 7+ (cross-platform) interpreter.',flags:{}},
  'forfiles':{risk:'HIGH',mitre:'T1202',desc:'Selects and executes commands on files. Abused to execute arbitrary commands via /c flag, bypassing application whitelisting.',flags:{'/c':'Command to execute for each file — can run arbitrary binaries','/p':'Starting path — often C:\\Windows to guarantee a file match','/m':'Search mask — often *.* to guarantee a match'}},
  'pcalua':{risk:'HIGH',mitre:'T1202',desc:'Program Compatibility Assistant helper. Executes arbitrary binaries via -a flag, bypassing application whitelisting with no visible window.',flags:{'-a':'Executable to launch — primary abuse vector'}},
  'msiexec':{risk:'HIGH',mitre:'T1218.007',desc:'Windows Installer. Installs .msi packages from remote URLs, enabling download and execution of malicious payloads.',flags:{'/i':'Install package — accepts URLs for remote payloads','/q':'Quiet mode — suppresses all UI','/y':'Register DLLs, similar to regsvr32 abuse'}},
  'hh':{risk:'HIGH',mitre:'T1218.001',desc:'HTML Help executable. Opens .chm files which can contain and execute embedded scripts, ActiveX, or shortcut commands.',flags:{'-decompile':'Extract .chm contents to disk — can drop embedded payloads'}},
  'mavinject':{risk:'HIGH',mitre:'T1055.001',desc:'Microsoft Application Virtualization Injector. Injects DLLs into running processes.',flags:{'/INJECTRUNNING':'Triggers DLL injection into specified running process'}},
  'diskshadow':{risk:'HIGH',mitre:'T1218',desc:'Disk shadow copy utility. Executes commands from a script file, can run arbitrary binaries in SYSTEM context.',flags:{'/s':'Execute commands from script file','exec':'Run arbitrary command within diskshadow script'}},
  'dnscmd':{risk:'HIGH',mitre:'T1543.003',desc:'DNS Server management CLI. Configures DNS server to load arbitrary DLLs as serverlevelplugindll, achieving SYSTEM-level code execution.',flags:{'/config /serverlevelplugindll':'Load arbitrary DLL into DNS service (SYSTEM context)'}},
  'syncappvpublishingserver':{risk:'HIGH',mitre:'T1218',desc:'App-V publishing server sync utility. Passes arguments directly to PowerShell for execution, bypassing constrained language mode.',flags:{}},
  'ftp':{risk:'MEDIUM',mitre:'T1202',desc:'Built-in FTP client. Executes commands from a script file via -s flag. The ! escape character runs local OS commands.',flags:{'-s':'Read commands from script file','!':'Execute local OS commands from within FTP'}},
  'esentutl':{risk:'MEDIUM',mitre:'T1105',desc:'Extensible Storage Engine utility. Copies files using raw operations, abused as alternate file copy. Can extract locked files like NTDS.dit via /vss.',flags:{'/y':'Copy file using raw operations','/vss':'Access Volume Shadow Copy — extract locked files like NTDS.dit or SAM','/d':'Destination file path'}},
  'msdeploy':{risk:'MEDIUM',mitre:'T1218',desc:'IIS Web Deploy tool. Can execute arbitrary commands via the runCommand provider.',flags:{'-source:runCommand':'Execute arbitrary OS command on target system'}},
  'expand':{risk:'MEDIUM',mitre:'T1140',desc:'Expands compressed CAB files. Used to extract payloads from CAB archives bypassing security tools that do not inspect CAB contents.',flags:{'-I':'Do not treat as CAB','-R':'Rename extracted files'}},
  'extrac32':{risk:'MEDIUM',mitre:'T1105',desc:'CAB extraction utility. Abused as alternate file copy/extraction mechanism to bypass monitoring.',flags:{'/Y':'Overwrite without prompting','/C':'Copy a single file from CAB'}},
  'finger':{risk:'MEDIUM',mitre:'T1105',desc:'Finger protocol client. Downloads data from remote servers. Abused as alternate download cradle to retrieve payloads.',flags:{}},
  'replace':{risk:'MEDIUM',mitre:'T1105',desc:'File replacement utility. Copies files to directories, abused to place malicious binaries in trusted paths.',flags:{'/a':'Add new files to destination'}},
  'infdefaultinstall':{risk:'HIGH',mitre:'T1218',desc:'INF file installer. Executes commands in .inf files including DLL registration, registry changes, and binary execution.',flags:{}},
  'ieexec':{risk:'HIGH',mitre:'T1218',desc:'.NET Framework executable that downloads and executes remote binaries from a URL argument. Rarely used legitimately.',flags:{}},
  'xwizard':{risk:'HIGH',mitre:'T1218',desc:'Extensible wizard host. Loads arbitrary COM objects by CLSID, enabling DLL execution via COM hijacking.',flags:{'RunWizard':'Load and execute COM object by CLSID'}},
  'presentationhost':{risk:'MEDIUM',mitre:'T1218',desc:'XAML Browser Application host. Executes .xbap files which can contain arbitrary .NET code.',flags:{}}
};

/**
 * Decode Base64 encoded PowerShell payload (UTF-16LE — -EncodedCommand format).
 * @param {string} encoded - Base64 string
 * @returns {string|null} decoded UTF-16LE text, or null on failure
 */
export function psDecodeBase64(encoded) {
  try {
    var raw = atob(encoded);
    // UTF-16LE: every other byte is the character (for ASCII range)
    var decoded = '';
    for (var i = 0; i < raw.length; i += 2) {
      var charCode = raw.charCodeAt(i) | (raw.charCodeAt(i + 1) << 8);
      if (charCode === 0) continue;
      decoded += String.fromCharCode(charCode);
    }
    return decoded.trim();
  } catch(e) { return null; }
}

/**
 * Decode a Base64 blob of unknown encoding. Tries the PowerShell UTF-16LE
 * convention first; if the result is not clean printable ASCII, falls back to
 * a UTF-8 decode. SOCDESK addition — the toolbelt takes arbitrary pasted Base64,
 * not just -EncodedCommand payloads.
 * @param {string} s
 * @returns {{ text: string, encoding: string }|null}
 */
export function smartDecodeBase64(s) {   // try UTF-16LE first, fall back to UTF-8
  const clean = String(s || "").trim().replace(/\s+/g, "");
  if (!clean) return null;
  const utf16 = psDecodeBase64(clean);
  if (utf16 && /^[\x09\x0a\x0d\x20-\x7e]+$/.test(utf16)) return { text: utf16, encoding: "UTF-16LE" };
  try {
    return { text: new TextDecoder().decode(Uint8Array.from(atob(clean), c => c.charCodeAt(0))),
             encoding: "UTF-8" };
  } catch { return null; }
}

/**
 * Parse a powershell.exe / pwsh.exe command line into structured flags + payload.
 * Tokenizes respecting quotes, resolves flag aliases via PS_FLAG_MAP,
 * scores risk via PS_RISK_FLAGS, decodes -EncodedCommand if present.
 * @param {string} cmdline - full command line string
 * @returns {{ binary: string, flags: Array, encodedPayload: string|null, decodedPayload: string|null, rawCommand: string|null, risk: string, riskReasons: Array, mitre: Array }}
 */
export function psParseCommandLine(cmdline) {
  var result = { binary: null, flags: [], encodedPayload: null, decodedPayload: null, rawCommand: null, risk: 'LOW', riskReasons: [], mitre: [] };

  // Tokenize — respect quotes
  var tokens = [];
  var current = '', inQuote = false, quoteChar = '';
  for (var i = 0; i < cmdline.length; i++) {
    var c = cmdline[i];
    if ((c === '"' || c === "'") && !inQuote) { inQuote = true; quoteChar = c; continue; }
    if (c === quoteChar && inQuote) { inQuote = false; tokens.push(current); current = ''; continue; }
    if (c === ' ' && !inQuote && current.length > 0) { tokens.push(current); current = ''; continue; }
    if (c !== ' ' || inQuote) current += c;
  }
  if (current.length > 0) tokens.push(current);

  if (tokens.length === 0) return result;

  // Identify binary
  result.binary = tokens[0].toLowerCase().replace(/\.exe$/, '').replace(/^.*[\\\/]/, '');

  // Parse flags
  var fi = 1;
  while (fi < tokens.length) {
    var token = tokens[fi];

    // Check if it's a flag
    if (token.startsWith('-') || token.startsWith('/')) {
      var normalized = token.startsWith('/') ? '-' + token.substring(1) : token;
      var normalizedLower = normalized.toLowerCase();

      // Resolve alias
      var resolved = PS_FLAG_MAP[normalizedLower] || normalized;

      // Check for flag+value pairs
      var value = null;
      if (resolved === '-EncodedCommand' && fi + 1 < tokens.length) {
        value = tokens[fi + 1]; fi++;
        result.encodedPayload = value;
        result.decodedPayload = psDecodeBase64(value);
      } else if (resolved === '-ExecutionPolicy' && fi + 1 < tokens.length) {
        value = tokens[fi + 1]; fi++;
        resolved = resolved + ' ' + value;
      } else if (resolved === '-WindowStyle' && fi + 1 < tokens.length) {
        value = tokens[fi + 1]; fi++;
        resolved = resolved + ' ' + value;
      } else if (resolved === '-Command' && fi + 1 < tokens.length) {
        // Everything after -Command is the command text
        result.rawCommand = tokens.slice(fi + 1).join(' ');
        fi = tokens.length;
      } else if (resolved === '-File' && fi + 1 < tokens.length) {
        value = tokens[fi + 1]; fi++;
        resolved = resolved + ' ' + value;
      }

      result.flags.push({ raw: token, resolved: resolved, value: value });

      // Check risk.
      // SOCDESK FIX (deliberate divergence from the CARL snapshot): the original
      // lookup is case-sensitive on the flag VALUE, so the overwhelmingly
      // common real-world `-w hidden` resolves to "-WindowStyle hidden" and
      // misses the "-WindowStyle Hidden" HIGH entry — under-scoring the single
      // most-used evasion flag. Match case-insensitively instead.
      var riskEntry = PS_RISK_FLAGS[resolved];
      if (!riskEntry) {
        var wanted = String(resolved).toLowerCase();
        for (var rk in PS_RISK_FLAGS) {
          if (rk.toLowerCase() === wanted) { riskEntry = PS_RISK_FLAGS[rk]; break; }
        }
      }
      if (riskEntry) {
        result.riskReasons.push({ flag: resolved, risk: riskEntry.risk, desc: riskEntry.desc });
        if (riskEntry.risk === 'HIGH' && result.risk !== 'HIGH') result.risk = 'HIGH';
        else if (riskEntry.risk === 'MEDIUM' && result.risk === 'LOW') result.risk = 'MEDIUM';
      }
    } else {
      // Non-flag token — might be part of command
      if (!result.rawCommand) result.rawCommand = tokens.slice(fi).join(' ');
      break;
    }
    fi++;
  }

  // MITRE mapping
  result.mitre.push('T1059.001'); // PowerShell execution
  if (result.encodedPayload) result.mitre.push('T1027'); // Obfuscated Files
  // case-insensitive for the same reason as the risk lookup above
  if (result.flags.some(function(f) {
    return String(f.resolved).toLowerCase().indexOf('hidden') !== -1;
  })) result.mitre.push('T1564'); // Hide Artifacts

  return result;
}

/**
 * Analyze a LOLBin command line: identify binary, match known flags,
 * return structured result with risk and MITRE mapping.
 * @param {string} cmdline - full command line string
 * @returns {{ binary: string, entry: Object, flagsFound: Array, fullCommand: string }|null}
 */
export function lolbinAnalyze(cmdline) {
  var tokens = cmdline.trim().split(/\s+/);
  if (tokens.length === 0) return null;
  var binary = tokens[0].toLowerCase().replace(/\.exe$/, '').replace(/^.*[\\\/]/, '');
  const db = LOLBIN_DB;
  var entry = db[binary];
  if (!entry) return null;

  var flagsFound = [];
  var cmdLower = cmdline.toLowerCase();
  for (var flag in entry.flags) {
    if (cmdLower.indexOf(flag.toLowerCase()) !== -1) {
      flagsFound.push({ flag: flag, desc: entry.flags[flag] });
    }
  }

  return { binary: binary, entry: entry, flagsFound: flagsFound, fullCommand: cmdline };
}
