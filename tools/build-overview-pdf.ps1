# Regenerate docs/SOCDesk-Overview.pdf from the HTML via headless Chrome/Edge.
# Uses a fresh unique --user-data-dir (avoids the profile-collision hang) and
# --headless=new (no --virtual-time-budget, which conflicts with it).
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$src  = Join-Path $root 'docs\SOCDesk-Overview.html'
$out  = Join-Path $root 'docs\SOCDesk-Overview.pdf'
$candidates = @(
  "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
  "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe",
  "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
  "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
)
$browser = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $browser) { throw "No Chrome/Edge found for print-to-pdf" }
$udd = Join-Path $env:TEMP ("cr-pdf-" + [guid]::NewGuid().ToString('N'))
$uri = "file:///" + ($src -replace '\\','/')
# Chrome logs the byte count to stderr; don't let that terminate the script.
$prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
& $browser --headless=new --disable-gpu --no-pdf-header-footer --print-to-pdf="$out" --user-data-dir="$udd" $uri 2>$null | Out-Null
$ErrorActionPreference = $prev
Start-Sleep -Milliseconds 600
Remove-Item -Recurse -Force $udd -ErrorAction SilentlyContinue
if (Test-Path $out) { "PDF regenerated: $((Get-Item $out).Length) bytes ($browser)" } else { throw "PDF regen produced no output" }
