# deploy-production.ps1 — flip socdesk.io to the new web/ app: push main, trigger
# the deploy workflow, watch it, then validate production. Run ONLY after
# deploy-preview.ps1 passed AND the preview looked right in a browser.
#
# Prereqs: git push access; gh CLI authed (`gh auth status`); Node.
#
#   pwsh tools\deploy-production.ps1
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

Write-Host "This pushes origin/main and flips PRODUCTION (socdesk.io) to web/." -ForegroundColor Yellow
$ok = Read-Host "Type 'flip' to proceed"
if ($ok -ne 'flip') { Write-Host "Aborted."; exit 1 }

Write-Host "==> Pushing origin/main ..." -ForegroundColor Cyan
git push origin main
if ($LASTEXITCODE) { exit 1 }

Write-Host "==> Triggering collect-and-deploy ..." -ForegroundColor Cyan
gh workflow run collect-and-deploy.yml
if ($LASTEXITCODE) { Write-Host "gh workflow run failed (gh auth?)" -ForegroundColor Red; exit 1 }
Start-Sleep -Seconds 10

$runId = gh run list --workflow=collect-and-deploy.yml --limit 1 --json databaseId --jq '.[0].databaseId'
Write-Host "==> Watching run $runId (build + deploy, a few minutes) ..." -ForegroundColor Cyan
gh run watch $runId --exit-status
if ($LASTEXITCODE) { Write-Host "Deploy run FAILED. Roll back with:  pwsh tools\rollback.ps1" -ForegroundColor Red; exit 1 }

Write-Host "==> Validating https://socdesk.io ..." -ForegroundColor Cyan
node tools/verify-deploy.mjs https://socdesk.io
if ($LASTEXITCODE -ne 0) {
  Write-Host "`nPRODUCTION VALIDATION FAILED — roll back with:  pwsh tools\rollback.ps1" -ForegroundColor Red
  exit 1
}
Write-Host "`nFlipped + verified: https://socdesk.io is now the new app." -ForegroundColor Green
Write-Host "In a browser that had the OLD site, hard-navigate once to let the sw.js tombstone replace the legacy service worker." -ForegroundColor Green
