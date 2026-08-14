# rollback.ps1 — restore the legacy site/ to production if the flip breaks.
#
# Durable path (uses the same trusted workflow that already deploys production):
# revert the deploy-dir change and re-run. Also restores the legacy sw.js, so no
# zombie-worker issue on the way back.
#
#   pwsh tools\rollback.ps1
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

Write-Host "== FAST rollback (immediate): redeploy legacy site/ from your machine ==" -ForegroundColor Yellow
Write-Host "   npx wrangler pages deploy site --project-name=socdesk --branch=main" -ForegroundColor Yellow
Write-Host "   (--branch must equal the project's production branch)`n"

$ok = Read-Host "Run the DURABLE rollback now (revert the flip commit + push + redeploy site via CI)? [y/N]"
if ($ok -ne 'y') { Write-Host "No action taken. Use the fast command above if you need an immediate restore."; exit 0 }

Write-Host "==> Reverting the deploy-dir flip (bf045ba) ..." -ForegroundColor Cyan
git revert --no-edit bf045ba
git push origin main
gh workflow run collect-and-deploy.yml
Write-Host "Reverted: the workflow now deploys site/ again. Watch: gh run watch" -ForegroundColor Green
