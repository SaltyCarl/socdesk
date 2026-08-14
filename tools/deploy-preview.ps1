# deploy-preview.ps1 — build web/ and deploy it to a Cloudflare Pages PREVIEW
# branch, then run the automated validation. Does NOT touch production.
#
# Prereqs: Node; wrangler auth (run `npx wrangler login` once, or set
# CLOUDFLARE_API_TOKEN + CLOUDFLARE_ACCOUNT_ID env vars). Uses whatever data is
# already in web/public/data/state (production gets fresh data from CI).
#
#   pwsh tools\deploy-preview.ps1
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

if (-not (Test-Path 'web/public/data/state/feed.json')) {
  Write-Host "web/public/data/state is empty — run `python run_pipeline.py` first (needs ABUSECH_API_KEY + IPINFO_TOKEN in env)." -ForegroundColor Red
  exit 1
}

Write-Host "==> Building web/ ..." -ForegroundColor Cyan
npm --prefix web ci
if ($LASTEXITCODE) { exit 1 }
npm --prefix web run build
if ($LASTEXITCODE) { exit 1 }

Write-Host "==> Deploying web/dist to preview branch 'preview-flip' ..." -ForegroundColor Cyan
npx wrangler pages deploy web/dist --project-name=socdesk --branch=preview-flip
if ($LASTEXITCODE) { Write-Host "wrangler deploy failed (auth? run npx wrangler login)" -ForegroundColor Red; exit 1 }

$previewUrl = "https://preview-flip.socdesk.pages.dev"
Write-Host "==> Validating $previewUrl ..." -ForegroundColor Cyan
node tools/verify-deploy.mjs $previewUrl
if ($LASTEXITCODE -ne 0) {
  Write-Host "`nPREVIEW VALIDATION FAILED — do NOT flip production. See failures above." -ForegroundColor Red
  exit 1
}
Write-Host "`nPreview OK + validated: $previewUrl" -ForegroundColor Green
Write-Host "Open it in a browser to eyeball it, then run:  pwsh tools\deploy-production.ps1" -ForegroundColor Green
