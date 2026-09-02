# deploy.ps1 — Windows One-Click Automated Deployment Script
param (
    [string]$Target = "all", # "all", "server", "agent"
    [string]$ServerURL = "http://localhost:8000"
)

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "       JOCKY FORENSIC FRAMEWORK — AUTOMATED DEPLOYMENT    " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Check Python
$py = Get-Command python -ErrorAction SilentlyContinue
if (-not $py) {
    Write-Host "[ERROR] Python 3 is not installed or not in PATH." -ForegroundColor Red
    exit 1
}

# 2. Install / Verify Requirements
Write-Host "[1/3] Verifying and installing dependencies..." -ForegroundColor Yellow
python -m pip install --quiet --upgrade pip
python -m pip install --quiet -r requirements.txt

# 3. Run Automated Tests
Write-Host "[2/3] Executing CI validation test suite..." -ForegroundColor Yellow
python tests/test_pipeline.py
if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERROR] CI Tests failed! Aborting deployment." -ForegroundColor Red
    exit 1
}
Write-Host "  ✓ All CI validation tests passed successfully." -ForegroundColor Green

# 4. Deployment Actions
Write-Host "[3/3] Deploying services (Target: $Target)..." -ForegroundColor Yellow

if ($Target -eq "all" -or $Target -eq "server") {
    Write-Host "  -> Starting JOCKY Central Management Server on port 8000..." -ForegroundColor Cyan
    Start-Process python -ArgumentList "backend/server.py" -WindowStyle Normal
    Start-Sleep -Seconds 2
}

if ($Target -eq "all" -or $Target -eq "agent") {
    Write-Host "  -> Starting JOCKY Target Agent on port 5000..." -ForegroundColor Cyan
    $env:JOCKY_SERVER_URL = $ServerURL
    Start-Process python -ArgumentList "agent/agent.py" -WindowStyle Normal
    Start-Sleep -Seconds 2
}

Write-Host "`n==========================================================" -ForegroundColor Green
Write-Host "  [DEPLOYMENT SUCCESSFUL] All services running!" -ForegroundColor Green
Write-Host "  • Management Console : http://localhost:8000" -ForegroundColor White
Write-Host "  • Target Agent       : http://localhost:5000" -ForegroundColor White
Write-Host "  • Frontend Dashboard : frontend/index.html" -ForegroundColor White
Write-Host "==========================================================" -ForegroundColor Green
