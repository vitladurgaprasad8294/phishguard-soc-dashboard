# Helper script to push PhishGuard to GitHub.
# Run from the phishguard folder:
#   .\push_to_github.ps1

$ErrorActionPreference = "Stop"

Set-Location $PSScriptRoot

Write-Host ""
Write-Host "PhishGuard GitHub Push Helper" -ForegroundColor Cyan
Write-Host ""

$git = Get-Command git -ErrorAction SilentlyContinue
if (-not $git) {
    Write-Host "Git is not installed or not in PATH." -ForegroundColor Red
    Write-Host "Install Git for Windows, then run this again." -ForegroundColor Red
    exit 1
}

if (!(Test-Path ".git")) {
    git init
}

git add .

try {
    git commit -m "Prepare PhishGuard SOC dashboard for deployment"
} catch {
    Write-Host "Nothing new to commit or commit failed. Continuing..." -ForegroundColor Yellow
}

git branch -M main

$existingRemote = ""
try {
    $existingRemote = git remote get-url origin
} catch {}

if (-not $existingRemote) {
    $remoteUrl = Read-Host "Paste your GitHub repository URL, e.g. https://github.com/YOUR_USERNAME/phishguard-soc-dashboard.git"
    git remote add origin $remoteUrl
} else {
    Write-Host "Existing origin remote: $existingRemote" -ForegroundColor Green
}

git push -u origin main

Write-Host ""
Write-Host "Push complete." -ForegroundColor Green
