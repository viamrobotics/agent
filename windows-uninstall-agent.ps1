# Viam Agent Uninstall Script for Windows
# Removes viam service, directories, firewall rules, and event log source.
[CmdletBinding()]
param(
    [switch]$Silent = $false,
    [string]$RootPath = "C:\opt\viam",
    [switch]$ServiceAccount = $false  # if set, reverts BFE DACL changes for virtual service account
)

$ErrorActionPreference = 'Stop'

# Remove a previously-added ACE from a Windows service's DACL.
function Remove-ServiceDaclAce {
    param([string]$ServiceName, [string]$Account, [string]$AccessMask)

    $sid = (New-Object System.Security.Principal.NTAccount($Account)).Translate(
        [System.Security.Principal.SecurityIdentifier]).Value
    $currentSD = ((& sc.exe sdshow $ServiceName) | Where-Object { $_ -match '^D:' })
    if (-not $currentSD) {
        Write-Warning "Failed to read DACL for service $ServiceName"
        return
    }
    $ace = "(A;;$AccessMask;;;$sid)"
    if ($currentSD -notmatch [regex]::Escape($ace)) { return }  # not present
    $newSD = $currentSD -replace [regex]::Escape($ace), ""
    & sc.exe sdset $ServiceName $newSD | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Failed to set DACL on service $ServiceName"
    }
}

# Check for admin privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    if (-not $Silent) {
        Write-Host "This script requires administrator privileges. Attempting to elevate..."
    }
    $scriptPath = $MyInvocation.MyCommand.Path
    $elevateArgs = "-ExecutionPolicy Bypass -File `"$scriptPath`" -Silent -RootPath `"$RootPath`""
    if ($ServiceAccount) { $elevateArgs += " -ServiceAccount" }
    Start-Process powershell.exe -ArgumentList $elevateArgs -Verb RunAs
    exit
}

if (-not $Silent) {
    Write-Host ""
    Write-Host "This script removes the viam-agent service, its directories, firewall rules,"
    Write-Host "and event log source."
    Write-Host ""
    Write-Host "  Root path: $RootPath"
    Write-Host ""

    $confirm = Read-Host "Remove viam-agent and all associated files? (y/n)"
    if ($confirm -ne "y") {
        Write-Host "Uninstall cancelled."
        exit 0
    }
}

# Stop and remove service
$serviceExists = Get-Service -Name "viam-agent" -ErrorAction SilentlyContinue
if ($serviceExists) {
    if (-not $Silent) { Write-Host "Stopping viam-agent service..." }
    Stop-Service -Name "viam-agent" -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2

    if (-not $Silent) { Write-Host "Deleting viam-agent service..." }
    & sc.exe delete "viam-agent" | Out-Null
    Start-Sleep -Seconds 2
    if (-not $Silent) { Write-Host "  Service removed." }
} else {
    if (-not $Silent) { Write-Host "Service viam-agent not found, skipping." }
}

# Remove firewall rule
if (-not $Silent) { Write-Host "Removing firewall rule..." }
Remove-NetFirewallRule -Name "viam-agent" -ErrorAction SilentlyContinue

# Remove event log source
if (-not $Silent) { Write-Host "Removing event log source..." }
Remove-EventLog -Source "viam-agent" -ErrorAction SilentlyContinue

# Revert BFE service DACL changes if -ServiceAccount was used during install
if ($ServiceAccount) {
    if (-not $Silent) { Write-Host "Reverting BFE firewall management rights..." }
    Remove-ServiceDaclAce -ServiceName "BFE" -Account "NT SERVICE\viam-agent" -AccessMask "CCLCRPWPRC"
}

# Remove viam directory tree
if (Test-Path $RootPath) {
    if (-not $Silent) { Write-Host "Removing $RootPath..." }
    Remove-Item -Path $RootPath -Recurse -Force
    if (-not $Silent) { Write-Host "  Removed $RootPath" }
} else {
    if (-not $Silent) { Write-Host "$RootPath does not exist, skipping." }
}

if (-not $Silent) {
    Write-Host ""
    Write-Host "Uninstall complete."
}
