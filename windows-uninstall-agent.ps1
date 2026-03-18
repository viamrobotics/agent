# Viam Agent Uninstall Script for Windows
# Removes viam service, directories, firewall rules, event log source, and optionally the service account.
[CmdletBinding()]
param(
    [switch]$Silent = $false,
    [string]$RootPath = "C:\opt\viam",
    [string]$UserAccount = ""  # if specified, removes service DACL changes (does NOT delete the user)
)

$ErrorActionPreference = 'Stop'

# Check for admin privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    if (-not $Silent) {
        Write-Host "This script requires administrator privileges. Attempting to elevate..."
    }
    $scriptPath = $MyInvocation.MyCommand.Path
    $elevateArgs = "-ExecutionPolicy Bypass -File `"$scriptPath`" -Silent -RootPath `"$RootPath`" -UserAccount `"$UserAccount`""
    Start-Process powershell.exe -ArgumentList $elevateArgs -Verb RunAs
    exit
}

if (-not $Silent) {
    Write-Host ""
    Write-Host "This script removes the viam-agent service, its directories, firewall rules,"
    Write-Host "and event log source. It does NOT delete user accounts."
    Write-Host ""
    Write-Host "  Root path:      $RootPath"
    if ($UserAccount -ne "") {
        Write-Host "  Service account: $UserAccount (will NOT be deleted)"
    }
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

# Revert BFE service DACL changes if a user account was specified
if ($UserAccount -ne "") {
    if (-not $Silent) { Write-Host "Reverting BFE firewall management rights for $UserAccount..." }
    try {
        $sid = (New-Object System.Security.Principal.NTAccount($UserAccount)).Translate(
            [System.Security.Principal.SecurityIdentifier]).Value
        $currentSD = ((& sc.exe sdshow BFE) | Where-Object { $_ -match '^D:' })
        if ($currentSD -match [regex]::Escape($sid)) {
            # Remove the ACE we added for this account
            $newSD = $currentSD -replace "\(A;;CCLCRPWPRC;;;$([regex]::Escape($sid))\)", ""
            & sc.exe sdset BFE $newSD | Out-Null
            if (-not $Silent) { Write-Host "  Reverted BFE DACL." }
        } else {
            if (-not $Silent) { Write-Host "  No BFE DACL entry found for $UserAccount, skipping." }
        }
    } catch {
        Write-Warning "Failed to revert BFE DACL: $_"
    }
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
    if ($UserAccount -ne "") {
        Write-Host "Note: User account '$UserAccount' was NOT deleted. Remove manually if needed:"
        Write-Host "  Remove-LocalUser -Name '$UserAccount'"
    }
}
