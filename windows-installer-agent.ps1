# Viam Agent Installation Script for Windows
[CmdletBinding()]
param(
    [switch]$Silent = $false
)

$ErrorActionPreference = 'Stop'

# Check for admin privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    if (-not $Silent) {
        Write-Host "This script requires administrator privileges. Attempting to elevate..."
    }
    
    # Self-elevate the script
    $scriptPath = $MyInvocation.MyCommand.Path
    Start-Process powershell.exe -ArgumentList "-ExecutionPolicy Bypass -File `"$scriptPath`" -Silent" -Verb RunAs
    exit
}

if (-not $Silent) {
    Write-Host "Starting Viam Agent installation..."
}

# Define installation paths
$rootPath = "C:\opt\viam"
$cachePath = Join-Path $rootPath "cache"
$binPath = Join-Path $rootPath "bin"
$agentCURLFileName = "viam-agent-windows-amd64-dev.exe" # TODO: update this to viam-agent-windows-amd64-stable.exe
$agentFileName = "viam-agent-from-installer.exe"
$agentCachePath = Join-Path $cachePath $agentFileName
$agentBinPath = Join-Path $binPath "viam-agent.exe"

# Check if service already exists and remove it if needed
if (-not $Silent) { Write-Host "Checking for existing service..." }
$serviceExists = Get-Service -Name "viam-agent" -ErrorAction SilentlyContinue
if ($serviceExists) {
    if (-not $Silent) { Write-Host "Existing service found. Removing..." }
    try {
        # Stop the service first
        Stop-Service -Name "viam-agent" -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2  # Give it time to stop
        
        # Delete the service
        Start-Process -FilePath "sc" -ArgumentList @("delete", "viam-agent") -NoNewWindow -Wait
        Start-Sleep -Seconds 2  # Give it time to complete
        
        if (-not $Silent) { Write-Host "Service removed successfully." }
    } catch {
        Write-Warning "Error removing existing service: $_"
        # Continue anyway since we'll try to create a new one
    }
}

# Remove old agent if it exists
if (Test-Path $agentBinPath) {
    if (-not $Silent) { Write-Host "Removing old agent..." }
    try {
        Remove-Item -Path $agentBinPath -Force
    } catch {
        Write-Error "Failed to remove old agent: $_"
        exit 1
    }
}

# Create directories if they don't exist
if (Test-Path $cachePath) {
    if (-not $Silent) { Write-Host "Cleaning up existing cache directory..." }
    Remove-Item -Path $cachePath -Recurse -Force
}

if (Test-Path $binPath) {
    if (-not $Silent) { Write-Host "Cleaning up existing bin directory..." }
    Remove-Item -Path $binPath -Recurse -Force
}

if (-not $Silent) { Write-Host "Creating cache directory..." }
New-Item -ItemType Directory -Path $cachePath -Force | Out-Null

if (-not $Silent) { Write-Host "Creating bin directory..." }
New-Item -ItemType Directory -Path $binPath -Force | Out-Null

# Download the agent
if (-not $Silent) { Write-Host "Downloading Viam Agent..." }
try {
    Invoke-WebRequest -Uri "https://storage.googleapis.com/packages.viam.com/temp/$agentCURLFileName" -OutFile $agentCachePath
    if (-not (Test-Path $agentCachePath)) {
        throw "Failed to download agent executable."
    }
} catch {
    Write-Error "Failed to download Viam Agent: $_"
    exit 1
}

if (-not $Silent) { Write-Host "Download completed successfully." }

# Create symbolic link
if (-not $Silent) { Write-Host "Creating symbolic link..." }
try {
    $linkArgs = @("`"$agentBinPath`"", "`"$agentCachePath`"")
    Start-Process -FilePath "cmd.exe" -ArgumentList "/c mklink $linkArgs" -NoNewWindow -Wait
} catch {
    Write-Error "Failed to create symbolic link: $_"
    exit 1
}


# Configure firewall
if (-not $Silent) { Write-Host "Configuring firewall..." }
try {
    $firewallArgs = @(
        "advfirewall", "firewall", "add", "rule", 
        "name=`"$agentBinPath`"", 
        "dir=in", 
        "action=allow", 
        "program=`"$agentBinPath`"", 
        "enable=yes"
    )
    Start-Process -FilePath "netsh" -ArgumentList $firewallArgs -NoNewWindow -Wait
} catch {
    Write-Warning "Failed to configure firewall: $_"
    # Continue despite firewall error
}
# Configure and start service
if (-not $Silent) { Write-Host "Configuring service..." }
try {
    # Create service
    $scArgs = @("create", "viam-agent", "binpath=", "`"$agentBinPath`"", "start=", "auto")
    Start-Process -FilePath "sc" -ArgumentList $scArgs -NoNewWindow -Wait
    
    # Configure failure actions
    $scFailArgs = @("failure", "viam-agent", "reset=", "0", "actions=", "restart/5000/restart/5000/restart/5000")
    Start-Process -FilePath "sc" -ArgumentList $scFailArgs -NoNewWindow -Wait
    
    # Set failure flag
    $scFlagArgs = @("failureflag", "viam-agent", "1")
    Start-Process -FilePath "sc" -ArgumentList $scFlagArgs -NoNewWindow -Wait
    
    # Start service
    if (-not $Silent) { Write-Host "Starting service..." }
    Start-Process -FilePath "sc" -ArgumentList @("start", "viam-agent") -NoNewWindow -Wait
} catch {
    Write-Error "Failed to configure or start service: $_"
    exit 1
}

if (-not $Silent) { Write-Host "Installation completed successfully." } 