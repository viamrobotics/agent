# Viam Agent Installation Script for Windows
[CmdletBinding()]
param(
    [switch]$Silent = $false,
    [string]$RootPath = "C:\opt\viam",
    [string]$UserAccount = "",  # empty = run as LocalSystem (default)
    [switch]$EnableAuditLogging = $false,
    [switch]$UwfCommit = $false  # commit registry changes through UWF overlay
)

$ErrorActionPreference = 'Stop'

# Ensure TLS 1.2 for HTTPS downloads (older Win10 may default to TLS 1.0/1.1)
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

# Check for admin privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    if (-not $Silent) {
        Write-Host "This script requires administrator privileges. Attempting to elevate..."
    }
    
    # Self-elevate the script
    $scriptPath = $MyInvocation.MyCommand.Path
    $elevateArgs = "-ExecutionPolicy Bypass -File `"$scriptPath`" -Silent -RootPath `"$RootPath`" -UserAccount `"$UserAccount`""
    if ($EnableAuditLogging) { $elevateArgs += " -EnableAuditLogging" }
    if ($UwfCommit) { $elevateArgs += " -UwfCommit" }
    Start-Process powershell.exe -ArgumentList $elevateArgs -Verb RunAs
    exit
}

if (-not $Silent) {
    Write-Host "Starting Viam Agent installation..."
}

# Enable security audit logging for diagnosing permission issues
if ($EnableAuditLogging) {
    if (-not $Silent) { Write-Host "Enabling audit logging for permission diagnostics..." }
    # Log failed object access attempts (file/registry/service ACL denials)
    & auditpol /set /subcategory:"Object Access" /failure:enable | Out-Null
    # Log failed privilege use (e.g. firewall, service control)
    & auditpol /set /subcategory:"Privilege Use" /failure:enable | Out-Null
    # Log process creation (helps trace what the agent spawns)
    & auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable | Out-Null
    if (-not $Silent) {
        Write-Host "  Audit logging enabled. View events in Event Viewer > Security log."
        Write-Host "  Relevant Event IDs: 4656 (handle request), 4673 (privilege use), 4688 (process creation)"
    }
}

# Define installation paths
$cachePath = Join-Path $RootPath "cache"
$binPath = Join-Path $RootPath "bin"
$agentCURLFileName = "viam-agent-stable-windows-x86_64"
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
        & sc.exe delete "viam-agent" | Out-Null
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
    Invoke-WebRequest -UseBasicParsing -Uri "https://storage.googleapis.com/packages.viam.com/apps/viam-agent/$agentCURLFileName" -OutFile $agentCachePath
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
    New-Item -ItemType SymbolicLink -Path $agentBinPath -Target $agentCachePath -Force | Out-Null
} catch {
    Write-Error "Failed to create symbolic link: $_"
    exit 1
}


# Configure firewall
if (-not $Silent) { Write-Host "Configuring firewall..." }
try {
    # Remove existing rule if present, then create fresh
    Remove-NetFirewallRule -Name "viam-agent" -ErrorAction SilentlyContinue
    New-NetFirewallRule -Name "viam-agent" -DisplayName "Viam Agent" `
        -Program $agentBinPath -Direction Inbound -Action Allow -Enabled True | Out-Null
} catch {
    Write-Warning "Failed to configure firewall: $_"
    # Continue despite firewall error
}

# If a user account is specified, set up permissions for non-SYSTEM operation
$svcCredential = $null
if ($UserAccount -ne "") {
    if (-not $Silent) { Write-Host "Configuring service account: $UserAccount" }

    # Verify the user exists
    $localUser = Get-LocalUser -Name $UserAccount -ErrorAction SilentlyContinue
    if (-not $localUser) {
        Write-Error "User account '$UserAccount' does not exist. Create it first or omit -UserAccount to run as SYSTEM."
        exit 1
    }

    # Prompt for the service account password
    $svcCredential = Get-Credential -UserName ".\$UserAccount" -Message "Enter password for service account $UserAccount"

    # Grant full control of viam directory to the service account
    if (-not $Silent) { Write-Host "  Granting $UserAccount full control of $RootPath..." }
    $acl = Get-Acl $RootPath
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $UserAccount, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    $acl.AddAccessRule($rule)
    Set-Acl -Path $RootPath -AclObject $acl

    # Register event log source (so the non-admin account can write events)
    New-EventLog -LogName Application -Source "viam-agent" -ErrorAction SilentlyContinue
}

# Configure and start service
if (-not $Silent) { Write-Host "Configuring service..." }
try {
    # Create service — pass --viam-dir so the agent uses the correct root
    $svcBinCmd = "`"$agentBinPath`" --viam-dir `"$RootPath`""
    $newSvcArgs = @{
        Name           = "viam-agent"
        BinaryPathName = $svcBinCmd
        StartupType    = "Automatic"
    }
    if ($svcCredential) {
        # New-Service -Credential automatically grants SeServiceLogonRight
        $newSvcArgs["Credential"] = $svcCredential
    }
    New-Service @newSvcArgs | Out-Null

    # Configure failure actions (no PS builtin for recovery policy)
    & sc.exe failure "viam-agent" reset= 0 actions= restart/5000/restart/5000/restart/5000 | Out-Null
    & sc.exe failureflag "viam-agent" 1 | Out-Null

    # If using a non-SYSTEM account, grant it permission to query/start/stop its own service.
    # SDDL rights: LC=query status, RP=start, WP=stop, LO=interrogate, RC=read control
    if ($UserAccount -ne "") {
        $sid = (New-Object System.Security.Principal.NTAccount($UserAccount)).Translate(
            [System.Security.Principal.SecurityIdentifier]).Value
        $currentSD = ((& sc.exe sdshow "viam-agent") | Where-Object { $_ -match '^D:' })
        $ace = "(A;;LCRPWPLORC;;;$sid)"
        # Insert the new ACE before the final closing paren of the DACL
        $newSD = $currentSD -replace '(S:)', "$ace`$1"
        if ($newSD -eq $currentSD) {
            # No SACL present, append before end
            $newSD = $currentSD + $ace
        }
        & sc.exe sdset "viam-agent" $newSD | Out-Null
        if (-not $Silent) { Write-Host "  Granted $UserAccount service self-management rights" }
    }

    # Start service
    if (-not $Silent) { Write-Host "Starting service..." }
    Start-Service -Name "viam-agent"
} catch {
    Write-Error "Failed to configure or start service: $_"
    exit 1
}

# Commit registry changes through UWF overlay so they survive reboot.
# This is needed on LTSC devices where UWF protects C: — without this,
# service registration, firewall rules, etc. are lost on reboot.
#
# TODO: finalize this list with procmon on an actual LTSC device.
# This list MUST be rechecked with procmon whenever the installer changes,
# since new operations may write to additional registry paths.
if ($UwfCommit) {
    if (-not $Silent) { Write-Host "Committing registry changes through UWF..." }

    # Check that uwfmgr is available
    $uwfmgr = Get-Command uwfmgr.exe -ErrorAction SilentlyContinue
    if (-not $uwfmgr) {
        Write-Warning "uwfmgr.exe not found — UWF may not be enabled on this system. Skipping commits."
    } else {
        # Registry paths written by this installer (best-known list, pending procmon verification):
        $registryCommits = @(
            # Service registration (New-Service, sc.exe failure/failureflag/sdset)
            "HKLM\SYSTEM\CurrentControlSet\Services\viam-agent"
            # Event log source (New-EventLog)
            "HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\viam-agent"
            # Firewall rule (New-NetFirewallRule) — rules stored under SharedAccess
            "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
        )

        # If a user account was created/configured, the security policy database
        # and SAM entries also need committing. These are harder to commit surgically:
        if ($UserAccount -ne "") {
            # SeServiceLogonRight is stored in the security policy database
            $registryCommits += "HKLM\SECURITY\Policy"
            # User account SID mapping
            $registryCommits += "HKLM\SAM\SAM"
        }

        foreach ($regPath in $registryCommits) {
            $result = & uwfmgr.exe registry commit "$regPath" 2>&1
            if ($LASTEXITCODE -eq 0) {
                if (-not $Silent) { Write-Host "  Committed: $regPath" }
            } else {
                Write-Warning "  Failed to commit $regPath : $result"
            }
        }

        if (-not $Silent) { Write-Host "UWF registry commits complete." }
    }
}

if (-not $Silent) { Write-Host "Installation completed successfully." } 