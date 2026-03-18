# Viam Agent Installation Script for Windows
#
# Organization: functions are defined first, main flow at the bottom.
# This stays as a single file for ps2exe compilation. If the script grows
# significantly, consider splitting into separate .ps1 files and using a
# build script (e.g. Invoke-Build) to concatenate before ps2exe.
[CmdletBinding()]
param(
    [switch]$Silent = $false,
    [string]$RootPath = "C:\opt\viam",
    [string]$UserAccount = "",  # empty = run as LocalSystem (default)
    [switch]$EnableAuditLogging = $false,
    [switch]$UwfCommit = $false  # commit registry changes through UWF overlay
)

$ErrorActionPreference = 'Stop'

$script:ServiceName = "viam-agent"
$script:AgentDownloadName = "viam-agent-stable-windows-x86_64"
$script:AgentCacheFileName = "viam-agent-from-installer.exe"

# ─── FUNCTIONS ────────────────────────────────────────────────────────────────

function Write-Status($msg) {
    if (-not $Silent) { Write-Host $msg }
}

function Assert-AdminPrivileges {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Status "This script requires administrator privileges. Attempting to elevate..."
        $scriptPath = $MyInvocation.PSCommandPath
        $elevateArgs = "-ExecutionPolicy Bypass -File `"$scriptPath`" -Silent -RootPath `"$RootPath`" -UserAccount `"$UserAccount`""
        if ($EnableAuditLogging) { $elevateArgs += " -EnableAuditLogging" }
        if ($UwfCommit) { $elevateArgs += " -UwfCommit" }
        Start-Process powershell.exe -ArgumentList $elevateArgs -Verb RunAs
        exit
    }
}

function Enable-AuditLogging {
    Write-Status "Enabling audit logging for permission diagnostics..."
    & auditpol /set /subcategory:"Object Access" /failure:enable | Out-Null
    & auditpol /set /subcategory:"Privilege Use" /failure:enable | Out-Null
    & auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable | Out-Null
    Write-Status "  Audit logging enabled. View events in Event Viewer > Security log."
    Write-Status "  Relevant Event IDs: 4656 (handle request), 4673 (privilege use), 4688 (process creation)"
}

function Remove-ExistingInstallation {
    param([string]$BinPath)

    Write-Status "Checking for existing service..."
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc) {
        Write-Status "Existing service found. Removing..."
        try {
            Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
            & sc.exe delete $ServiceName | Out-Null
            Start-Sleep -Seconds 2
            Write-Status "  Service removed."
        } catch {
            Write-Warning "Error removing existing service: $_"
        }
    }

    $agentBinPath = Join-Path $BinPath "viam-agent.exe"
    if (Test-Path $agentBinPath) {
        Write-Status "Removing old agent binary..."
        Remove-Item -Path $agentBinPath -Force
    }
}

function Install-AgentBinary {
    param([string]$CachePath, [string]$BinPath)

    # Clean and recreate directories
    foreach ($dir in @($CachePath, $BinPath)) {
        if (Test-Path $dir) {
            Write-Status "  Cleaning $dir..."
            Remove-Item -Path $dir -Recurse -Force
        }
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }

    # Download
    $agentCachePath = Join-Path $CachePath $AgentCacheFileName
    $downloadUrl = "https://storage.googleapis.com/packages.viam.com/apps/viam-agent/$AgentDownloadName"
    Write-Status "Downloading Viam Agent..."
    Invoke-WebRequest -UseBasicParsing -Uri $downloadUrl -OutFile $agentCachePath
    if (-not (Test-Path $agentCachePath)) {
        throw "Failed to download agent executable."
    }
    Write-Status "  Download complete."

    # Symlink from bin to cache
    $agentBinPath = Join-Path $BinPath "viam-agent.exe"
    Write-Status "Creating symbolic link..."
    New-Item -ItemType SymbolicLink -Path $agentBinPath -Target $agentCachePath -Force | Out-Null

    return $agentBinPath
}

function Set-FirewallRule {
    param([string]$AgentBinPath)

    Write-Status "Configuring firewall rule..."
    try {
        Remove-NetFirewallRule -Name $ServiceName -ErrorAction SilentlyContinue
        New-NetFirewallRule -Name $ServiceName -DisplayName "Viam Agent" `
            -Program $AgentBinPath -Direction Inbound -Action Allow -Enabled True | Out-Null
    } catch {
        Write-Warning "Failed to configure firewall: $_"
    }
}

function Grant-FirewallManagement {
    param([string]$Account)

    # Grant the service account permission to add firewall rules at runtime.
    # The agent downloads binaries (viam-server, subsystems) and creates firewall
    # exceptions for each via netsh. netsh goes through the BFE (Base Filtering Engine)
    # service, which enforces admin-only access by default.
    #
    # We add an ACE to the BFE service DACL granting the service account
    # CCLCRPRC (connect, query status, start, read control) + WP (write property,
    # needed to add filter rules).
    Write-Status "  Granting $Account firewall management rights (BFE service)..."
    $sid = (New-Object System.Security.Principal.NTAccount($Account)).Translate(
        [System.Security.Principal.SecurityIdentifier]).Value
    $currentSD = ((& sc.exe sdshow BFE) | Where-Object { $_ -match '^D:' })
    $ace = "(A;;CCLCRPWPRC;;;$sid)"
    $newSD = $currentSD -replace '(S:)', "$ace`$1"
    if ($newSD -eq $currentSD) {
        $newSD = $currentSD + $ace
    }
    & sc.exe sdset BFE $newSD | Out-Null
}

function Set-UserAccountPermissions {
    param([string]$Account, [string]$ViamDir)

    Write-Status "Configuring service account: $Account"

    # Verify the user exists
    $localUser = Get-LocalUser -Name $Account -ErrorAction SilentlyContinue
    if (-not $localUser) {
        Write-Error "User account '$Account' does not exist. Create it first or omit -UserAccount to run as SYSTEM."
        exit 1
    }

    # Grant full control of viam directory
    Write-Status "  Granting $Account full control of $ViamDir..."
    $acl = Get-Acl $ViamDir
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $Account, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    $acl.AddAccessRule($rule)
    Set-Acl -Path $ViamDir -AclObject $acl

    # Register event log source (so the non-admin account can write events)
    New-EventLog -LogName Application -Source $ServiceName -ErrorAction SilentlyContinue

    # Allow creating firewall rules at runtime (for viam-server and other subsystems)
    Grant-FirewallManagement -Account $Account

    # Prompt for password and return credential
    return (Get-Credential -UserName ".\$Account" -Message "Enter password for service account $Account")
}

function Grant-ServiceLogonRight {
    param([string]$Account)

    # New-Service -Credential does NOT auto-grant SeServiceLogonRight (DSC's Service
    # resource does, but the raw cmdlet doesn't). Without it the service fails to start
    # with error 1069.
    Write-Status "  Granting SeServiceLogonRight to $Account..."
    $tempInf = [System.IO.Path]::GetTempFileName()
    $tempDb  = [System.IO.Path]::GetTempFileName()
    try {
        secedit /export /cfg $tempInf /quiet
        $content = Get-Content $tempInf -Raw
        if ($content -notmatch [regex]::Escape($Account)) {
            $content = $content -replace '(SeServiceLogonRight\s*=\s*.*)', "`$1,$Account"
            $content | Set-Content $tempInf
            secedit /configure /db $tempDb /cfg $tempInf /quiet
        }
    } finally {
        Remove-Item $tempInf, $tempDb -ErrorAction SilentlyContinue
    }
}

function Grant-ServiceSelfManagement {
    param([string]$Account)

    # Grant permission to query/start/stop its own service.
    # SDDL rights: LC=query status, RP=start, WP=stop, LO=interrogate, RC=read control
    $sid = (New-Object System.Security.Principal.NTAccount($Account)).Translate(
        [System.Security.Principal.SecurityIdentifier]).Value
    $currentSD = ((& sc.exe sdshow $ServiceName) | Where-Object { $_ -match '^D:' })
    $ace = "(A;;LCRPWPLORC;;;$sid)"
    $newSD = $currentSD -replace '(S:)', "$ace`$1"
    if ($newSD -eq $currentSD) {
        # No SACL present, append to end
        $newSD = $currentSD + $ace
    }
    & sc.exe sdset $ServiceName $newSD | Out-Null
    Write-Status "  Granted $Account service self-management rights"
}

function Install-AgentService {
    param([string]$AgentBinPath, [pscredential]$Credential)

    Write-Status "Configuring service..."

    $svcBinCmd = "`"$AgentBinPath`" --viam-dir `"$RootPath`""
    $newSvcArgs = @{
        Name           = $ServiceName
        BinaryPathName = $svcBinCmd
        StartupType    = "Automatic"
    }
    if ($Credential) {
        $newSvcArgs["Credential"] = $Credential
    }
    New-Service @newSvcArgs | Out-Null

    if ($UserAccount -ne "") {
        Grant-ServiceLogonRight -Account $UserAccount
    }

    # Configure failure actions (no PS builtin for recovery policy)
    & sc.exe failure $ServiceName reset= 0 actions= restart/5000/restart/5000/restart/5000 | Out-Null
    & sc.exe failureflag $ServiceName 1 | Out-Null

    if ($UserAccount -ne "") {
        Grant-ServiceSelfManagement -Account $UserAccount
    }

    Write-Status "Starting service..."
    Start-Service -Name $ServiceName
}

function Invoke-UwfCommit {
    # Commit registry changes through UWF overlay so they survive reboot.
    #
    # TODO: finalize this list with procmon on an actual LTSC device.
    # This list MUST be rechecked with procmon whenever the installer changes,
    # since new operations may write to additional registry paths.
    Write-Status "Committing registry changes through UWF..."

    $uwfmgr = Get-Command uwfmgr.exe -ErrorAction SilentlyContinue
    if (-not $uwfmgr) {
        Write-Warning "uwfmgr.exe not found — UWF may not be enabled on this system. Skipping commits."
        return
    }

    $registryCommits = @(
        "HKLM\SYSTEM\CurrentControlSet\Services\viam-agent"
        "HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\viam-agent"
        "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
    )

    if ($UserAccount -ne "") {
        $registryCommits += "HKLM\SECURITY\Policy"
        $registryCommits += "HKLM\SAM\SAM"
        # BFE service DACL (Grant-FirewallManagement)
        $registryCommits += "HKLM\SYSTEM\CurrentControlSet\Services\BFE"
    }

    foreach ($regPath in $registryCommits) {
        $result = & uwfmgr.exe registry commit "$regPath" 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Status "  Committed: $regPath"
        } else {
            Write-Warning "  Failed to commit $regPath : $result"
        }
    }

    Write-Status "UWF registry commits complete."
}

# ─── MAIN ─────────────────────────────────────────────────────────────────────

Assert-AdminPrivileges

Write-Status "Starting Viam Agent installation..."

if ($EnableAuditLogging) { Enable-AuditLogging }

$cachePath = Join-Path $RootPath "cache"
$binPath   = Join-Path $RootPath "bin"

Remove-ExistingInstallation -BinPath $binPath

$agentBinPath = Install-AgentBinary -CachePath $cachePath -BinPath $binPath

Set-FirewallRule -AgentBinPath $agentBinPath

$svcCredential = $null
if ($UserAccount -ne "") {
    $svcCredential = Set-UserAccountPermissions -Account $UserAccount -ViamDir $RootPath
}

Install-AgentService -AgentBinPath $agentBinPath -Credential $svcCredential

if ($UwfCommit) { Invoke-UwfCommit }

Write-Status "Installation completed successfully."
