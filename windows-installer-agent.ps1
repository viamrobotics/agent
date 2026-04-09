# Viam Agent Installation Script for Windows
[CmdletBinding()]
param(
    [switch]$Silent = $false,
    [string]$RootPath = "C:\opt\viam",
    [switch]$ServiceAccount = $false,  # use NT SERVICE\viam-agent virtual account instead of SYSTEM
    [string]$Url = "",  # override agent download URL entirely
    [string]$ConfigPath = ""  # path to viam.json -- passed as --config to the agent
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
    $elevateArgs = "-ExecutionPolicy Bypass -File `"$scriptPath`" -RootPath `"$RootPath`""
    if ($Silent) { $elevateArgs += " -Silent" }
    if ($ServiceAccount) { $elevateArgs += " -ServiceAccount" }
    if ($Url -ne "") { $elevateArgs += " -Url `"$Url`"" }
    if ($ConfigPath -ne "") { $elevateArgs += " -ConfigPath `"$ConfigPath`"" }
    Start-Process powershell.exe -ArgumentList $elevateArgs -Verb RunAs
    exit
}

if (-not $Silent) {
    Write-Host "Starting Viam Agent installation..."
}

# Define installation paths
$cachePath = Join-Path $RootPath "cache"
$binPath = Join-Path $RootPath "bin"
if ($Url -ne "") {
    $downloadUrl = $Url
    $agentFileName = $Url.Split("/")[-1]
} else {
    $agentFileName = "viam-agent-from-installer.exe"
    $downloadUrl = "https://storage.googleapis.com/packages.viam.com/apps/viam-agent/viam-agent-stable-windows-x86_64"
}
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
        if ($LASTEXITCODE -ne 0) {
            throw "sc.exe delete failed with exit code $LASTEXITCODE"
        }
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
    # Suppress per-chunk progress bar -- it redraws on every read and makes
    # Invoke-WebRequest extremely slow on PS 5.1.
    $prevPref = $ProgressPreference
    $ProgressPreference = 'SilentlyContinue'
    # todo: System.Net.WebClient has a progress hook for less greedy logging
    Invoke-WebRequest -UseBasicParsing -Uri $downloadUrl -OutFile $agentCachePath
    if (-not (Test-Path $agentCachePath)) {
        throw "Failed to download agent executable."
    }
} catch {
    Write-Error "Failed to download Viam Agent: $_"
    exit 1
} finally {
    $ProgressPreference = $prevPref
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

# Configure and start service
if (-not $Silent) { Write-Host "Configuring service..." }
try {
    # Create service -- pass --viam-dir so the agent uses the correct root
    $svcBinCmd = "`"$agentBinPath`" --viam-dir `"$RootPath`""
    if ($ConfigPath -ne "") { $svcBinCmd += " --config `"$ConfigPath`"" }
    New-Service -Name "viam-agent" -BinaryPathName $svcBinCmd -StartupType Automatic | Out-Null

    # Set VIAM_HOME environment variable on the service so child processes
    # (viam-server, modules) inherit the correct root path.
    if ($PSBoundParameters.ContainsKey('RootPath')) {
        $svcRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\viam-agent"
        Set-ItemProperty -Path $svcRegPath -Name "Environment" -Value @("VIAM_HOME=$RootPath") -Type MultiString
    }

    # Configure failure actions (no PS builtin for recovery policy)
    & sc.exe failure "viam-agent" reset= 0 actions= restart/5000/restart/5000/restart/5000 | Out-Null
    & sc.exe failureflag "viam-agent" 1 | Out-Null

    # If -ServiceAccount, switch from SYSTEM to the virtual service account.
    # NT SERVICE\viam-agent is auto-created by Windows, has no password, and
    # implicitly has SeServiceLogonRight. The service must exist first so
    # Windows can resolve the virtual account SID.
    if ($ServiceAccount) {
        $svcAccountName = "NT SERVICE\viam-agent"
        if (-not $Silent) { Write-Host "  Configuring virtual service account: $svcAccountName" }

        & sc.exe config "viam-agent" obj= "$svcAccountName" | Out-Null

        # Grant full control of viam directory
        if (-not $Silent) { Write-Host "  Granting $svcAccountName full control of $RootPath..." }
        $acl = Get-Acl $RootPath
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $svcAccountName, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
        $acl.AddAccessRule($rule)
        Set-Acl -Path $RootPath -AclObject $acl

        # Grant read access to the config file's directory so the service account
        # can read viam.json.
        if ($ConfigPath -ne "") {
            $configDir = Split-Path -Parent $ConfigPath
        } else {
            $configDir = "C:\etc"
        }
        if (-not (Test-Path $configDir)) {
            New-Item -ItemType Directory -Path $configDir -Force | Out-Null
        }
        if (-not $Silent) { Write-Host "  Granting $svcAccountName read access to $configDir..." }
        $cfgAcl = Get-Acl $configDir
        $cfgRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $svcAccountName, "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")
        $cfgAcl.AddAccessRule($cfgRule)
        Set-Acl -Path $configDir -AclObject $cfgAcl

        # Grant SeCreateSymbolicLinkPrivilege so the agent can create symlinks
        # at runtime when downloading new versions of itself and viam-server.
        # secedit uses *SID format (not account names), so resolve first.
        if (-not $Silent) { Write-Host "  Granting $svcAccountName symlink creation privilege..." }
        $svcSid = (New-Object System.Security.Principal.NTAccount($svcAccountName)).Translate(
            [System.Security.Principal.SecurityIdentifier]).Value
        $tempInf = [System.IO.Path]::GetTempFileName()
        $tempDb  = [System.IO.Path]::GetTempFileName()
        try {
            secedit /export /cfg $tempInf /quiet
            # secedit exports ANSI on Win11. Use Default encoding to match.
            $content = [IO.File]::ReadAllText($tempInf, [Text.Encoding]::Default)
            if ($content -notmatch "SeCreateSymbolicLinkPrivilege[^\r\n]*$([regex]::Escape($svcSid))") {
                # [^\r\n]* instead of .* to avoid capturing \r from CRLF line endings
                $content = $content -replace '(SeCreateSymbolicLinkPrivilege\s*=\s*[^\r\n]*)', "`$1,*$svcSid"
                [IO.File]::WriteAllText($tempInf, $content, [Text.Encoding]::Default)
                # secedit expects to create the .sdb fresh -- delete the empty temp file
                Remove-Item $tempDb -ErrorAction SilentlyContinue
                secedit /configure /db $tempDb /cfg $tempInf /quiet
                if ($LASTEXITCODE -ne 0) {
                    Write-Warning "secedit /configure failed (exit code $LASTEXITCODE) -- symlink privilege may not be granted"
                } else {
                    if (-not $Silent) { Write-Host "  Granted SeCreateSymbolicLinkPrivilege to SID $svcSid" }
                }
            } else {
                if (-not $Silent) { Write-Host "  SeCreateSymbolicLinkPrivilege already granted." }
            }
        } catch {
            Write-Warning "Failed to grant SeCreateSymbolicLinkPrivilege: $_"
        } finally {
            Remove-Item $tempInf, $tempDb -ErrorAction SilentlyContinue
        }

        # Register event log source (so the non-admin account can write events)
        New-EventLog -LogName Application -Source "viam-agent" -ErrorAction SilentlyContinue
    }

    # Start service
    if (-not $Silent) { Write-Host "Starting service..." }
    Start-Service -Name "viam-agent"
} catch {
    Write-Error "Failed to configure or start service: $_"
    exit 1
}

if (-not $Silent) { Write-Host "Installation completed successfully." }
