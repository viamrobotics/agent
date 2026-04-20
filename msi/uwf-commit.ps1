#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Persist the viam-agent MSI install across reboots on a UWF-protected drive.

.DESCRIPTION
  Looks up the installed ProductCode via the known UpgradeCode, then for each
  registry key the MSI touches:
    1. `uwfmgr registry add-exclusion` so future writes bypass the overlay.
    2. `uwfmgr registry commit` for every value currently in the overlay so
       the already-installed state survives the next reboot.

  Run AFTER `msiexec /i viam-agent.msi` on a machine with UWF enabled on C:.
  Exclusions take effect on next reboot; commits apply immediately.

  Also handles HKLM\SECURITY\Policy\Accounts\<viam-agent-SID>: commits
  the four default values lsass.exe wrote there (the account object,
  SecDesc, Sid, Privilgs — this is where SeCreateSymbolicLinkPrivilege
  lives) and adds the subtree to the exclusion list. uwfmgr operates
  below the Win32 ACL layer via the UWF kernel filter, so commits on
  SECURITY paths succeed from an admin shell even though Get-Item does
  not. LSA caches policy in memory, so the grant takes effect at the
  next boot (when LSA re-reads the hive), not immediately.
#>

[CmdletBinding()]
param(
    [string]$UpgradeCode  = '3FBC9034-E5C1-46B2-8BB8-3BA9A82158C3',
    [string]$ServiceName  = 'viam-agent'
)

$ErrorActionPreference = 'Stop'

function Convert-GuidToPacked([string]$guid) {
    $bytes = [guid]::Parse($guid).ToByteArray()
    -join ($bytes | ForEach-Object {
        $h = '{0:X2}' -f $_
        [string]$h[1] + [string]$h[0]
    })
}

function Convert-PackedToGuid([string]$packed) {
    $bytes = [byte[]]::new(16)
    for ($i = 0; $i -lt 16; $i++) {
        $hex = [string]$packed[$i * 2 + 1] + [string]$packed[$i * 2]
        $bytes[$i] = [Convert]::ToByte($hex, 16)
    }
    [guid]::new($bytes).ToString('B').ToUpper()
}

function ConvertTo-UwfPath([string]$psPath) {
    ($psPath -replace '^Microsoft\.PowerShell\.Core\\Registry::', '') -replace '^HKEY_LOCAL_MACHINE', 'HKLM' -replace '^HKEY_USERS', 'HKU' -replace '^HKLM:', 'HKLM' -replace '^HKU:', 'HKU'
}

function Format-UwfOutput {
    $input |
        Where-Object { $_ -notmatch 'Unified Write Filter Configuration Utility|Copyright \(C\) Microsoft' -and $_.ToString().Trim() -ne '' } |
        ForEach-Object { "    $_" } | Write-Host
}

function Invoke-Uwfmgr {
    param([string[]]$Arguments)
    & uwfmgr.exe @Arguments 2>&1 | Format-UwfOutput
    return $LASTEXITCODE
}

# TODO: add a -SkipExclusions switch so callers can choose commits-only runs
# (e.g. one-shot migration of an already-installed machine where future writes
# are not expected).

function Protect-Key {
    param([string]$PsPath)

    if (-not (Test-Path -LiteralPath $PsPath)) {
        Write-Host "skip (missing): $PsPath"
        return
    }
    $uwfPath = ConvertTo-UwfPath $PsPath
    Write-Host "exclude: $uwfPath"
    $null = Invoke-Uwfmgr @('registry', 'add-exclusion', $uwfPath)

    $key = Get-Item -LiteralPath $PsPath
    foreach ($name in $key.Property) {
        if ([string]::IsNullOrEmpty($name)) { continue }
        Write-Host "commit:  $uwfPath :: $name"
        $null = Invoke-Uwfmgr @('registry', 'commit', $uwfPath, $name)
    }
    foreach ($sub in Get-ChildItem -LiteralPath $PsPath -ErrorAction SilentlyContinue) {
        Protect-Key -PsPath $sub.PSPath
    }
}

if (-not (Get-Command uwfmgr.exe -ErrorAction SilentlyContinue)) {
    throw "uwfmgr.exe not found. Enable the Unified Write Filter feature."
}

$packedUpgrade = Convert-GuidToPacked $UpgradeCode
$upgradeKey    = "HKLM:\SOFTWARE\Classes\Installer\UpgradeCodes\$packedUpgrade"

if (-not (Test-Path -LiteralPath $upgradeKey)) {
    throw "UpgradeCode $UpgradeCode not registered. Is the MSI installed?"
}

$productCodesPacked = (Get-Item -LiteralPath $upgradeKey).Property |
    Where-Object { $_ -match '^[0-9A-F]{32}$' }

if (-not $productCodesPacked) {
    throw "No ProductCodes found under $upgradeKey."
}

foreach ($pcPacked in $productCodesPacked) {
    $pc = Convert-PackedToGuid $pcPacked
    Write-Host "`n=== ProductCode $pc ==="
    $perProduct = @(
        "HKLM:\SOFTWARE\Classes\Installer\Products\$pcPacked"
        "HKLM:\SOFTWARE\Classes\Installer\Features\$pcPacked"
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$pc"
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\$pcPacked"
    )
    foreach ($k in $perProduct) { Protect-Key -PsPath $k }
}

Write-Host "`n=== product-independent keys ==="
$fixed = @(
    'HKLM:\SYSTEM\CurrentControlSet\Services\viam-agent'
    'HKLM:\SOFTWARE\Viam'
    $upgradeKey
)
foreach ($k in $fixed) { Protect-Key -PsPath $k }

Write-Host "`n=== LSA privilege grant (SECURITY hive) ==="
$sidLine = (& sc.exe showsid $ServiceName | Select-String -Pattern 'SERVICE SID').ToString()
if ($sidLine -match '(S-1-5-80-[\d-]+)') {
    $serviceSid = $Matches[1]
    $secRoot = "HKLM\SECURITY\Policy\Accounts\$serviceSid"
    Write-Host "exclude: $secRoot  (service SID for $ServiceName)"
    $null = Invoke-Uwfmgr @('registry', 'add-exclusion', $secRoot)
    foreach ($sub in '', '\SecDesc', '\Sid', '\Privilgs') {
        $k = "$secRoot$sub"
        Write-Host "commit:  $k :: (Default)"
        # PS 5.1 strips empty-string args to native exes; round-trip through cmd.exe to preserve "".
        & cmd.exe /c "uwfmgr.exe registry commit `"$k`" `"`"" 2>&1 | Format-UwfOutput
    }
    Write-Host "note: LSA caches policy in memory; the grant activates at next boot when LSA re-reads the hive."
} else {
    Write-Warning "Could not resolve service SID for '$ServiceName'; skipping SECURITY exclusion."
}

Write-Host "`nDone. Exclusions take effect after the next reboot; committed values persist now."
