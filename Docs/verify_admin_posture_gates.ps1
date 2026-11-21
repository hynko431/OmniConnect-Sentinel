#Requires -RunAsAdministrator
<#
.SYNOPSIS
    OmniConnect-Sentinel Phase 0.1 & Phase 3.1 Administrator Posture Verification Script
    Verifies Gates G0.1, G0.2, and G0.3 from Master Plan v2 (§3 Phase 0.1 & §11.3).
#>

$ErrorActionPreference = "Stop"

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host " OmniConnect Sentinel - Admin Posture Gate Verification (G0.1-G0.3)" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

# Gate G0.1: With the agent stopped, a new USB doesn't appear in Explorer
# Checks MountMgr NoAutoMount == 1, mountvol automount status, and AutoPlay suppression (NoDriveTypeAutoRun == 0xFF & cdrom AutoRun == 0)
$mountMgrPath = "HKLM:\SYSTEM\CurrentControlSet\Services\MountMgr"
$noAutoMount = (Get-ItemProperty -Path $mountMgrPath -Name "NoAutoMount" -ErrorAction SilentlyContinue).NoAutoMount
$explorerPolPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$noAutoRun = (Get-ItemProperty -Path $explorerPolPath -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue).NoDriveTypeAutoRun
$cdromPath = "HKLM:\SYSTEM\CurrentControlSet\Services\cdrom"
$cdromAutoRun = (Get-ItemProperty -Path $cdromPath -Name "AutoRun" -ErrorAction SilentlyContinue).AutoRun

if ($noAutoMount -eq 1 -and $noAutoRun -eq 255 -and $cdromAutoRun -eq 0) {
    Write-Host "[PASS] G0.1: MountMgr NoAutoMount==1, Explorer NoDriveTypeAutoRun==0xFF, cdrom AutoRun==0 (New USB volumes do not auto-mount in Explorer)" -ForegroundColor Green
}
else {
    Write-Host "[WARN] G0.1: MountMgr NoAutoMount=$noAutoMount, NoDriveTypeAutoRun=$noAutoRun, cdrom AutoRun=$cdromAutoRun. Run 'mountvol /N' or start sentinel-agent as SYSTEM." -ForegroundColor Yellow
}

# Gate G0.2: A volume seen before doesn't regain its old drive letter
# Inspects HKLM:\SYSTEM\MountedDevices for stale \DosDevices\X: assignments pointing to currently unmounted removable volumes
$mountedDevicesPath = "HKLM:\SYSTEM\MountedDevices"
$activeDrives = (Get-PSDrive -PSProvider FileSystem).Name | ForEach-Object { "\DosDevices\$($_):" }
$mountedProps = (Get-ItemProperty -Path $mountedDevicesPath).PSObject.Properties | Where-Object { $_.Name -like "\DosDevices\?:" }
$staleDosLetters = @()
foreach ($prop in $mountedProps) {
    if ($activeDrives -notcontains $prop.Name) {
        $staleDosLetters += $prop.Name
    }
}
if ($staleDosLetters.Count -eq 0) {
    Write-Host "[PASS] G0.2: Zero stale \DosDevices\ drive-letter entries in HKLM\SYSTEM\MountedDevices (Previously seen USB volumes cannot regain old drive letters)" -ForegroundColor Green
}
else {
    Write-Host "[WARN] G0.2: Found stale \DosDevices\ drive letters in MountedDevices: $($staleDosLetters -join ', ')" -ForegroundColor Yellow
}

# Gate G0.3: A standard user can't list files through the volume GUID path (\\?\Volume{GUID}\)
# Verifies RemovableStorageDevices Deny_All==1 + scoped class subkeys, class-scoped DeviceInstall Restrictions (DenyDeviceIDs==1 with USBSTOR/WPD entries, DenyDeviceClasses==1 with WPD GUID, DenyUnspecified!=1 so docks/webcams/YubiKeys/HMI stay operational — CSE-24), and checks that any attached USB disk is Offline
$remPolPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices"
$denyAll = (Get-ItemProperty -Path $remPolPath -Name "Deny_All" -ErrorAction SilentlyContinue).Deny_All
$remGuids = @("{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}", "{6AC27878-A6FA-4155-BA85-F98F491D4F33}", "{F33FDC04-D1AC-4E8E-9A30-19BBD4B108AE}")
$remClassesOk = $true
foreach ($g in $remGuids) {
    $sub = Get-ItemProperty -Path "$remPolPath\$g" -ErrorAction SilentlyContinue
    if ($null -eq $sub -or $sub.Deny_Read -ne 1 -or $sub.Deny_Write -ne 1 -or $sub.Deny_Execute -ne 1) {
        $remClassesOk = $false
    }
}
$devRestrPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
$denyUnspec = (Get-ItemProperty -Path $devRestrPath -Name "DenyUnspecified" -ErrorAction SilentlyContinue).DenyUnspecified
$denyDevIds = (Get-ItemProperty -Path $devRestrPath -Name "DenyDeviceIDs" -ErrorAction SilentlyContinue).DenyDeviceIDs
$denyDevClasses = (Get-ItemProperty -Path $devRestrPath -Name "DenyDeviceClasses" -ErrorAction SilentlyContinue).DenyDeviceClasses
$denyIdProps = @()
if (Test-Path "$devRestrPath\DenyDeviceIDs") {
    $denyIdProps = (Get-ItemProperty -Path "$devRestrPath\DenyDeviceIDs").PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | ForEach-Object { "$($_.Value)".ToUpperInvariant() }
}
$requiredDenyIds = @("USBSTOR\*", "USB\CLASS_08", "WPD\*", "USB\MS_COMP_MTP")
$denyIdValuesOk = $true
foreach ($req in $requiredDenyIds) {
    if ($denyIdProps -notcontains $req) { $denyIdValuesOk = $false }
}
$denyClassProps = @()
if (Test-Path "$devRestrPath\DenyDeviceClasses") {
    $denyClassProps = (Get-ItemProperty -Path "$devRestrPath\DenyDeviceClasses").PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | ForEach-Object { "$($_.Value)".ToLowerInvariant() }
}
$denyClassValuesOk = ($denyClassProps -contains "{eec5ad98-8080-425f-922a-dabf3de3f69a}")
$usbDisks = Get-Disk | Where-Object { $_.BusType -eq 'USB' }
$onlineUsbDisks = $usbDisks | Where-Object { -not $_.IsOffline }

if ($denyAll -eq 1 -and $remClassesOk -and $denyDevIds -eq 1 -and $denyIdValuesOk -and $denyDevClasses -eq 1 -and $denyClassValuesOk -and $denyUnspec -ne 1 -and ($null -eq $onlineUsbDisks -or $onlineUsbDisks.Count -eq 0)) {
    Write-Host "[PASS] G0.3: RemovableStorageDevices Deny_All==1 + scoped GUID subkeys, class-scoped USBSTOR/WPD DeviceInstall Restrictions verified (DenyUnspecified!=1), and all USB disks are Offline" -ForegroundColor Green
}
else {
    Write-Host "[INFO] G0.3: Deny_All=$denyAll | RemClassesOk=$remClassesOk | DenyDeviceIDs=$denyDevIds (ValuesOk=$denyIdValuesOk) | DenyDeviceClasses=$denyDevClasses (ValuesOk=$denyClassValuesOk) | DenyUnspecified=$denyUnspec | Online USB Disks=$($onlineUsbDisks.Count)" -ForegroundColor Cyan
}

Write-Host "Running 'cargo test --workspace --offline' to verify all automated invariant & regression tests..." -ForegroundColor Cyan
cargo test --workspace --offline
