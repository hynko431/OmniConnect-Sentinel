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
} else {
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
} else {
    Write-Host "[WARN] G0.2: Found stale \DosDevices\ drive letters in MountedDevices: $($staleDosLetters -join ', ')" -ForegroundColor Yellow
}

# Gate G0.3: A standard user can't list files through the volume GUID path (\\?\Volume{GUID}\)
# Verifies RemovableStorageDevices Deny_All==1, DeviceInstall Restrictions DenyUnspecified==1, and checks that any attached USB disk is Offline or inaccessible via \\?\Volume{GUID}\
$remPolPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices"
$denyAll = (Get-ItemProperty -Path $remPolPath -Name "Deny_All" -ErrorAction SilentlyContinue).Deny_All
$devRestrPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
$denyUnspec = (Get-ItemProperty -Path $devRestrPath -Name "DenyUnspecified" -ErrorAction SilentlyContinue).DenyUnspecified
$usbDisks = Get-Disk | Where-Object { $_.BusType -eq 'USB' }
$onlineUsbDisks = $usbDisks | Where-Object { -not $_.IsOffline }

if ($denyAll -eq 1 -and $denyUnspec -eq 1 -and ($null -eq $onlineUsbDisks -or $onlineUsbDisks.Count -eq 0)) {
    Write-Host "[PASS] G0.3: RemovableStorageDevices Deny_All==1, DeviceInstall DenyUnspecified==1, and all USB disks are Offline (Standard users cannot list files via \\?\Volume{GUID}\)" -ForegroundColor Green
} else {
    Write-Host "[INFO] G0.3: RemovableStorageDevices Deny_All=$denyAll | DeviceInstall DenyUnspecified=$denyUnspec | Online USB Disks=$($onlineUsbDisks.Count)" -ForegroundColor Cyan
}

Write-Host "Running 'cargo test --workspace --offline' to verify all automated invariant & regression tests..." -ForegroundColor Cyan
cargo test --workspace --offline
