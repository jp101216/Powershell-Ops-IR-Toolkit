#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Scans for and applies driver, firmware, and BIOS updates on Windows 11.

.DESCRIPTION
    A layered, OPSEC-friendly update assistant:
      1. Reports system identity + current BIOS / firmware version.
      2. Pulls DRIVER + FIRMWARE updates published through Windows Update
         (uses the built-in Windows Update Agent COM API - no module needed).
      3. Routes BIOS / firmware to the correct OEM tool (Dell / HP / Lenovo /
         Surface) or flags a manual path for custom / whitebox builds.
      4. Optionally upgrades installed apps + OEM utilities via winget.

    SAFETY: This script never flashes the BIOS itself. A failed flash can brick
    a board. OEM tools (Dell Command Update, etc.) include AC/battery checks and
    recovery paths, so the actual flash is delegated to them on purpose.

.PARAMETER AutoInstall
    Apply Windows Update driver/firmware updates without an interactive prompt.

.PARAMETER IncludeApps
    Also run `winget upgrade --all` for installed applications.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Update-System.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Update-System.ps1 -AutoInstall -IncludeApps

.NOTES
    Must run elevated (the #Requires line enforces this).
    Log is written to %ProgramData%\SystemUpdateToolkit\.
#>

[CmdletBinding()]
param(
    [switch]$AutoInstall,
    [switch]$IncludeApps
)

# ---------------------------------------------------------------------------
# Setup + logging
# ---------------------------------------------------------------------------
$ErrorActionPreference = 'Stop'
$logDir = Join-Path $env:ProgramData 'SystemUpdateToolkit'
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
$logFile = Join-Path $logDir ("update_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))
Start-Transcript -Path $logFile -Append | Out-Null

function Write-Section($t) {
    Write-Host ''
    Write-Host ('=' * 72) -ForegroundColor DarkCyan
    Write-Host "  $t"        -ForegroundColor Cyan
    Write-Host ('=' * 72) -ForegroundColor DarkCyan
}
function Write-Info($t) { Write-Host "[*] $t" -ForegroundColor Gray }
function Write-Good($t) { Write-Host "[+] $t" -ForegroundColor Green }
function Write-Warn2($t){ Write-Host "[!] $t" -ForegroundColor Yellow }
function Write-Bad($t)  { Write-Host "[x] $t" -ForegroundColor Red }

# ---------------------------------------------------------------------------
# 1. System identity
# ---------------------------------------------------------------------------
function Get-SystemInfo {
    Write-Section 'System Identity'
    $cs   = Get-CimInstance Win32_ComputerSystem
    $bios = Get-CimInstance Win32_BIOS
    $os   = Get-CimInstance Win32_OperatingSystem
    $bb   = Get-CimInstance Win32_BaseBoard

    $info = [pscustomobject]@{
        Manufacturer = $cs.Manufacturer
        Model        = $cs.Model
        Motherboard  = "$($bb.Manufacturer) $($bb.Product)"
        Serial       = $bios.SerialNumber
        BiosVersion  = $bios.SMBIOSBIOSVersion
        BiosDate     = $bios.ReleaseDate
        OS           = "$($os.Caption) (build $($os.BuildNumber))"
    }

    $info | Format-List | Out-String | Write-Host
    return $info
}

# ---------------------------------------------------------------------------
# 2. Driver + firmware updates via the Windows Update Agent (COM)
# ---------------------------------------------------------------------------
function Invoke-WindowsUpdateDrivers {
    param([switch]$Apply)

    Write-Section 'Windows Update - Drivers & Firmware'

    # Opt in to the Microsoft Update service for broader driver coverage.
    try {
        $sm = New-Object -ComObject Microsoft.Update.ServiceManager
        $sm.AddService2('7971f918-a847-4430-9279-4a52d1efe18d', 7, '') | Out-Null
        Write-Info 'Microsoft Update service registered.'
    } catch {
        Write-Warn2 "Could not register Microsoft Update service: $($_.Exception.Message)"
    }

    $session  = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()

    Write-Info 'Searching for driver and firmware updates...'
    # Firmware on Windows is delivered as a driver update, so this covers both.
    $result = $searcher.Search("IsInstalled=0 AND Type='Driver'")

    if ($result.Updates.Count -eq 0) {
        Write-Good 'No driver/firmware updates available from Windows Update.'
        return
    }

    Write-Warn2 "$($result.Updates.Count) update(s) found:"
    foreach ($u in $result.Updates) {
        Write-Host "    - $($u.Title)" -ForegroundColor White
    }

    if (-not $Apply) {
        Write-Info 'Scan only. Re-run with -AutoInstall (or choose Install from the menu) to apply.'
        return
    }

    $toInstall = New-Object -ComObject Microsoft.Update.UpdateColl
    foreach ($u in $result.Updates) {
        if (-not $u.EulaAccepted) { $u.AcceptEula() }
        $toInstall.Add($u) | Out-Null
    }

    Write-Info 'Downloading...'
    $downloader = $session.CreateUpdateDownloader()
    $downloader.Updates = $toInstall
    $downloader.Download() | Out-Null

    Write-Info 'Installing...'
    $installer = $session.CreateUpdateInstaller()
    $installer.Updates = $toInstall
    $install = $installer.Install()

    switch ($install.ResultCode) {
        2 { Write-Good 'Installation succeeded.' }
        3 { Write-Warn2 'Installation succeeded with errors. Check the log.' }
        default { Write-Bad "Install result code: $($install.ResultCode)" }
    }
    if ($install.RebootRequired) {
        Write-Warn2 'A reboot is required to finish installation.'
    }
}

# ---------------------------------------------------------------------------
# 3. BIOS / firmware routing by manufacturer
# ---------------------------------------------------------------------------
function Invoke-BiosRouting {
    param([Parameter(Mandatory)] $Info)

    Write-Section 'BIOS / Firmware (OEM tool routing)'
    Write-Info "Current BIOS: $($Info.BiosVersion)  (released $($Info.BiosDate))"

    $mfr = ($Info.Manufacturer + ' ' + $Info.Motherboard).ToLower()

    # winget package IDs for the relevant OEM updater. Verify with `winget search`.
    $tool = switch -Regex ($mfr) {
        'dell'                 { @{ Name='Dell Command | Update';   Id='Dell.CommandUpdate' }; break }
        'lenovo'               { @{ Name='Lenovo System Update';    Id='Lenovo.SystemUpdate' }; break }
        'hp|hewlett'           { @{ Name='HP Image Assistant';      Id='HP.ImageAssistant' }; break }
        'microsoft'            { @{ Name='Surface (via Windows Update / MSI)'; Id=$null }; break }
        'asus'                 { @{ Name='MyASUS / Armoury Crate';  Id='9N7R5S6B0ZZH' }; break }   # MyASUS (Store id)
        'msi|micro-star'       { @{ Name='MSI Center';              Id='9NVMNJCR03XV' }; break }    # MSI Center (Store id)
        'gigabyte'             { @{ Name='GIGABYTE Control Center'; Id=$null }; break }
        'asrock'               { @{ Name='ASRock (manual)';         Id=$null }; break }
        default                { @{ Name=$null; Id=$null } }
    }

    if (-not $tool.Name) {
        Write-Warn2 'Manufacturer not recognized for automated BIOS routing.'
        Write-Info  "Update BIOS manually from your motherboard vendor's support page for: $($Info.Motherboard)"
        return
    }

    Write-Info "Recommended OEM tool: $($tool.Name)"

    if ($tool.Id) {
        $choice = Read-Host "Install/launch $($tool.Name) via winget now? (y/N)"
        if ($choice -eq 'y') {
            try {
                winget install --id $tool.Id --accept-source-agreements --accept-package-agreements -e
                Write-Good "$($tool.Name) installed. Open it to review and apply BIOS/firmware updates."
            } catch {
                Write-Bad "winget install failed: $($_.Exception.Message)"
                Write-Info "Try `winget search '$($tool.Name)'` to confirm the package id."
            }
        }
    } else {
        Write-Info "No winget package mapped. Get the BIOS update from the vendor support site and let their tool perform the flash."
    }

    Write-Warn2 'BIOS flash safety: plug in AC power, do not interrupt, and let the OEM tool do the actual flash.'
}

# ---------------------------------------------------------------------------
# 4. App / utility upgrades via winget
# ---------------------------------------------------------------------------
function Invoke-WingetUpgrade {
    Write-Section 'Application & Utility Upgrades (winget)'
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-Bad 'winget not found. Install "App Installer" from the Microsoft Store.'
        return
    }
    Write-Info 'Listing available upgrades...'
    winget upgrade --include-unknown
    $choice = Read-Host 'Upgrade all listed apps now? (y/N)'
    if ($choice -eq 'y') {
        winget upgrade --all --include-unknown --accept-source-agreements --accept-package-agreements
        Write-Good 'winget upgrade complete.'
    }
}

# ---------------------------------------------------------------------------
# Menu
# ---------------------------------------------------------------------------
function Show-Menu {
    param([Parameter(Mandatory)] $Info)
    while ($true) {
        Write-Section 'System Update Toolkit'
        Write-Host '  1) Scan for driver/firmware updates (Windows Update)'
        Write-Host '  2) Scan AND install driver/firmware updates'
        Write-Host '  3) BIOS / firmware (route to OEM tool)'
        Write-Host '  4) App / utility upgrades (winget)'
        Write-Host '  5) Run everything'
        Write-Host '  Q) Quit'
        $sel = Read-Host 'Select'
        switch ($sel.ToUpper()) {
            '1' { Invoke-WindowsUpdateDrivers }
            '2' { Invoke-WindowsUpdateDrivers -Apply }
            '3' { Invoke-BiosRouting -Info $Info }
            '4' { Invoke-WingetUpgrade }
            '5' { Invoke-WindowsUpdateDrivers -Apply; Invoke-BiosRouting -Info $Info; Invoke-WingetUpgrade }
            'Q' { return }
            default { Write-Warn2 'Invalid choice.' }
        }
    }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
try {
    $info = Get-SystemInfo

    if ($AutoInstall -or $IncludeApps) {
        # Non-interactive path
        Invoke-WindowsUpdateDrivers -Apply:$AutoInstall
        Invoke-BiosRouting -Info $info
        if ($IncludeApps) { Invoke-WingetUpgrade }
    } else {
        Show-Menu -Info $info
    }
}
catch {
    Write-Bad "Fatal error: $($_.Exception.Message)"
}
finally {
    Write-Info "Log saved to: $logFile"
    Stop-Transcript | Out-Null
}
