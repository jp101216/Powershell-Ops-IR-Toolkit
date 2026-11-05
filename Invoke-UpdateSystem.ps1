#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Scans for and applies driver, firmware, and BIOS updates on Windows 10/11 and Windows Server.

.DESCRIPTION
    Version 2.0.0 - modernized from Invoke-UpdateSystem.ps1.

    A layered, OPSEC-friendly update assistant:
      1. Reports system identity and the current BIOS / firmware version.
      2. Pulls DRIVER and FIRMWARE updates published through Windows Update,
         using the built-in Windows Update Agent COM API. No module is needed.
      3. Routes BIOS / firmware to the correct OEM tool (Dell / HP / Lenovo /
         Surface / ASUS / MSI / Gigabyte / ASRock / Acer / Samsung) or flags
         a manual path for custom / whitebox builds.
      4. Optionally upgrades installed apps and OEM utilities via winget.

    SAFETY: This script never flashes the BIOS itself. A failed flash can
    brick a board. OEM tools include AC/battery checks and recovery paths,
    so the actual flash is deliberately delegated to them.

    What changed in v2:
      - Works on Windows PowerShell 5.1 AND PowerShell 7.x on Windows.
        The code stays 5.1-compatible (no ternary, null-coalescing, or
        PS7-only operators) and guards PS7-only behaviour.
      - Non-interactive mode actually works. The original script prompted
        with Read-Host even when -AutoInstall was used, which hangs a
        scheduled task. -NonInteractive skips prompts; -Force answers
        them "yes" instead of hanging.
      - -WhatIf / -Confirm support via SupportsShouldProcess.
      - Per-update download/install results, including HResult, instead of
        only an overall result code.
      - Windows Update COM objects are released in a finally block.
      - Each CIM query is isolated, so one unreadable class no longer
        aborts the whole run. BIOS dates are formatted, not raw CIM dates.
      - OEM detection checks manufacturer, then model, then motherboard,
        checks whether the OEM tool is already installed, and no longer
        hard-codes Microsoft Store IDs that change without warning.
      - winget failures are checked via $LASTEXITCODE, not ignored.
      - A machine-readable JSON report is written next to the transcript
        log, so the run can be audited or fed into another tool.
      - Transcript start/stop is guarded: a transcript that is already
        running, or a host that does not support one, no longer crashes
        the script.

.PARAMETER AutoInstall
    Apply Windows Update driver/firmware updates without an interactive prompt.

.PARAMETER ScanOnly
    Report system identity, available driver/firmware updates, and the OEM
    recommendation without entering the menu or applying updates. Scans use
    the configured Windows Update source and write the usual audit report.

.PARAMETER IncludeApps
    Also run `winget upgrade --all` for installed applications.

.PARAMETER NonInteractive
    Never prompt. Prompts are skipped unless -Force is also given, in which
    case they are answered "yes". Use this for scheduled tasks. If input is
    redirected, the script behaves as non-interactive even without this switch.

.PARAMETER Force
    In interactive mode, skip confirmation prompts. In non-interactive mode,
    answer prompts "yes" instead of skipping the action.

.PARAMETER SkipBiosRouting
    Skip the BIOS / firmware OEM-tool routing step.

.PARAMETER AllowReboot
    If a reboot is required, offer to reboot immediately (interactive mode
    only). Without this switch the script only reports that a reboot is needed.
    It never reboots on its own.

.PARAMETER LogDirectory
    Directory for the transcript log and the default JSON report.
    Defaults to %ProgramData%\SystemUpdateToolkit.

.PARAMETER ReportPath
    Full path for the JSON summary report. Defaults to a timestamped file
    inside LogDirectory.

.PARAMETER RedactSerial
    Replace the system serial number with "REDACTED" in console output,
    the transcript, and the JSON report.

.EXAMPLE
    powershell -File .\Invoke-UpdateSystem.ps1

.EXAMPLE
    powershell -File .\Invoke-UpdateSystem.ps1 -AutoInstall -IncludeApps

.EXAMPLE
    powershell -File .\Invoke-UpdateSystem.ps1 -ScanOnly -ReportPath C:\Reports\update.json

.EXAMPLE
    # Dry run: show what would be installed, change nothing.
    powershell -File .\Invoke-UpdateSystem.ps1 -AutoInstall -WhatIf

.NOTES
    Must run elevated. The #Requires line enforces this on Windows.
    Log and report are written to %ProgramData%\SystemUpdateToolkit\ by default.
    This script was reviewed for PowerShell 5.1 / 7.x syntax on Windows 10/11
    and Windows Server 2016-2025. Run a scan-only pass first on a new host
    before using -AutoInstall.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [switch]$AutoInstall,
    [switch]$ScanOnly,
    [switch]$IncludeApps,
    [switch]$NonInteractive,
    [switch]$Force,
    [switch]$SkipBiosRouting,
    [switch]$AllowReboot,
    [switch]$RedactSerial,
    [string]$LogDirectory,
    [string]$ReportPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($ScanOnly -and ($AutoInstall -or $IncludeApps -or $AllowReboot)) {
    throw '-ScanOnly cannot be combined with -AutoInstall, -IncludeApps, or -AllowReboot.'
}

# Script-level state, initialised up front for Set-StrictMode.
$script:IsNonInteractive = $false
$script:TranscriptStarted = $false
$script:LogFile = $null
$script:ReportFile = $null
$script:Report = $null

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
function Write-Section {
    param([Parameter(Mandatory = $true)][string]$Text)
    Write-Host ''
    Write-Host ('=' * 72) -ForegroundColor DarkCyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host ('=' * 72) -ForegroundColor DarkCyan
}

function Write-Info {
    param([Parameter(Mandatory = $true)][string]$Text)
    Write-Host "[*] $Text" -ForegroundColor Gray
}

function Write-Good {
    param([Parameter(Mandatory = $true)][string]$Text)
    Write-Host "[+] $Text" -ForegroundColor Green
}

function Write-Warn {
    param([Parameter(Mandatory = $true)][string]$Text)
    Write-Host "[!] $Text" -ForegroundColor Yellow
}

function Write-Bad {
    param([Parameter(Mandatory = $true)][string]$Text)
    Write-Host "[x] $Text" -ForegroundColor Red
}

function Test-IsInteractive {
    # Console input redirection is the reliable signal for a scheduled task
    # or piped run, even if the caller forgot -NonInteractive.
    if ($script:IsNonInteractive) { return $false }
    try {
        if ([Console]::IsInputRedirected) { return $false }
    }
    catch {
        # Some hosts do not expose Console input; fall through to interactive.
    }
    return $true
}

function Confirm-UserChoice {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [string]$Prompt = ' (y/N) '
    )
    if (-not (Test-IsInteractive)) {
        # Non-interactive: -Force means "yes", otherwise skip the action.
        return [bool]$Force
    }
    if ($Force) { return $true }
    $choice = Read-Host ($Message + $Prompt)
    return ($choice -eq 'y' -or $choice -eq 'Y' -or $choice -eq 'yes' -or $choice -eq 'Yes' -or $choice -eq 'YES')
}

# ---------------------------------------------------------------------------
# 1. System identity
# ---------------------------------------------------------------------------
function Get-CimInstanceSafe {
    param(
        [Parameter(Mandatory = $true)][string]$ClassName,
        [string[]]$Property
    )
    try {
        if ($Property) {
            return Get-CimInstance -ClassName $ClassName -Property $Property -ErrorAction Stop |
                Select-Object -First 1
        }
        else {
            return Get-CimInstance -ClassName $ClassName -ErrorAction Stop |
                Select-Object -First 1
        }
    }
    catch {
        Write-Warn "Could not read $ClassName`: $($_.Exception.Message)"
        return $null
    }
}

function Get-SystemInfo {
    Write-Section 'System Identity'

    $cs = Get-CimInstanceSafe -ClassName 'Win32_ComputerSystem' -Property @('Manufacturer', 'Model', 'PCSystemType')
    $bios = Get-CimInstanceSafe -ClassName 'Win32_BIOS' -Property @('SerialNumber', 'SMBIOSBIOSVersion', 'ReleaseDate')
    $os = Get-CimInstanceSafe -ClassName 'Win32_OperatingSystem' -Property @('Caption', 'BuildNumber', 'OSArchitecture', 'Version')
    $bb = Get-CimInstanceSafe -ClassName 'Win32_BaseBoard' -Property @('Manufacturer', 'Product')

    $biosDate = $null
    if ($null -ne $bios -and $null -ne $bios.ReleaseDate) {
        if ($bios.ReleaseDate -is [datetime]) {
            $biosDate = $bios.ReleaseDate.ToString('yyyy-MM-dd')
        }
        else {
            $biosDate = [string]$bios.ReleaseDate
        }
    }

    $serial = $null
    if ($null -ne $bios) { $serial = $bios.SerialNumber }
    if ($RedactSerial) { $serial = 'REDACTED' }

    $info = [pscustomobject]@{
        Manufacturer = if ($null -ne $cs) { $cs.Manufacturer }
        Model        = if ($null -ne $cs) { $cs.Model }
        IsPortable   = ($null -ne $cs -and $cs.PCSystemType -eq 2)
        Motherboard  = if ($null -ne $bb) { "$($bb.Manufacturer) $($bb.Product)".Trim() }
        Serial       = $serial
        BiosVersion  = if ($null -ne $bios) { $bios.SMBIOSBIOSVersion }
        BiosDate     = $biosDate
        OS           = if ($null -ne $os) { $os.Caption }
        OSBuild      = if ($null -ne $os) { $os.BuildNumber }
        OSVersion    = if ($null -ne $os) { $os.Version }
        Architecture = if ($null -ne $os) { $os.OSArchitecture }
    }

    $info | Format-List | Out-String | Write-Host
    return $info
}

function Test-AcPower {
    # Returns 'Online', 'Offline', or 'Unknown'. Never throws.
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop | Out-Null
        $status = [System.Windows.Forms.SystemInformation]::PowerStatus
        return $status.PowerLineStatus.ToString()
    }
    catch {
        return 'Unknown'
    }
}

# ---------------------------------------------------------------------------
# 2. Driver + firmware updates via the Windows Update Agent (COM)
# ---------------------------------------------------------------------------
function Invoke-WindowsUpdateDrivers {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([switch]$Apply)

    Write-Section 'Windows Update - Drivers & Firmware'

    $session = $null
    $searcher = $null
    $downloader = $null
    $installer = $null
    $toDownload = $null
    $toInstall = $null
    $result = $null
    $downloadResult = $null
    $installResult = $null

    $summary = [pscustomobject]@{
        Found          = 0
        Titles         = @()
        ScanStatus     = 'Failed'
        InstallStatus  = if ($Apply) { 'NotStarted' } else { 'NotRequested' }
        Updates        = @()
        Installed      = $false
        InstallErrors  = @()
        RebootRequired = $false
    }

    try {
        # Let WUA select the configured source and manage its service lifecycle.
        $session = New-Object -ComObject 'Microsoft.Update.Session' -ErrorAction Stop
        $searcher = $session.CreateUpdateSearcher()

        Write-Info 'Searching for driver and firmware updates...'
        # Firmware on Windows is delivered as a driver update, so this covers both.
        # IsHidden=0 keeps hidden / declined updates out of the list.
        $result = $searcher.Search("IsInstalled=0 AND Type='Driver' AND IsHidden=0")

        if ($null -eq $result -or $result.ResultCode -notin @(2, 3)) {
            $resultCode = if ($null -ne $result) { $result.ResultCode } else { 'unavailable' }
            throw "Windows Update search did not complete (ResultCode $resultCode)."
        }
        $summary.ScanStatus = 'Succeeded'
        if ($result.ResultCode -eq 3) {
            $summary.ScanStatus = 'Partial'
            $message = 'Windows Update search returned partial results. Installation skipped.'
            $summary.InstallErrors += $message
            Write-Warn $message
        }

        $summary.Found = $result.Updates.Count
        if ($summary.Found -eq 0) {
            if ($summary.ScanStatus -eq 'Succeeded') {
                Write-Good 'No driver/firmware updates available from the configured source.'
                if ($Apply) { $summary.InstallStatus = 'NoUpdates' }
            }
            return $summary
        }
        Write-Warn "$($summary.Found) update(s) found:"
        $summary.Updates = @(foreach ($update in $result.Updates) {
            Write-Host "    - $($update.Title)" -ForegroundColor White
            [pscustomobject]@{
                Title              = $update.Title
                DownloadResultCode = $null
                DownloadHResult    = $null
                InstallResultCode  = $null
                InstallHResult     = $null
            }
        })
        $summary.Titles = @($summary.Updates.Title)

        if (-not $Apply) {
            Write-Info 'Scan only. Re-run with -AutoInstall to apply.'
            return $summary
        }
        if ($summary.ScanStatus -ne 'Succeeded') { return $summary }

        if (-not $PSCmdlet.ShouldProcess("$($summary.Found) driver/firmware update(s)", 'Download and install')) {
            Write-Info 'Skipped by -WhatIf / -Confirm.'
            $summary.InstallStatus = 'Skipped'
            return $summary
        }

        $summary.InstallStatus = 'Failed'
        $toDownload = New-Object -ComObject 'Microsoft.Update.UpdateColl' -ErrorAction Stop
        foreach ($update in $result.Updates) {
            if (-not $update.EulaAccepted) { $update.AcceptEula() | Out-Null }
            $toDownload.Add($update) | Out-Null
        }

        Write-Info 'Downloading...'
        $downloader = $session.CreateUpdateDownloader()
        $downloader.Updates = $toDownload
        $downloadResult = $downloader.Download()

        $toInstall = New-Object -ComObject 'Microsoft.Update.UpdateColl' -ErrorAction Stop
        $installDetails = @(for ($i = 0; $i -lt $toDownload.Count; $i++) {
            $update = $toDownload.Item($i)
            $detail = $summary.Updates[$i]
            $itemResult = $downloadResult.GetUpdateResult($i)
            $detail.DownloadResultCode = $itemResult.ResultCode
            $detail.DownloadHResult = '0x{0:X8}' -f $itemResult.HResult
            if ($itemResult.ResultCode -ne 2) {
                $message = "$($detail.Title) download returned ResultCode $($detail.DownloadResultCode) (HResult $($detail.DownloadHResult))."
                $summary.InstallErrors += $message
                Write-Warn $message
            }
            if ($update.IsDownloaded) {
                $toInstall.Add($update) | Out-Null
                $detail
            }
        })
        if ($downloadResult.ResultCode -notin @(2, 3) -or $toInstall.Count -eq 0) {
            $message = "No installation performed (download ResultCode $($downloadResult.ResultCode), $($toInstall.Count) ready to install)."
            Write-Bad $message
            $summary.InstallErrors += $message
            return $summary
        }

        Write-Info 'Installing...'
        $installer = $session.CreateUpdateInstaller()
        $installer.Updates = $toInstall
        $installResult = $installer.Install()
        $summary.RebootRequired = [bool]$installResult.RebootRequired

        $successful = 0
        for ($i = 0; $i -lt $toInstall.Count; $i++) {
            $detail = $installDetails[$i]
            $itemResult = $installResult.GetUpdateResult($i)
            $detail.InstallResultCode = $itemResult.ResultCode
            $detail.InstallHResult = '0x{0:X8}' -f $itemResult.HResult
            if ($itemResult.ResultCode -in @(2, 3)) { $successful++ }
            if ($itemResult.ResultCode -ne 2) {
                $message = "$($detail.Title) installation returned ResultCode $($detail.InstallResultCode) (HResult $($detail.InstallHResult))."
                $summary.InstallErrors += $message
                Write-Bad $message
            }
        }

        $summary.Installed = $successful -gt 0
        if ($installResult.ResultCode -eq 2 -and $successful -eq $summary.Found -and $summary.InstallErrors.Count -eq 0) {
            $summary.InstallStatus = 'Succeeded'
            Write-Good 'Installation succeeded.'
        }
        else {
            if ($summary.Installed) { $summary.InstallStatus = 'Partial' }
            $message = "Installation $($summary.InstallStatus.ToLowerInvariant()) (ResultCode $($installResult.ResultCode))."
            Write-Warn $message
            $summary.InstallErrors += $message
        }
        if ($summary.RebootRequired) {
            Write-Warn 'A reboot is required to finish installation.'
        }
        return $summary
    }
    catch {
        Write-Bad "Windows Update failed: $($_.Exception.Message)"
        $summary.InstallErrors += $_.Exception.Message
        return $summary
    }
    finally {
        $comObjects = $installResult, $downloadResult, $result, $installer, $downloader,
                      $toInstall, $toDownload, $searcher, $session
        foreach ($comObject in $comObjects) {
            if ($null -ne $comObject) {
                try { [System.Runtime.InteropServices.Marshal]::ReleaseComObject($comObject) | Out-Null } catch { }
            }
        }
    }
}

# ---------------------------------------------------------------------------
# 3. BIOS / firmware routing by manufacturer
# ---------------------------------------------------------------------------
function Get-OemTool {
    param([Parameter(Mandatory = $true)]$Info)

    # Check the system manufacturer before the model or motherboard vendor.
    # For vendors without a mapped winget package, use SearchName.
    $candidates = @(
        @{ Pattern = 'dell';                Name = 'Dell Command | Update'; Id = 'Dell.CommandUpdate';  SearchName = 'Dell Command Update'; CliNames = @('dcu-cli.exe') }
        @{ Pattern = 'lenovo';              Name = 'Lenovo System Update';   Id = 'Lenovo.SystemUpdate'; SearchName = 'Lenovo System Update'; CliNames = @() }
        @{ Pattern = '\bhp\b|hewlett';      Name = 'HP Image Assistant';     Id = 'HP.ImageAssistant';  SearchName = 'HP Image Assistant';   CliNames = @() }
        @{ Pattern = 'microsoft|surface';   Name = 'Surface (via Windows Update)'; Id = $null; SearchName = 'Surface firmware'; CliNames = @() }
        @{ Pattern = 'asus|asustek';        Name = 'MyASUS';                 Id = $null; SearchName = 'MyASUS';                 CliNames = @() }
        @{ Pattern = 'msi|micro-star';      Name = 'MSI Center';             Id = $null; SearchName = 'MSI Center';             CliNames = @() }
        @{ Pattern = 'gigabyte';            Name = 'GIGABYTE Control Center'; Id = $null; SearchName = 'GIGABYTE Control Center'; CliNames = @() }
        @{ Pattern = 'asrock';              Name = 'ASRock (manual)';        Id = $null; SearchName = 'ASRock BIOS';            CliNames = @() }
        @{ Pattern = 'acer';                Name = 'Acer Care Center';       Id = $null; SearchName = 'Acer Care Center';       CliNames = @() }
        @{ Pattern = 'samsung';             Name = 'Samsung Update';         Id = $null; SearchName = 'Samsung Update';         CliNames = @() }
    )

    foreach ($value in @($Info.Manufacturer, $Info.Model, $Info.Motherboard)) {
        foreach ($candidate in $candidates) {
            if ($value -match $candidate.Pattern) {
                return [pscustomobject]$candidate
            }
        }
    }
    return $null
}

function Test-OemToolInstalled {
    param([Parameter(Mandatory = $true)]$Tool)
    foreach ($cliName in $Tool.CliNames) {
        $command = Get-Command -Name $cliName -ErrorAction SilentlyContinue
        if ($null -ne $command) { return $command }
    }
    return $null
}

function Invoke-BiosRouting {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]$Info,
        [switch]$RecommendOnly
    )

    Write-Section 'BIOS / Firmware (OEM tool routing)'
    Write-Info "Current BIOS: $($Info.BiosVersion)  (released $($Info.BiosDate))"

    $powerStatus = Test-AcPower
    if ($Info.IsPortable -and $powerStatus -eq 'Offline') {
        Write-Warn 'This looks like a laptop running on battery. Plug in AC power before any BIOS flash.'
    }
    elseif ($powerStatus -eq 'Unknown') {
        Write-Info 'AC power status could not be determined. Plug in AC power before any BIOS flash.'
    }
    Write-Warn 'BIOS flash safety: plug in AC power, do not interrupt, and let the OEM tool do the actual flash. This script never flashes itself.'

    $tool = Get-OemTool -Info $Info
    if ($null -eq $tool) {
        Write-Warn 'Manufacturer not recognized for automated BIOS routing.'
        Write-Info "Update BIOS manually from your motherboard vendor's support page for: $($Info.Motherboard)"
        return $tool
    }

    Write-Info "Recommended OEM tool: $($tool.Name)"
    if ($tool.Name -like 'HP Image Assistant*') {
        Write-Info 'Note: HP Image Assistant is the enterprise tool. On a consumer HP PC, HP Support Assistant may be the right tool instead.'
    }
    if ($tool.Name -like 'Surface*') {
        Write-Info 'Surface firmware normally arrives through Windows Update. No separate OEM installer is needed.'
        return $tool
    }

    $installedCommand = Test-OemToolInstalled -Tool $tool
    if ($null -ne $installedCommand) {
        Write-Good "$($tool.Name) appears to be installed ($($installedCommand.Source)). Open it to review and apply BIOS/firmware updates."
        return $tool
    }
    if ($RecommendOnly) { return $tool }

    if ($tool.Id) {
        if (-not (Test-IsInteractive) -and -not $Force) {
            Write-Info "Skipping OEM tool install in non-interactive mode. Re-run with -Force to install $($tool.Name) via winget."
            return $tool
        }
        if ($PSCmdlet.ShouldProcess($tool.Name, 'Install via winget')) {
            if ((Test-IsInteractive) -and -not $Force) {
                if (-not (Confirm-UserChoice -Message "Install $($tool.Name) via winget now?")) {
                    Write-Info 'Skipped OEM tool install.'
                    return $tool
                }
            }
            try {
                $wingetArgs = @('install', '--id', $tool.Id, '--accept-source-agreements', '--accept-package-agreements', '-e')
                if (-not (Test-IsInteractive)) { $wingetArgs += '--disable-interactivity' }
                & winget @wingetArgs | Out-Host
                if ($LASTEXITCODE -eq 0) {
                    Write-Good "$($tool.Name) installed. Open it to review and apply BIOS/firmware updates."
                }
                else {
                    Write-Bad "winget install failed (exit code $LASTEXITCODE)."
                    Write-Info "Try: winget search '$($tool.SearchName)' to confirm the package id."
                }
            }
            catch {
                Write-Bad "winget install failed: $($_.Exception.Message)"
                Write-Info "Try: winget search '$($tool.SearchName)' to confirm the package id."
            }
        }
    }
    else {
        Write-Info "No stable winget package mapped for $($tool.Name). Get it from the Microsoft Store (search '$($tool.SearchName)') or the vendor support site, and let their tool perform the flash."
    }
    return $tool
}

# ---------------------------------------------------------------------------
# 4. App / utility upgrades via winget
# ---------------------------------------------------------------------------
function Test-Winget {
    $command = Get-Command -Name 'winget' -ErrorAction SilentlyContinue
    if ($null -eq $command) { return $null }
    $version = $null
    try {
        $version = (& winget --version 2>$null) -join ' '
        if ($LASTEXITCODE -ne 0) { $version = $null }
    }
    catch {
        $version = $null
    }
    return [pscustomobject]@{ Command = $command; Version = $version }
}

function Invoke-WingetUpgrade {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()

    Write-Section 'Application & Utility Upgrades (winget)'
    if ($WhatIfPreference) {
        $null = $PSCmdlet.ShouldProcess('all installed apps', 'winget upgrade --all')
        return $false
    }

    $winget = Test-Winget
    if ($null -eq $winget) {
        Write-Bad 'winget not found. Install "App Installer" from the Microsoft Store.'
        return $false
    }
    if ($winget.Version) { Write-Info "winget version: $($winget.Version)" }

    Write-Info 'Listing available upgrades...'
    $listArgs = @('upgrade', '--include-unknown')
    if (-not (Test-IsInteractive)) { $listArgs += '--disable-interactivity' }
    & winget @listArgs | Out-Host
    if ($LASTEXITCODE -ne 0) {
        Write-Warn "winget upgrade listing returned exit code $LASTEXITCODE. Continuing to the prompt anyway."
    }

    if (-not (Test-IsInteractive) -and -not $Force) {
        Write-Info 'Non-interactive mode without -Force: listing only, apps were not upgraded.'
        return $false
    }

    if (-not $PSCmdlet.ShouldProcess('all installed apps', 'winget upgrade --all')) {
        Write-Info 'Skipped by -WhatIf / -Confirm.'
        return $false
    }

    if ((Test-IsInteractive) -and -not $Force) {
        if (-not (Confirm-UserChoice -Message 'Upgrade all listed apps now?')) {
            Write-Info 'Skipped app upgrades.'
            return $false
        }
    }

    $upgradeArgs = @('upgrade', '--all', '--include-unknown', '--accept-source-agreements', '--accept-package-agreements')
    if (-not (Test-IsInteractive)) { $upgradeArgs += '--disable-interactivity' }
    & winget @upgradeArgs | Out-Host
    if ($LASTEXITCODE -eq 0) {
        Write-Good 'winget upgrade complete.'
        return $true
    }
    else {
        Write-Bad "winget upgrade failed (exit code $LASTEXITCODE)."
        return $false
    }
}

# ---------------------------------------------------------------------------
# Menu
# ---------------------------------------------------------------------------
function Update-WindowsUpdateReport {
    param([Parameter(Mandatory = $true)]$Result)

    $script:Report.WindowsUpdate = $Result
    $script:Report.WindowsUpdateRuns += $Result
    if ($Result.RebootRequired) { $script:Report.RebootRequired = $true }
    $script:Report.Errors += $Result.InstallErrors
}

function Show-Menu {
    param([Parameter(Mandatory = $true)]$Info)
    while ($true) {
        Write-Section 'System Update Toolkit'
        Write-Host '  1) Scan for driver/firmware updates (Windows Update)'
        Write-Host '  2) Scan AND install driver/firmware updates'
        Write-Host '  3) BIOS / firmware (route to OEM tool)'
        Write-Host '  4) App / utility upgrades (winget)'
        Write-Host '  5) Run everything'
        Write-Host '  Q) Quit'
        $selection = Read-Host 'Select'
        if ([string]::IsNullOrWhiteSpace($selection)) { continue }
        switch ($selection.ToUpperInvariant()) {
            '1' { Update-WindowsUpdateReport -Result (Invoke-WindowsUpdateDrivers) }
            '2' { Update-WindowsUpdateReport -Result (Invoke-WindowsUpdateDrivers -Apply) }
            '3' {
                if ($SkipBiosRouting) { Write-Info 'BIOS routing skipped (-SkipBiosRouting).' }
                else { $script:Report.BiosTool = (Invoke-BiosRouting -Info $Info | Select-Object -ExpandProperty Name) }
            }
            '4' { if (Invoke-WingetUpgrade) { $script:Report.WingetUpgraded = $true } }
            '5' {
                Update-WindowsUpdateReport -Result (Invoke-WindowsUpdateDrivers -Apply)
                if (-not $SkipBiosRouting) {
                    $script:Report.BiosTool = (Invoke-BiosRouting -Info $Info | Select-Object -ExpandProperty Name)
                }
                if (Invoke-WingetUpgrade) { $script:Report.WingetUpgraded = $true }
            }
            'Q' { return }
            default { Write-Warn 'Invalid choice.' }
        }
        if (Test-IsInteractive) {
            Read-Host 'Press Enter to continue' | Out-Null
        }
    }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
try {
    # Platform gate that works in both editions: $IsWindows does not exist
    # in Windows PowerShell 5.1, so do not rely on it here.
    if ([Environment]::OSVersion.Platform -ne 'Win32NT') {
        throw 'This script requires Windows. The Windows Update COM API, CIM classes, and winget paths used here are Windows-only.'
    }

    # Elevation gate with a clear message if #Requires was bypassed.
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'This script must run elevated. Re-run from an elevated PowerShell prompt.'
    }

    $script:IsNonInteractive = [bool]$NonInteractive
    try {
        if ([Console]::IsInputRedirected) { $script:IsNonInteractive = $true }
    }
    catch { }

    if (-not $WhatIfPreference) {
        $logDir = $LogDirectory
        if ([string]::IsNullOrWhiteSpace($logDir)) {
            $logDir = Join-Path $env:ProgramData 'SystemUpdateToolkit'
        }
        try {
            if (-not (Test-Path -LiteralPath $logDir)) {
                New-Item -ItemType Directory -Path $logDir -Force -Confirm:$false -ErrorAction Stop | Out-Null
            }
        }
        catch {
            Write-Warn "Could not create log directory $logDir`: $($_.Exception.Message). Falling back to TEMP."
            $logDir = Join-Path $env:TEMP 'SystemUpdateToolkit'
            New-Item -ItemType Directory -Path $logDir -Force -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
        }

        $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss_fff'
        $script:LogFile = Join-Path $logDir ("update_{0}.log" -f $timestamp)
        $script:ReportFile = $ReportPath
        if ([string]::IsNullOrWhiteSpace($script:ReportFile)) {
            $script:ReportFile = Join-Path $logDir ("report_{0}.json" -f $timestamp)
        }

        try {
            Start-Transcript -LiteralPath $script:LogFile -NoClobber -ErrorAction Stop | Out-Null
            $script:TranscriptStarted = $true
        }
        catch {
            Write-Warn "Transcript could not be started ($($_.Exception.Message)). Continuing without it; the JSON report will still be written."
        }
    }

    $script:Report = [ordered]@{
        Timestamp       = (Get-Date).ToString('o')
        PowerShell      = $PSVersionTable.PSVersion.ToString()
        PSEdition       = $PSVersionTable.PSEdition
        Computer        = $env:COMPUTERNAME
        System          = $null
        WindowsUpdate   = $null
        WindowsUpdateRuns = @()
        BiosTool        = $null
        WingetUpgraded  = $false
        RebootRequired  = $false
        Errors          = @()
    }

    $info = Get-SystemInfo
    $script:Report.System = $info

    $automated = $ScanOnly -or $AutoInstall -or $IncludeApps -or $script:IsNonInteractive

    if ($automated) {
        # Non-interactive path: no menu, no Read-Host surprises.
        Update-WindowsUpdateReport -Result (Invoke-WindowsUpdateDrivers -Apply:$AutoInstall)

        if (-not $SkipBiosRouting) {
            $biosTool = Invoke-BiosRouting -Info $info -RecommendOnly:$ScanOnly
            if ($null -ne $biosTool) { $script:Report.BiosTool = $biosTool.Name }
        }

        if ($IncludeApps) {
            $script:Report.WingetUpgraded = (Invoke-WingetUpgrade)
        }
    }
    else {
        Show-Menu -Info $info
    }
}
catch {
    Write-Bad "Fatal error: $($_.Exception.Message)"
    if ($null -ne $script:Report) {
        $script:Report.Errors += $_.Exception.Message
    }
}
finally {
    if ($null -ne $script:Report -and $null -ne $script:ReportFile) {
        try {
            $script:Report | ConvertTo-Json -Depth 6 -ErrorAction Stop |
                Set-Content -LiteralPath $script:ReportFile -Encoding utf8 -Confirm:$false -ErrorAction Stop
            Write-Info "Report saved to: $($script:ReportFile)"
        }
        catch {
            Write-Warn "Could not write JSON report: $($_.Exception.Message)"
        }
    }
    if ($script:TranscriptStarted) {
        Write-Info "Log saved to: $($script:LogFile)"
    }
    if ($script:TranscriptStarted) {
        try { Stop-Transcript -ErrorAction Stop | Out-Null } catch { }
    }
}

if ($AllowReboot -and $null -ne $script:Report -and $script:Report.RebootRequired) {
    if ((Test-IsInteractive) -and $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Restart after installing updates')) {
        if (Confirm-UserChoice -Message 'Reboot now?') {
            Restart-Computer -Force -Confirm:$false
        }
    }
}
