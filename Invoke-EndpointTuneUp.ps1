#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Endpoint tune-up: resets and repairs the network stack and all network
    adapters, then cleans and optimizes the PC.

.DESCRIPTION
    Version 2.0.0 - modernized from Invoke-EndpointTuneUp.ps1.

    Designed to be run in an ELEVATED PowerShell session on the user's machine
    (e.g., a remote support session using admin credentials from a PAM/privileged-access vault).

    NETWORK   - snapshot ipconfig /all (before/after), flush + re-register DNS,
                purge ARP and NetBIOS caches, normalize TCP autotuning,
                disable NIC power-saving, Winsock + TCP/IP stack reset,
                restart physical adapters, DHCP release/renew.
    CLEANUP   - temp files (all user profiles + C:\Windows\Temp);
                optional Recycle Bin; optional DISM/SFC.
    OPTIMIZE  - Optimize-Volume on C: (TRIM for SSD / defrag for HDD),
                gpupdate /force, SCCM/MECM client policy + inventory triggers.

    A full transcript is written to C:\ProgramData\EndpointTuneUp\Logs by
    default, and a machine-readable JSON summary report is written next to
    it (see -ReportPath). The JSON report lists every step, its status and
    duration, failed and skipped steps, free space before/after, and whether
    a reboot is needed, so a run can be audited or pasted into a ticket
    without reading the whole transcript.

    Deliberately NOT included (compliance + managed-endpoint safety).
    None of these actions appear in this script, and none were added in v2:
      - Clearing Windows event logs
      - Resetting Windows Firewall policy
      - Clearing Prefetch (hurts performance; Windows rebuilds it)
      - Resetting the WinHTTP proxy (can break Zscaler/GPO proxy config)
      - Clearing the Windows Update download cache (SoftwareDistribution\Download)
      - Clearing the Delivery Optimization cache
      - Clearing Windows Error Reporting queues

    What changed in v2 (behaviour is otherwise unchanged):
      - Works on Windows PowerShell 5.1 AND PowerShell 7.x on Windows.
        The code stays 5.1-compatible (no ternary, null-coalescing, or
        PS7-only operators) and guards PS7-only behaviour. The Windows
        check uses [Environment]::OSVersion.Platform, not the automatic
        variable that does not exist in 5.1, and there is a clear
        elevation check if #Requires is bypassed.
      - Set-StrictMode -Version Latest and $ErrorActionPreference = 'Stop'
        are now set, so a failing cmdlet no longer logs "done". Every
        variable used under StrictMode is initialised up front, and the
        adapter wait loop, SCCM result, and free-space helpers all handle
        the null / missing-object case explicitly.
      - Native commands are now checked. The original script piped
        ipconfig, netsh, DISM, SFC, gpupdate, and shutdown output away
        and logged "done" even when the command failed, because a native
        command never throws in PowerShell. v2 checks $LASTEXITCODE for
        every native command and marks the step failed on a non-zero exit.
        Two deliberate exceptions: nbtstat and DHCP release/renew only
        warn on a non-zero exit, because NetBIOS is disabled on many
        modern hosts and a mixed static/DHCP machine can legitimately
        report per-adapter errors while succeeding overall.
      - Transcript handling is guarded. The original called
        Start-Transcript unguarded and then Stop-Transcript in finally,
        so if a transcript was already running the script died before
        any work, and the finally block could stop the caller's
        transcript. v2 only stops a transcript it started itself, and
        continues (with the JSON report) if a transcript cannot be started.
      - -WhatIf / -Confirm support via SupportsShouldProcess. Every
        mutating step is gated; read-only captures and the summary are
        not. With -WhatIf, no change is made, including no reboot.
      - -Quiet mode, in the house style: per-step console chatter is
        suppressed and a plain-text, ServiceNow-pasteable summary is
        printed at the end and copied to the clipboard on a best-effort
        basis (a clipboard failure never fails the run). In Quiet mode
        the ipconfig before/after snapshots are saved to files in the
        log directory instead of being dumped to the console, and the
        JSON report is the detailed step record.
      - -NonInteractive / -Force. Input redirection is treated as
        non-interactive, as in the companion UpdateSystem v2 script.
        -ClearRecycleBin now honours its own help text ("confirm with
        the user first"): in interactive mode it prompts unless -Force
        is given, and in non-interactive mode it is skipped unless
        -Force is given, so an unattended run cannot silently empty
        the Recycle Bin.
      - Per-adapter and per-schedule failures are no longer masked.
        Restarting adapters, changing NIC power management, and
        triggering SCCM schedules now report which adapter or schedule
        failed instead of silently continuing, and the SCCM step now
        checks that the client is running and checks the CIM method
        ReturnValue instead of logging "triggered" unconditionally.
      - The adapter wait loop now treats a missing adapter as still
        down, instead of counting it as back up because it was absent
        from the query result.
      - Log directory, report path, and log retention are configurable,
        with the original defaults preserved. Old JSON reports are
        pruned alongside old logs.

.PARAMETER Phase
    Run one or more of Network, Cleanup, and Optimize, in that order.
    Defaults to all three phases. Omitted steps appear as skipped in the report.

.PARAMETER SkipTempCleanup
    Skip temp folder cleanup. Combine with -Phase Cleanup -DeepClean to run
    DISM and SFC without clearing temp folders.

.PARAMETER SkipStackReset
    Skip 'netsh winsock reset' and 'netsh int ip/ipv6 reset'. Use this on
    machines with STATIC IP configs (the stack reset wipes them) or when a
    reboot is not possible today. The stack reset requires a reboot to apply.

.PARAMETER SkipAdapterRestart
    Skip the two steps that momentarily drop the remote session: restarting
    the physical adapters and DHCP release/renew. Most remote-support tools
    reconnect on their own within ~30-60 seconds, but use this if the session
    is fragile (e.g., user on weak Wi-Fi/VPN).

.PARAMETER ClearRecycleBin
    Also empty the Recycle Bin. Off by default because it deletes files the
    user may still expect to recover. In interactive mode you are prompted
    to confirm unless -Force is given. In non-interactive mode it is skipped
    unless -Force is given.

.PARAMETER DeepClean
    Also run DISM component-store cleanup and SFC /scannow. Adds roughly
    15-45 minutes; use when corruption is suspected or disk space is critical.
    A non-zero SFC exit code marks the step failed; check CBS.log.

.PARAMETER Reboot
    Restart the machine automatically when finished (with a countdown warning
    shown to the user). A reboot is required for the stack reset to apply.
    With -WhatIf, the reboot is skipped, not performed.

.PARAMETER RebootDelaySeconds
    Countdown before the automatic reboot. Default 60.

.PARAMETER Quiet
    Suppress per-step console output and print only warnings, errors, and a
    plain-text summary at the end, suitable for pasting into a ticket.
    The summary is also copied to the clipboard on a best-effort basis.
    Transcript and JSON report are still written; in Quiet mode the
    ipconfig snapshots go to files in the log directory instead of the
    console, and the JSON report is the detailed step record.

.PARAMETER NonInteractive
    Never prompt. Prompts are skipped unless -Force is also given, in which
    case they are answered "yes". Use this for scheduled or unattended runs.
    If input is redirected, the script behaves as non-interactive even
    without this switch.

.PARAMETER Force
    Skip the Recycle Bin confirmation prompt, and answer non-interactive
    prompts "yes" instead of skipping the action. -Force does not override
    an explicit -Confirm prompt.

.PARAMETER LogDirectory
    Directory for the transcript log, the JSON report, and (in Quiet mode)
    the ipconfig snapshots. Defaults to C:\ProgramData\EndpointTuneUp\Logs.

.PARAMETER ReportPath
    Full path for the JSON summary report. Defaults to a timestamped
    TuneUp_<HOST>_<timestamp>.json file inside LogDirectory.

.PARAMETER LogRetentionDays
    Prune tune-up transcripts, JSON reports, and network snapshots older than this many days from
    LogDirectory after a successful log-directory setup. Default 90.
    Use 0 to disable pruning.

.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File .\Invoke-EndpointTuneUp.ps1

.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File .\Invoke-EndpointTuneUp.ps1 -DeepClean -Reboot

.EXAMPLE
    # Fragile connection: keep the session alive, skip reboot-dependent resets
    powershell.exe -ExecutionPolicy Bypass -File .\Invoke-EndpointTuneUp.ps1 -SkipAdapterRestart -SkipStackReset

.EXAMPLE
    # Dry run: show what would change, change nothing (including no reboot)
    powershell.exe -ExecutionPolicy Bypass -File .\Invoke-EndpointTuneUp.ps1 -DeepClean -Reboot -WhatIf

.EXAMPLE
    # Quiet, ticket-ready run with a JSON report for automation
    powershell.exe -ExecutionPolicy Bypass -File .\Invoke-EndpointTuneUp.ps1 -Quiet -ReportPath C:\Reports\TuneUp.json

.NOTES
    Must run elevated. The #Requires line enforces this on Windows.
    Windows PowerShell 5.1 and PowerShell 7 smoke tests run in GitHub Actions.
    The Windows 11 job also runs DISM cleanup and SFC on a disposable runner.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [ValidateSet('Network', 'Cleanup', 'Optimize')]
    [string[]]$Phase = @('Network', 'Cleanup', 'Optimize'),
    [switch]$SkipTempCleanup,
    [switch]$SkipStackReset,
    [switch]$SkipAdapterRestart,
    [switch]$ClearRecycleBin,
    [switch]$DeepClean,
    [switch]$Reboot,
    [ValidateRange(10, 3600)]
    [int]$RebootDelaySeconds = 60,
    [switch]$Quiet,
    [switch]$NonInteractive,
    [switch]$Force,
    [string]$LogDirectory = 'C:\ProgramData\EndpointTuneUp\Logs',
    [string]$ReportPath,
    [ValidateRange(0, 365)]
    [int]$LogRetentionDays = 90
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Script-level state, initialised up front for Set-StrictMode.
$script:TranscriptStarted = $false
$script:LogFile = $null
$script:ReportFile = $null
$script:IpconfigBeforeFile = $null
$script:IpconfigAfterFile = $null
$script:RebootNeeded = $false
$script:FatalError = $null
$script:CurrentPhase = 'Setup'
$script:QuietMode = [bool]$Quiet
$script:NonInteractiveMode = [bool]$NonInteractive
$script:ForceMode = [bool]$Force
$script:StepFailures = New-Object System.Collections.Generic.List[string]
$script:SkippedSteps = New-Object System.Collections.Generic.List[string]
$script:StepResults = New-Object System.Collections.Generic.List[object]
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

# ---------------------------------------------------------------- logging ---
function Write-Log {
    param(
        [AllowEmptyString()][Parameter(Mandatory = $true)][string]$Message,
        [ValidateSet('Info', 'Warn', 'Error', 'Good')][string]$Level = 'Info'
    )
    # Quiet mode: only warnings and errors reach the console. The final
    # pasteable summary is printed separately, in plain text.
    if ($script:QuietMode -and ($Level -eq 'Info' -or $Level -eq 'Good')) {
        return
    }
    $stamp = Get-Date -Format 'HH:mm:ss'
    switch ($Level) {
        'Warn'  { Write-Host "[$stamp] WARN  $Message" -ForegroundColor Yellow }
        'Error' { Write-Host "[$stamp] ERROR $Message" -ForegroundColor Red }
        'Good'  { Write-Host "[$stamp] $Message" -ForegroundColor Green }
        default { Write-Host "[$stamp] $Message" }
    }
}

function Test-IsInteractive {
    if ($script:NonInteractiveMode) { return $false }
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
        return $script:ForceMode
    }
    if ($script:ForceMode) { return $true }
    $choice = Read-Host ($Message + $Prompt)
    return ($choice -eq 'y' -or $choice -eq 'Y' -or $choice -eq 'yes' -or $choice -eq 'Yes' -or $choice -eq 'YES')
}

function Add-SkippedStep {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [string]$Reason = 'Skipped'
    )
    $script:SkippedSteps.Add($Name) | Out-Null
    $script:StepResults.Add([pscustomobject]@{
        Phase           = $script:CurrentPhase
        Name            = $Name
        Status          = 'Skipped'
        DurationSeconds = 0
        Error           = $Reason
    }) | Out-Null
}

function Invoke-NativeCommand {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [string[]]$Arguments = @(),
        [int[]]$AllowedExitCodes = @(0),
        [switch]$WarnOnNonZero,
        [switch]$SuppressOutput
    )
    # A native command never throws in PowerShell, so its exit code is the
    # only failure signal. Capture $LASTEXITCODE immediately after it runs.
    if ($SuppressOutput) {
        & $Command @Arguments | Out-Null
    }
    else {
        & $Command @Arguments
    }
    $exitCode = $LASTEXITCODE
    if ($null -eq $exitCode) { $exitCode = 0 }
    if ($AllowedExitCodes -notcontains $exitCode) {
        if ($WarnOnNonZero) {
            Write-Log "    native command $Command exited with code $exitCode (treated as a warning, not a step failure)" -Level Warn
            return $exitCode
        }
        throw "$Command exited with code $exitCode"
    }
    return $exitCode
}

function Invoke-Step {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$Action,
        [switch]$ReadOnly,
        [string]$Target,
        [string]$Operation,
        [string]$Prompt
    )
    if ($script:CurrentPhase -ne 'Summary' -and $Phase -notcontains $script:CurrentPhase) {
        Add-SkippedStep -Name $Name -Reason "Phase excluded by -Phase ($($script:CurrentPhase))"
        return
    }
    if (-not $ReadOnly) {
        $targetName = $Name
        if (-not [string]::IsNullOrWhiteSpace($Target)) { $targetName = $Target }
        $operationName = 'Run step'
        if (-not [string]::IsNullOrWhiteSpace($Operation)) { $operationName = $Operation }
        if (-not $PSCmdlet.ShouldProcess($targetName, $operationName)) {
            Write-Log "    skipped (WhatIf/Confirm): $Name" -Level Warn
            Add-SkippedStep -Name $Name -Reason 'Skipped by -WhatIf / -Confirm'
            return
        }
        if ($Prompt -and -not (Confirm-UserChoice -Message $Prompt)) {
            $reason = 'Not confirmed by user'
            if (-not (Test-IsInteractive)) { $reason = 'Skipped in non-interactive mode without -Force' }
            Write-Log "    skipped: $Name ($reason)" -Level Warn
            Add-SkippedStep -Name $Name -Reason $reason
            return
        }
    }
    Write-Log "==> $Name"
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        & $Action
        $sw.Stop()
        Write-Log ("    done: {0} ({1:n1}s)" -f $Name, $sw.Elapsed.TotalSeconds)
        $script:StepResults.Add([pscustomobject]@{
            Phase           = $script:CurrentPhase
            Name            = $Name
            Status          = 'Success'
            DurationSeconds = [math]::Round($sw.Elapsed.TotalSeconds, 1)
            Error           = $null
        }) | Out-Null
    }
    catch {
        $sw.Stop()
        $script:StepFailures.Add($Name) | Out-Null
        Write-Log ("    FAILED: {0} ({1:n1}s) -- {2}" -f $Name, $sw.Elapsed.TotalSeconds, $_.Exception.Message) -Level Warn
        $script:StepResults.Add([pscustomobject]@{
            Phase           = $script:CurrentPhase
            Name            = $Name
            Status          = 'Failed'
            DurationSeconds = [math]::Round($sw.Elapsed.TotalSeconds, 1)
            Error           = $_.Exception.Message
        }) | Out-Null
    }
}

function Get-FreeSpaceGB {
    try {
        $disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'" -ErrorAction Stop
        if ($null -eq $disk -or $null -eq $disk.FreeSpace) { return $null }
        return [math]::Round($disk.FreeSpace / 1GB, 2)
    }
    catch {
        Write-Log "Could not read free space on C:: $($_.Exception.Message)" -Level Warn
        return $null
    }
}

function Get-OperatingSystemInfo {
    try {
        return Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    }
    catch {
        Write-Log "Could not read operating system info: $($_.Exception.Message)" -Level Warn
        return $null
    }
}

function Format-FreeSpaceGB {
    param($Gigabytes)
    if ($null -eq $Gigabytes) { return 'unknown' }
    return "$Gigabytes GB"
}

function Write-Summary {
    param(
        [AllowNull()][Parameter(Mandatory = $true)]$FreeBefore,
        [AllowNull()][Parameter(Mandatory = $true)]$FreeAfter
    )
    $spaceFreed = $null
    if ($null -ne $FreeBefore -and $null -ne $FreeAfter) {
        $spaceFreed = [math]::Round($FreeAfter - $FreeBefore, 2)
    }
    $spaceFreedText = 'unknown'
    if ($null -ne $spaceFreed) { $spaceFreedText = "$spaceFreed GB" }
    $failedText = 'none'
    if ($script:StepFailures.Count -gt 0) { $failedText = ($script:StepFailures -join '; ') }
    $skippedText = 'none'
    if ($script:SkippedSteps.Count -gt 0) { $skippedText = ($script:SkippedSteps -join '; ') }
    $osText = 'unknown'
    if ($null -ne $script:OsInfo) { $osText = "$($script:OsInfo.Caption) $($script:OsInfo.Version)" }

    if ($script:QuietMode) {
        # Plain text, no timestamps and no colours, for pasting into a ticket.
        $pasteLines = @(
            '===================================================='
            "  ENDPOINT TUNE-UP - $env:COMPUTERNAME"
            '===================================================='
            "Completed : $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))"
            "User      : $env:USERDOMAIN\$env:USERNAME"
            "OS        : $osText"
            "Elapsed   : $($stopwatch.Elapsed.ToString('hh\:mm\:ss'))"
            "Free C: before : $(Format-FreeSpaceGB -Gigabytes $FreeBefore)"
            "Free C: after  : $(Format-FreeSpaceGB -Gigabytes $FreeAfter)"
            "Space freed    : $spaceFreedText"
            "Failed steps   : $failedText"
            "Skipped steps  : $skippedText"
            "Reboot needed  : $($script:RebootNeeded)"
            "Log file       : $($script:LogFile)"
            "Report file    : $($script:ReportFile)"
        )
        $pasteText = $pasteLines -join "`r`n"
        Write-Output $pasteText
        if (-not $WhatIfPreference) {
            try { Set-Clipboard -Value $pasteText -ErrorAction Stop } catch { }
        }
        return
    }

    Write-Log ''
    Write-Log '=============================================================='
    Write-Log ' SUMMARY'
    Write-Log (" Elapsed        : {0:hh\:mm\:ss} (hh:mm:ss)" -f $stopwatch.Elapsed)
    Write-Log " Free C: before : $(Format-FreeSpaceGB -Gigabytes $FreeBefore)"
    Write-Log " Free C: after  : $(Format-FreeSpaceGB -Gigabytes $FreeAfter)"
    Write-Log " Space freed    : $spaceFreedText"
    if ($script:StepFailures.Count -gt 0) {
        Write-Log " Failed steps   : $failedText" -Level Warn
    }
    else {
        Write-Log ' Failed steps   : none'
    }
    if ($script:SkippedSteps.Count -gt 0) {
        Write-Log " Skipped steps  : $skippedText" -Level Warn
    }
    Write-Log " Reboot needed  : $($script:RebootNeeded)"
    Write-Log " Log file       : $($script:LogFile)"
    Write-Log " Report file    : $($script:ReportFile)"
    Write-Log '=============================================================='
}

# ----------------------------------------------------------------- main ---
# $script:OsInfo is set inside try below and read by Write-Summary.
$script:OsInfo = $null
$freeBefore = $null
$freeAfter = $null

try {
    # Platform gate that works in both editions: the automatic variable for
    # "is Windows" does not exist in Windows PowerShell 5.1, so do not
    # rely on it here.
    if ([Environment]::OSVersion.Platform -ne 'Win32NT') {
        throw 'This script requires Windows. The NetAdapter, CIM, DISM, SFC, and gpupdate tools used here are Windows-only.'
    }

    # Elevation gate with a clear message if #Requires was bypassed.
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'This script must run elevated. Re-run from an elevated PowerShell prompt.'
    }

    try {
        if ([Console]::IsInputRedirected) { $script:NonInteractiveMode = $true }
    }
    catch { }

    # ------------------------------------------------------------ logging ---
    if (-not $WhatIfPreference) {
        $logDir = $LogDirectory
        if ([string]::IsNullOrWhiteSpace($logDir)) {
            $logDir = 'C:\ProgramData\EndpointTuneUp\Logs'
        }
        try {
            if (-not (Test-Path -LiteralPath $logDir)) {
                New-Item -ItemType Directory -Path $logDir -Force -Confirm:$false -ErrorAction Stop | Out-Null
            }
        }
        catch {
            Write-Log "Could not create log directory $logDir`: $($_.Exception.Message). Falling back to TEMP." -Level Warn
            $logDir = Join-Path $env:TEMP 'EndpointTuneUp\Logs'
            New-Item -ItemType Directory -Path $logDir -Force -Confirm:$false -ErrorAction Stop | Out-Null
        }

        if ($LogRetentionDays -gt 0) {
            try {
                $cutoff = (Get-Date).AddDays(-$LogRetentionDays)
                foreach ($file in (Get-ChildItem -LiteralPath $logDir -File -ErrorAction Stop)) {
                    $isAuditFile = $file.Name -match '^TuneUp_.+_\d{8}-\d{6}(?:-\d{3})?\.(?:log|json)$' -or
                        $file.Name -match '^Ipconfig(?:Before|After)_.+_\d{8}-\d{6}(?:-\d{3})?\.txt$'
                    if ($isAuditFile -and $file.LastWriteTime -lt $cutoff) {
                        Remove-Item -LiteralPath $file.FullName -Force -Confirm:$false -ErrorAction Stop
                    }
                }
            }
            catch {
                Write-Log "Old log/report pruning failed (continuing): $($_.Exception.Message)" -Level Warn
            }
        }

        $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss-fff'
        $script:LogFile = Join-Path $logDir ("TuneUp_{0}_{1}.log" -f $env:COMPUTERNAME, $timestamp)
        $script:ReportFile = $ReportPath
        if ([string]::IsNullOrWhiteSpace($script:ReportFile)) {
            $script:ReportFile = Join-Path $logDir ("TuneUp_{0}_{1}.json" -f $env:COMPUTERNAME, $timestamp)
        }
        if ($script:QuietMode -and 'Network' -in $Phase) {
            $script:IpconfigBeforeFile = Join-Path $logDir ("IpconfigBefore_{0}_{1}.txt" -f $env:COMPUTERNAME, $timestamp)
            $script:IpconfigAfterFile = Join-Path $logDir ("IpconfigAfter_{0}_{1}.txt" -f $env:COMPUTERNAME, $timestamp)
        }

        try {
            Start-Transcript -LiteralPath $script:LogFile -NoClobber -ErrorAction Stop | Out-Null
            $script:TranscriptStarted = $true
        }
        catch {
            Write-Log "Transcript could not be started ($($_.Exception.Message)). Continuing without it; the JSON report will still be written." -Level Warn
        }
    }

    # ---------------------------------------------------------------- header ---
    $script:OsInfo = Get-OperatingSystemInfo
    $freeBefore = Get-FreeSpaceGB
    $osHeader = 'unknown'
    if ($null -ne $script:OsInfo) { $osHeader = "$($script:OsInfo.Caption) $($script:OsInfo.Version)" }

    Write-Log '=============================================================='
    Write-Log ' Endpoint Tune-Up'
    Write-Log " Computer : $env:COMPUTERNAME"
    Write-Log " User     : $env:USERDOMAIN\$env:USERNAME"
    Write-Log " OS       : $osHeader"
    Write-Log " Free C:  : $(Format-FreeSpaceGB -Gigabytes $freeBefore)"
    Write-Log " Log file : $($script:LogFile)"
    Write-Log '=============================================================='
    if ('Network' -in $Phase -and -not $SkipAdapterRestart) {
        Write-Log 'NOTE: the adapter restart / DHCP renew steps near the end of the'
        Write-Log 'network phase will briefly drop the remote session. The script'
        Write-Log 'keeps running locally; the remote-support tool should reconnect on its own.' -Level Warn
    }

    # ============================================================ NETWORK ===
    $script:CurrentPhase = 'Network'
    Write-Log ''
    Write-Log '--- PHASE 1: NETWORK RESET & REPAIR ---'

    Invoke-Step 'Capture network state (before)' -ReadOnly {
        if ($script:IpconfigBeforeFile) {
            ipconfig.exe /all | Out-File -FilePath $script:IpconfigBeforeFile -Encoding utf8
            if ($LASTEXITCODE -ne 0) { throw "ipconfig /all exited with code $LASTEXITCODE" }
        }
        elseif (-not $script:QuietMode) {
            ipconfig.exe /all | Out-Host
            if ($LASTEXITCODE -ne 0) { throw "ipconfig /all exited with code $LASTEXITCODE" }
        }
        else { ipconfig.exe /all | Out-Null }
    }

    Invoke-Step 'Flush DNS resolver cache' -Target 'DNS resolver cache' -Operation 'Flush DNS cache' {
        Invoke-NativeCommand -Command 'ipconfig.exe' -Arguments @('/flushdns') -SuppressOutput | Out-Null
    }

    Invoke-Step 'Re-register DNS records' -Target 'DNS records' -Operation 'Re-register DNS records' {
        Invoke-NativeCommand -Command 'ipconfig.exe' -Arguments @('/registerdns') -SuppressOutput | Out-Null
    }

    Invoke-Step 'Purge ARP/neighbor cache' -Target 'ARP cache' -Operation 'Purge ARP cache' {
        Invoke-NativeCommand -Command 'netsh.exe' -Arguments @('interface', 'ip', 'delete', 'arpcache') -SuppressOutput | Out-Null
    }

    Invoke-Step 'Purge and reload NetBIOS name cache' -Target 'NetBIOS name cache' -Operation 'Purge and reload NetBIOS cache' {
        # NetBIOS is disabled on many modern hosts, so a non-zero exit here
        # is a warning, not a step failure.
        Invoke-NativeCommand -Command 'nbtstat.exe' -Arguments @('-R') -SuppressOutput -WarnOnNonZero | Out-Null
        Invoke-NativeCommand -Command 'nbtstat.exe' -Arguments @('-RR') -SuppressOutput -WarnOnNonZero | Out-Null
    }

    Invoke-Step 'Set TCP receive autotuning to normal' -Target 'TCP autotuning' -Operation 'Set TCP autotuning to normal' {
        Invoke-NativeCommand -Command 'netsh.exe' -Arguments @('int', 'tcp', 'set', 'global', 'autotuninglevel=normal') -SuppressOutput | Out-Null
    }

    Invoke-Step 'Disable power-saving on physical network adapters' -Target 'NIC power-saving' -Operation 'Disable NIC power-saving' {
        Get-NetAdapter -Physical -ErrorAction Stop | ForEach-Object {
            $adapterName = $_.Name
            # SilentlyContinue is deliberate here: adapters without power
            # management support return no object, and that is not a failure.
            $pm = Get-NetAdapterPowerManagement -Name $adapterName -ErrorAction SilentlyContinue
            if ($null -eq $pm) { return }
            if ($pm.AllowComputerToTurnOffDevice -notin @('Unsupported', 'Inactive')) {
                try {
                    $pm.AllowComputerToTurnOffDevice = 'Disabled'
                    $pm | Set-NetAdapterPowerManagement -ErrorAction Stop
                    Write-Log "    power saving disabled on: $adapterName"
                }
                catch {
                    Write-Log "    could not change power management on ${adapterName}: $($_.Exception.Message)" -Level Warn
                }
            }
        }
    }

    if ($SkipStackReset) {
        Write-Log 'Skipping Winsock/TCP-IP stack reset (-SkipStackReset).'
        Add-SkippedStep -Name 'Reset Winsock catalog (applies after reboot)' -Reason 'Skipped via -SkipStackReset'
        Add-SkippedStep -Name 'Reset TCP/IP stack - IPv4 and IPv6 (applies after reboot)' -Reason 'Skipped via -SkipStackReset'
    }
    else {
        Invoke-Step 'Reset Winsock catalog (applies after reboot)' -Target 'Winsock catalog' -Operation 'Reset Winsock catalog' {
            Invoke-NativeCommand -Command 'netsh.exe' -Arguments @('winsock', 'reset') -SuppressOutput:$script:QuietMode | Out-Null
            $script:RebootNeeded = $true
        }
        Invoke-Step 'Reset TCP/IP stack - IPv4 and IPv6 (applies after reboot)' -Target 'TCP/IP stack' -Operation 'Reset TCP/IP stack' {
            Invoke-NativeCommand -Command 'netsh.exe' -Arguments @('int', 'ip', 'reset') -SuppressOutput:$script:QuietMode | Out-Null
            $script:RebootNeeded = $true
            Invoke-NativeCommand -Command 'netsh.exe' -Arguments @('int', 'ipv6', 'reset') -SuppressOutput:$script:QuietMode | Out-Null
        }
    }

    if ($SkipAdapterRestart) {
        Write-Log 'Skipping adapter restart and DHCP release/renew (-SkipAdapterRestart).'
        Add-SkippedStep -Name 'Restart physical network adapters (session will blip)' -Reason 'Skipped via -SkipAdapterRestart'
        Add-SkippedStep -Name 'DHCP release/renew (session will blip)' -Reason 'Skipped via -SkipAdapterRestart'
    }
    else {
        Invoke-Step 'Restart physical network adapters (session will blip)' -Target 'Physical network adapters' -Operation 'Restart physical network adapters' {
            $upAdapters = @(Get-NetAdapter -Physical -ErrorAction Stop |
                Where-Object { $_.Status -eq 'Up' })
            if ($upAdapters.Count -eq 0) {
                Write-Log '    no physical adapters in Up state - nothing to restart.'
                return
            }
            $expectedNames = @($upAdapters.Name)
            $restartFailures = New-Object System.Collections.Generic.List[string]
            foreach ($adapter in $upAdapters) {
                try {
                    Restart-NetAdapter -Name $adapter.Name -Confirm:$false -ErrorAction Stop
                }
                catch {
                    $restartFailures.Add($adapter.Name) | Out-Null
                    Write-Log "    FAILED to restart $($adapter.Name): $($_.Exception.Message)" -Level Warn
                }
            }
            if ($restartFailures.Count -eq $upAdapters.Count) {
                throw 'All physical adapters failed to restart.'
            }
            if ($restartFailures.Count -gt 0) {
                Write-Log "    some adapters failed to restart: $($restartFailures -join ', ')" -Level Warn
            }
            $adapterWaitSeconds = 60
            $deadline = (Get-Date).AddSeconds($adapterWaitSeconds)
            $down = @()
            do {
                Start-Sleep -Seconds 3
                $currentUpNames = @(Get-NetAdapter -Name $expectedNames -ErrorAction SilentlyContinue |
                    Where-Object { $_.Status -eq 'Up' } |
                    Select-Object -ExpandProperty Name)
                # An adapter that no longer appears is still down, not up.
                $down = @($expectedNames | Where-Object { $currentUpNames -notcontains $_ })
            } until ($down.Count -eq 0 -or (Get-Date) -ge $deadline)
            if ($down.Count -gt 0) {
                Write-Log "    not back Up after ${adapterWaitSeconds}s: $($down -join ', ')" -Level Warn
            }
        }

        Invoke-Step 'DHCP release/renew (session will blip)' -Target 'DHCP lease' -Operation 'DHCP release/renew' {
            # A mixed static/DHCP machine can legitimately report
            # per-adapter errors here while succeeding overall, so a
            # non-zero exit is a warning, not a step failure.
            Invoke-NativeCommand -Command 'ipconfig.exe' -Arguments @('/release') -SuppressOutput -WarnOnNonZero | Out-Null
            Invoke-NativeCommand -Command 'ipconfig.exe' -Arguments @('/renew') -SuppressOutput -WarnOnNonZero | Out-Null
        }
    }

    Invoke-Step 'Capture network state (after)' -ReadOnly {
        if ($script:IpconfigAfterFile) {
            ipconfig.exe /all | Out-File -FilePath $script:IpconfigAfterFile -Encoding utf8
            if ($LASTEXITCODE -ne 0) { throw "ipconfig /all exited with code $LASTEXITCODE" }
        }
        elseif (-not $script:QuietMode) {
            ipconfig.exe /all | Out-Host
            if ($LASTEXITCODE -ne 0) { throw "ipconfig /all exited with code $LASTEXITCODE" }
        }
        else { ipconfig.exe /all | Out-Null }
    }

    # ============================================================ CLEANUP ===
    $script:CurrentPhase = 'Cleanup'
    Write-Log ''
    Write-Log '--- PHASE 2: DISK & SYSTEM CLEANUP ---'

    $tempStep = 'Clear temp folders (all profiles + Windows; in-use files skipped)'
    if ($SkipTempCleanup) {
        Add-SkippedStep -Name $tempStep -Reason 'Skipped via -SkipTempCleanup'
    }
    else {
        Invoke-Step $tempStep -Target 'Temp folders' -Operation 'Clear temp folders' {
            $tempTargets = @("$env:SystemRoot\Temp")
            $tempTargets += Get-ChildItem -LiteralPath "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue |
                ForEach-Object { Join-Path $_.FullName 'AppData\Local\Temp' } |
                Where-Object { Test-Path -LiteralPath $_ -PathType Container }
            foreach ($target in $tempTargets) {
                $items = @(Get-ChildItem -LiteralPath $target -Force -ErrorAction SilentlyContinue)
                foreach ($item in $items) {
                    Remove-Item -LiteralPath $item.FullName -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue
                }
                Write-Log "    processed: $target ($($items.Count) item(s) found; in-use files skipped)"
            }
        }
    }

    if ($ClearRecycleBin) {
        Invoke-Step 'Empty Recycle Bin' -Target 'Recycle Bin' -Operation 'Empty Recycle Bin' `
            -Prompt 'Empty the Recycle Bin now? This deletes files the user may still expect to recover.' {
            Clear-RecycleBin -Force -Confirm:$false -ErrorAction Stop
        }
    }

    if ($DeepClean) {
        Invoke-Step 'DISM component-store cleanup (10-30 min)' -Target 'Component store' -Operation 'DISM component-store cleanup' {
            Invoke-NativeCommand -Command 'dism.exe' -Arguments @('/Online', '/Cleanup-Image', '/StartComponentCleanup', '/NoRestart') -SuppressOutput:$script:QuietMode | Out-Null
        }
        Invoke-Step 'System file check - sfc /scannow (10-20 min)' -Target 'System files' -Operation 'Run sfc /scannow' {
            Invoke-NativeCommand -Command 'sfc.exe' -Arguments @('/scannow') -SuppressOutput:$script:QuietMode | Out-Null
        }
    }

    # =========================================================== OPTIMIZE ===
    $script:CurrentPhase = 'Optimize'
    Write-Log ''
    Write-Log '--- PHASE 3: OPTIMIZE ---'

    Invoke-Step 'Optimize C: (TRIM for SSD / defrag for HDD)' -Target 'Volume C:' -Operation 'Optimize volume C:' {
        if ($script:QuietMode) {
            Optimize-Volume -DriveLetter C -ErrorAction Stop | Out-Null
        }
        else {
            Optimize-Volume -DriveLetter C -Verbose -ErrorAction Stop | Out-Null
        }
    }

    Invoke-Step 'Refresh Group Policy (gpupdate /force)' -Target 'Group Policy' -Operation 'Refresh Group Policy' {
        Invoke-NativeCommand -Command 'gpupdate.exe' -Arguments @('/force') -SuppressOutput:$script:QuietMode | Out-Null
    }

    Invoke-Step 'Trigger SCCM/MECM client actions (if client present)' -Target 'SCCM client' -Operation 'Trigger SCCM client schedules' {
        $ccmService = Get-Service -Name CcmExec -ErrorAction SilentlyContinue
        if ($null -eq $ccmService) {
            Write-Log '    SCCM client not found - skipped.'
        }
        elseif ($ccmService.Status -ne 'Running') {
            Write-Log "    SCCM client found but not running ($($ccmService.Status)) - skipped." -Level Warn
        }
        else {
            $schedules = [ordered]@{
                'Machine policy retrieval & evaluation' = '{00000000-0000-0000-0000-000000000021}'
                'Application deployment evaluation'     = '{00000000-0000-0000-0000-000000000121}'
                'Hardware inventory'                    = '{00000000-0000-0000-0000-000000000001}'
            }
            foreach ($name in $schedules.Keys) {
                $cimResult = $null
                try {
                    $cimResult = Invoke-CimMethod -Namespace 'root\ccm' -ClassName SMS_Client `
                        -MethodName TriggerSchedule `
                        -Arguments @{ sScheduleID = $schedules[$name] } `
                        -ErrorAction Stop
                }
                catch {
                    Write-Log "    FAILED to trigger ${name}: $($_.Exception.Message)" -Level Warn
                    continue
                }
                if ($null -ne $cimResult -and $cimResult.ReturnValue -eq 0) {
                    Write-Log "    triggered: $name"
                }
                else {
                    $returnValue = $null
                    if ($null -ne $cimResult) { $returnValue = $cimResult.ReturnValue }
                    Write-Log "    FAILED to trigger ${name} (ReturnValue $returnValue)" -Level Warn
                }
            }
        }
    }

    # ============================================================ SUMMARY ===
    $script:CurrentPhase = 'Summary'
    foreach ($k in @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
    )) {
        if (Test-Path $k) { $script:RebootNeeded = $true }
    }

    $freeAfter = Get-FreeSpaceGB
    $stopwatch.Stop()

    if ($Reboot) {
        Invoke-Step 'Reboot (shutdown /r)' -Target 'Computer' -Operation 'Restart computer' {
            Invoke-NativeCommand -Command 'shutdown.exe' -Arguments @('/r', '/t', "$RebootDelaySeconds", '/c', 'IT maintenance is complete. This PC will restart shortly - please save your work.') | Out-Null
        }
    }
    elseif ($script:RebootNeeded) {
        Write-Log 'A REBOOT IS REQUIRED to finish pending system changes.' -Level Warn
    }
    Write-Summary -FreeBefore $freeBefore -FreeAfter $freeAfter
}
catch {
    $script:FatalError = $_.Exception.Message
    Write-Log "Fatal error: $($_.Exception.Message)" -Level Error
}
finally {
    $spaceFreed = $null
    if ($null -ne $freeBefore -and $null -ne $freeAfter) {
        $spaceFreed = [math]::Round($freeAfter - $freeBefore, 2)
    }
    $report = [ordered]@{
        Timestamp       = (Get-Date).ToString('o')
        Computer        = $env:COMPUTERNAME
        User            = "$env:USERDOMAIN\$env:USERNAME"
        OS              = $null
        PowerShell      = $PSVersionTable.PSVersion.ToString()
        PSEdition       = $PSVersionTable.PSEdition
        Parameters      = [ordered]@{
            Phase              = $Phase
            SkipTempCleanup    = [bool]$SkipTempCleanup
            SkipStackReset     = [bool]$SkipStackReset
            SkipAdapterRestart = [bool]$SkipAdapterRestart
            ClearRecycleBin    = [bool]$ClearRecycleBin
            DeepClean          = [bool]$DeepClean
            Reboot             = [bool]$Reboot
            RebootDelaySeconds = $RebootDelaySeconds
            Quiet              = [bool]$Quiet
            NonInteractive     = [bool]$NonInteractive
            Force              = [bool]$Force
            LogRetentionDays   = $LogRetentionDays
        }
        ElapsedSeconds  = [math]::Round($stopwatch.Elapsed.TotalSeconds, 1)
        Steps           = $script:StepResults
        FreeBeforeGB    = $freeBefore
        FreeAfterGB     = $freeAfter
        SpaceFreedGB    = $spaceFreed
        FailedSteps     = $script:StepFailures
        SkippedSteps    = $script:SkippedSteps
        RebootNeeded    = $script:RebootNeeded
        FatalError      = $script:FatalError
        LogFile         = $script:LogFile
        ReportFile      = $script:ReportFile
        IpconfigBefore  = $script:IpconfigBeforeFile
        IpconfigAfter   = $script:IpconfigAfterFile
    }
    if ($null -ne $script:OsInfo) {
        $report.OS = "$($script:OsInfo.Caption) $($script:OsInfo.Version)"
    }
    if ($null -ne $script:ReportFile) {
        try {
            $report | ConvertTo-Json -Depth 4 -ErrorAction Stop |
                Set-Content -LiteralPath $script:ReportFile -Encoding utf8 -Confirm:$false -ErrorAction Stop
            Write-Log "Report saved to: $($script:ReportFile)"
        }
        catch {
            Write-Log "Could not write JSON report: $($_.Exception.Message)" -Level Warn
        }
    }
    if ($null -ne $script:LogFile) {
        Write-Log "Log saved to: $($script:LogFile)"
    }
    if ($script:TranscriptStarted) {
        try { Stop-Transcript -ErrorAction Stop | Out-Null } catch { }
    }
}
