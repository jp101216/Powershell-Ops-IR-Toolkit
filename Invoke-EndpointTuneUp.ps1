<#
.SYNOPSIS
    Endpoint tune-up: resets and repairs the network stack and all network
    adapters, then cleans and optimizes the PC.

.DESCRIPTION
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

    A full transcript is written to C:\ProgramData\EndpointTuneUp\Logs.

    Deliberately NOT included (compliance + managed-endpoint safety):
      - Clearing Windows event logs
      - Resetting Windows Firewall policy
      - Clearing Prefetch (hurts performance; Windows rebuilds it)
      - Resetting the WinHTTP proxy (can break Zscaler/GPO proxy config)
      - Clearing the Windows Update download cache (SoftwareDistribution\Download)
      - Clearing the Delivery Optimization cache
      - Clearing Windows Error Reporting queues

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
    user may still expect to recover - confirm with the user first.

.PARAMETER DeepClean
    Also run DISM component-store cleanup and SFC /scannow. Adds roughly
    15-45 minutes; use when corruption is suspected or disk space is critical.

.PARAMETER Reboot
    Restart the machine automatically when finished (with a countdown warning
    shown to the user). A reboot is required for the stack reset to apply.

.PARAMETER RebootDelaySeconds
    Countdown before the automatic reboot. Default 60.

.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File .\Invoke-EndpointTuneUp.ps1

.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File .\Invoke-EndpointTuneUp.ps1 -DeepClean -Reboot

.EXAMPLE
    # Fragile connection: keep the session alive, skip reboot-dependent resets
    powershell.exe -ExecutionPolicy Bypass -File .\Invoke-EndpointTuneUp.ps1 -SkipAdapterRestart -SkipStackReset
#>

#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [switch]$SkipStackReset,
    [switch]$SkipAdapterRestart,
    [switch]$ClearRecycleBin,
    [switch]$DeepClean,
    [switch]$Reboot,
    [ValidateRange(10, 3600)]
    [int]$RebootDelaySeconds = 60
)

$ErrorActionPreference = 'Continue'
$script:RebootNeeded = $false
$script:StepFailures = New-Object System.Collections.Generic.List[string]
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

# ---------------------------------------------------------------- logging ---
$logDir = 'C:\ProgramData\EndpointTuneUp\Logs'
if (-not (Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}
Get-ChildItem -Path $logDir -Filter 'TuneUp_*.log' -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-90) } |
    Remove-Item -Force -ErrorAction SilentlyContinue
$logFile = Join-Path $logDir ("TuneUp_{0}_{1:yyyyMMdd-HHmmss}.log" -f $env:COMPUTERNAME, (Get-Date))
Start-Transcript -Path $logFile -Force | Out-Null

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Warn', 'Error')][string]$Level = 'Info'
    )
    $stamp = Get-Date -Format 'HH:mm:ss'
    switch ($Level) {
        'Warn'  { Write-Host "[$stamp] WARN  $Message" -ForegroundColor Yellow }
        'Error' { Write-Host "[$stamp] ERROR $Message" -ForegroundColor Red }
        default { Write-Host "[$stamp] $Message" }
    }
}

function Invoke-Step {
    param(
        [string]$Name,
        [scriptblock]$Action
    )
    Write-Log "==> $Name"
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        & $Action
        Write-Log ("    done: {0} ({1:n1}s)" -f $Name, $sw.Elapsed.TotalSeconds)
    }
    catch {
        $script:StepFailures.Add($Name)
        Write-Log ("    FAILED: {0} ({1:n1}s) -- {2}" -f $Name, $sw.Elapsed.TotalSeconds, $_.Exception.Message) -Level Warn
    }
}

function Get-FreeSpaceGB {
    $disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
    return [math]::Round($disk.FreeSpace / 1GB, 2)
}

# ----------------------------------------------------------------- header ---
$os = Get-CimInstance Win32_OperatingSystem
$freeBefore = Get-FreeSpaceGB

Write-Log '=============================================================='
Write-Log " Endpoint Tune-Up"
Write-Log " Computer : $env:COMPUTERNAME"
Write-Log " User     : $env:USERDOMAIN\$env:USERNAME"
Write-Log " OS       : $($os.Caption) $($os.Version)"
Write-Log " Free C:  : $freeBefore GB"
Write-Log " Log file : $logFile"
Write-Log '=============================================================='
if (-not $SkipAdapterRestart) {
    Write-Log 'NOTE: the adapter restart / DHCP renew steps near the end of the'
    Write-Log 'network phase will briefly drop the remote session. The script'
    Write-Log 'keeps running locally; the remote-support tool should reconnect on its own.' -Level Warn
}

try {
    # ============================================================ NETWORK ===
    Write-Log ''
    Write-Log '--- PHASE 1: NETWORK RESET & REPAIR ---'

    Invoke-Step 'Capture network state (before)' {
        ipconfig.exe /all | Out-Host
    }

    Invoke-Step 'Flush DNS resolver cache' {
        ipconfig.exe /flushdns | Out-Null
    }

    Invoke-Step 'Re-register DNS records' {
        ipconfig.exe /registerdns | Out-Null
    }

    Invoke-Step 'Purge ARP/neighbor cache' {
        netsh.exe interface ip delete arpcache | Out-Null
    }

    Invoke-Step 'Purge and reload NetBIOS name cache' {
        nbtstat.exe -R  | Out-Null
        nbtstat.exe -RR | Out-Null
    }

    Invoke-Step 'Set TCP receive autotuning to normal' {
        netsh.exe int tcp set global autotuninglevel=normal | Out-Null
    }

    Invoke-Step 'Disable power-saving on physical network adapters' {
        Get-NetAdapter -Physical -ErrorAction Stop | ForEach-Object {
            $pm = Get-NetAdapterPowerManagement -Name $_.Name -ErrorAction SilentlyContinue
            if ($pm -and $pm.AllowComputerToTurnOffDevice -notin @('Unsupported', 'Inactive')) {
                $pm.AllowComputerToTurnOffDevice = 'Disabled'
                $pm | Set-NetAdapterPowerManagement -ErrorAction SilentlyContinue
                Write-Log "    power saving disabled on: $($_.Name)"
            }
        }
    }

    if ($SkipStackReset) {
        Write-Log 'Skipping Winsock/TCP-IP stack reset (-SkipStackReset).'
    }
    else {
        Invoke-Step 'Reset Winsock catalog (applies after reboot)' {
            netsh.exe winsock reset | Out-Host
            $script:RebootNeeded = $true
        }
        Invoke-Step 'Reset TCP/IP stack - IPv4 and IPv6 (applies after reboot)' {
            netsh.exe int ip reset | Out-Host
            netsh.exe int ipv6 reset | Out-Host
            $script:RebootNeeded = $true
        }
    }

    if ($SkipAdapterRestart) {
        Write-Log 'Skipping adapter restart and DHCP release/renew (-SkipAdapterRestart).'
    }
    else {
        Invoke-Step 'Restart physical network adapters (session will blip)' {
            $upAdapters = @(Get-NetAdapter -Physical -ErrorAction Stop |
                Where-Object { $_.Status -eq 'Up' })
            if ($upAdapters.Count -eq 0) {
                Write-Log '    no physical adapters in Up state - nothing to restart.'
                return
            }
            $upAdapters | Restart-NetAdapter -Confirm:$false -ErrorAction SilentlyContinue
            $deadline = (Get-Date).AddSeconds(60)
            do {
                Start-Sleep -Seconds 3
                $down = @(Get-NetAdapter -Name $upAdapters.Name -ErrorAction SilentlyContinue |
                    Where-Object { $_.Status -ne 'Up' })
            } until ($down.Count -eq 0 -or (Get-Date) -ge $deadline)
            if ($down.Count -gt 0) {
                Write-Log "    not back Up after 60s: $($down.Name -join ', ')" -Level Warn
            }
        }

        Invoke-Step 'DHCP release/renew (session will blip)' {
            ipconfig.exe /release | Out-Null
            ipconfig.exe /renew   | Out-Null
        }
    }

    Invoke-Step 'Capture network state (after)' {
        ipconfig.exe /all | Out-Host
    }

    # ============================================================ CLEANUP ===
    Write-Log ''
    Write-Log '--- PHASE 2: DISK & SYSTEM CLEANUP ---'

    Invoke-Step 'Clear temp folders (all profiles + Windows; in-use files skipped)' {
        $tempTargets = @("$env:SystemRoot\Temp")
        $tempTargets += Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue |
            ForEach-Object { Join-Path $_.FullName 'AppData\Local\Temp' } |
            Where-Object { Test-Path $_ }
        foreach ($t in $tempTargets) {
            Get-ChildItem -LiteralPath $t -Force -ErrorAction SilentlyContinue |
                Remove-Item -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue
            Write-Log "    cleared: $t"
        }
    }

    if ($ClearRecycleBin) {
        Invoke-Step 'Empty Recycle Bin' {
            Clear-RecycleBin -Force -ErrorAction SilentlyContinue
        }
    }

    if ($DeepClean) {
        Invoke-Step 'DISM component-store cleanup (10-30 min)' {
            & dism.exe /Online /Cleanup-Image /StartComponentCleanup /NoRestart | Out-Host
        }
        Invoke-Step 'System file check - sfc /scannow (10-20 min)' {
            & sfc.exe /scannow | Out-Host
        }
    }

    # =========================================================== OPTIMIZE ===
    Write-Log ''
    Write-Log '--- PHASE 3: OPTIMIZE ---'

    Invoke-Step 'Optimize C: (TRIM for SSD / defrag for HDD)' {
        Optimize-Volume -DriveLetter C -Verbose
    }

    Invoke-Step 'Refresh Group Policy (gpupdate /force)' {
        & gpupdate.exe /force | Out-Host
    }

    Invoke-Step 'Trigger SCCM/MECM client actions (if client present)' {
        if (Get-Service -Name CcmExec -ErrorAction SilentlyContinue) {
            $schedules = [ordered]@{
                'Machine policy retrieval & evaluation' = '{00000000-0000-0000-0000-000000000021}'
                'Application deployment evaluation'     = '{00000000-0000-0000-0000-000000000121}'
                'Hardware inventory'                    = '{00000000-0000-0000-0000-000000000001}'
            }
            foreach ($name in $schedules.Keys) {
                Invoke-CimMethod -Namespace 'root\ccm' -ClassName SMS_Client `
                    -MethodName TriggerSchedule `
                    -Arguments @{ sScheduleID = $schedules[$name] } `
                    -ErrorAction SilentlyContinue | Out-Null
                Write-Log "    triggered: $name"
            }
        }
        else {
            Write-Log '    SCCM client not found - skipped.'
        }
    }

    # ============================================================ SUMMARY ===
    foreach ($k in @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
    )) {
        if (Test-Path $k) { $script:RebootNeeded = $true }
    }

    $freeAfter = Get-FreeSpaceGB
    $stopwatch.Stop()

    Write-Log ''
    Write-Log '=============================================================='
    Write-Log ' SUMMARY'
    Write-Log (" Elapsed        : {0:hh\:mm\:ss} (hh:mm:ss)" -f $stopwatch.Elapsed)
    Write-Log " Free C: before : $freeBefore GB"
    Write-Log " Free C: after  : $freeAfter GB"
    Write-Log (" Space freed    : {0} GB" -f [math]::Round($freeAfter - $freeBefore, 2))
    if ($script:StepFailures.Count -gt 0) {
        Write-Log " Failed steps   : $($script:StepFailures -join '; ')" -Level Warn
    }
    else {
        Write-Log ' Failed steps   : none'
    }
    Write-Log " Reboot needed  : $script:RebootNeeded"
    Write-Log " Log file       : $logFile"
    Write-Log '=============================================================='

    if ($Reboot) {
        Write-Log "Rebooting in $RebootDelaySeconds seconds (shutdown /r)..." -Level Warn
        & shutdown.exe /r /t $RebootDelaySeconds /c 'IT maintenance is complete. This PC will restart shortly - please save your work.'
    }
    elseif ($script:RebootNeeded) {
        Write-Log 'A REBOOT IS REQUIRED for the network stack reset to take effect.' -Level Warn
        Write-Log 'Re-run with -Reboot to restart automatically, or restart manually.' -Level Warn
    }
}
finally {
    Stop-Transcript | Out-Null
}
