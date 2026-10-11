<#
.SYNOPSIS
    Network & System Slowness Triage Tool

.DESCRIPTION
    Interactive, read-only endpoint triage for "computer is slow" and
    "network is slow/down" tickets. Collects:
      - System baseline (user, model, uptime, pending reboot)
      - Performance snapshot (CPU, memory, disk free space + disk latency, top
        processes by real-time CPU% and working set)
      - Network config (adapters, IPv4/IPv6, gateway, DNS)
      - VPN detection (Cisco Secure Client + Zscaler via per-user SID hive,
        including tunnel adapter IP for either client)
      - Proxy configuration (WinHTTP + per-user IE/WinInet settings)
      - Latency/quality metrics (RTT + packet loss to gateway/DNS, DNS resolve time)
      - Core infrastructure health (TCP reachability + connect latency).
        The target list can be overridden via a CoreInfrastructure.json file
        placed alongside the script.
      - Optional single-target diagnostic (DNS + ping + multi-port TCP test)
      - External/egress IP

    Produces a color-coded, threshold-flagged console summary AND a plain-text
    "KEY FINDINGS" summary suitable for pasting into a ServiceNow ticket. A full
    JSON record and a .txt summary are written to disk (default: a per-user
    folder under %LOCALAPPDATA%, so exports aren't left world-readable on
    shared endpoints). Older exports beyond -RetainCount are pruned
    automatically. The script only reads state - it makes no configuration
    changes.

.PARAMETER TargetDestination
    Optional hostname or IP the user reports as broken/slow. Prompted if omitted.

.PARAMETER TargetPorts
    One or more TCP ports to test against the target (default 443, 80, 445, 3389).
    Accepts the alias -TargetPort for backward compatibility.

.PARAMETER ExportPath
    JSON output path. Defaults to a timestamped file under
    %LOCALAPPDATA%\NetTriage (per-user, not shared C:\Temp). A matching .txt
    summary is written alongside it.

.PARAMETER RetainCount
    Number of past Triage_*.json/.txt export pairs to keep in the export
    folder; older ones are deleted after a successful run. Default 20. Set to
    0 to disable pruning.

.PARAMETER PingCount
    ICMP echoes per latency probe (default 4).

.PARAMETER TcpTimeoutMs
    Per-host TCP connect timeout for infra/port checks (default 1500 ms).

.PARAMETER PingTimeoutMs
    Per-echo ICMP timeout (default 1000 ms).

.PARAMETER SkipExternalIP
    Skip the outbound egress-IP lookup (useful on locked-down egress).

.PARAMETER Quiet
    Suppress the colored dashboard and emit only the plain-text ServiceNow
    summary to the console. Also auto-copies that summary to the clipboard.

.PARAMETER CopyToClipboard
    Copy the plain-text ServiceNow summary to the clipboard (implied by -Quiet).

.EXAMPLE
    .\Invoke-NetTriage.ps1
    Interactive run with the full colored dashboard.

.EXAMPLE
    .\Invoke-NetTriage.ps1 -TargetDestination intranet.example.com -Quiet
    Ticket-ready plain-text summary, copied to the clipboard.

.EXAMPLE
    .\Invoke-NetTriage.ps1 -TargetDestination fileserver01 -TargetPorts 445,139,3389
    Test a file/RDP server on specific ports.

.NOTES
    Compatible with Windows PowerShell 5.1 and PowerShell 7+.
    Read-only. Safe to run in a user or PAM/elevated context.
    Version 2.2
#>

[CmdletBinding()]
param (
    [string]$TargetDestination = "",

    [Alias('TargetPort')]
    [int[]] $TargetPorts        = @(443, 80, 445, 3389),

    [string]$ExportPath         = "$env:LOCALAPPDATA\NetTriage\Triage_$((Get-Date).ToString('yyyyMMdd_HHmmss')).json",
    [int]   $PingCount          = 4,
    [int]   $TcpTimeoutMs       = 1500,
    [int]   $PingTimeoutMs      = 1000,
    [int]   $RetainCount        = 20,
    [switch]$SkipExternalIP,
    [switch]$Quiet,
    [switch]$CopyToClipboard
)

# Suppress progress bars (speeds up Test-* cmdlets and keeps output clean)
$ProgressPreference = 'SilentlyContinue'

# --------------------------------------------------------------------------
# THRESHOLDS  (tune here - warn = yellow, crit = red)
# --------------------------------------------------------------------------
$Thresholds = @{
    UptimeDays  = @{ Warn = 7;   Crit = 14 }   # higher is worse (recommend reboot)
    CpuPct      = @{ Warn = 75;  Crit = 90 }   # higher is worse
    MemPct      = @{ Warn = 80;  Crit = 90 }   # higher is worse (% used)
    DiskFreePct = @{ Warn = 15;  Crit = 10 }   # LOWER is worse (% free)
    WifiPct     = @{ Warn = 70;  Crit = 50 }   # LOWER is worse (signal %)
    GwRttMs     = @{ Warn = 20;  Crit = 50 }   # higher is worse (LAN)
    NetRttMs    = @{ Warn = 80;  Crit = 150 }  # higher is worse (beyond LAN)
    DnsMs       = @{ Warn = 100; Crit = 300 }  # higher is worse (resolve time)
    LossPct     = @{ Warn = 1;   Crit = 10 }   # higher is worse
    DiskLatencyMs = @{ Warn = 15; Crit = 30 }  # higher is worse (avg disk sec/transfer, ms)
}

# Findings collector (populated in the analysis pass, surfaced in both views)
$Findings = New-Object System.Collections.Generic.List[object]

# --------------------------------------------------------------------------
# CORE INFRASTRUCTURE  (organization reachability targets)
# --------------------------------------------------------------------------
$CoreInfrastructure = @(
    @{ Name = "Internet Reachability";         Host = "8.8.8.8";                       Port = 53  }
    @{ Name = "SharePoint (Cloud)";            Host = "yourorg.sharepoint.com";        Port = 443 }
    @{ Name = "Identity Federation (SSO)";     Host = "sso.corp.example.com";           Port = 443 }
    @{ Name = "Active Directory (Round Robin)";Host = "corp.example.com";               Port = 389 }
    @{ Name = "Specific DC (DC01)";            Host = "DC01.corp.example.com";          Port = 389 }
)

# Optional override: drop a CoreInfrastructure.json (array of {Name,Host,Port})
# next to this script to change targets without editing script code.
$CoreInfraConfigPath = Join-Path -Path $PSScriptRoot -ChildPath 'CoreInfrastructure.json'
if ($PSScriptRoot -and (Test-Path $CoreInfraConfigPath)) {
    try {
        $CustomInfra = Get-Content -Path $CoreInfraConfigPath -Raw | ConvertFrom-Json -ErrorAction Stop
        if ($CustomInfra) {
            $CoreInfrastructure = @($CustomInfra | ForEach-Object {
                @{ Name = $_.Name; Host = $_.Host; Port = [int]$_.Port }
            })
        }
    }
    catch {
        Write-Warning "Failed to load CoreInfrastructure.json - using built-in defaults: $($_.Exception.Message)"
    }
}

# ==========================================================================
# HELPER FUNCTIONS
# ==========================================================================

function Get-Severity {
    <# Returns 'Ok' | 'Warn' | 'Crit' based on warn/crit thresholds. #>
    param(
        [double]$Value,
        [double]$Warn,
        [double]$Crit,
        [switch]$LowerIsWorse
    )
    if ($LowerIsWorse) {
        if ($Value -le $Crit) { 'Crit' } elseif ($Value -le $Warn) { 'Warn' } else { 'Ok' }
    }
    else {
        if ($Value -ge $Crit) { 'Crit' } elseif ($Value -ge $Warn) { 'Warn' } else { 'Ok' }
    }
}

function Get-SeverityColor {
    <# Maps a severity string to a console color. #>
    param([string]$Sev)
    switch ($Sev) {
        'Crit'  { [ConsoleColor]::Red;    break }
        'Fail'  { [ConsoleColor]::Red;    break }
        'Warn'  { [ConsoleColor]::Yellow; break }
        'Ok'    { [ConsoleColor]::Green;  break }
        default { [ConsoleColor]::White;  break }
    }
}

function Get-SeverityRank {
    <# Sort order for findings: Crit, Fail, Warn, then anything else. #>
    param([string]$Sev)
    switch ($Sev) {
        'Crit'  { 0; break }
        'Fail'  { 1; break }
        'Warn'  { 2; break }
        default { 3; break }
    }
}

function Get-MetricColor {
    <# Convenience: value + thresholds -> console color (single source of logic). #>
    param(
        [double]$Value,
        [double]$Warn,
        [double]$Crit,
        [switch]$LowerIsWorse
    )
    Get-SeverityColor (Get-Severity -Value $Value -Warn $Warn -Crit $Crit -LowerIsWorse:$LowerIsWorse)
}

function Add-Finding {
    <# Record a flagged metric for the KEY FINDINGS section. #>
    param([string]$Sev, [string]$Msg)
    $Findings.Add([pscustomobject]@{ Severity = $Sev; Message = $Msg })
}

function Write-Field {
    <# Consistent "Label : Value" console line with optional colored note. #>
    param(
        [string]$Label,
        [string]$Value,
        [ConsoleColor]$Color = [ConsoleColor]::Green,
        [string]$Note = ''
    )
    Write-Host ($Label.PadRight(16) + ' : ') -NoNewline
    Write-Host $Value -ForegroundColor $Color -NoNewline
    if ($Note) { Write-Host ('  ' + $Note) -ForegroundColor DarkYellow }
    else { Write-Host '' }
}

function Format-PingStat {
    <# Plain-text render of a ping-stats object. #>
    param($P)
    if (-not $P -or [string]::IsNullOrWhiteSpace($P.Target)) { return 'n/a' }
    if ($P.Received -eq 0) { return 'unreachable (100% loss)' }
    return "$($P.AvgMs) ms avg, $($P.LossPct)% loss"
}

function Test-TcpPort {
    <# Timeout-bounded TCP connect. Returns success flag + connect latency. #>
    param(
        [string]$ComputerName,
        [int]$Port,
        [int]$TimeoutMs = 1500
    )
    $result = [ordered]@{ Success = $false; LatencyMs = $null; Error = $null }
    if ([string]::IsNullOrWhiteSpace($ComputerName)) {
        $result.Error = 'No host specified'
        return $result
    }
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $sw  = [System.Diagnostics.Stopwatch]::StartNew()
        $iar = $client.BeginConnect($ComputerName, $Port, $null, $null)
        if ($iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
            $client.EndConnect($iar)   # throws if the connection was refused
            $sw.Stop()
            $result.Success   = $true
            $result.LatencyMs = [math]::Round($sw.Elapsed.TotalMilliseconds, 0)
        }
        else {
            $result.Error = "Timeout (${TimeoutMs}ms)"
        }
    }
    catch {
        $result.Error = $_.Exception.Message
    }
    finally {
        $client.Close()
    }
    return $result
}

function Get-PingStats {
    <# Sends N ICMP echoes; returns avg/min/max RTT and packet-loss %. #>
    param(
        [string]$ComputerName,
        [int]$Count = 4,
        [int]$TimeoutMs = 1000
    )
    $out = [ordered]@{
        Target = $ComputerName; Sent = $Count; Received = 0
        LossPct = 100; AvgMs = $null; MinMs = $null; MaxMs = $null
    }
    if ([string]::IsNullOrWhiteSpace($ComputerName) -or $ComputerName -eq '0.0.0.0') { return $out }

    $ping = New-Object System.Net.NetworkInformation.Ping
    $rtts = New-Object System.Collections.Generic.List[int]
    for ($i = 0; $i -lt $Count; $i++) {
        try {
            $reply = $ping.Send($ComputerName, $TimeoutMs)
            if ($reply.Status -eq 'Success') { $rtts.Add([int]$reply.RoundtripTime) }
        }
        catch { }
    }
    $ping.Dispose()

    $out.Received = $rtts.Count
    $out.LossPct  = [math]::Round((($Count - $rtts.Count) / $Count) * 100, 0)
    if ($rtts.Count -gt 0) {
        $out.AvgMs = [math]::Round(($rtts | Measure-Object -Average).Average, 0)
        $out.MinMs = ($rtts | Measure-Object -Minimum).Minimum
        $out.MaxMs = ($rtts | Measure-Object -Maximum).Maximum
    }
    return $out
}

function Get-WifiInfo {
    <# Parses `netsh wlan show interfaces`. Returns $null if not on Wi-Fi. #>
    $extract = {
        param($lines, $name)
        $m = $lines | Select-String -Pattern ('^\s*' + [regex]::Escape($name) + '\s*:\s*(.+)$')
        if ($m) { return $m.Matches[0].Groups[1].Value.Trim() }
        return $null
    }
    try {
        $raw = netsh wlan show interfaces 2>$null
        if (-not $raw) { return $null }
        if ($raw -match 'There is no wireless interface') { return $null }

        $state = & $extract $raw 'State'
        if (-not $state -or $state -notmatch 'connected') { return $null }

        $signalRaw = & $extract $raw 'Signal'
        $signalPct = if ($signalRaw) { [int]($signalRaw -replace '[^0-9]', '') } else { $null }

        return [ordered]@{
            SSID      = (& $extract $raw 'SSID')
            SignalPct = $signalPct
            RxMbps    = (& $extract $raw 'Receive rate (Mbps)')
            TxMbps    = (& $extract $raw 'Transmit rate (Mbps)')
            Channel   = (& $extract $raw 'Channel')
            Radio     = (& $extract $raw 'Radio type')
        }
    }
    catch { return $null }
}

function Get-PendingReboot {
    <# Best-effort pending-reboot detection across common sources. #>
    $reasons = @()
    try {
        if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') {
            $reasons += 'Servicing'
        }
        if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') {
            $reasons += 'Windows Update'
        }
        $pfro = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' `
                    -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations
        if ($pfro) { $reasons += 'Pending file rename' }
    }
    catch { }
    return [ordered]@{ Pending = ($reasons.Count -gt 0); Reasons = ($reasons -join ', ') }
}

function Get-DiskLatency {
    <# Avg disk sec/transfer + current queue length, aggregated across physical disks. #>
    try {
        $perf = Get-CimInstance -ClassName Win32_PerfFormattedData_PerfDisk_PhysicalDisk `
                    -Filter "Name='_Total'" -ErrorAction Stop
        if ($perf) {
            return [ordered]@{
                AvgLatencyMs = [math]::Round($perf.AvgDisksecPerTransfer * 1000, 1)
                QueueLength  = [math]::Round($perf.CurrentDiskQueueLength, 1)
            }
        }
    }
    catch { }
    return $null
}

function Get-TopCpuProcesses {
    <# Real-time CPU% via two Get-Process snapshots (cumulative CPU seconds
       since process start is misleading for "what's slow right now"). #>
    param(
        [int]$Top = 3,
        [int]$SampleMs = 700,
        [int]$LogicalProcessors = 1
    )
    try {
        $before = Get-Process -ErrorAction Stop | Select-Object Id, ProcessName, CPU
        Start-Sleep -Milliseconds $SampleMs
        $after = Get-Process -ErrorAction Stop | Select-Object Id, ProcessName, CPU

        $beforeCpu = @{}
        foreach ($p in $before) { if ($p.CPU) { $beforeCpu[$p.Id] = $p.CPU } }

        $cores = [math]::Max($LogicalProcessors, 1)
        $rows = foreach ($p in $after) {
            if ($p.CPU -and $beforeCpu.ContainsKey($p.Id)) {
                $deltaSec = $p.CPU - $beforeCpu[$p.Id]
                if ($deltaSec -gt 0) {
                    [pscustomobject]@{
                        Name   = $p.ProcessName
                        PctCpu = [math]::Round(($deltaSec / ($SampleMs / 1000.0) / $cores) * 100, 0)
                    }
                }
            }
        }
        return @($rows | Sort-Object PctCpu -Descending | Select-Object -First $Top)
    }
    catch { return @() }
}

function Get-ProxyConfig {
    <# WinHTTP (machine-wide) + per-user IE/WinInet proxy settings via SID hive. #>
    param([string]$UserName)

    $result = [ordered]@{ WinHTTP = 'Direct (no proxy)'; IE = $null }
    try {
        $raw = netsh winhttp show proxy 2>$null
        $line = $raw | Where-Object { $_ -match 'Proxy Server' }
        if ($line -and $line -match ':\s*(.+)$') { $result.WinHTTP = $Matches[1].Trim() }
    }
    catch { }

    try {
        if ($UserName) {
            $UserObj = New-Object System.Security.Principal.NTAccount($UserName)
            $UserSID = $UserObj.Translate([System.Security.Principal.SecurityIdentifier]).Value
            $ieKey = "Registry::HKEY_USERS\$UserSID\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
            if (Test-Path $ieKey) {
                $ie = Get-ItemProperty -Path $ieKey -ErrorAction SilentlyContinue
                if ($ie.ProxyEnable -eq 1 -and $ie.ProxyServer) { $result.IE = $ie.ProxyServer }
                elseif ($ie.AutoConfigURL) { $result.IE = "PAC: $($ie.AutoConfigURL)" }
                else { $result.IE = 'Direct (no proxy)' }
            }
        }
    }
    catch { }
    return $result
}

function Remove-OldTriageExports {
    <# Prunes Triage_*.json/.txt pairs beyond -Keep, oldest first. #>
    param([string]$Directory, [int]$Keep = 20)
    if ($Keep -le 0 -or -not $Directory -or -not (Test-Path $Directory)) { return }
    try {
        $files = Get-ChildItem -Path $Directory -Filter 'Triage_*.json' -File -ErrorAction SilentlyContinue |
                 Sort-Object LastWriteTime -Descending
        if ($files.Count -gt $Keep) {
            foreach ($old in ($files | Select-Object -Skip $Keep)) {
                Remove-Item -Path $old.FullName -Force -ErrorAction SilentlyContinue
                $txt = [System.IO.Path]::ChangeExtension($old.FullName, 'txt')
                if (Test-Path $txt) { Remove-Item -Path $txt -Force -ErrorAction SilentlyContinue }
            }
        }
    }
    catch { }
}

function Build-ServiceNowSummary {
    <# Renders a plain-text, copy-paste-ready summary from the collected data. #>
    param($Data, $FindingsList, [string]$JsonPath)

    $L = New-Object System.Collections.Generic.List[string]

    $L.Add(("ENDPOINT DIAGNOSTIC SUMMARY  ({0})" -f (Get-Date).ToString('yyyy-MM-dd HH:mm')))
    $L.Add('=' * 52)
    $L.Add('')

    # ---- Key findings (the punchline) ----
    $L.Add('KEY FINDINGS:')
    if (-not $FindingsList -or $FindingsList.Count -eq 0) {
        $L.Add('  - None. All checked metrics are within normal thresholds.')
    }
    else {
        foreach ($f in ($FindingsList | Sort-Object @{ E = { Get-SeverityRank $_.Severity } })) {
            $L.Add(("  - [{0}] {1}" -f $f.Severity.ToUpper(), $f.Message))
        }
    }
    $L.Add('')

    # ---- System ----
    $L.Add('SYSTEM')
    $L.Add(("  Logged-on User: {0}" -f $(if ($Data.System.LoggedOnUser) { $Data.System.LoggedOnUser } else { 'None / not detected' })))
    $L.Add(("  Computer      : {0}  ({1})" -f $Data.System.Hostname, $Data.System.Model))
    $L.Add(("  OS            : {0} (build {1})" -f $Data.System.OS, $Data.System.OSBuild))
    $L.Add(("  Uptime        : {0} days" -f $Data.System.Uptime_Days))
    $L.Add(("  Pending Reboot: {0}" -f $(if ($Data.System.PendingReboot) { "Yes - $($Data.System.RebootReasons)" } else { 'No' })))
    $L.Add('')

    # ---- Performance ----
    $p = $Data.Performance
    $L.Add('PERFORMANCE')
    $L.Add(("  CPU Load      : {0}%" -f $p.CPU_LoadPct))
    $L.Add(("  Memory        : {0}% used ({1} GB free of {2} GB)" -f $p.Memory_UsedPct, $p.Memory_FreeGB, $p.Memory_TotalGB))
    $L.Add(("  Disk {0} free   : {1}% ({2} GB free of {3} GB)" -f $p.Disk, $p.Disk_FreePct, $p.Disk_FreeGB, $p.Disk_SizeGB))
    if ($null -ne $p.Disk_LatencyMs) { $L.Add(("  Disk Latency  : {0} ms avg (queue {1})" -f $p.Disk_LatencyMs, $p.Disk_QueueLength)) }
    if ($p.TopCPU.Count)    { $L.Add(("  Top CPU       : {0}" -f ($p.TopCPU -join ', '))) }
    if ($p.TopMemory.Count) { $L.Add(("  Top Memory    : {0}" -f ($p.TopMemory -join ', '))) }
    $L.Add('')

    # ---- Network ----
    $L.Add('NETWORK')
    $L.Add(("  VPN           : {0}" -f $Data.VPN_Status))
    if ($Data.Zscaler_State)  { $L.Add(("  Zscaler       : {0}" 