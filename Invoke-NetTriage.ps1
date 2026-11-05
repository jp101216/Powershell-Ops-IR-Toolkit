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
      - VPN client activity and active tunnel-interface evidence
      - Destination route, source address, and interface DNS configuration
      - Proxy configuration (WinHTTP + per-user IE/WinInet settings)
      - Latency/quality metrics (RTT + packet loss to gateway/DNS, DNS resolve time)
      - Core infrastructure health (TCP reachability + connect latency)
        using a CoreInfrastructure.json file or -CoreInfrastructurePath.
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

.PARAMETER SkipPublicProbes
    Skip the built-in public DNS name lookup, public TCP probe, and egress-IP
    lookup. Local checks and explicitly configured destinations still run.

.PARAMETER DnsProbeName
    DNS name to resolve for the timed DNS check. Defaults to www.microsoft.com
    unless -SkipPublicProbes is set. An explicit name works with either mode.

.PARAMETER CoreInfrastructurePath
    Path to a JSON array of objects with Name, Host, and Port properties.
    Defaults to CoreInfrastructure.json beside the script when present.

.PARAMETER NonInteractive
    Skip the target prompt when -TargetDestination is omitted.

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

.EXAMPLE
    .\Invoke-NetTriage.ps1 -NonInteractive -SkipPublicProbes -DnsProbeName intranet.example.com -CoreInfrastructurePath .\BranchOffice.json
    Check the configured infrastructure and internal DNS name.

.NOTES
    Compatible with Windows PowerShell 5.1 and PowerShell 7+.
    Read-only. Safe to run in a user or PAM/elevated context.
    Version 2.2
    v2 RECONSTRUCTION NOTE: The repo original was truncated at exactly
    20000 bytes, ending mid-line inside Build-ServiceNowSummary. This v2
    file keeps the original code up to that truncation point, then
    reconstructs the missing summary tail, dashboard, $Data collection,
    findings analysis, export, and pruning from the README and the
    script's own helpers/field names. Every reconstructed section is
    marked 'RECONSTRUCTED in v2'. Do not treat reconstructed code as
    Jessie's original. This tool remains READ-ONLY.
#>

[CmdletBinding()]
param (
    [string]$TargetDestination = "",

    [Alias('TargetPort')]
    [ValidateRange(1, 65535)]
    [int[]] $TargetPorts        = @(443, 80, 445, 3389),

    [string]$ExportPath         = "$env:LOCALAPPDATA\NetTriage\Triage_$((Get-Date).ToString('yyyyMMdd_HHmmss_fff')).json",
    [ValidateRange(1, 20)]
    [int]   $PingCount          = 4,
    [ValidateRange(1, 60000)]
    [int]   $TcpTimeoutMs       = 1500,
    [ValidateRange(1, 60000)]
    [int]   $PingTimeoutMs      = 1000,
    [ValidateRange(0, [int]::MaxValue)]
    [int]   $RetainCount        = 20,
    [switch]$SkipExternalIP,
    [switch]$SkipPublicProbes,
    [ValidateNotNullOrEmpty()]
    [string]$DnsProbeName,
    [ValidateNotNullOrEmpty()]
    [string]$CoreInfrastructurePath,
    [switch]$NonInteractive,
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
$CoreInfrastructure = @()
if (-not $CoreInfrastructurePath) {
    $defaultConfigPath = Join-Path -Path $PSScriptRoot -ChildPath 'CoreInfrastructure.json'
    if (Test-Path -LiteralPath $defaultConfigPath -PathType Leaf) {
        $CoreInfrastructurePath = $defaultConfigPath
    }
}
if ($CoreInfrastructurePath) {
    $configJson = Get-Content -LiteralPath $CoreInfrastructurePath -Raw -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($configJson) -or -not $configJson.TrimStart().StartsWith('[')) {
        throw "Infrastructure config '$CoreInfrastructurePath' must contain a JSON array."
    }
    # Wrap the JSON to preserve null entries and empty arrays in both editions.
    $config = ('{"Targets":' + $configJson + '}') | ConvertFrom-Json -ErrorAction Stop
    if ($config.Targets -isnot [array] -or @($config.PSObject.Properties).Count -ne 1) {
        throw "Infrastructure config '$CoreInfrastructurePath' must contain a JSON array."
    }
    $CoreInfrastructure = @(for ($i = 0; $i -lt $config.Targets.Count; $i++) {
        $targetConfig = $config.Targets[$i]
        $portNumber = 0
        if ($targetConfig.Name -isnot [string] -or [string]::IsNullOrWhiteSpace($targetConfig.Name) -or
            $targetConfig.Host -isnot [string] -or [string]::IsNullOrWhiteSpace($targetConfig.Host) -or
            -not [int]::TryParse([string]$targetConfig.Port, [ref]$portNumber) -or $portNumber -lt 1 -or $portNumber -gt 65535) {
            throw "Infrastructure config '$CoreInfrastructurePath', entry $($i + 1): expected Name, Host, and a TCP port from 1 to 65535."
        }
        @{ Name = $targetConfig.Name.Trim(); Host = $targetConfig.Host.Trim(); Port = $portNumber }
    })
}
elseif (-not $SkipPublicProbes) {
    $CoreInfrastructure = @(@{ Name = 'Public DNS TCP probe'; Host = '8.8.8.8'; Port = 53 })
}
if (-not $DnsProbeName -and -not $SkipPublicProbes) {
    $DnsProbeName = 'www.microsoft.com'
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
    $client = $null
    $waitHandle = $null
    try {
        $address = $null
        if ([System.Net.IPAddress]::TryParse($ComputerName, [ref]$address)) {
            $client = New-Object System.Net.Sockets.TcpClient -ArgumentList $address.AddressFamily
        }
        else { $client = New-Object System.Net.Sockets.TcpClient }
        $sw  = [System.Diagnostics.Stopwatch]::StartNew()
        $iar = $client.BeginConnect($ComputerName, $Port, $null, $null)
        $waitHandle = $iar.AsyncWaitHandle
        if ($waitHandle.WaitOne($TimeoutMs, $false)) {
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
        if ($null -ne $client) { $client.Close() }
        if ($null -ne $waitHandle) { $waitHandle.Dispose() }
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
    if ($Count -le 0) { $out.Sent = 0; $out.LossPct = 100; return $out }
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

function Resolve-DiagnosticTarget {
    param([Parameter(Mandatory = $true)][string]$Name)
    $result = [pscustomobject]@{ Address = $null; Addresses = @(); Error = $null }
    try {
        $address = $null
        if ([System.Net.IPAddress]::TryParse($Name, [ref]$address)) {
            $result.Addresses = @($address.ToString())
        }
        else {
            $result.Addresses = @([System.Net.Dns]::GetHostAddresses($Name) |
                ForEach-Object { $_.ToString() } | Select-Object -Unique)
        }
        if ($result.Addresses.Count -eq 0) { throw 'The resolver returned no IP addresses.' }
        $result.Address = $result.Addresses[0]
    }
    catch { $result.Error = $_.Exception.Message }
    return $result
}

function Get-DiagnosticRoute {
    param([string]$RemoteAddress)
    $context = [pscustomobject]@{
        RemoteAddress = $RemoteAddress
        Selection = 'Destination'
        InterfaceIndex = $null
        InterfaceAlias = $null
        LocalAddress = $null
        NextHop = $null
        DestinationPrefix = $null
        DNSServers = @()
        Error = $null
        DNSError = $null
    }
    try {
        if ($RemoteAddress) {
            $selected = @(Find-NetRoute -RemoteIPAddress $RemoteAddress -ErrorAction Stop)
            $route = $selected | Where-Object { $_.PSObject.Properties['DestinationPrefix'] } | Select-Object -First 1
            $local = $selected | Where-Object { $_.PSObject.Properties['IPAddress'] } | Select-Object -First 1
            if ($local) { $context.LocalAddress = $local.IPAddress }
        }
        else {
            $routes = @(Get-NetRoute -ErrorAction Stop |
                Where-Object { $_.DestinationPrefix -in @('0.0.0.0/0', '::/0') })
            $interfaces = @(Get-NetIPInterface -ErrorAction Stop | Where-Object { $_.ConnectionState -eq 'Connected' })
            $routes = @($routes | Where-Object {
                $candidate = $_
                @($interfaces | Where-Object {
                    $_.InterfaceIndex -eq $candidate.InterfaceIndex -and
                    [string]$_.AddressFamily -eq [string]$candidate.AddressFamily
                }).Count -gt 0
            })
            $ipv4 = @($routes | Where-Object { $_.DestinationPrefix -eq '0.0.0.0/0' })
            $context.Selection = 'DefaultIPv6'
            if ($ipv4.Count -gt 0) { $routes = $ipv4; $context.Selection = 'DefaultIPv4' }
            $route = $routes | Sort-Object @{ Expression = { [long]$_.RouteMetric + [long]$_.InterfaceMetric } }, InterfaceIndex |
                Select-Object -First 1
        }
        if ($null -eq $route) { throw 'Windows returned no usable route.' }
        $context.InterfaceIndex = $route.InterfaceIndex
        $context.InterfaceAlias = $route.InterfaceAlias
        $context.NextHop = $route.NextHop
        $context.DestinationPrefix = $route.DestinationPrefix
        try {
            $context.DNSServers = @(Get-DnsClientServerAddress -InterfaceIndex $route.InterfaceIndex -ErrorAction Stop |
                ForEach-Object { $_.ServerAddresses } | Where-Object { $_ } | ForEach-Object {
                    $serverAddress = $null
                    if ([System.Net.IPAddress]::TryParse($_, [ref]$serverAddress) -and
                        $serverAddress.IsIPv6LinkLocal -and $serverAddress.ScopeId -eq 0) {
                        "$_%$($route.InterfaceIndex)"
                    }
                    else { $_ }
                } | Select-Object -Unique)
        }
        catch { $context.DNSError = $_.Exception.Message }
    }
    catch { $context.Error = $_.Exception.Message }
    return $context
}

function Test-ResolvedTcpPort {
    param($Resolution, [int]$Port, [int]$TimeoutMs)
    $result = [pscustomobject]@{
        Success = $false; LatencyMs = $null; Error = $Resolution.Error
        ResolvedAddress = $null; Route = $null; Attempts = @()
    }
    if ($Resolution.Error) { return $result }
    $clock = [System.Diagnostics.Stopwatch]::StartNew()
    for ($i = 0; $i -lt $Resolution.Addresses.Count; $i++) {
        $remaining = $TimeoutMs - [int]$clock.Elapsed.TotalMilliseconds
        if ($remaining -le 0) { break }
        $budget = [math]::Max(1, [math]::Floor($remaining / ($Resolution.Addresses.Count - $i)))
        $address = $Resolution.Addresses[$i]
        $probe = Test-TcpPort -ComputerName $address -Port $Port -TimeoutMs $budget
        $result.ResolvedAddress = $address
        $result.Attempts += [pscustomobject]@{
            Address = $address; Success = $probe.Success; LatencyMs = $probe.LatencyMs; Error = $probe.Error
        }
        if ($probe.Success) {
            $result.Success = $true
            $result.LatencyMs = $probe.LatencyMs
            break
        }
    }
    if ($result.ResolvedAddress) {
        $result.Route = Get-DiagnosticRoute -RemoteAddress $result.ResolvedAddress
    }
    if (-not $result.Success) {
        $details = @($result.Attempts | ForEach-Object { "$($_.Address) - $($_.Error)" })
        if ($result.Attempts.Count -lt $Resolution.Addresses.Count) { $details += 'TCP probe time budget exhausted.' }
        $result.Error = $details -join ' | '
    }
    return $result
}

function Get-VpnEvidence {
    $evidence = [pscustomobject]@{
        Clients = @()
        Tunnels = @()
        Errors = @()
        Summary = 'No VPN indicators detected'
    }
    foreach ($provider in @(
        @{ Name = 'Cisco Secure Client'; Services = @('vpnagent'); Processes = @('vpnui', 'vpnagent'); Pattern = 'Cisco.*(AnyConnect|Secure Client)|AnyConnect' }
        @{ Name = 'Zscaler'; Services = @('ZSATunnel', 'ZSAService'); Processes = @('ZSATunnel', 'ZSAService'); Pattern = 'Zscaler' }
    )) {
        $running = @(Get-Service -Name $provider.Services -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Running' }).Count -gt 0
        $processes = @(Get-Process -Name $provider.Processes -ErrorAction SilentlyContinue)
        $evidence.Clients += [pscustomobject]@{
            Name = $provider.Name; Pattern = $provider.Pattern
            Running = ($running -or $processes.Count -gt 0)
            TunnelObserved = $false
        }
    }
    try {
        $adapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object {
            $_.Status -eq 'Up' -and $_.InterfaceDescription -match
                'Cisco.*(AnyConnect|Secure Client)|AnyConnect|Zscaler|VPN|WireGuard|Wintun|TAP-Windows|OpenVPN|GlobalProtect|Fortinet|FortiClient|SonicWall'
        })
        foreach ($adapter in $adapters) {
            try {
                $addresses = @(Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -Type Unicast -ErrorAction Stop |
                    Where-Object {
                        $parsed = $null
                        $_.AddressState -eq 'Preferred' -and -not $_.SkipAsSource -and
                        [System.Net.IPAddress]::TryParse($_.IPAddress, [ref]$parsed) -and
                        -not [System.Net.IPAddress]::IsLoopback($parsed) -and
                        -not $parsed.Equals([System.Net.IPAddress]::Any) -and
                        -not $parsed.Equals([System.Net.IPAddress]::IPv6Any) -and
                        -not $parsed.IsIPv6LinkLocal -and $_.IPAddress -notlike '169.254.*'
                    } | Select-Object -ExpandProperty IPAddress)
                if ($addresses.Count -eq 0) { continue }
                $providerName = 'Unidentified VPN'
                foreach ($client in $evidence.Clients) {
                    if ($adapter.InterfaceDescription -match $client.Pattern) {
                        $client.TunnelObserved = $true
                        $providerName = $client.Name
                    }
                }
                $evidence.Tunnels += [pscustomobject]@{
                    Provider = $providerName; InterfaceIndex = $adapter.ifIndex
                    InterfaceAlias = $adapter.Name; Description = $adapter.InterfaceDescription
                    Addresses = $addresses
                }
            }
            catch { $evidence.Errors += "$($adapter.Name) tunnel inspection failed. $($_.Exception.Message)" }
        }
    }
    catch { $evidence.Errors += $_.Exception.Message }
    $states = @(
        foreach ($client in $evidence.Clients) {
            if ($client.TunnelObserved) { "Tunnel interface active - $($client.Name)" }
            elseif ($client.Running) { "Client running - tunnel unverified - $($client.Name)" }
        }
        foreach ($tunnel in $evidence.Tunnels | Where-Object { $_.Provider -eq 'Unidentified VPN' }) {
            "VPN interface active - $($tunnel.InterfaceAlias)"
        }
    )
    if ($evidence.Errors.Count -gt 0) { $states += 'Tunnel inspection incomplete' }
    if ($states.Count -gt 0) { $evidence.Summary = $states -join ' | ' }
    return $evidence
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
    param([string]$Directory, [int]$Keep = 20, [string]$CurrentPath)
    if ($Keep -le 0 -or -not $Directory) { return }
    try {
        $files = @(Get-ChildItem -LiteralPath $Directory -Filter 'Triage_*.json' -File -ErrorAction Stop |
                 Where-Object { $_.Name -match '^Triage_\d{8}_\d{6}(?:_\d{3})?\.json$' } |
                 Sort-Object LastWriteTime -Descending)
        $current = @( $files | Where-Object { $_.FullName -eq $CurrentPath } )
        $older = $files | Where-Object { $_.FullName -ne $CurrentPath } | Select-Object -Skip ($Keep - $current.Count)
        foreach ($old in $older) {
            Remove-Item -LiteralPath $old.FullName -Force -ErrorAction Stop
            $txt = [System.IO.Path]::ChangeExtension($old.FullName, 'txt')
            if (Test-Path -LiteralPath $txt -PathType Leaf) {
                Remove-Item -LiteralPath $txt -Force -ErrorAction Stop
            }
        }
    }
    catch { Write-Warning "Export pruning failed: $($_.Exception.Message)" }
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
    # ======================================================================
    # RECONSTRUCTED in v2 - not present in the truncated repo original
    # The repo original ends mid-line on the Zscaler line above. Everything
    # from here to the end of Build-ServiceNowSummary is reconstruction
    # based on the README, the $Data field names already used above, and
    # the script's own helpers (Format-PingStat, Get-SeverityRank, etc.).
    # ======================================================================
    if ($Data.Zscaler_State) { $L.Add(("  Zscaler       : {0}" -f $Data.Zscaler_State)) }
    if ($Data.VPN_TunnelIP) { $L.Add(("  Tunnel IP       : {0}" -f $Data.VPN_TunnelIP)) }
    if ($Data.VPN_Detail) { $L.Add(("  VPN Detail      : {0}" -f $Data.VPN_Detail)) }
    if ($Data.Network.Adapters -and $Data.Network.Adapters.Count -gt 0) {
        foreach ($adapter in $Data.Network.Adapters) {
            $L.Add(("  Adapter       : {0}" -f $adapter))
        }
    }
    if ($Data.Network.Gateway) { $L.Add(("  Gateway       : {0}" -f $Data.Network.Gateway)) }
    if ($Data.Network.Route -and -not $Data.Network.Route.Error) {
        $L.Add(("  Route interface  {0} (index {1})" -f $Data.Network.Route.InterfaceAlias, $Data.Network.Route.InterfaceIndex))
        $L.Add(("  Route selection  {0}" -f $Data.Network.Route.Selection))
        if ($Data.Network.Route.LocalAddress) {
            $L.Add(("  Route source     {0} to {1}" -f $Data.Network.Route.LocalAddress, $Data.Network.Route.RemoteAddress))
        }
    }
    if ($Data.Network.DNS -and $Data.Network.DNS.Count -gt 0) {
        $L.Add(("  DNS Servers   : {0}" -f ($Data.Network.DNS -join ', ')))
    }
    if ($Data.Network.WifiSSID) {
        $L.Add(("  Wi-Fi         : {0} ({1}% signal)" -f $Data.Network.WifiSSID, $Data.Network.WifiSignalPct))
    }
    if ($Data.Proxy_WinHTTP) { $L.Add(("  Proxy (WinHTTP): {0}" -f $Data.Proxy_WinHTTP)) }
    if ($Data.Proxy_IE) { $L.Add(("  Proxy (IE)    : {0}" -f $Data.Proxy_IE)) }
    $L.Add('')

    # ---- Latency / quality ----
    $L.Add('LATENCY')
    if ($Data.Latency.Gateway) {
        $L.Add(("  Gateway ({0}) : {1}" -f $Data.Latency.Gateway.Target, (Format-PingStat $Data.Latency.Gateway)))
    }
    else {
        $L.Add('  Gateway       : n/a')
    }
    if ($Data.Latency.DNS) {
        $L.Add(("  DNS ({0})     : {1}" -f $Data.Latency.DNS.Target, (Format-PingStat $Data.Latency.DNS)))
    }
    else {
        $L.Add('  DNS           : n/a')
    }
    if ($Data.Latency.DNS_ProbeError) {
        $L.Add(("  DNS resolve   : {0} failed" -f $Data.Latency.DNS_ProbeName))
    }
    elseif ($null -ne $Data.Latency.DNS_ResolveMs) {
        $L.Add(("  DNS resolve   : {0} in {1} ms" -f $Data.Latency.DNS_ProbeName, $Data.Latency.DNS_ResolveMs))
    }
    $L.Add('')

    # ---- Core infrastructure ----
    $L.Add('CORE INFRASTRUCTURE')
    if ($Data.CoreInfrastructure -and $Data.CoreInfrastructure.Count -gt 0) {
        foreach ($item in $Data.CoreInfrastructure) {
            if ($item.Success) {
                $L.Add(("  [OK]   {0} ({1}:{2}) - {3} ms" -f $item.Name, $item.Host, $item.Port, $item.LatencyMs))
            }
            else {
                $L.Add(("  [FAIL] {0} ({1}:{2}) - {3}" -f $item.Name, $item.Host, $item.Port, $item.Error))
            }
            if ($item.Route -and -not $item.Route.Error) {
                $L.Add(("    Via {0} (index {1}), destination {2}" -f $item.Route.InterfaceAlias, $item.Route.InterfaceIndex, $item.ResolvedAddress))
            }
            elseif ($item.Route) { $L.Add(("    Route unavailable  {0}" -f $item.Route.Error)) }
        }
    }
    else {
        $L.Add('  (no core infrastructure results)')
    }
    $L.Add('')

    # ---- Single-target diagnostic ----
    $L.Add('TARGET DIAGNOSTIC')
    if ($Data.Target -and $Data.Target.Destination) {
        $L.Add(("  Target        : {0}" -f $Data.Target.Destination))
        if ($Data.Target.DNS_Resolved) { $L.Add(("  DNS resolved  : {0}" -f $Data.Target.DNS_Resolved)) }
        if ($Data.Target.Ping) {
            $L.Add(("  Ping          : {0}" -f (Format-PingStat $Data.Target.Ping)))
        }
        if ($Data.Target.Ports -and $Data.Target.Ports.Count -gt 0) {
            foreach ($portResult in $Data.Target.Ports) {
                if ($portResult.Success) {
                    $L.Add(("  Port {0}       : open ({1} ms)" -f $portResult.Port, $portResult.LatencyMs))
                }
                else {
                    $L.Add(("  Port {0}       : failed - {1}" -f $portResult.Port, $portResult.Error))
                }
            }
        }
    }
    else {
        $L.Add('  (no target destination supplied)')
    }
    $L.Add('')

    # ---- Egress ----
    $L.Add('EGRESS')
    if ($Data.ExternalIP) {
        $L.Add(("  External IP   : {0}" -f $Data.ExternalIP))
    }
    else {
        $L.Add('  External IP   : n/a (skipped or lookup failed)')
    }
    $L.Add('')

    if ($JsonPath) {
        $L.Add(("Full JSON : {0}" -f $JsonPath))
    }

    return ($L -join "`r`n")
}

# ==========================================================================
# RECONSTRUCTED in v2 - not present in the truncated repo original
# Interactive dashboard. This is the color-coded console view described in
# the README / help. It prints only to the console (Write-Host); Quiet mode
# never calls it, so a Quiet pipeline stays clean for clipboard use.
# ==========================================================================
function Show-Dashboard {
    param($Data, $FindingsList)

    Write-Host ''
    Write-Host '============================================================' -ForegroundColor Cyan
    Write-Host ("  NETWORK & SYSTEM TRIAGE  -  {0}" -f $Data.System.Hostname) -ForegroundColor Cyan
    Write-Host '============================================================' -ForegroundColor Cyan
    Write-Host ''

    Write-Host 'KEY FINDINGS' -ForegroundColor White
    if (-not $FindingsList -or $FindingsList.Count -eq 0) {
        Write-Host '  - None. All checked metrics are within normal thresholds.' -ForegroundColor Green
    }
    else {
        foreach ($finding in ($FindingsList | Sort-Object @{ E = { Get-SeverityRank $_.Severity } })) {
            $color = Get-SeverityColor $finding.Severity
            Write-Host ("  - [{0}] {1}" -f $finding.Severity.ToUpper(), $finding.Message) -ForegroundColor $color
        }
    }
    Write-Host ''

    Write-Host 'SYSTEM' -ForegroundColor White
    Write-Field 'Logged-on User' $Data.System.LoggedOnUser
    Write-Field 'Computer' ("{0} ({1})" -f $Data.System.Hostname, $Data.System.Model)
    Write-Field 'OS' ("{0} (build {1})" -f $Data.System.OS, $Data.System.OSBuild)
    $uptimeSev = Get-Severity -Value $Data.System.Uptime_Days -Warn $Thresholds.UptimeDays.Warn -Crit $Thresholds.UptimeDays.Crit
    Write-Field 'Uptime' ("{0} days" -f $Data.System.Uptime_Days) (Get-SeverityColor $uptimeSev)
    $rebootText = 'No'
    if ($Data.System.PendingReboot) { $rebootText = "Yes - $($Data.System.RebootReasons)" }
    $rebootColor = [ConsoleColor]::Green
    if ($Data.System.PendingReboot) { $rebootColor = [ConsoleColor]::Yellow }
    Write-Field 'Pending Reboot' $rebootText $rebootColor
    Write-Host ''

    $perf = $Data.Performance
    Write-Host 'PERFORMANCE' -ForegroundColor White
    Write-Field 'CPU Load' ("{0}%" -f $perf.CPU_LoadPct) (Get-MetricColor -Value $perf.CPU_LoadPct -Warn $Thresholds.CpuPct.Warn -Crit $Thresholds.CpuPct.Crit)
    Write-Field 'Memory' ("{0}% used ({1} GB free of {2} GB)" -f $perf.Memory_UsedPct, $perf.Memory_FreeGB, $perf.Memory_TotalGB) (Get-MetricColor -Value $perf.Memory_UsedPct -Warn $Thresholds.MemPct.Warn -Crit $Thresholds.MemPct.Crit)
    Write-Field ("Disk {0}" -f $perf.Disk) ("{0}% free ({1} GB free of {2} GB)" -f $perf.Disk_FreePct, $perf.Disk_FreeGB, $perf.Disk_SizeGB) (Get-MetricColor -Value $perf.Disk_FreePct -Warn $Thresholds.DiskFreePct.Warn -Crit $Thresholds.DiskFreePct.Crit -LowerIsWorse)
    if ($null -ne $perf.Disk_LatencyMs) {
        Write-Field 'Disk Latency' ("{0} ms avg (queue {1})" -f $perf.Disk_LatencyMs, $perf.Disk_QueueLength) (Get-MetricColor -Value $perf.Disk_LatencyMs -Warn $Thresholds.DiskLatencyMs.Warn -Crit $Thresholds.DiskLatencyMs.Crit)
    }
    if ($perf.TopCPU.Count -gt 0) { Write-Field 'Top CPU' ($perf.TopCPU -join ', ') }
    if ($perf.TopMemory.Count -gt 0) { Write-Field 'Top Memory' ($perf.TopMemory -join ', ') }
    Write-Host ''

    Write-Host 'NETWORK' -ForegroundColor White
    Write-Field 'VPN' $Data.VPN_Status
    if ($Data.Zscaler_State) { Write-Field 'Zscaler' $Data.Zscaler_State }
    if ($Data.VPN_TunnelIP) { Write-Field 'Tunnel IP' $Data.VPN_TunnelIP }
    if ($Data.Network.Adapters -and $Data.Network.Adapters.Count -gt 0) {
        foreach ($adapter in $Data.Network.Adapters) { Write-Field 'Adapter' $adapter }
    }
    if ($Data.Network.Gateway) { Write-Field 'Gateway' $Data.Network.Gateway }
    if ($Data.Network.Route -and -not $Data.Network.Route.Error) {
        Write-Field 'Route interface' ("{0} (index {1})" -f $Data.Network.Route.InterfaceAlias, $Data.Network.Route.InterfaceIndex)
        Write-Field 'Route selection' $Data.Network.Route.Selection
        if ($Data.Network.Route.LocalAddress) {
            Write-Field 'Route source' ("{0} to {1}" -f $Data.Network.Route.LocalAddress, $Data.Network.Route.RemoteAddress)
        }
    }
    if ($Data.Network.DNS -and $Data.Network.DNS.Count -gt 0) { Write-Field 'DNS Servers' ($Data.Network.DNS -join ', ') }
    if ($Data.Network.WifiSSID) {
        if ($null -ne $Data.Network.WifiSignalPct) {
            $wifiColor = Get-MetricColor -Value $Data.Network.WifiSignalPct -Warn $Thresholds.WifiPct.Warn -Crit $Thresholds.WifiPct.Crit -LowerIsWorse
            Write-Field 'Wi-Fi' ("{0} ({1}%)" -f $Data.Network.WifiSSID, $Data.Network.WifiSignalPct) $wifiColor
        }
        else {
            Write-Field 'Wi-Fi' $Data.Network.WifiSSID
        }
    }
    if ($Data.Proxy_WinHTTP) { Write-Field 'Proxy (WinHTTP)' $Data.Proxy_WinHTTP }
    if ($Data.Proxy_IE) { Write-Field 'Proxy (IE)' $Data.Proxy_IE }
    Write-Host ''

    Write-Host 'LATENCY' -ForegroundColor White
    if ($Data.Latency.Gateway) {
        Write-Field ("Gateway ({0})" -f $Data.Latency.Gateway.Target) (Format-PingStat $Data.Latency.Gateway)
    }
    if ($Data.Latency.DNS) {
        Write-Field ("DNS ({0})" -f $Data.Latency.DNS.Target) (Format-PingStat $Data.Latency.DNS)
    }
    if ($Data.Latency.DNS_ProbeError) {
        Write-Field 'DNS resolve' "$($Data.Latency.DNS_ProbeName) failed" Yellow
    }
    elseif ($null -ne $Data.Latency.DNS_ResolveMs) {
        Write-Field 'DNS resolve' ("{0} in {1} ms" -f $Data.Latency.DNS_ProbeName, $Data.Latency.DNS_ResolveMs) (Get-MetricColor -Value $Data.Latency.DNS_ResolveMs -Warn $Thresholds.DnsMs.Warn -Crit $Thresholds.DnsMs.Crit)
    }
    Write-Host ''

    Write-Host 'CORE INFRASTRUCTURE' -ForegroundColor White
    if ($Data.CoreInfrastructure -and $Data.CoreInfrastructure.Count -gt 0) {
        foreach ($item in $Data.CoreInfrastructure) {
            $color = [ConsoleColor]::Green
            $statusText = 'OK'
            if (-not $item.Success) { $color = [ConsoleColor]::Red; $statusText = 'FAIL' }
            $detail = $item.Error
            if ($item.Success) { $detail = ("{0} ms" -f $item.LatencyMs) }
            Write-Field $item.Name ("{0}:{1} - {2} ({3})" -f $item.Host, $item.Port, $statusText, $detail) $color
        }
    }
    Write-Host ''

    if ($Data.Target -and $Data.Target.Destination) {
        Write-Host 'TARGET DIAGNOSTIC' -ForegroundColor White
        Write-Field 'Target' $Data.Target.Destination
        if ($Data.Target.DNS_Resolved) { Write-Field 'DNS resolved' $Data.Target.DNS_Resolved }
        if ($Data.Target.Ping) { Write-Field 'Ping' (Format-PingStat $Data.Target.Ping) }
        if ($Data.Target.Ports -and $Data.Target.Ports.Count -gt 0) {
            foreach ($portResult in $Data.Target.Ports) {
                $color = [ConsoleColor]::Green
                $detail = ("open ({0} ms)" -f $portResult.LatencyMs)
                if (-not $portResult.Success) { $color = [ConsoleColor]::Red; $detail = ("failed - {0}" -f $portResult.Error) }
                Write-Field ("Port {0}" -f $portResult.Port) $detail $color
            }
        }
        Write-Host ''
    }

    Write-Host 'EGRESS' -ForegroundColor White
    if ($Data.ExternalIP) { Write-Field 'External IP' $Data.ExternalIP } else { Write-Field 'External IP' 'n/a' }
    Write-Host ''
}

# ==========================================================================
# RECONSTRUCTED in v2 - MAIN FLOW
# Not present in the truncated repo original. The original ends inside
# Build-ServiceNowSummary, so there is no $Data population, dashboard call,
# export, or pruning in the repo file at all. This flow populates $Data
# using only the helpers already in the file, plus standard CIM / network
# cmdlets, in the same field names the summary above already expects.
# READ-ONLY: no step here changes configuration, clears caches, or
# restarts anything. Export pruning only deletes this script's own old
# Triage_*.json/.txt pairs, as documented.
# ==========================================================================

# Prompt for a target only when interactive. Quiet / redirected runs must
# not hang on Read-Host, so they simply skip the target diagnostic.
if ([string]::IsNullOrWhiteSpace($TargetDestination)) {
    $isInteractive = $true
    try {
        if ([Console]::IsInputRedirected) { $isInteractive = $false }
    }
    catch { }
    if ($isInteractive -and -not $Quiet -and -not $NonInteractive) {
        $prompted = Read-Host 'Target hostname/IP to diagnose (press Enter to skip)'
        if (-not [string]::IsNullOrWhiteSpace($prompted)) { $TargetDestination = $prompted.Trim() }
    }
}

$Data = [ordered]@{
    CollectedUtc = (Get-Date).ToUniversalTime().ToString('o')
    Computer     = $env:COMPUTERNAME
    System       = [ordered]@{
        LoggedOnUser  = $env:USERNAME
        Hostname      = $env:COMPUTERNAME
        Model         = $null
        OS            = $null
        OSBuild       = $null
        Uptime_Days   = 0
        PendingReboot = $false
        RebootReasons = ''
    }
    Performance  = [ordered]@{
        CPU_LoadPct    = 0
        Memory_UsedPct = 0
        Memory_FreeGB  = 0
        Memory_TotalGB = 0
        Disk           = 'C:'
        Disk_FreePct   = 0
        Disk_FreeGB    = 0
        Disk_SizeGB    = 0
        Disk_LatencyMs = $null
        Disk_QueueLength = $null
        TopCPU         = @()
        TopMemory      = @()
    }
    Network      = [ordered]@{
        Adapters     = @()
        Gateway      = $null
        DNS          = @()
        AllDNS       = @()
        Gateways     = @()
        Route        = $null
        WifiSSID     = $null
        WifiSignalPct = $null
    }
    VPN          = $null
    VPN_Status   = 'Not detected'
    Zscaler_State = 'Not detected'
    VPN_TunnelIP = $null
    VPN_Detail   = $null
    Proxy_WinHTTP = $null
    Proxy_IE     = $null
    Latency      = [ordered]@{
        Gateway        = $null
        DNS            = $null
        DNS_ResolveMs  = $null
        DNS_ProbeName  = $DnsProbeName
        DNS_ProbeError = $null
    }
    CoreInfrastructure = @()
    Target       = $null
    ExternalIP   = $null
    Findings     = @()
}

# ---- System baseline ----
$osInfo = $null
try {
    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $csInfo = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    $Data.System.OS = $osInfo.Caption
    $Data.System.OSBuild = $osInfo.BuildNumber
    $Data.System.Model = $csInfo.Model
    if ($csInfo.UserName) { $Data.System.LoggedOnUser = $csInfo.UserName }
    if ($osInfo.LastBootUpTime) {
        $Data.System.Uptime_Days = [math]::Round(((Get-Date) - $osInfo.LastBootUpTime).TotalDays, 1)
    }
    $pending = Get-PendingReboot
    $Data.System.PendingReboot = $pending.Pending
    $Data.System.RebootReasons = $pending.Reasons
}
catch {
    Write-Warning "System baseline collection failed: $($_.Exception.Message)"
}

# ---- Performance snapshot ----
$processors = @()
try {
    $processors = @(Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop)
    if ($processors.Count -gt 0) {
        $loadValues = @($processors | Where-Object { $null -ne $_.LoadPercentage } | ForEach-Object { $_.LoadPercentage })
        if ($loadValues.Count -gt 0) {
            $Data.Performance.CPU_LoadPct = [math]::Round(($loadValues | Measure-Object -Average).Average, 0)
        }
    }
}
catch { Write-Warning "CPU load collection failed: $($_.Exception.Message)" }

try {
    if ($null -ne $osInfo -and $osInfo.TotalVisibleMemorySize -gt 0) {
        $totalKB = $osInfo.TotalVisibleMemorySize
        $freeKB = $osInfo.FreePhysicalMemory
        $Data.Performance.Memory_TotalGB = [math]::Round($totalKB / 1MB, 1)
        $Data.Performance.Memory_FreeGB = [math]::Round($freeKB / 1MB, 1)
        $Data.Performance.Memory_UsedPct = [math]::Round((($totalKB - $freeKB) / $totalKB) * 100, 0)
    }
}
catch { Write-Warning "Memory collection failed: $($_.Exception.Message)" }

try {
    $systemDrive = 'C:'
    if ($env:SystemDrive) { $systemDrive = $env:SystemDrive }
    $disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter ("DeviceID='{0}'" -f $systemDrive) -ErrorAction Stop
    if ($disk -and $disk.Size -gt 0) {
        $Data.Performance.Disk = $systemDrive
        $Data.Performance.Disk_SizeGB = [math]::Round($disk.Size / 1GB, 1)
        $Data.Performance.Disk_FreeGB = [math]::Round($disk.FreeSpace / 1GB, 1)
        $Data.Performance.Disk_FreePct = [math]::Round(($disk.FreeSpace / $disk.Size) * 100, 0)
    }
    $diskLatency = Get-DiskLatency
    if ($diskLatency) {
        $Data.Performance.Disk_LatencyMs = $diskLatency.AvgLatencyMs
        $Data.Performance.Disk_QueueLength = $diskLatency.QueueLength
    }
}
catch { Write-Warning "Disk collection failed: $($_.Exception.Message)" }

try {
    $logicalProcessors = [Environment]::ProcessorCount
    if ($processors.Count -gt 0) {
        $cpuCount = ($processors | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum
        if ($cpuCount -gt 0) { $logicalProcessors = $cpuCount }
    }
    $topCpu = Get-TopCpuProcesses -Top 3 -LogicalProcessors $logicalProcessors
    $Data.Performance.TopCPU = @($topCpu | ForEach-Object { "{0} ({1}%)" -f $_.Name, $_.PctCpu })
}
catch { $Data.Performance.TopCPU = @() }

try {
    $topMem = @(Get-Process -ErrorAction Stop | Sort-Object WorkingSet64 -Descending | Select-Object -First 3)
    $Data.Performance.TopMemory = @($topMem | ForEach-Object { "{0} ({1:N1} GB)" -f $_.ProcessName, ($_.WorkingSet64 / 1GB) })
}
catch { $Data.Performance.TopMemory = @() }

# ---- Network config ----
try {
    $adapters = @()
    $gateways = @()
    $dnsServers = @()
    $netConfigs = @(Get-NetIPConfiguration -ErrorAction Stop)
    foreach ($config in $netConfigs) {
        $ipv4 = $null
        $ipv6 = $null
        if ($config.IPv4Address) { $ipv4 = $config.IPv4Address.IPAddress }
        if ($config.IPv6Address) { $ipv6 = $config.IPv6Address.IPAddress }
        $adapterText = $config.InterfaceAlias
        if ($ipv4) { $adapterText = "{0}: {1}" -f $adapterText, $ipv4 }
        if ($ipv6) { $adapterText = "{0} / {1}" -f $adapterText, $ipv6 }
        $adapters += $adapterText
        if ($config.IPv4DefaultGateway) { $gateways += $config.IPv4DefaultGateway.NextHop }
        if ($config.DNSServer) {
            foreach ($dns in $config.DNSServer) {
                if ($dns.ServerAddresses) { $dnsServers += $dns.ServerAddresses }
            }
        }
    }
    if ($adapters.Count -eq 0) { throw 'Get-NetIPConfiguration returned no adapters' }
    $Data.Network.Adapters = $adapters
    $Data.Network.Gateways = @($gateways | Select-Object -Unique)
    $Data.Network.AllDNS = @($dnsServers | Select-Object -Unique)
}
catch {
    # Fallback: CIM adapter configuration, for hosts without the NetTCPIP module.
    try {
        $cimAdapters = @(Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=TRUE' -ErrorAction Stop)
        $adapters = @()
        $gateways = @()
        $dnsServers = @()
        foreach ($cim in $cimAdapters) {
            $ipText = ''
            if ($cim.IPAddress) { $ipText = ($cim.IPAddress -join ', ') }
            $adapters += ("{0}: {1}" -f $cim.Description, $ipText)
            if ($cim.DefaultIPGateway) { $gateways += $cim.DefaultIPGateway }
            if ($cim.DNSServerSearchOrder) { $dnsServers += $cim.DNSServerSearchOrder }
        }
        $Data.Network.Adapters = $adapters
        $Data.Network.Gateways = @($gateways | Select-Object -Unique)
        $Data.Network.AllDNS = @($dnsServers | Select-Object -Unique)
    }
    catch {
        Write-Warning "Network config collection failed: $($_.Exception.Message)"
    }
}

try {
    $wifi = Get-WifiInfo
    if ($wifi) {
        $Data.Network.WifiSSID = $wifi.SSID
        $Data.Network.WifiSignalPct = $wifi.SignalPct
    }
}
catch { }

# ---- VPN client and tunnel-interface evidence ----
$Data.VPN = Get-VpnEvidence
$Data.VPN_Status = $Data.VPN.Summary
$zscalerClient = $Data.VPN.Clients | Where-Object { $_.Name -eq 'Zscaler' }
if ($zscalerClient.Running) { $Data.Zscaler_State = 'Running' }
if ($Data.VPN.Tunnels.Count -gt 0) {
    $Data.VPN_TunnelIP = $Data.VPN.Tunnels[0].Addresses[0]
    $Data.VPN_Detail = $Data.VPN.Tunnels[0].Description
}
foreach ($vpnError in $Data.VPN.Errors) { Add-Finding 'Warn' "VPN inspection incomplete - $vpnError" }

# ---- Proxy ----
try {
    $proxy = Get-ProxyConfig -UserName $Data.System.LoggedOnUser
    $Data.Proxy_WinHTTP = $proxy.WinHTTP
    $Data.Proxy_IE = $proxy.IE
}
catch { }

# ---- Single-target diagnostic and its selected route ----
if (-not [string]::IsNullOrWhiteSpace($TargetDestination)) {
    $resolved = Resolve-DiagnosticTarget -Name $TargetDestination
    $targetPortsData = @(foreach ($port in $TargetPorts) {
        $probe = Test-ResolvedTcpPort -Resolution $resolved -Port $port -TimeoutMs $TcpTimeoutMs
        [pscustomobject]@{
            Port = $port; Success = $probe.Success; LatencyMs = $probe.LatencyMs; Error = $probe.Error
            ResolvedAddress = $probe.ResolvedAddress; Route = $probe.Route; Attempts = $probe.Attempts
        }
    })
    $primaryProbe = $targetPortsData | Where-Object { $_.Success } | Select-Object -First 1
    if (-not $primaryProbe) { $primaryProbe = $targetPortsData | Select-Object -First 1 }
    $selectedAddress = $null
    $Data.Network.Route = $null
    if ($primaryProbe) {
        $selectedAddress = $primaryProbe.ResolvedAddress
        $Data.Network.Route = $primaryProbe.Route
    }
    if (-not $selectedAddress) { $selectedAddress = $resolved.Address }
    if (-not $Data.Network.Route) {
        if ($selectedAddress) { $Data.Network.Route = Get-DiagnosticRoute -RemoteAddress $selectedAddress }
        else { $Data.Network.Route = [pscustomobject]@{ Error = $resolved.Error } }
    }
    $Data.Target = [ordered]@{
        Destination = $TargetDestination
        DNS_Resolved = $selectedAddress
        ResolvedAddresses = $resolved.Addresses
        DNS_Error = $resolved.Error
        Route = $Data.Network.Route
        Ping = $null
        Ports = $targetPortsData
    }
    if ($selectedAddress) {
        $Data.Target.Ping = Get-PingStats -ComputerName $selectedAddress -Count $PingCount -TimeoutMs $PingTimeoutMs
    }
}
else { $Data.Network.Route = Get-DiagnosticRoute }
if ($Data.Network.Route.Error) {
    Add-Finding 'Warn' "Route selection unavailable - $($Data.Network.Route.Error)"
}
else {
    $nextHop = $Data.Network.Route.NextHop
    $nextHopAddress = $null
    if ([System.Net.IPAddress]::TryParse($nextHop, [ref]$nextHopAddress) -and
        -not $nextHopAddress.Equals([System.Net.IPAddress]::Any) -and
        -not $nextHopAddress.Equals([System.Net.IPAddress]::IPv6Any)) {
        if ($nextHopAddress.IsIPv6LinkLocal -and $nextHopAddress.ScopeId -eq 0) {
            $nextHop += '%' + $Data.Network.Route.InterfaceIndex
        }
        $Data.Network.Gateway = $nextHop
    }
    $Data.Network.DNS = @($Data.Network.Route.DNSServers)
    if ($Data.Network.Route.DNSError) {
        Add-Finding 'Warn' "Selected-interface DNS configuration unavailable - $($Data.Network.Route.DNSError)"
    }
}

# ---- Latency / quality ----
if ($Data.Network.Gateway) {
    $Data.Latency.Gateway = Get-PingStats -ComputerName $Data.Network.Gateway -Count $PingCount -TimeoutMs $PingTimeoutMs
}
if ($Data.Network.DNS -and $Data.Network.DNS.Count -gt 0) {
    $Data.Latency.DNS = Get-PingStats -ComputerName $Data.Network.DNS[0] -Count $PingCount -TimeoutMs $PingTimeoutMs
}
if ($DnsProbeName) {
    try {
        $dnsCmd = Get-Command -Name 'Resolve-DnsName' -ErrorAction SilentlyContinue
        $dnsStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        if ($dnsCmd) {
            $null = Resolve-DnsName -Name $DnsProbeName -DnsOnly -ErrorAction Stop
        }
        else {
            $null = [System.Net.Dns]::GetHostAddresses($DnsProbeName)
        }
        $Data.Latency.DNS_ResolveMs = [math]::Round($dnsStopwatch.Elapsed.TotalMilliseconds, 0)
    }
    catch {
        $Data.Latency.DNS_ProbeError = $_.Exception.Message
    }
}

# ---- Core infrastructure reachability ----
$coreResults = @()
foreach ($targetItem in $CoreInfrastructure) {
    $resolved = Resolve-DiagnosticTarget -Name $targetItem.Host
    $tcpResult = Test-ResolvedTcpPort -Resolution $resolved -Port ([int]$targetItem.Port) -TimeoutMs $TcpTimeoutMs
    $coreResults += [ordered]@{
        Name = $targetItem.Name
        Host = $targetItem.Host
        Port = [int]$targetItem.Port
        ResolvedAddress = $tcpResult.ResolvedAddress
        Route = $tcpResult.Route
        Attempts = $tcpResult.Attempts
        Success = $tcpResult.Success
        LatencyMs = $tcpResult.LatencyMs
        Error = $tcpResult.Error
    }
}
$Data.CoreInfrastructure = $coreResults

# ---- Egress IP ----
if (-not $SkipExternalIP -and -not $SkipPublicProbes) {
    try {
        $egress = Invoke-RestMethod -Uri 'https://ifconfig.me/ip' -TimeoutSec 5 -ErrorAction Stop
        $Data.ExternalIP = "$egress".Trim()
    }
    catch {
        try {
            $egress = Invoke-RestMethod -Uri 'https://api.ipify.org' -TimeoutSec 5 -ErrorAction Stop
            $Data.ExternalIP = "$egress".Trim()
        }
        catch {
            $Data.ExternalIP = $null
        }
    }
}

# ---- Findings analysis (thresholds + failures) ----
# RECONSTRUCTED in v2: the original populates $Findings in collectors, but
# no analysis pass survives in the truncated file. This pass uses only the
# thresholds already defined at the top of the original.
if ($Data.System.PendingReboot) {
    Add-Finding 'Warn' ("Pending reboot - {0}" -f $Data.System.RebootReasons)
}
if ($Data.System.Uptime_Days -ge $Thresholds.UptimeDays.Crit) {
    Add-Finding 'Crit' ("Uptime {0} days - consider reboot" -f $Data.System.Uptime_Days)
}
elseif ($Data.System.Uptime_Days -ge $Thresholds.UptimeDays.Warn) {
    Add-Finding 'Warn' ("Uptime {0} days - consider reboot" -f $Data.System.Uptime_Days)
}
if ($Data.Performance.CPU_LoadPct -ge $Thresholds.CpuPct.Crit) {
    Add-Finding 'Crit' ("CPU load {0}% is critically high" -f $Data.Performance.CPU_LoadPct)
}
elseif ($Data.Performance.CPU_LoadPct -ge $Thresholds.CpuPct.Warn) {
    Add-Finding 'Warn' ("CPU load {0}% is high" -f $Data.Performance.CPU_LoadPct)
}
if ($Data.Performance.Memory_UsedPct -ge $Thresholds.MemPct.Crit) {
    Add-Finding 'Crit' ("Memory {0}% used" -f $Data.Performance.Memory_UsedPct)
}
elseif ($Data.Performance.Memory_UsedPct -ge $Thresholds.MemPct.Warn) {
    Add-Finding 'Warn' ("Memory {0}% used" -f $Data.Performance.Memory_UsedPct)
}
if ($Data.Performance.Disk_FreePct -le $Thresholds.DiskFreePct.Crit -and $Data.Performance.Disk_SizeGB -gt 0) {
    Add-Finding 'Crit' ("Disk {0} only {1}% free" -f $Data.Performance.Disk, $Data.Performance.Disk_FreePct)
}
elseif ($Data.Performance.Disk_FreePct -le $Thresholds.DiskFreePct.Warn -and $Data.Performance.Disk_SizeGB -gt 0) {
    Add-Finding 'Warn' ("Disk {0} only {1}% free" -f $Data.Performance.Disk, $Data.Performance.Disk_FreePct)
}
if ($null -ne $Data.Performance.Disk_LatencyMs -and $Data.Performance.Disk_LatencyMs -ge $Thresholds.DiskLatencyMs.Crit) {
    Add-Finding 'Crit' ("Disk latency {0} ms avg is critically high" -f $Data.Performance.Disk_LatencyMs)
}
elseif ($null -ne $Data.Performance.Disk_LatencyMs -and $Data.Performance.Disk_LatencyMs -ge $Thresholds.DiskLatencyMs.Warn) {
    Add-Finding 'Warn' ("Disk latency {0} ms avg is high" -f $Data.Performance.Disk_LatencyMs)
}
if ($null -ne $Data.Network.WifiSignalPct) {
    if ($Data.Network.WifiSignalPct -le $Thresholds.WifiPct.Crit) {
        Add-Finding 'Crit' ("Weak Wi-Fi signal {0}% on '{1}'" -f $Data.Network.WifiSignalPct, $Data.Network.WifiSSID)
    }
    elseif ($Data.Network.WifiSignalPct -le $Thresholds.WifiPct.Warn) {
        Add-Finding 'Warn' ("Weak Wi-Fi signal {0}% on '{1}'" -f $Data.Network.WifiSignalPct, $Data.Network.WifiSSID)
    }
}
if ($Data.Latency.Gateway -and $null -ne $Data.Latency.Gateway.AvgMs) {
    if ($Data.Latency.Gateway.AvgMs -ge $Thresholds.GwRttMs.Crit) {
        Add-Finding 'Crit' ("Gateway latency {0} ms avg is critically high" -f $Data.Latency.Gateway.AvgMs)
    }
    elseif ($Data.Latency.Gateway.AvgMs -ge $Thresholds.GwRttMs.Warn) {
        Add-Finding 'Warn' ("Gateway latency {0} ms avg is high" -f $Data.Latency.Gateway.AvgMs)
    }
    if ($Data.Latency.Gateway.LossPct -ge $Thresholds.LossPct.Crit) {
        Add-Finding 'Crit' ("Gateway packet loss {0}%" -f $Data.Latency.Gateway.LossPct)
    }
    elseif ($Data.Latency.Gateway.LossPct -ge $Thresholds.LossPct.Warn) {
        Add-Finding 'Warn' ("Gateway packet loss {0}%" -f $Data.Latency.Gateway.LossPct)
    }
}
if ($Data.Latency.DNS_ProbeError) {
    Add-Finding 'Warn' ("DNS probe for {0} failed: {1}" -f $DnsProbeName, $Data.Latency.DNS_ProbeError)
}
elseif ($null -ne $Data.Latency.DNS_ResolveMs) {
    if ($Data.Latency.DNS_ResolveMs -ge $Thresholds.DnsMs.Crit) {
        Add-Finding 'Crit' ("DNS resolve time {0} ms is critically slow" -f $Data.Latency.DNS_ResolveMs)
    }
    elseif ($Data.Latency.DNS_ResolveMs -ge $Thresholds.DnsMs.Warn) {
        Add-Finding 'Warn' ("DNS resolve time {0} ms is slow" -f $Data.Latency.DNS_ResolveMs)
    }
}
foreach ($item in $Data.CoreInfrastructure) {
    if (-not $item.Success) {
        Add-Finding 'Fail' ("Cannot reach {0} ({1}:{2})" -f $item.Name, $item.Host, $item.Port)
    }
}
if ($Data.Target -and $Data.Target.Ports) {
    foreach ($portResult in $Data.Target.Ports) {
        if (-not $portResult.Success) {
            Add-Finding 'Fail' ("Target {0}:{1} unreachable - {2}" -f $Data.Target.Destination, $portResult.Port, $portResult.Error)
        }
    }
    if ($Data.Target.Ping -and $Data.Target.Ping.Received -eq 0) {
        Add-Finding 'Warn' ("Target {0} did not respond to ICMP ping (100% loss)" -f $Data.Target.Destination)
    }
}
$Data.Findings = @($Findings.ToArray())

# ---- Export (JSON + plain-text summary), then prune old exports ----
# RECONSTRUCTED in v2. ExportPath is a file path, not a folder, so the
# .txt summary sits alongside it and pruning uses its folder.
$exportDirectory = $null
$txtPath = $null
$exportSucceeded = $false
try {
    $ExportPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ExportPath)
    $txtPath = [System.IO.Path]::ChangeExtension($ExportPath, 'txt')
    if ($txtPath -eq $ExportPath) { throw 'The JSON export path and text summary path must be different.' }
    $exportDirectory = Split-Path -Parent $ExportPath
    if (-not (Test-Path -LiteralPath $exportDirectory)) {
        [System.IO.Directory]::CreateDirectory($exportDirectory) | Out-Null
    }
    $summaryText = Build-ServiceNowSummary -Data $Data -FindingsList $Findings -JsonPath $ExportPath
    $Data | ConvertTo-Json -Depth 6 -ErrorAction Stop | Set-Content -LiteralPath $ExportPath -Encoding UTF8 -Force -ErrorAction Stop
    $summaryText | Set-Content -LiteralPath $txtPath -Encoding UTF8 -Force -ErrorAction Stop
    $exportSucceeded = $true
}
catch {
    Write-Warning "Export failed: $($_.Exception.Message)"
    # Still build the summary for console/clipboard use, without a JSON path.
    $summaryText = Build-ServiceNowSummary -Data $Data -FindingsList $Findings -JsonPath ''
}

if ($exportSucceeded -and $exportDirectory) {
    Remove-OldTriageExports -Directory $exportDirectory -Keep $RetainCount -CurrentPath $ExportPath
}

# ---- Output ----
if ($Quiet) {
    # Plain-text summary only. This is the last output, so a pipeline
    # like '-Quiet | clip' receives only the summary.
    try { $summaryText | Set-Clipboard -ErrorAction Stop } catch { Write-Warning "Could not copy summary to clipboard: $($_.Exception.Message)" }
    Write-Output $summaryText
}
else {
    Show-Dashboard -Data $Data -FindingsList $Findings
    if ($exportSucceeded) {
        Write-Host ("JSON export : {0}" -f $ExportPath) -ForegroundColor Gray
        Write-Host ("Text summary: {0}" -f $txtPath) -ForegroundColor Gray
    }
    if ($CopyToClipboard) {
        try {
            $summaryText | Set-Clipboard -ErrorAction Stop
            Write-Host 'Plain-text summary copied to clipboard.' -ForegroundColor Gray
        }
        catch {
            Write-Warning "Could not copy summary to clipboard: $($_.Exception.Message)"
        }
    }
}
