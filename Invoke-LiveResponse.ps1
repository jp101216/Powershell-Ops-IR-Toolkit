#Requires -Version 5.1
# Invoke-LiveResponse v2 - RECONSTRUCTED TAIL
# --------------------------------------------------------------------------
# The original in jp101216/Powershell-Ops-IR-Toolkit was truncated in the
# repo itself at exactly 20000 bytes, ending mid-line inside the 'Services'
# collector. Everything from that point on in this file is RECONSTRUCTED
# in v2 from the README's collector list and the script's own patterns.
# Every reconstructed section is marked in comments with:
#   'RECONSTRUCTED in v2 - not present in the truncated repo original'
# Do NOT present reconstructed code as if it were the author's original.
# This tool remains READ-ONLY: it inspects state, it never remediates or
# changes the host (apart from writing its own report files under
# -OutputPath, which is the tool's documented purpose).
# Modernization notes (v2): Windows PowerShell 5.1 AND PowerShell 7.x on
# Windows, 5.1-compatible syntax only (no ternary, null-coalescing, or
# PS7-only operators). Reconstructed code is written to be
# Set-StrictMode-safe (variables initialised, nulls checked before
# property access), but Set-StrictMode is deliberately NOT turned on
# globally: the original collectors rely on PowerShell's null-tolerant
# property access in places, and turning it on could turn a partial
# collector into a failed collector. Each collector is still isolated
# by Invoke-Collector, so a failing collector must not kill the run.
# PowerShell is not available on the Linux VM used to build this file,
# so it has NOT been executed on Windows here. Run it in a lab first.
# --------------------------------------------------------------------------
<#
.SYNOPSIS
    Live-response artifact collector for first-responder triage.

.DESCRIPTION
    Collects volatile and persistence artifacts from a Windows host and writes a
    structured JSON report plus a ServiceNow-pasteable text summary. This is a
    READ-ONLY collector: it inspects state, it does not remediate or change the
    host. Run it elevated for full coverage (WMI subscriptions, prefetch, other
    users' artifacts, and the Security event log all require admin).

    Collectors:
      - Host context (OS, uptime, logged-on users, elevation)
      - Processes (SHA256, Authenticode status, parent lineage, owner)
      - Network (TCP connections mapped to owning process, listeners, DNS cache)
      - Autoruns / persistence (Run keys, Winlogon, AppInit_DLLs, IFEO debuggers,
        scheduled tasks, services, WMI event subscriptions, startup folders)
      - Local accounts + Administrators membership
      - Recently written executable-ish files
      - Prefetch (execution evidence)
      - PowerShell console history (per user)
      - Defender status + recent detections, firewall profile state
      - High-signal Security / System events

    Findings are scored High / Medium / Info and surfaced at the top so the box
    is triage-ready instead of a raw dump.

.PARAMETER OutputPath
    Root output folder. A per-run subfolder <HOSTNAME>_<timestamp> is created
    underneath it. Defaults to %TEMP%\LiveResponse.

.PARAMETER Quiet
    Console prints only the ServiceNow-pasteable summary (files are still written).
    Use for `.\Invoke-LiveResponse.ps1 -Quiet | clip`.

.PARAMETER SkipHashes
    Skip SHA256 hashing of images/files (faster on slow disks or busy hosts).

.PARAMETER SkipEventLogs
    Skip Security/System event log collection (faster; avoids the noisiest step).

.PARAMETER RecentFileHours
    Look-back window (hours) for "recently written" executable files. Default 24.

.PARAMETER MaxEvents
    Cap on events pulled per log. Default 200.

.EXAMPLE
    .\Invoke-LiveResponse.ps1

.EXAMPLE
    .\Invoke-LiveResponse.ps1 -OutputPath C:\IR -RecentFileHours 72

.EXAMPLE
    .\Invoke-LiveResponse.ps1 -Quiet | clip
    # copies the pasteable summary straight to the clipboard for a ServiceNow note

.NOTES
    For authorized defensive/IR use on systems you are permitted to examine.
    Suggested invocation when script execution is restricted:
        powershell -ExecutionPolicy Bypass -File .\Invoke-LiveResponse.ps1
#>
[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path $env:TEMP 'LiveResponse'),
    [switch]$Quiet,
    [switch]$SkipHashes,
    [switch]$SkipEventLogs,
    [ValidateRange(1, 720)]
    [int]$RecentFileHours = 24,
    [ValidateRange(1, 1000)]
    [int]$MaxEvents = 200
)

$ErrorActionPreference = 'Stop'

# Modernization (v2): fallbacks for hosts where $env:TEMP / $env:COMPUTERNAME
# are not set (notably some PowerShell 7 hosts). Original defaults are kept
# when the variables are present.
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path ([IO.Path]::GetTempPath()) 'LiveResponse'
}
$script:HostName = $env:COMPUTERNAME
if ([string]::IsNullOrWhiteSpace($script:HostName)) {
    $script:HostName = [Environment]::MachineName
}

# --------------------------------------------------------------------------
# State
# --------------------------------------------------------------------------
$script:Findings  = New-Object System.Collections.Generic.List[object]
$script:MetaCache = @{}
$script:ProcById  = @{}
$script:Elevated  = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
$report = [ordered]@{}

# Detection heuristics ------------------------------------------------------
$script:SuspiciousCmdPatterns = @(
    '-enc\b', '-e\b\s+[A-Za-z0-9+/=]{20,}', 'encodedcommand', 'frombase64string',
    '-w\s+hidden', '-windowstyle\s+hidden', '\biex\b', 'invoke-expression',
    'downloadstring', 'downloadfile', 'start-bitstransfer', 'net\.webclient',
    'certutil.*-urlcache', 'certutil.*-decode', '\bmshta\b', 'regsvr32.*scrobj',
    'rundll32.*javascript', 'wscript.*http', 'cscript.*http',
    'executionpolicy\s+bypass', 'hidden.*bypass', 'bypass.*hidden'
)
$script:SuspiciousPathPatterns = @(
    '\\AppData\\', '\\Local\\Temp\\', '\\Windows\\Temp\\', '\\Downloads\\',
    '\\Users\\Public\\', '\\\$Recycle', '\\ProgramData\\', '\\Temp\\'
)
$script:LineageParents = @('winword','excel','powerpnt','outlook','onenote','mshta',
    'wscript','cscript','iexplore','msedge','chrome','firefox','acrord32','acrobat','hh')
$script:LineageChildren = @('powershell','pwsh','cmd','wscript','cscript','mshta',
    'rundll32','regsvr32','bitsadmin','certutil','curl','wget')

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
function Write-Section([string]$Title) {
    if (-not $Quiet) { Write-Host "`n== $Title ==" -ForegroundColor Cyan }
}
function Write-Note([string]$Message, [string]$Color = 'Gray') {
    if (-not $Quiet) { Write-Host $Message -ForegroundColor $Color }
}
function Add-Finding {
    param(
        [ValidateSet('High','Medium','Info')][string]$Severity,
        [string]$Category,
        [string]$Detail
    )
    $script:Findings.Add([pscustomobject]@{
        Severity = $Severity; Category = $Category; Detail = $Detail
    })
}
function Count($Value) { if ($null -eq $Value) { 0 } else { @($Value).Count } }

function Get-FirstLine([string]$Text) {
    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }
    (($Text -split '\r?\n') | Select-Object -First 1).Trim()
}

function Test-SuspiciousPath([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    foreach ($p in $script:SuspiciousPathPatterns) { if ($Path -match $p) { return $true } }
    return $false
}
function Get-SuspiciousReasons([string]$Text) {
    $r = @()
    if ([string]::IsNullOrWhiteSpace($Text)) { return $r }
    foreach ($pat in $script:SuspiciousCmdPatterns) { if ($Text -match $pat) { $r += $pat } }
    if (Test-SuspiciousPath $Text) { $r += 'user-writable-path' }
    return $r
}

function Test-PrivateIP([string]$IPString) {
    # Returns $true for loopback / RFC1918 / link-local / multicast / unknown.
    $ip = $null
    if (-not [System.Net.IPAddress]::TryParse($IPString, [ref]$ip)) { return $true }
    $b = $ip.GetAddressBytes()
    if ($ip.AddressFamily -eq 'InterNetworkV6') {
        if ($ip.IsIPv6LinkLocal -or $ip.IsIPv6SiteLocal) { return $true }
        if ($IPString -eq '::1') { return $true }
        if (($b[0] -band 0xFE) -eq 0xFC) { return $true }   # ULA fc00::/7
        return $false
    }
    switch ($b[0]) {
        0   { return $true }
        10  { return $true }
        127 { return $true }
        169 { if ($b[1] -eq 254) { return $true } }
        172 { if ($b[1] -ge 16 -and $b[1] -le 31) { return $true } }
        192 { if ($b[1] -eq 168) { return $true } }
    }
    if ($b[0] -ge 224) { return $true }   # multicast / reserved / broadcast
    return $false
}

function Get-FileMeta([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) {
        return [pscustomobject]@{ Hash = $null; Signed = $null; Signer = $null }
    }
    if ($script:MetaCache.ContainsKey($Path)) { return $script:MetaCache[$Path] }
    $hash = $null; $signed = 'Unknown'; $signer = $null
    try {
        $sig = Get-AuthenticodeSignature -FilePath $Path -ErrorAction Stop
        $signed = $sig.Status.ToString()
        if ($sig.SignerCertificate) { $signer = $sig.SignerCertificate.Subject }
    } catch { $signed = 'Unknown' }
    if (-not $SkipHashes) {
        try { $hash = (Get-FileHash -Algorithm SHA256 -Path $Path -ErrorAction Stop).Hash }
        catch { $hash = $null }
    }
    $obj = [pscustomobject]@{ Hash = $hash; Signed = $signed; Signer = $signer }
    $script:MetaCache[$Path] = $obj
    $obj
}

function Get-ServiceExe([string]$PathName) {
    if ([string]::IsNullOrWhiteSpace($PathName)) { return $null }
    $p = $PathName.Trim()
    if ($p.StartsWith('"')) {
        $end = $p.IndexOf('"', 1)
        if ($end -gt 0) { return $p.Substring(1, $end - 1) }
    }
    $m = [regex]::Match($p, '^(.*?\.exe)', 'IgnoreCase')
    if ($m.Success) { return $m.Groups[1].Value }
    return ($p -split '\s+')[0]
}

function Invoke-Collector([string]$Name, [scriptblock]$Body) {
    Write-Section $Name
    try { & $Body }
    catch {
        Write-Note ("  [!] {0} failed: {1}" -f $Name, $_.Exception.Message) 'DarkYellow'
        Add-Finding 'Info' 'Collector' ("{0} failed: {1}" -f $Name, $_.Exception.Message)
    }
}

# --------------------------------------------------------------------------
# Setup
# --------------------------------------------------------------------------
$stamp  = Get-Date -Format 'yyyyMMdd_HHmmss'
$runDir = Join-Path $OutputPath ("{0}_{1}" -f $script:HostName, $stamp)
try {
    New-Item -ItemType Directory -Path $runDir -Force -ErrorAction Stop | Out-Null
}
catch {
    throw "Could not create report folder '$runDir': $($_.Exception.Message)"
}

if (-not $Quiet) {
    Write-Host "Live-Response Collector" -ForegroundColor White
    Write-Host ("Host: {0}   Elevated: {1}" -f $env:COMPUTERNAME, $script:Elevated) -ForegroundColor Gray
    if (-not $script:Elevated) {
        Write-Host "  [!] Not elevated - some collectors will be partial (WMI subs, prefetch, Security log, other users)." -ForegroundColor Yellow
    }
}

# --------------------------------------------------------------------------
# Collectors
# --------------------------------------------------------------------------
Invoke-Collector 'Host Context' {
    $os = Get-CimInstance Win32_OperatingSystem
    $cs = Get-CimInstance Win32_ComputerSystem
    $boot = $os.LastBootUpTime
    $interactive = @()
    try {
        $interactive = @(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" |
            ForEach-Object {
                try { $o = Invoke-CimMethod -InputObject $_ -MethodName GetOwner -ErrorAction Stop
                      if ($o.User) { "{0}\{1}" -f $o.Domain, $o.User } } catch {}
            } | Where-Object { $_ } | Select-Object -Unique)
    } catch {}
    $report.Host = [ordered]@{
        Hostname      = $env:COMPUTERNAME
        Domain        = $cs.Domain
        OS            = $os.Caption
        Build         = $os.BuildNumber
        Version       = $os.Version
        LastBoot      = $boot
        UptimeHours   = [math]::Round(((Get-Date) - $boot).TotalHours, 1)
        CurrentUser   = "{0}\{1}" -f $env:USERDOMAIN, $env:USERNAME
        Elevated      = $script:Elevated
        InteractiveUsers = $interactive
        CollectedUtc  = (Get-Date).ToUniversalTime().ToString('o')
    }
    Write-Note ("  {0}  build {1}  up {2}h" -f $os.Caption, $os.BuildNumber, $report.Host.UptimeHours)
}

Invoke-Collector 'Processes' {
    $procs = Get-CimInstance Win32_Process
    foreach ($p in $procs) { $script:ProcById[[int]$p.ProcessId] = $p }
    $out = foreach ($p in $procs) {
        $meta = if ($p.ExecutablePath) { Get-FileMeta $p.ExecutablePath } else { $null }
        $parent = $script:ProcById[[int]$p.ParentProcessId]
        $reasons = New-Object System.Collections.Generic.List[string]
        $cmd = $p.CommandLine
        foreach ($pat in $script:SuspiciousCmdPatterns) {
            if ($cmd -and $cmd -match $pat) { $reasons.Add("cmdline:$pat") }
        }
        $unsigned = $meta -and $meta.Signed -ne 'Valid'
        $badPath  = Test-SuspiciousPath $p.ExecutablePath
        if ($unsigned -and $badPath) { $reasons.Add('unsigned+userpath') }
        if ($parent) {
            $pn = [IO.Path]::GetFileNameWithoutExtension($parent.Name).ToLower()
            $cn = [IO.Path]::GetFileNameWithoutExtension($p.Name).ToLower()
            if ($script:LineageParents -contains $pn -and $script:LineageChildren -contains $cn) {
                $reasons.Add("lineage:$pn->$cn")
            }
        }
        $owner = $null
        try { $o = Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction Stop
              if ($o.User) { $owner = "{0}\{1}" -f $o.Domain, $o.User } } catch {}

        if ($reasons -match '^cmdline:') {
            Add-Finding 'High' 'Process' ("PID {0} {1}: suspicious command line -> {2}" -f $p.ProcessId, $p.Name, $cmd)
        } elseif ($unsigned -and $badPath) {
            Add-Finding 'Medium' 'Process' ("PID {0} {1}: unsigned image in user-writable path -> {2}" -f $p.ProcessId, $p.Name, $p.ExecutablePath)
        }
        if ($reasons -match '^lineage:') {
            Add-Finding 'Medium' 'Process' ("Suspicious lineage {0} -> {1} (PID {2})" -f $parent.Name, $p.Name, $p.ProcessId)
        }

        [pscustomobject][ordered]@{
            PID = [int]$p.ProcessId; PPID = [int]$p.ParentProcessId
            Name = $p.Name; Parent = if ($parent) { $parent.Name } else { $null }
            Owner = $owner; Path = $p.ExecutablePath; CommandLine = $cmd
            SHA256 = if ($meta) { $meta.Hash } else { $null }
            Signature = if ($meta) { $meta.Signed } else { $null }
            Signer = if ($meta) { $meta.Signer } else { $null }
            Suspicious = ($reasons.Count -gt 0); Reasons = @($reasons)
        }
    }
    $report.Processes = @($out | Sort-Object -Property @{E={ -not $_.Suspicious }}, Name)
    Write-Note ("  {0} processes, {1} flagged" -f (Count $report.Processes), (Count ($report.Processes | Where-Object { $_.Suspicious })))
}

Invoke-Collector 'Network' {
    $conns = Get-NetTCPConnection -ErrorAction SilentlyContinue
    $out = foreach ($c in $conns) {
        $op = $script:ProcById[[int]$c.OwningProcess]
        $pName = if ($op) { $op.Name } else { (Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue).ProcessName }
        $pPath = if ($op) { $op.ExecutablePath } else { $null }
        $remote = $c.RemoteAddress
        $external = ($c.State -eq 'Established') -and (-not (Test-PrivateIP $remote)) -and ($remote -ne '0.0.0.0') -and ($remote -ne '::')
        if ($external -and $pPath -and (Test-SuspiciousPath $pPath)) {
            Add-Finding 'High' 'Network' ("{0} (PID {1}) -> {2}:{3} from user-writable path" -f $pName, $c.OwningProcess, $remote, $c.RemotePort)
        }
        [pscustomobject][ordered]@{
            Local = "{0}:{1}" -f $c.LocalAddress, $c.LocalPort
            Remote = "{0}:{1}" -f $remote, $c.RemotePort
            State = "$($c.State)"; PID = [int]$c.OwningProcess
            Process = $pName; Path = $pPath; External = $external
        }
    }
    $report.Network = @($out | Sort-Object -Property @{E={ -not $_.External }}, State, Remote)
    $report.Listeners = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Select-Object @{n='Local';e={ "{0}:{1}" -f $_.LocalAddress, $_.LocalPort }}, OwningProcess |
        Sort-Object Local -Unique)
    $report.DnsCache = @(Get-DnsClientCache -ErrorAction SilentlyContinue |
        Select-Object Entry, @{n='Data';e={ $_.Data }}, @{n='Type';e={ "$($_.Type)" }})
    Write-Note ("  {0} connections ({1} external), {2} listeners" -f (Count $report.Network), (Count ($report.Network | Where-Object { $_.External })), (Count $report.Listeners))
}

Invoke-Collector 'Autoruns / Persistence Keys' {
    $autoruns = @()
    $runKeys = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    foreach ($k in $runKeys) {
        if (-not (Test-Path $k)) { continue }
        $props = Get-ItemProperty $k -ErrorAction SilentlyContinue
        foreach ($n in $props.PSObject.Properties.Name) {
            if ($n -in 'PSPath','PSParentPath','PSChildName','PSDrive','PSProvider') { continue }
            $v = "$($props.$n)"
            $reasons = Get-SuspiciousReasons $v
            if ($reasons.Count) { Add-Finding 'Medium' 'Autorun' ("{0}\{1} = {2}" -f $k, $n, $v) }
            $autoruns += [pscustomobject]@{ Type='Run'; Location=$k; Name=$n; Value=$v; Suspicious=($reasons.Count -gt 0); Reasons=@($reasons) }
        }
    }
    # Winlogon Shell / Userinit
    $wl = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
    if (Test-Path $wl) {
        $p = Get-ItemProperty $wl -ErrorAction SilentlyContinue
        foreach ($n in 'Shell','Userinit') {
            if ($p.PSObject.Properties.Name -contains $n) {
                $v = "$($p.$n)"
                $expected = if ($n -eq 'Shell') { 'explorer\.exe' } else { 'userinit\.exe' }
                $reasons = Get-SuspiciousReasons $v
                if ($v -notmatch $expected) { $reasons += "unexpected-$n" }
                if ($reasons.Count) { Add-Finding 'High' 'Autorun' ("Winlogon {0} = {1}" -f $n, $v) }
                $autoruns += [pscustomobject]@{ Type='Winlogon'; Location=$wl; Name=$n; Value=$v; Suspicious=($reasons.Count -gt 0); Reasons=@($reasons) }
            }
        }
    }
    # AppInit_DLLs
    $win = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows'
    if (Test-Path $win) {
        $p = Get-ItemProperty $win -ErrorAction SilentlyContinue
        if ($p.PSObject.Properties.Name -contains 'AppInit_DLLs') {
            $v = "$($p.AppInit_DLLs)".Trim()
            if ($v) {
                Add-Finding 'High' 'Autorun' ("AppInit_DLLs set: {0}" -f $v)
                $autoruns += [pscustomobject]@{ Type='AppInit_DLLs'; Location=$win; Name='AppInit_DLLs'; Value=$v; Suspicious=$true; Reasons=@('appinit-set') }
            }
        }
    }
    # IFEO debuggers
    $ifeo = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    if (Test-Path $ifeo) {
        Get-ChildItem $ifeo -ErrorAction SilentlyContinue | ForEach-Object {
            $sub = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
            if ($sub -and ($sub.PSObject.Properties.Name -contains 'Debugger')) {
                $dbg = "$($sub.Debugger)"
                Add-Finding 'High' 'Autorun' ("IFEO debugger on {0}: {1}" -f $_.PSChildName, $dbg)
                $autoruns += [pscustomobject]@{ Type='IFEO'; Location=$_.PSChildName; Name='Debugger'; Value=$dbg; Suspicious=$true; Reasons=@('ifeo-debugger') }
            }
        }
    }
    $report.Autoruns = @($autoruns)
    Write-Note ("  {0} autorun entries ({1} flagged)" -f (Count $autoruns), (Count ($autoruns | Where-Object { $_.Suspicious })))
}

Invoke-Collector 'Scheduled Tasks' {
    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
    $out = foreach ($t in $tasks) {
        $actions = @($t.Actions | ForEach-Object {
            (("{0} {1}" -f $_.Execute, $_.Arguments)).Trim() }) | Where-Object { $_ }
        $actionStr = ($actions -join ' ; ')
        $nonMs = $t.TaskPath -notlike '\Microsoft\*'
        $reasons = Get-SuspiciousReasons $actionStr
        if ($reasons.Count) { Add-Finding 'Medium' 'ScheduledTask' ("{0}{1}: {2}" -f $t.TaskPath, $t.TaskName, $actionStr) }
        [pscustomobject][ordered]@{
            TaskName = $t.TaskName; Path = $t.TaskPath; State = "$($t.State)"
            RunAs = $t.Principal.UserId; Action = $actionStr; NonMicrosoft = $nonMs
            Suspicious = ($reasons.Count -gt 0)
        }
    }
    # Keep the report readable: non-Microsoft or script-hosting tasks only.
    $report.ScheduledTasks = @($out | Where-Object {
        $_.NonMicrosoft -or $_.Action -match 'powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32|bitsadmin|certutil'
    } | Sort-Object -Property @{E={ -not $_.Suspicious }}, Path)
    Write-Note ("  {0} tasks total, {1} shown" -f (Count $out), (Count $report.ScheduledTasks))
}

Invoke-Collector 'Services' {
    $svc = Get-CimInstance Win32_Service
    $out = foreach ($s in $svc) {
        $bin = $s.PathName
        $exe = Get-ServiceExe $bin
        $meta = if ($exe -and (Test-Path $exe -ErrorAction SilentlyContinue)) { Get-FileMeta $exe } else { $null }
        $unsigned = $meta -and $meta.Signed -ne 'Valid'
        $userPath = Test-SuspiciousPath $exe
        $unquoted = ($bin) -and (-not $bin.Trim().StartsWith('"')) -and ($exe) -and ($exe -match '\s')
        # RECONSTRUCTED in v2 - not present in the truncated repo original:
        # the line above was cut off here in the repo. The completion below
        # follows the script's own Process/Autorun finding style.
        if ($unsigned -and $userPath) { Add-Finding 'Medium' 'Service' ("{0}: unsigned binary in user-writable path -> {1}" -f $s.Name, $exe) }
        $serviceReasons = New-Object System.Collections.Generic.List[string]
        if ($unsigned -and $userPath) { $serviceReasons.Add('unsigned+userpath') }
        if ($unquoted) {
            $serviceReasons.Add('unquoted-service-path')
            Add-Finding 'Medium' 'Service' ("{0}: unquoted service path with spaces -> {1}" -f $s.Name, $bin)
        }
        $cmdReasons = Get-SuspiciousReasons $bin
        foreach ($reason in $cmdReasons) {
            if ($serviceReasons -notcontains $reason) { $serviceReasons.Add($reason) }
        }
        if ($cmdReasons.Count -gt 0) {
            Add-Finding 'Medium' 'Service' ("{0}: suspicious service command line -> {1}" -f $s.Name, $bin)
        }
        [pscustomobject][ordered]@{
            Name = $s.Name; DisplayName = $s.DisplayName; State = "$($s.State)"
            StartMode = "$($s.StartMode)"; Path = $bin; Exe = $exe
            SHA256 = if ($meta) { $meta.Hash } else { $null }
            Signature = if ($meta) { $meta.Signed } else { $null }
            Signer = if ($meta) { $meta.Signer } else { $null }
            UnquotedPath = [bool]$unquoted
            Suspicious = ($serviceReasons.Count -gt 0); Reasons = @($serviceReasons)
        }
    }
    $report.Services = @($out | Sort-Object -Property @{E={ -not $_.Suspicious }}, Name)
    Write-Note ("  {0} services, {1} flagged" -f (Count $report.Services), (Count ($report.Services | Where-Object { $_.Suspicious })))
}
# --------------------------------------------------------------------------
# RECONSTRUCTED in v2 - not present in the truncated repo original
# The collectors below are reconstructed from the README's collector list
# and this script's own patterns (Invoke-Collector, Write-Note, Add-Finding,
# Count, Get-SuspiciousReasons, Get-FileMeta). They are READ-ONLY.
# --------------------------------------------------------------------------

Invoke-Collector 'WMI Event Subscriptions' {
    # RECONSTRUCTED in v2 - not present in the truncated repo original.
    # __EventFilter / __EventConsumer / __FilterToConsumerBinding live in
    # root/subscription. Any persistent binding is high-signal persistence;
    # script/command consumers are flagged Medium, others Info, so a clean
    # host is not flooded with High findings for legitimate subscriptions.
    $filters = @()
    $consumers = @()
    $bindings = @()
    try { $filters = @(Get-CimInstance -Namespace 'root/subscription' -ClassName '__EventFilter' -ErrorAction Stop) } catch { $filters = @() }
    $consumerClasses = @('__EventConsumer', 'ActiveScriptEventConsumer', 'CommandLineEventConsumer', 'LogFileEventConsumer', 'NTEventLogEventConsumer', 'SMTPEventConsumer')
    foreach ($className in $consumerClasses) {
        try {
            $found = @(Get-CimInstance -Namespace 'root/subscription' -ClassName $className -ErrorAction Stop)
            # Enumerating the base __EventConsumer class already returns
            # subclass instances; de-duplicate by Name + class below.
            foreach ($item in $found) { $consumers += $item }
        } catch { }
    }
    $seenConsumers = @{}
    $uniqueConsumers = @()
    foreach ($consumer in $consumers) {
        $key = "{0}|{1}" -f $consumer.CimClass.CimClassName, $consumer.Name
        if (-not $seenConsumers.ContainsKey($key)) {
            $seenConsumers[$key] = $true
            $uniqueConsumers += $consumer
        }
    }
    $consumers = $uniqueConsumers
    try { $bindings = @(Get-CimInstance -Namespace 'root/subscription' -ClassName '__FilterToConsumerBinding' -ErrorAction Stop) } catch { $bindings = @() }

    $out = @()
    foreach ($binding in $bindings) {
        # Filter / Consumer references are CIM instance paths like:
        # \\HOST\root\subscription:__EventFilter.Name="Name"
        $filterRef = "$($binding.Filter)"
        $consumerRef = "$($binding.Consumer)"
        $filterName = $filterRef
        if ($filterName -match 'Name="([^"]+)"') { $filterName = $Matches[1] }
        $consumerName = $consumerRef
        if ($consumerName -match 'Name="([^"]+)"') { $consumerName = $Matches[1] }
        $consumerClass = $null
        if ($consumerRef -match ':([A-Za-z]+EventConsumer)') { $consumerClass = $Matches[1] }
        $isScriptConsumer = ($consumerClass -eq 'ActiveScriptEventConsumer' -or $consumerClass -eq 'CommandLineEventConsumer')
        if ($isScriptConsumer) {
            Add-Finding 'Medium' 'WMI' ("WMI subscription: filter '{0}' -> {1} consumer '{2}'" -f $filterName, $consumerClass, $consumerName)
        } else {
            Add-Finding 'Info' 'WMI' ("WMI subscription: filter '{0}' -> consumer '{1}'" -f $filterName, $consumerName)
        }
        $out += [pscustomobject][ordered]@{
            Filter = $filterName; Consumer = $consumerName; ConsumerClass = $consumerClass
            FilterReference = $filterRef; ConsumerReference = $consumerRef
            Suspicious = [bool]$isScriptConsumer
        }
    }
    $report.WmiSubscriptions = @($out)
    $report.WmiFilters = @($filters | Select-Object Name, Query, EventNamespace)
    $report.WmiConsumers = @($consumers | Select-Object @{n='Class';e={ $_.CimClass.CimClassName }}, Name)
    Write-Note ("  {0} WMI bindings, {1} filters, {2} consumers" -f (Count $report.WmiSubscriptions), (Count $report.WmiFilters), (Count $report.WmiConsumers))
}

Invoke-Collector 'Startup Folders' {
    # RECONSTRUCTED in v2 - not present in the truncated repo original.
    # Common startup folder + every local user profile's startup folder.
    # .lnk targets are read best-effort via WScript.Shell; if that fails
    # the file itself is still recorded, never skipped.
    $startupPaths = @()
    if ($env:ProgramData) { $startupPaths += (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp') }
    if ($env:APPDATA) { $startupPaths += (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup') }
    try {
        $profiles = @(Get-CimInstance Win32_UserProfile -ErrorAction Stop | Where-Object { $_.LocalPath -and -not $_.Special })
        foreach ($profile in $profiles) {
            $candidate = Join-Path $profile.LocalPath 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'
            if ($candidate -notin $startupPaths) { $startupPaths += $candidate }
        }
    } catch { }
    $out = @()
    foreach ($folder in $startupPaths) {
        if (-not (Test-Path -LiteralPath $folder -ErrorAction SilentlyContinue)) { continue }
        $files = @(Get-ChildItem -LiteralPath $folder -File -ErrorAction SilentlyContinue)
        foreach ($file in $files) {
            $target = $null
            if ($file.Extension -eq '.lnk') {
                try {
                    $shell = New-Object -ComObject 'WScript.Shell' -ErrorAction Stop
                    try { $target = $shell.CreateShortcut($file.FullName).TargetPath } catch { $target = $null }
                    try { [System.Runtime.InteropServices.Marshal]::ReleaseComObject($shell) | Out-Null } catch { }
                } catch { $target = $null }
            }
            $checkText = if ($target) { $target } else { $file.FullName }
            $reasons = Get-SuspiciousReasons $checkText
            if ($reasons.Count -gt 0) {
                Add-Finding 'Medium' 'Startup' ("Startup item: {0} -> {1}" -f $file.FullName, $checkText)
            }
            $out += [pscustomobject][ordered]@{
                Folder = $folder; File = $file.Name; FullPath = $file.FullName
                Target = $target; LastWriteTime = $file.LastWriteTime
                Suspicious = ($reasons.Count -gt 0); Reasons = @($reasons)
            }
        }
    }
    $report.StartupItems = @($out | Sort-Object -Property @{E={ -not $_.Suspicious }}, FullPath)
    Write-Note ("  {0} startup items ({1} flagged)" -f (Count $report.StartupItems), (Count ($report.StartupItems | Where-Object { $_.Suspicious })))
}

Invoke-Collector 'Local Accounts' {
    # RECONSTRUCTED in v2 - not present in the truncated repo original.
    # README sample finding: '3 member(s) in local Administrators - verify
    # all are expected' is an Info finding, not a Medium, so this collector
    # follows that: membership is reported and flagged Info, not assumed bad.
    $accounts = @()
    try { $accounts = @(Get-CimInstance Win32_UserAccount -Filter 'LocalAccount=True' -ErrorAction Stop) } catch { $accounts = @() }
    $adminMembers = @()
    $adminSource = $null
    try {
        $members = @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop)
        $adminSource = 'Get-LocalGroupMember'
        foreach ($member in $members) { $adminMembers += "$($member.ObjectClass): $($member.Name)" }
    } catch {
        try {
            $group = [ADSI]'WinNT://./Administrators,group'
            $members = @($group.Invoke('Members'))
            $adminSource = 'ADSI WinNT'
            foreach ($member in $members) {
                $memberName = $null
                try { $memberName = $member.Name } catch { $memberName = $null }
                if ([string]::IsNullOrWhiteSpace($memberName)) {
                    try { $memberName = $member.GetType().InvokeMember('Name', [System.Reflection.BindingFlags]::GetProperty, $null, $member, $null) } catch { $memberName = $null }
                }
                if ($memberName) { $adminMembers += $memberName }
            }
        } catch { $adminMembers = @() }
    }
    $out = @()
    foreach ($account in $accounts) {
        $isAdmin = $false
        foreach ($member in $adminMembers) {
            # Match a full account name, not a substring ('admin' must not
            # match 'administrator').
            if ($member -eq $account.Name -or $member -match ("\\{0}$" -f [regex]::Escape($account.Name))) { $isAdmin = $true }
        }
        $out += [pscustomobject][ordered]@{
            Name = $account.Name; FullName = $account.FullName; SID = $account.SID
            Disabled = [bool]$account.Disabled; LocalAccount = [bool]$account.LocalAccount
            PasswordRequired = $account.PasswordRequired; PasswordExpires = $account.PasswordExpires
            IsAdministrator = $isAdmin
        }
    }
    $report.LocalAccounts = @($out | Sort-Object Name)
    $report.Administrators = @($adminMembers | Sort-Object -Unique)
    $report.AdministratorsSource = $adminSource
    if ((Count $report.Administrators) -gt 0) {
        Add-Finding 'Info' 'Accounts' ("{0} member(s) in local Administrators - verify all are expected" -f (Count $report.Administrators))
    }
    Write-Note ("  {0} local accounts, {1} in Administrators" -f (Count $report.LocalAccounts), (Count $report.Administrators))
}

Invoke-Collector 'Recently Written Executables' {
    # RECONSTRUCTED in v2 - not present in the truncated repo original.
    # Bounded to known drop zones (Temp, ProgramData, Downloads, Desktop)
    # rather than a full-disk scan, so a triage run stays fast. Results
    # are capped at 500; the cap is reported, never silently hidden.
    $cutoff = (Get-Date).AddHours(-$RecentFileHours)
    $roots = @()
    if ($env:TEMP) { $roots += $env:TEMP }
    if ($env:ProgramData) { $roots += $env:ProgramData }
    try {
        $profiles = @(Get-CimInstance Win32_UserProfile -ErrorAction Stop | Where-Object { $_.LocalPath -and -not $_.Special })
        foreach ($profile in $profiles) {
            foreach ($sub in @('Downloads', 'Desktop', 'AppData\Local\Temp')) {
                $candidate = Join-Path $profile.LocalPath $sub
                if ($candidate -notin $roots) { $roots += $candidate }
            }
        }
    } catch { }
    $extensions = @('*.exe', '*.dll', '*.ps1', '*.psm1', '*.bat', '*.cmd', '*.vbs', '*.js', '*.scr', '*.com', '*.msi')
    $out = @()
    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root -ErrorAction SilentlyContinue)) { continue }
        $files = @(Get-ChildItem -LiteralPath $root -Recurse -File -Include $extensions -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -ge $cutoff })
        foreach ($file in $files) {
            $meta = $null
            if ($file.Extension -eq '.exe' -or $file.Extension -eq '.dll') {
                $meta = Get-FileMeta $file.FullName
            }
            $reasons = Get-SuspiciousReasons $file.FullName
            $unsigned = $meta -and $meta.Signed -ne 'Valid'
            if ($unsigned) { $reasons += 'unsigned' }
            if ($reasons.Count -gt 0) {
                Add-Finding 'Medium' 'RecentFile' ("Recently written: {0} ({1})" -f $file.FullName, $file.LastWriteTime.ToString('yyyy-MM-dd HH:mm'))
            }
            $out += [pscustomobject][ordered]@{
                Path = $file.FullName; LastWriteTime = $file.LastWriteTime; Length = $file.Length
                SHA256 = if ($meta) { $meta.Hash } else { $null }
                Signature = if ($meta) { $meta.Signed } else { $null }
                Suspicious = ($reasons.Count -gt 0); Reasons = @($reasons)
            }
            if ((Count $out) -ge 500) { break }
        }
        if ((Count $out) -ge 500) { break }
    }
    $report.RecentFiles = @($out | Sort-Object -Property @{E={ -not $_.Suspicious }}, LastWriteTime -Descending)
    $report.RecentFilesCapped = ((Count $out) -ge 500)
    Write-Note ("  {0} recently written executables in last {1}h ({2} flagged)" -f (Count $report.RecentFiles), $RecentFileHours, (Count ($report.RecentFiles | Where-Object { $_.Suspicious })))
}

Invoke-Collector 'Prefetch' {
    # RECONSTRUCTED in v2 - not present in the truncated repo original.
    # Prefetch filenames are '<Executable>-<Hash>.pf'; the executable name
    # is everything before the last '-'. Run counts are NOT decoded here
    # (that would require parsing the binary prefetch format); times and
    # names are recorded, which is what first-responder triage needs.
    # Reading prefetch normally requires elevation; without it this
    # collector records an empty result instead of failing the run.
    $prefetchDir = $null
    if ($env:SystemRoot) { $prefetchDir = Join-Path $env:SystemRoot 'Prefetch' }
    $out = @()
    if ($prefetchDir -and (Test-Path -LiteralPath $prefetchDir -ErrorAction SilentlyContinue)) {
        $files = @(Get-ChildItem -LiteralPath $prefetchDir -Filter '*.pf' -File -ErrorAction SilentlyContinue)
        foreach ($file in $files) {
            $baseName = [IO.Path]::GetFileNameWithoutExtension($file.Name)
            $exeName = $baseName
            $dashIndex = $baseName.LastIndexOf('-')
            if ($dashIndex -gt 0) { $exeName = $baseName.Substring(0, $dashIndex) }
            $reasons = @()
            if ($script:LineageChildren -contains $exeName.ToLower()) { $reasons += 'script-host-prefetch' }
            if ($reasons.Count -gt 0) {
                Add-Finding 'Info' 'Prefetch' ("Prefetch present for script host: {0} ({1})" -f $exeName, $file.LastWriteTime.ToString('yyyy-MM-dd HH:mm'))
            }
            $out += [pscustomobject][ordered]@{
                PrefetchFile = $file.Name; Executable = $exeName
                LastWriteTime = $file.LastWriteTime; Length = $file.Length
                Suspicious = ($reasons.Count -gt 0); Reasons = @($reasons)
            }
        }
    }
    $report.Prefetch = @($out | Sort-Object LastWriteTime -Descending)
    Write-Note ("  {0} prefetch entries" -f (Count $report.Prefetch))
}

Invoke-Collector 'PowerShell Console History' {
    # RECONSTRUCTED in v2 - not present in the truncated repo original.
    # PSReadLine history per user profile, capped at 500 lines per user.
    # Suspicious command lines follow the same rule as Processes: High.
    $historyPaths = @()
    try {
        $profiles = @(Get-CimInstance Win32_UserProfile -ErrorAction Stop | Where-Object { $_.LocalPath -and -not $_.Special })
        foreach ($profile in $profiles) {
            $candidate = Join-Path $profile.LocalPath 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
            if ($candidate -notin $historyPaths) { $historyPaths += $candidate }
        }
    } catch { }
    if ($env:APPDATA) {
        $current = Join-Path $env:APPDATA 'Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
        if ($current -notin $historyPaths) { $historyPaths += $current }
    }
    $out = @()
    foreach ($historyPath in $historyPaths) {
        if (-not (Test-Path -LiteralPath $historyPath -ErrorAction SilentlyContinue)) { continue }
        $lines = @()
        try { $lines = @(Get-Content -LiteralPath $historyPath -Tail 500 -ErrorAction Stop) } catch { $lines = @() }
        foreach ($line in $lines) {
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            $reasons = Get-SuspiciousReasons $line
            if ($reasons.Count -gt 0) {
                Add-Finding 'High' 'PowerShellHistory' ("Suspicious history in {0}: {1}" -f $historyPath, (Get-FirstLine $line))
            }
            $out += [pscustomobject][ordered]@{
                HistoryPath = $historyPath; Command = $line
                Suspicious = ($reasons.Count -gt 0); Reasons = @($reasons)
            }
        }
    }
    # Keep only suspicious history in the JSON by default, to avoid dumping
    # every user's full command history into a report that may be shared.
    # The count of all lines read is still recorded.
    $report.PowerShellHistoryTotalLines = (Count $out)
    $report.PowerShellHistory = @($out | Where-Object { $_.Suspicious })
    Write-Note ("  {0} history lines read, {1} flagged" -f (Count $out), (Count $report.PowerShellHistory))
}

Invoke-Collector 'Defender and Firewall' {
    # RECONSTRUCTED in v2 - not present in the truncated repo original.
    # Defender cmdlets are absent on hosts with a third-party AV or on
    # Server Core without Defender; that is recorded as NotAvailable,
    # not as a collector failure.
    $defender = $null
    $defenderAvailable = $false
    try {
        $defender = Get-MpComputerStatus -ErrorAction Stop
        $defenderAvailable = $true
    } catch { $defenderAvailable = $false }
    if ($defenderAvailable) {
        if ($defender.RealTimeProtectionEnabled -eq $false) {
            Add-Finding 'Medium' 'Defender' 'Real-time protection is disabled'
        }
        if ($defender.AntivirusEnabled -eq $false) {
            Add-Finding 'Medium' 'Defender' 'Antivirus is disabled'
        }
        $report.Defender = [pscustomobject][ordered]@{
            Available = $true
            RealTimeProtectionEnabled = $defender.RealTimeProtectionEnabled
            AntivirusEnabled = $defender.AntivirusEnabled
            AntispywareEnabled = $defender.AntispywareEnabled
            BehaviorMonitorEnabled = $defender.BehaviorMonitorEnabled
            IoavProtectionEnabled = $defender.IoavProtectionEnabled
            NisEnabled = $defender.NISEnabled
            AntivirusSignatureLastUpdated = $defender.AntivirusSignatureLastUpdated
            QuickScanAgeDays = $defender.QuickScanAge
            FullScanAgeDays = $defender.FullScanAge
        }
    } else {
        $report.Defender = [pscustomobject][ordered]@{ Available = $false }
        Add-Finding 'Info' 'Defender' 'Defender status not available (third-party AV, Defender removed, or cmdlet unavailable)'
    }
    $detections = @()
    if ($defenderAvailable) {
        try {
            $detections = @(Get-MpThreatDetection -ErrorAction Stop | Select-Object -First 20 |
                Select-Object DetectionTime, ThreatID, ThreatName, ActionSuccess, Resources)
            foreach ($detection in $detections) {
                Add-Finding 'Medium' 'Defender' ("Threat detection: {0} at {1}" -f $detection.ThreatName, $detection.DetectionTime)
            }
        } catch { $detections = @() }
    }
    $report.DefenderDetections = @($detections)
    $firewall = @()
    try { $firewall = @(Get-NetFirewallProfile -ErrorAction Stop) } catch { $firewall = @() }
    $firewallOut = @()
    foreach ($profile in $firewall) {
        if ($profile.Enabled -eq $false) {
            Add-Finding 'Medium' 'Firewall' ("Firewall profile disabled: {0}" -f $profile.Name)
        }
        $firewallOut += [pscustomobject][ordered]@{
            Profile = "$($profile.Name)"; Enabled = $profile.Enabled
            DefaultInboundAction = "$($profile.DefaultInboundAction)"
            DefaultOutboundAction = "$($profile.DefaultOutboundAction)"
        }
    }
    $report.FirewallProfiles = @($firewallOut)
    Write-Note ("  Defender available: {0}, detections: {1}, firewall profiles: {2}" -f $defenderAvailable, (Count $report.DefenderDetections), (Count $report.FirewallProfiles))
}

Invoke-Collector 'Security and System Events' {
    # RECONSTRUCTED in v2 - not present in the truncated repo original.
    # -SkipEventLogs skips this collector entirely (README). Otherwise
    # -MaxEvents is the cap PER LOG, as documented in the README.
    if ($SkipEventLogs) {
        $report.Events = @()
        $report.EventsSkipped = $true
        Write-Note '  Skipped (-SkipEventLogs)'
    } else {
        $report.EventsSkipped = $false
        $securityIds = @(4625, 4648, 4672, 4697, 4698, 4702, 4719, 4720, 4728, 4732, 4740, 4756, 4688, 4946, 4947)
        $systemIds = @(7045, 7034, 7023, 7024, 1000)
        $startTime = (Get-Date).AddDays(-7)
        $events = @()
        foreach ($logSpec in @(
            @{ LogName = 'Security'; Ids = $securityIds }
            @{ LogName = 'System'; Ids = $systemIds }
        )) {
            $found = @()
            try {
                $found = @(Get-WinEvent -FilterHashtable @{ LogName = $logSpec.LogName; Id = $logSpec.Ids; StartTime = $startTime } -MaxEvents $MaxEvents -ErrorAction Stop)
            } catch { $found = @() }
            foreach ($event in $found) {
                $isHighSignal = $event.Id -in @(4697, 4698, 4702, 4719, 4720, 4732)
                if ($isHighSignal) {
                    Add-Finding 'Medium' 'Event' ("{0} event {1}: {2}" -f $logSpec.LogName, $event.Id, (Get-FirstLine $event.Message))
                }
                $events += [pscustomobject][ordered]@{
                    TimeCreated = $event.TimeCreated; Log = $logSpec.LogName; Id = $event.Id
                    Level = "$($event.LevelDisplayName)"; Provider = $event.ProviderName
                    Message = (Get-FirstLine $event.Message)
                }
            }
        }
        $report.Events = @($events | Sort-Object TimeCreated -Descending)
        Write-Note ("  {0} high-signal events (last 7 days, max {1} per log)" -f (Count $report.Events), $MaxEvents)
    }
}

# --------------------------------------------------------------------------
# Report writing and summary
# RECONSTRUCTED in v2 - not present in the truncated repo original.
# --------------------------------------------------------------------------
$report.CollectedUtc = (Get-Date).ToUniversalTime().ToString('o')
$report.RunDirectory = $runDir

# Findings first, ordered High, then Medium, then Info, preserving the
# order findings were added within each severity.
$severityRank = @{ High = 0; Medium = 1; Info = 2 }
$report.Findings = @($script:Findings | Sort-Object -Property @{ E = { $severityRank[$_.Severity] } })
$report.FindingCounts = [pscustomobject][ordered]@{
    High = (Count ($script:Findings | Where-Object { $_.Severity -eq 'High' }))
    Medium = (Count ($script:Findings | Where-Object { $_.Severity -eq 'Medium' }))
    Info = (Count ($script:Findings | Where-Object { $_.Severity -eq 'Info' }))
    Total = (Count $script:Findings)
}
$reviewCount = $report.FindingCounts.High + $report.FindingCounts.Medium

$jsonPath = Join-Path $runDir 'LiveResponse.json'
$summaryPath = Join-Path $runDir 'LiveResponse.txt'
try {
    $report | ConvertTo-Json -Depth 5 -ErrorAction Stop | Set-Content -Path $jsonPath -Encoding utf8 -ErrorAction Stop
} catch {
    # JSON depth/serialization must not lose the whole run: try a shallower
    # depth before giving up, and record the failure as a finding.
    try {
        $report | ConvertTo-Json -Depth 3 -ErrorAction Stop | Set-Content -Path $jsonPath -Encoding utf8 -ErrorAction Stop
    } catch {
        Add-Finding 'Info' 'Report' ("JSON report could not be written: {0}" -f $_.Exception.Message)
    }
}

# ServiceNow-pasteable summary, in the README's sample format. Plain text,
# no colour codes, so it pastes cleanly and so -Quiet | clip works.
$summaryLines = New-Object System.Collections.Generic.List[string]
$summaryLines.Add('====================================================')
$summaryLines.Add(("  LIVE RESPONSE  -  {0}" -f $script:HostName))
$summaryLines.Add('====================================================')
$summaryLines.Add(("Collected : {0} UTC" -f (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')))
$summaryLines.Add(("By        : {0}\{1}  (Elevated: {2})" -f $env:USERDOMAIN, $env:USERNAME, $script:Elevated))
if ($null -ne $report.Host) {
    $summaryLines.Add(("OS        : {0}  (Build {1})  Uptime {2}h" -f $report.Host.OS, $report.Host.Build, $report.Host.UptimeHours))
}
$summaryLines.Add('')
$summaryLines.Add(("VERDICT   : {0} item(s) to review" -f $reviewCount))
$summaryLines.Add('')
$summaryLines.Add('-- FINDINGS --')
if ((Count $report.Findings) -eq 0) {
    $summaryLines.Add('  No findings.')
} else {
    foreach ($finding in $report.Findings) {
        $summaryLines.Add(("  [{0}] {1,-12} {2}" -f $finding.Severity, $finding.Category, $finding.Detail))
    }
}
$summaryLines.Add('')
$summaryLines.Add('-- COUNTS --')
$summaryLines.Add(("  Processes            : {0} (flagged {1})" -f (Count $report.Processes), (Count ($report.Processes | Where-Object { $_.Suspicious }))))
$summaryLines.Add(("  External connections : {0}" -f (Count ($report.Network | Where-Object { $_.External }))))
$summaryLines.Add(("  Listeners            : {0}" -f (Count $report.Listeners)))
$summaryLines.Add(("  Autoruns             : {0}" -f (Count $report.Autoruns)))
$summaryLines.Add(("  Scheduled tasks shown: {0}" -f (Count $report.ScheduledTasks)))
$summaryLines.Add(("  Services             : {0} (flagged {1})" -f (Count $report.Services), (Count ($report.Services | Where-Object { $_.Suspicious }))))
$summaryLines.Add(("  WMI subscriptions    : {0}" -f (Count $report.WmiSubscriptions)))
$summaryLines.Add(("  Startup items        : {0}" -f (Count $report.StartupItems)))
$summaryLines.Add(("  Local accounts       : {0}" -f (Count $report.LocalAccounts)))
$summaryLines.Add(("  Administrators       : {0}" -f (Count $report.Administrators)))
$summaryLines.Add(("  Recent files         : {0}" -f (Count $report.RecentFiles)))
$summaryLines.Add(("  Prefetch entries     : {0}" -f (Count $report.Prefetch)))
$summaryLines.Add(("  Defender detections  : {0}" -f (Count $report.DefenderDetections)))
$summaryLines.Add(("  Events               : {0}" -f (Count $report.Events)))
$summary = ($summaryLines -join "`r`n")
try { Set-Content -Path $summaryPath -Value $summary -Encoding utf8 -ErrorAction Stop } catch { }

# Quiet mode: console prints ONLY the summary, so -Quiet | clip pastes
# cleanly. Files are still written either way. In non-quiet mode, also
# print the file paths (outside the summary, so clip output stays clean
# when Quiet is used).
foreach ($line in $summaryLines) { Write-Host $line }
if (-not $Quiet) {
    Write-Host ''
    Write-Host ("JSON report: {0}" -f $jsonPath) -ForegroundColor Gray
    Write-Host ("Summary    : {0}" -f $summaryPath) -ForegroundColor Gray
}
