#Requires -Version 5.1
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
    [int]$RecentFileHours = 24,
    [int]$MaxEvents = 200
)

$ErrorActionPreference = 'Stop'

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
$runDir = Join-Path $OutputPath ("{0}_{1}" -f $env:COMPUTERNAME, $stamp)
New-Item -ItemType Directory -Path $runDir -Force | Out-Null

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
        if ($unsigned -and $userPath) { Add-Finding 'Medium' 'Service' ("{0}: unsigned binary in user-writable path -> {