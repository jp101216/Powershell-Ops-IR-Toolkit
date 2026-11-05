#Requires -Version 5.1
<#
.SYNOPSIS
    Compares two NetTriage exports from the same endpoint.

.DESCRIPTION
    Reads saved JSON exports and compares TCP and named DNS checks, latency,
    packet loss, and pending-reboot status. Results include recovered checks,
    regressions, continuing failures, and checks added or removed between runs.
    Missing measurements and unnamed legacy DNS probes are reported as gaps.

    Writes a JSON comparison and a ServiceNow-ready text summary. Output files
    must be new paths. The default is a unique Comparison_* pair in the user's
    local NetTriage folder. The command works offline with PowerShell 5.1 or 7.

.PARAMETER BeforePath
    JSON export collected before the troubleshooting change.

.PARAMETER AfterPath
    JSON export collected afterward from the same computer.

.PARAMETER ExportPath
    New JSON output path. A matching .txt summary is written beside it.

.PARAMETER Quiet
    Emit only the plain-text summary to the success stream.

.PARAMETER CopyToClipboard
    Also copy the summary to the clipboard when the host supports it.

.EXAMPLE
    .\Compare-NetTriage.ps1 -BeforePath .\before.json -AfterPath .\after.json -Quiet

.EXAMPLE
    .\Compare-NetTriage.ps1 .\before.json .\after.json -ExportPath C:\Tickets\comparison.json
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateNotNullOrEmpty()][string]$BeforePath,
    [Parameter(Mandatory = $true, Position = 1)]
    [ValidateNotNullOrEmpty()][string]$AfterPath,
    [string]$ExportPath,
    [switch]$Quiet,
    [switch]$CopyToClipboard
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-Field {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -ne $property) { return $property.Value }
    return $null
}

function Get-Measurement {
    param($Value)
    $number = 0.0
    $text = [Convert]::ToString($Value, [Globalization.CultureInfo]::InvariantCulture)
    if ([double]::TryParse($text, [Globalization.NumberStyles]::Float,
            [Globalization.CultureInfo]::InvariantCulture, [ref]$number) -and
        -not [double]::IsNaN($number) -and -not [double]::IsInfinity($number) -and $number -ge 0) {
        return $number
    }
    return $null
}

function Read-Snapshot {
    param([string]$Path)
    $file = Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($file.PSProvider.Name -ne 'FileSystem' -or $file.PSIsContainer -or $file.Length -gt 16MB) {
        throw "Expected a JSON file of at most 16 MB at '$Path'."
    }
    $json = Get-Content -LiteralPath $file.FullName -Raw -Encoding UTF8
    if ([string]::IsNullOrWhiteSpace($json) -or -not $json.TrimStart().StartsWith('{')) {
        throw "Expected a NetTriage JSON object at '$Path'."
    }
    $data = $json | ConvertFrom-Json -ErrorAction Stop
    $system = Get-Field $data 'System'
    $computer = Get-Field $data 'Computer'
    $hostname = Get-Field $system 'Hostname'
    if (-not $computer) { $computer = $hostname }
    if ($computer -isnot [string] -or [string]::IsNullOrWhiteSpace($computer) -or $null -eq $system) {
        throw "NetTriage computer identity or System data is missing in '$Path'."
    }
    if ($hostname -and $computer.Trim() -ine ([string]$hostname).Trim()) {
        throw "Conflicting computer identities in '$Path'."
    }
    $collected = $null
    $timestamp = Get-Field $data 'CollectedUtc'
    if ($timestamp -is [datetime]) {
        if ($timestamp.Kind -eq [DateTimeKind]::Unspecified) {
            $timestamp = [datetime]::SpecifyKind($timestamp, [DateTimeKind]::Utc)
        }
        $collected = ([datetimeoffset]$timestamp).ToUniversalTime()
    }
    elseif ($timestamp) {
        $parsed = [datetimeoffset]::MinValue
        if (-not [datetimeoffset]::TryParse([string]$timestamp, [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$parsed)) {
            throw "Invalid CollectedUtc timestamp in '$Path'."
        }
        $collected = $parsed.ToUniversalTime()
    }
    return [pscustomobject]@{ Data = $data; Computer = $computer.Trim(); Collected = $collected; Path = $file.FullName }
}

function Get-HostKey {
    param([string]$Name)
    $address = $null
    if ([System.Net.IPAddress]::TryParse($Name, [ref]$address)) { return $address.ToString().ToLowerInvariant() }
    return $Name.Trim().TrimEnd('.').ToLowerInvariant()
}

function Get-SnapshotChecks {
    param($Snapshot, [string]$Side, $Notes)
    $checks = @{}
    $groups = @(
        @{ Category = 'Core'; Rows = @(Get-Field $Snapshot.Data 'CoreInfrastructure'); HostName = $null }
        @{ Category = 'Target'; Rows = @(Get-Field (Get-Field $Snapshot.Data 'Target') 'Ports')
            HostName = Get-Field (Get-Field $Snapshot.Data 'Target') 'Destination' }
    )
    foreach ($group in $groups) {
        foreach ($row in $group.Rows) {
            if ($null -eq $row) { continue }
            $hostName = $group.HostName
            if ($group.Category -eq 'Core') { $hostName = Get-Field $row 'Host' }
            $port = 0
            if ($hostName -isnot [string] -or [string]::IsNullOrWhiteSpace($hostName) -or
                -not [int]::TryParse([string](Get-Field $row 'Port'), [ref]$port) -or $port -lt 1 -or $port -gt 65535) {
                throw "Invalid $($group.Category) TCP endpoint in the $Side snapshot."
            }
            $key = '{0}|{1}|{2}' -f $group.Category, (Get-HostKey $hostName), $port
            $success = Get-Field $row 'Success'
            if ($success -isnot [bool]) { $success = $null }
            $name = Get-Field $row 'Name'
            if (-not $name) { $name = $hostName }
            if ($checks.ContainsKey($key)) {
                $checks[$key].Success = $null
                $checks[$key].LatencyMs = $null
                $Notes.Add("$Side has duplicate $($group.Category) TCP checks for $hostName port $port. Their results are ambiguous.") | Out-Null
                continue
            }
            $checks[$key] = [pscustomobject]@{
                Category = $group.Category
                Label = "$name ($hostName port $port)"
                Success = $success
                LatencyMs = Get-Measurement (Get-Field $row 'LatencyMs')
                Error = Get-Field $row 'Error'
            }
        }
    }
    $latency = Get-Field $Snapshot.Data 'Latency'
    $dnsName = Get-Field $latency 'DNS_ProbeName'
    $dnsError = Get-Field $latency 'DNS_ProbeError'
    $dnsMs = Get-Measurement (Get-Field $latency 'DNS_ResolveMs')
    if ($dnsName -or $dnsError -or $null -ne $dnsMs) {
        $dnsSuccess = $null
        $key = 'DNS|unknown'
        $label = 'DNS lookup (probe name unavailable)'
        if ($dnsName -is [string] -and -not [string]::IsNullOrWhiteSpace($dnsName)) {
            $key = 'DNS|' + (Get-HostKey $dnsName)
            $label = "DNS lookup $dnsName"
            if ($dnsError) { $dnsSuccess = $false }
            elseif ($null -ne $dnsMs) { $dnsSuccess = $true }
        }
        else { $Notes.Add("$Side has a legacy DNS timing without a probe name. A matching DNS target cannot be verified.") | Out-Null }
        $checks[$key] = [pscustomobject]@{ Category = 'DNS'; Label = $label; Success = $dnsSuccess; LatencyMs = $dnsMs; Error = $dnsError }
    }
    $pending = Get-Field (Get-Field $Snapshot.Data 'System') 'PendingReboot'
    $rebootClear = $null
    if ($pending -is [bool]) { $rebootClear = -not $pending }
    $checks['System|Reboot'] = [pscustomobject]@{
        Category = 'System'; Label = 'Pending reboot cleared'; Success = $rebootClear; LatencyMs = $null; Error = $null
    }
    return $checks
}

function Get-QualityMeasurements {
    param($Snapshot)
    $measurements = @{}
    foreach ($kind in @('Gateway', 'DNS')) {
        $ping = Get-Field (Get-Field $Snapshot.Data 'Latency') $kind
        $target = Get-Field $ping 'Target'
        if ($target -isnot [string] -or [string]::IsNullOrWhiteSpace($target)) { continue }
        foreach ($metric in @(@{ Property = 'AvgMs'; Label = 'ICMP RTT'; Unit = 'ms' },
                              @{ Property = 'LossPct'; Label = 'ICMP loss'; Unit = '%' })) {
            $value = $null
            if ((Get-Measurement (Get-Field $ping 'Sent')) -gt 0) {
                $value = Get-Measurement (Get-Field $ping $metric.Property)
            }
            $key = '{0}|{1}|{2}' -f $kind, (Get-HostKey $target), $metric.Property
            $measurements[$key] = [pscustomobject]@{ Label = "$kind $target $($metric.Label)"; Unit = $metric.Unit; Value = $value }
        }
    }
    return $measurements
}

$before = Read-Snapshot $BeforePath
$after = Read-Snapshot $AfterPath
if ($before.Computer -ine $after.Computer) { throw 'The exports must identify the same computer.' }
if ($null -ne $before.Collected -and $null -ne $after.Collected -and $before.Collected -gt $after.Collected) {
    throw 'BeforePath contains a newer snapshot than AfterPath.'
}
$notes = New-Object System.Collections.Generic.List[string]
if ($null -eq $before.Collected -or $null -eq $after.Collected) {
    $notes.Add('A collection timestamp is missing. Snapshot order could not be verified.') | Out-Null
}
$beforeChecks = Get-SnapshotChecks $before 'Before' $notes
$afterChecks = Get-SnapshotChecks $after 'After' $notes
$changes = @(foreach ($key in (@($beforeChecks.Keys) + @($afterChecks.Keys) | Sort-Object -Unique)) {
    $left = $beforeChecks[$key]
    $right = $afterChecks[$key]
    $label = $left
    if ($null -ne $right) { $label = $right }
    $change = 'NotComparable'
    $delta = $null
    if ($null -eq $left) { $change = 'Added' }
    elseif ($null -eq $right) { $change = 'Removed' }
    elseif ($null -ne $left.Success -and $null -ne $right.Success) {
        if ($left.Success -and $right.Success) { $change = 'Healthy' }
        elseif (-not $left.Success -and $right.Success) { $change = 'Recovered' }
        elseif ($left.Success -and -not $right.Success) { $change = 'Regressed' }
        else { $change = 'StillFailing' }
        if ($left.Success -and $right.Success -and $null -ne $left.LatencyMs -and $null -ne $right.LatencyMs) {
            $delta = [math]::Round($right.LatencyMs - $left.LatencyMs, 2)
        }
    }
    [pscustomobject]@{ Key = $key; Label = $label.Label; Category = $label.Category; Change = $change; Before = $left; After = $right; LatencyDeltaMs = $delta }
})
$beforeMetrics = Get-QualityMeasurements $before
$afterMetrics = Get-QualityMeasurements $after
$metrics = @(foreach ($key in (@($beforeMetrics.Keys) + @($afterMetrics.Keys) | Sort-Object -Unique)) {
    $left = $beforeMetrics[$key]
    $right = $afterMetrics[$key]
    $label = $left
    if ($null -ne $right) { $label = $right }
    $delta = $null
    if ($null -ne $left -and $null -ne $right -and $null -ne $left.Value -and $null -ne $right.Value) {
        $delta = [math]::Round($right.Value - $left.Value, 2)
    }
    [pscustomobject]@{ Key = $key; Label = $label.Label; Unit = $label.Unit; Before = Get-Field $left 'Value'; After = Get-Field $right 'Value'; Delta = $delta }
})
$counts = [ordered]@{}
foreach ($kind in @('Recovered', 'Regressed', 'StillFailing', 'Healthy', 'Added', 'Removed', 'NotComparable')) {
    $counts[$kind] = @($changes | Where-Object { $_.Change -eq $kind }).Count
}

if ([string]::IsNullOrWhiteSpace($ExportPath)) {
    $localRoot = [Environment]::GetFolderPath('LocalApplicationData')
    if (-not $localRoot) { $localRoot = [System.IO.Path]::GetTempPath() }
    $name = 'Comparison_{0}_{1}.json' -f (Get-Date -Format 'yyyyMMdd_HHmmss'), [guid]::NewGuid().ToString('N')
    $ExportPath = Join-Path (Join-Path $localRoot 'NetTriage') $name
}
$ExportPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ExportPath)
$textPath = [System.IO.Path]::ChangeExtension($ExportPath, 'txt')
if ([System.IO.Path]::GetExtension($ExportPath) -ine '.json') { throw 'ExportPath must end in .json.' }
$pathComparison = [StringComparison]::Ordinal
if ([Environment]::OSVersion.Platform -eq 'Win32NT') { $pathComparison = [StringComparison]::OrdinalIgnoreCase }
foreach ($path in @($ExportPath, $textPath)) {
    if ((Test-Path -LiteralPath $path) -or [string]::Equals($path, $before.Path, $pathComparison) -or
        [string]::Equals($path, $after.Path, $pathComparison)) {
        throw "Comparison output must use a new path. '$path' already exists or identifies an input."
    }
}
$beforeTime = Get-Field $before 'Collected'
$afterTime = Get-Field $after 'Collected'
$report = [ordered]@{
    SchemaVersion = 1
    Computer = $before.Computer
    BeforePath = $before.Path
    AfterPath = $after.Path
    BeforeCollectedUtc = $(if ($null -ne $beforeTime) { $beforeTime.ToString('o') })
    AfterCollectedUtc = $(if ($null -ne $afterTime) { $afterTime.ToString('o') })
    Counts = $counts
    Checks = $changes
    Quality = $metrics
    Notes = $notes.ToArray()
}
$lines = New-Object System.Collections.Generic.List[string]
$lines.Add('NETTRIAGE BEFORE AND AFTER')
$lines.Add("Computer  $($report.Computer)")
$lines.Add("Before    $($report.BeforeCollectedUtc)")
$lines.Add("After     $($report.AfterCollectedUtc)")
$lines.Add('')
$lines.Add('CHECK RESULTS')
foreach ($kind in $counts.Keys) { $lines.Add("$kind  $($counts[$kind])") }
foreach ($item in $changes) {
    $lines.Add("- $($item.Change)  $($item.Label)")
    foreach ($side in @('Before', 'After')) {
        $check = $item.$side
        $state = 'Not present'
        if ($null -ne $check) {
            $state = 'Unknown'
            if ($null -ne $check.Success) {
                $state = 'Failed'
                if ($check.Success) { $state = 'Passed' }
            }
        }
        $lines.Add("  $side state  $state")
    }
    if ($null -ne $item.After -and $item.After.Success -eq $false -and $item.After.Error) {
        $lines.Add("  After error  $($item.After.Error)")
    }
}
$lines.Add('')
$lines.Add('LATENCY AND QUALITY')
foreach ($item in $changes | Where-Object { $null -ne $_.LatencyDeltaMs }) {
    $lines.Add("- $($item.Label)  $($item.Before.LatencyMs) to $($item.After.LatencyMs) ms (change $($item.LatencyDeltaMs) ms)")
}
foreach ($item in $metrics) {
    if ($null -ne $item.Delta) {
        $lines.Add("- $($item.Label)  $($item.Before) to $($item.After) $($item.Unit) (change $($item.Delta) $($item.Unit))")
    }
    else { $lines.Add("- $($item.Label)  comparison unavailable") }
}
foreach ($note in $notes) { $lines.Add("Note  $note") }
$lines.Add('')
$lines.Add("JSON  $ExportPath")
$summary = $lines -join "`r`n"

$directory = Split-Path -Parent $ExportPath
[System.IO.Directory]::CreateDirectory($directory) | Out-Null
$jsonTemp = Join-Path $directory ([guid]::NewGuid().ToString('N') + '.tmp')
$textTemp = Join-Path $directory ([guid]::NewGuid().ToString('N') + '.tmp')
$jsonPublished = $false
try {
    $report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $jsonTemp -Encoding UTF8
    $summary | Set-Content -LiteralPath $textTemp -Encoding UTF8
    [System.IO.File]::Move($jsonTemp, $ExportPath)
    $jsonPublished = $true
    [System.IO.File]::Move($textTemp, $textPath)
}
catch {
    if ($jsonPublished) { Remove-Item -LiteralPath $ExportPath -Force }
    throw
}
finally {
    foreach ($tempPath in @($jsonTemp, $textTemp)) {
        if (Test-Path -LiteralPath $tempPath) { Remove-Item -LiteralPath $tempPath -Force }
    }
}
if ($CopyToClipboard) {
    try { Set-Clipboard -Value $summary -ErrorAction Stop }
    catch { Write-Warning "Could not copy comparison to clipboard. $($_.Exception.Message)" }
}
if ($Quiet) { Write-Output $summary }
else { Write-Host $summary -ForegroundColor Cyan }
