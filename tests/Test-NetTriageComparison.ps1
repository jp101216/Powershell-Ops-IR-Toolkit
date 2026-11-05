#Requires -Version 5.1
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$commandPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'Compare-NetTriage.ps1'
$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('ComparisonTests_' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $tempRoot

function Assert-Result {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

function Write-Fixture {
    param($Data, [string]$Name)
    $path = Join-Path $tempRoot $Name
    $Data | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $path -Encoding UTF8
    return $path
}

function Invoke-Comparison {
    param($Before, $After)
    $left = Write-Fixture $Before 'before[1].json'
    $right = Write-Fixture $After 'after[1].json'
    $output = Join-Path $tempRoot ([guid]::NewGuid().ToString('N') + '.json')
    $text = & $commandPath $left $right -ExportPath $output -Quiet
    Assert-Result ($text -is [string] -and $text -match 'NETTRIAGE BEFORE AND AFTER') 'Quiet output must contain one ticket summary.'
    Assert-Result ((Get-Content -LiteralPath ([System.IO.Path]::ChangeExtension($output, 'txt')) -Raw).TrimEnd() -eq $text.TrimEnd()) 'Saved text differs from console summary.'
    return Get-Content -LiteralPath $output -Raw | ConvertFrom-Json
}

function Assert-Rejected {
    param([scriptblock]$Action, [string]$Pattern)
    $rejected = $false
    try { & $Action | Out-Null }
    catch { $rejected = $_.Exception.Message -match $Pattern }
    Assert-Result $rejected "Expected rejection matching '$Pattern'."
}

function New-Snapshot {
    param([bool]$After)
    $collected = '2026-11-05T10:00:00.123Z'
    $pending = $true
    $dnsMs = $null
    $dnsError = 'DNS query failed'
    $appSuccess = $false
    $dbSuccess = $true
    $latency = 30
    if ($After) {
        $collected = '2026-11-05T11:00:00.456Z'
        $pending = $false
        $dnsMs = 12
        $dnsError = $null
        $appSuccess = $true
        $dbSuccess = $false
        $latency = 10
    }
    return [pscustomobject]@{
        Computer = 'LAB-01'
        CollectedUtc = $collected
        System = [pscustomobject]@{ Hostname = 'lab-01'; PendingReboot = $pending }
        CoreInfrastructure = @(
            [pscustomobject]@{ Name = 'App'; Host = 'APP.EXAMPLE.COM.'; Port = 443; Success = $appSuccess; LatencyMs = $null; Error = $null }
            [pscustomobject]@{ Name = 'Database'; Host = 'db.example.com'; Port = 1433; Success = $dbSuccess; LatencyMs = $null; Error = $null }
            [pscustomobject]@{ Name = 'File server'; Host = 'files.example.com'; Port = 445; Success = $false; LatencyMs = $null; Error = 'Timeout' }
        )
        Target = [pscustomobject]@{
            Destination = 'intranet.example.com'
            Ports = @([pscustomobject]@{ Port = 443; Success = $true; LatencyMs = $latency; Error = $null })
        }
        Latency = [pscustomobject]@{
            DNS_ProbeName = 'intranet.example.com'; DNS_ResolveMs = $dnsMs; DNS_ProbeError = $dnsError
            Gateway = [pscustomobject]@{ Target = '10.0.0.1'; Sent = 4; AvgMs = $latency; LossPct = 0 }
            DNS = $null
        }
    }
}

try {
    $before = New-Snapshot $false
    $after = New-Snapshot $true
    $after.CoreInfrastructure[0].Host = 'app.example.com'
    $after.CoreInfrastructure[0].Name = 'Renamed app check'
    $result = Invoke-Comparison $before $after
    Assert-Result ($result.Counts.Recovered -eq 3 -and $result.Counts.Regressed -eq 1 -and $result.Counts.StillFailing -eq 1) 'Reachability and reboot changes were classified incorrectly.'
    $tcp = @($result.Checks | Where-Object { $_.Category -eq 'Target' })
    Assert-Result ($tcp.Count -eq 1 -and $tcp[0].Change -eq 'Healthy' -and $tcp[0].LatencyDeltaMs -eq -20) 'TCP latency delta is incorrect.'
    $rtt = @($result.Quality | Where-Object { $_.Unit -eq 'ms' })
    Assert-Result ($rtt.Count -eq 1 -and $rtt[0].Delta -eq -20) 'Gateway RTT delta is incorrect.'
    Assert-Result (([datetimeoffset]$result.BeforeCollectedUtc).Millisecond -eq 123 -and ([datetimeoffset]$result.AfterCollectedUtc).Millisecond -eq 456) 'Collection timestamp precision was lost.'
    $before.CollectedUtc = '2026-11-05T10:00:00.123'
    $result = Invoke-Comparison $before $after
    Assert-Result (([datetimeoffset]$result.BeforeCollectedUtc).UtcDateTime.Hour -eq 10) 'A CollectedUtc value without an offset must be interpreted as UTC.'
    $before = New-Snapshot $false

    $after.Target.Destination = 'different.example.com'
    $result = Invoke-Comparison $before $after
    Assert-Result ($result.Counts.Added -eq 1 -and $result.Counts.Removed -eq 1) 'Different TCP targets must appear as added and removed.'
    Assert-Result (@($result.Checks | Where-Object { $_.Category -eq 'Target' -and $null -ne $_.LatencyDeltaMs }).Count -eq 0) 'Different TCP targets must not have a latency delta.'

    $before = New-Snapshot $false
    $after = New-Snapshot $true
    $before.Latency.PSObject.Properties.Remove('DNS_ProbeName')
    $before.Latency.DNS_ResolveMs = 8
    $before.Latency.PSObject.Properties.Remove('DNS_ProbeError')
    $before.System.PSObject.Properties.Remove('PendingReboot')
    $before.PSObject.Properties.Remove('CollectedUtc')
    $result = Invoke-Comparison $before $after
    Assert-Result ($result.Notes.Count -eq 2) 'Legacy DNS and timestamp gaps must be reported.'
    Assert-Result (@($result.Checks | Where-Object { $_.Category -eq 'System' -and $_.Change -eq 'NotComparable' }).Count -eq 1) 'Missing reboot data must not be interpreted as clear.'
    Assert-Result (@($result.Checks | Where-Object { $_.Category -eq 'DNS' -and $_.Change -eq 'Recovered' }).Count -eq 0) 'Unnamed legacy DNS probes must not claim recovery.'

    $before = New-Snapshot $false
    $after = New-Snapshot $true
    $before.CoreInfrastructure += $before.CoreInfrastructure[0]
    $after.CoreInfrastructure[1].Success = 'false'
    $after.Latency.Gateway.Sent = 0
    $result = Invoke-Comparison $before $after
    Assert-Result ($result.Counts.NotComparable -eq 2 -and $result.Notes.Count -eq 1) 'Duplicate and non-boolean checks must remain unknown.'
    Assert-Result (@($result.Quality | Where-Object { $null -ne $_.Delta }).Count -eq 0) 'An unattempted ping must not be treated as a measurement.'

    $before = New-Snapshot $false
    $after = New-Snapshot $true
    $before.System.Hostname = 'other-host'
    Assert-Rejected { Invoke-Comparison $before $after } 'Conflicting computer'
    $before = New-Snapshot $false
    $after.Computer = 'OTHER-PC'
    $after.System.Hostname = 'OTHER-PC'
    Assert-Rejected { Invoke-Comparison $before $after } 'same computer'
    $after = New-Snapshot $true
    Assert-Rejected { Invoke-Comparison $after $before } 'newer snapshot'
    $before.CollectedUtc = 'invalid timestamp'
    Assert-Rejected { Invoke-Comparison $before $after } 'Invalid CollectedUtc'

    $left = Write-Fixture (New-Snapshot $false) 'before.json'
    $right = Write-Fixture (New-Snapshot $true) 'after.json'
    Assert-Rejected { & $commandPath $left $right -ExportPath $left -Quiet } 'new path'
    $existingText = Join-Path $tempRoot 'existing.txt'
    'Keep this text' | Set-Content -LiteralPath $existingText
    Assert-Rejected { & $commandPath $left $right -ExportPath (Join-Path $tempRoot 'existing.json') -Quiet } 'new path'
    Assert-Result ((Get-Content -LiteralPath $existingText -Raw).Trim() -eq 'Keep this text') 'An existing text file was changed.'
    Assert-Result (-not (Test-Path -LiteralPath (Join-Path $tempRoot 'existing.json'))) 'A failed export left a JSON file behind.'

    $sharedOutput = Join-Path $tempRoot 'concurrent.json'
    $jobs = @(1..2 | ForEach-Object {
        Start-Job -ScriptBlock {
            param($Command, $Before, $After, $Output)
            $ErrorActionPreference = 'Stop'
            try {
                & $Command $Before $After -ExportPath $Output -Quiet | Out-Null
                [pscustomobject]@{ Succeeded = $true }
            }
            catch { [pscustomobject]@{ Succeeded = $false } }
        } -ArgumentList $commandPath, $left, $right, $sharedOutput
    })
    try {
        $outcomes = @($jobs | Wait-Job | Receive-Job)
        Assert-Result (@($outcomes | Where-Object { $_.Succeeded }).Count -eq 1) 'Concurrent exports should publish exactly one comparison.'
        $saved = Get-Content -LiteralPath $sharedOutput -Raw | ConvertFrom-Json
        Assert-Result ($saved.Computer -eq 'LAB-01' -and (Test-Path -LiteralPath ([System.IO.Path]::ChangeExtension($sharedOutput, 'txt')))) 'Concurrent output is incomplete.'
    }
    finally { $jobs | Remove-Job -Force }

    $bad = Join-Path $tempRoot 'bad.json'
    '[]' | Set-Content -LiteralPath $bad
    Assert-Rejected { & $commandPath $bad $right -Quiet } 'NetTriage JSON object'
    $large = [System.IO.File]::Create($bad)
    try { $large.SetLength(16MB + 1) } finally { $large.Dispose() }
    Assert-Rejected { & $commandPath $bad $right -Quiet } 'at most 16 MB'
    Assert-Result (@(Get-ChildItem -LiteralPath $tempRoot -Filter '*.tmp').Count -eq 0) 'Temporary export files were left behind.'
    Write-Host "NetTriage comparison tests passed in PowerShell $($PSVersionTable.PSVersion)."
}
finally { Remove-Item -LiteralPath $tempRoot -Recurse -Force }
