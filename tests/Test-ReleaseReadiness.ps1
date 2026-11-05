#Requires -Version 5.1
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repo = Split-Path -Parent $PSScriptRoot
function Assert-Result {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}
$asts = @{}
foreach ($file in @('Invoke-EndpointTuneUp.ps1', 'Invoke-NetTriage.ps1')) {
    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $repo $file), [ref]$tokens, [ref]$errors)
    if ($errors) { throw ($errors -join ', ') }
    $asts[$file] = $ast
    foreach ($definition in $ast.EndBlock.Statements | Where-Object { $_ -is [System.Management.Automation.Language.FunctionDefinitionAst] }) {
        if ($definition.Name -in @('Invoke-Step', 'Add-StepDetail', 'Add-SkippedStep', 'Test-ReparsePath',
                'Clear-OldTemporaryFiles', 'Write-AtomicJsonReport', 'Write-TriageExportPair')) {
            . ([scriptblock]::Create($definition.Extent.Text))
        }
    }
}
function Write-Log { param([AllowEmptyString()][string]$Message, [string]$Level) }
function Get-StepAction {
    param([string]$Name)
    $command = $asts['Invoke-EndpointTuneUp.ps1'].FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.CommandAst] -and
        $node.GetCommandName() -eq 'Invoke-Step' -and
        $node.CommandElements[1] -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
        $node.CommandElements[1].Value -eq $Name
    }, $true) | Select-Object -First 1
    return ($command.CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.ScriptBlockExpressionAst] }).ScriptBlock.GetScriptBlock()
}

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('Readiness_' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $tempRoot
$global:ToolkitReadiness = @{ Changed = @{}; Schedules = 0; ClientPresent = $true }
try {
    & {
        function Get-NetAdapter {
            [CmdletBinding()] param([switch]$Physical)
            foreach ($name in @('Good', 'Rejected', 'Unsupported')) { [pscustomobject]@{ Name = $name } }
        }
        function Get-NetAdapterPowerManagement {
            [CmdletBinding()] param([string]$Name)
            $state = 'Enabled'
            if ($global:ToolkitReadiness.Changed.ContainsKey($Name)) { $state = 'Disabled' }
            if ($Name -eq 'Unsupported') { $state = 'Unsupported' }
            [pscustomobject]@{ Name = $Name; DeviceSleepOnDisconnect = $state; SelectiveSuspend = $state }
        }
        function Disable-NetAdapterPowerManagement {
            [CmdletBinding(SupportsShouldProcess)] param($InputObject, [switch]$DeviceSleepOnDisconnect, [switch]$SelectiveSuspend, [switch]$NoRestart)
            Assert-Result ($DeviceSleepOnDisconnect -and $SelectiveSuspend -and $NoRestart) 'NIC settings or restart policy are incorrect.'
            if ($InputObject.Name -eq 'Rejected') { throw 'Fixture driver rejection' }
            $global:ToolkitReadiness.Changed[$InputObject.Name] = $true
        }
        function Get-Service {
            [CmdletBinding()] param([string]$Name)
            if ($global:ToolkitReadiness.ClientPresent) { [pscustomobject]@{ Status = 'Running' } }
        }
        function Invoke-CimMethod {
            [CmdletBinding()] param([string]$Namespace, [string]$ClassName, [string]$MethodName, [hashtable]$Arguments)
            $global:ToolkitReadiness.Schedules++
            if ($global:ToolkitReadiness.Schedules -eq 2) { throw 'Fixture schedule failure' }
            [pscustomobject]@{ ReturnValue = $(if ($global:ToolkitReadiness.Schedules -eq 1) { 0 } else { 5 }) }
        }
        $Phase = @('Network', 'Optimize')
        $RemoteSafe = $false
        $script:StepResults = New-Object System.Collections.Generic.List[object]
        $script:StepFailures = New-Object System.Collections.Generic.List[string]
        $script:SkippedSteps = New-Object System.Collections.Generic.List[string]
        $script:CurrentPhase = 'Network'
        Invoke-Step 'NIC fixture' -Action (Get-StepAction 'Disable supported NIC sleep settings') -Confirm:$false
        Assert-Result ($script:StepResults[0].Status -eq 'Partial' -and $script:StepResults[0].Details.Count -eq 3) 'A rejected adapter must produce a partial step.'
        $script:CurrentPhase = 'Optimize'
        Invoke-Step 'SCCM fixture' -Action (Get-StepAction 'Trigger SCCM/MECM client actions (if client present)') -Confirm:$false
        Assert-Result ($script:StepResults[1].Status -eq 'Partial' -and $script:StepResults[1].Details.Count -eq 3) 'Failed SCCM schedules must produce a partial step.'
        $global:ToolkitReadiness.ClientPresent = $false
        Invoke-Step 'Absent SCCM' -Action (Get-StepAction 'Trigger SCCM/MECM client actions (if client present)') -Confirm:$false
        Assert-Result ($script:StepResults[2].Status -eq 'Skipped') 'An absent SCCM client must be skipped.'
        Invoke-Step 'Interrupted batch' -Confirm:$false -Action {
            Add-StepDetail 'Completed item' 'Success' 'Applied.'
            throw 'Failure after a completed item'
        }
        Assert-Result ($script:StepResults[3].Status -eq 'Partial') 'A failure after completed work must remain partial.'
    }

    $root = Join-Path $tempRoot 'cleanup'
    $outside = Join-Path $tempRoot 'outside'
    $null = New-Item -ItemType Directory -Path $root, $outside
    $old = Join-Path $root 'old.txt'
    $recent = Join-Path $root 'recent.txt'
    $marker = Join-Path $outside 'marker.txt'
    'old' | Set-Content -LiteralPath $old
    'recent' | Set-Content -LiteralPath $recent
    'keep' | Set-Content -LiteralPath $marker
    [System.IO.File]::SetLastWriteTimeUtc($recent, [datetime]::UtcNow.AddHours(2))
    $link = Join-Path $root 'redirect'
    $linkType = 'SymbolicLink'
    if ([Environment]::OSVersion.Platform -eq 'Win32NT') { $linkType = 'Junction' }
    $null = New-Item -ItemType $linkType -Path $link -Target $outside
    try {
        $counts = Clear-OldTemporaryFiles $root ([datetime]::UtcNow.AddMinutes(1))
        Assert-Result ($counts.FilesDeleted -eq 1 -and $counts.RecentSkipped -eq 1 -and $counts.LinksSkipped -eq 1 -and $counts.Failed -eq 0) 'Cleanup counts or age protection are incorrect.'
        Assert-Result (Test-Path -LiteralPath $marker) 'Cleanup followed a directory link.'
        $counts = Clear-OldTemporaryFiles $link ([datetime]::UtcNow.AddMinutes(1))
        Assert-Result ($counts.LinksSkipped -eq 1 -and (Test-Path -LiteralPath $marker)) 'A linked cleanup root must be skipped.'
    }
    finally { [System.IO.Directory]::Delete($link, $false) }
    if ([Environment]::OSVersion.Platform -eq 'Win32NT') {
        $agedPath = Join-Path $root 'aged.txt'
        $freshPath = Join-Path $root 'freshly-created.txt'
        'aged' | Set-Content -LiteralPath $agedPath
        'fresh' | Set-Content -LiteralPath $freshPath
        [System.IO.File]::SetCreationTimeUtc($agedPath, [datetime]::UtcNow.AddDays(-3))
        [System.IO.File]::SetLastWriteTimeUtc($agedPath, [datetime]::UtcNow.AddDays(-3))
        [System.IO.File]::SetLastWriteTimeUtc($freshPath, [datetime]::UtcNow.AddDays(-3))
        $counts = Clear-OldTemporaryFiles $root ([datetime]::UtcNow.AddDays(-1))
        Assert-Result (-not (Test-Path -LiteralPath $agedPath) -and (Test-Path -LiteralPath $freshPath)) 'Creation age must protect freshly extracted files with old modification times.'
        $lockedPath = Join-Path $root 'locked.txt'
        'locked' | Set-Content -LiteralPath $lockedPath
        $held = [System.IO.File]::Open($lockedPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        try {
            $counts = Clear-OldTemporaryFiles $root ([datetime]::UtcNow.AddMinutes(1))
            Assert-Result ($counts.LockedSkipped -eq 1 -and (Test-Path -LiteralPath $lockedPath)) 'A locked file must be counted and preserved.'
        }
        finally { $held.Dispose() }
    }

    $json = Join-Path $tempRoot 'pair.json'
    $text = Join-Path $tempRoot 'pair.txt'
    Write-TriageExportPair $json $text @{ Id = 1 } '1'
    Write-TriageExportPair $json $text @{ Id = 2 } '2'
    Assert-Result ((Get-Content -LiteralPath $json -Raw | ConvertFrom-Json).Id -eq 2 -and (Get-Content -LiteralPath $text -Raw).Trim() -eq '2') 'An existing report pair was not replaced consistently.'
    if ([Environment]::OSVersion.Platform -eq 'Win32NT') {
        $held = [System.IO.File]::Open($text, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        $failed = $false
        try { Write-TriageExportPair $json $text @{ Id = 3 } '3' }
        catch { $failed = $true }
        finally { $held.Dispose() }
        Assert-Result ($failed -and (Get-Content -LiteralPath $json -Raw | ConvertFrom-Json).Id -eq 2 -and (Get-Content -LiteralPath $text -Raw).Trim() -eq '2') 'A failed text replacement must restore the preceding JSON.'
    }
    $definition = (Get-Command Write-TriageExportPair).Definition
    $jobs = @(3..4 | ForEach-Object {
        Start-Job -ScriptBlock {
            param($Body, $Json, $Text, $Id)
            $ErrorActionPreference = 'Stop'
            . ([scriptblock]::Create('function Write-TriageExportPair {' + $Body + '}'))
            Write-TriageExportPair $Json $Text @{ Id = $Id } ([string]$Id)
            $Id
        } -ArgumentList $definition, $json, $text, $_
    })
    try {
        $results = @($jobs | Wait-Job | Receive-Job -ErrorAction Stop)
        Assert-Result ($results.Count -eq 2) 'Concurrent report writers did not complete.'
        $saved = Get-Content -LiteralPath $json -Raw | ConvertFrom-Json
        Assert-Result ([string]$saved.Id -eq (Get-Content -LiteralPath $text -Raw).Trim()) 'Concurrent replacement mixed two collections.'
    }
    finally { $jobs | Remove-Job -Force }
    & {
        function Get-CimInstance {
            [CmdletBinding()] param([string]$ClassName, [string]$Filter, [string[]]$Property)
            if ($ClassName -eq 'Win32_Processor') { throw 'Fixture CPU query failure' }
            CimCmdlets\Get-CimInstance @PSBoundParameters
        }
        function Get-Service { [CmdletBinding()] param([string[]]$Name) }
        function Set-Clipboard { [CmdletBinding()] param([Parameter(ValueFromPipeline)]$Value) process {} }
        $config = Join-Path $tempRoot 'empty.json'
        '[]' | Set-Content -LiteralPath $config
        $reportPath = Join-Path $tempRoot 'incomplete.json'
        $summary = & (Join-Path $repo 'Invoke-NetTriage.ps1') -NonInteractive -Quiet -SkipPublicProbes -CoreInfrastructurePath $config -TargetDestination '127.0.0.1' -TargetPorts @() -ExportPath $reportPath -RetainCount 0
        Assert-Result ($LASTEXITCODE -eq 2) 'Incomplete collection must return exit code 2.'
        $report = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
        Assert-Result ($null -eq $report.Performance.CPU_LoadPct -and $report.CollectionStatus -eq 'Partial' -and $summary -match 'CPU Load\s+: Unknown') 'Failed CPU collection must remain unknown in JSON and text.'
        $null = & (Join-Path $repo 'Invoke-NetTriage.ps1') -NonInteractive -Quiet -SkipPublicProbes -CoreInfrastructurePath $config -TargetDestination '127.0.0.1' -TargetPorts @() -ExportPath $tempRoot -RetainCount 0
        Assert-Result ($LASTEXITCODE -eq 1) 'Report publication failure must return exit code 1.'
    }
    if ([Environment]::OSVersion.Platform -eq 'Win32NT') {
        $engine = (Get-Process -Id $PID).Path
        & $engine -NoLogo -NoProfile -NonInteractive -File (Join-Path $repo 'Invoke-EndpointTuneUp.ps1') -Phase Cleanup -SkipTempCleanup -Quiet -LogDirectory $tempRoot -ReportPath $tempRoot -LogRetentionDays 0 | Out-Null
        Assert-Result ($LASTEXITCODE -eq 1) 'A failed maintenance report must produce a nonzero process exit.'
    }
    Assert-Result (@(Get-ChildItem -LiteralPath $tempRoot -Filter '*.tmp').Count -eq 0 -and @(Get-ChildItem -LiteralPath $tempRoot -Filter '*.lock').Count -eq 0) 'Report temporary files were left behind.'
    Write-Host "Release-readiness tests passed in PowerShell $($PSVersionTable.PSVersion)."
    $global:LASTEXITCODE = 0
}
finally {
    Remove-Variable -Name ToolkitReadiness -Scope Global
    Remove-Item -LiteralPath $tempRoot -Recurse -Force
}
