#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [switch]$IncludeWindowsUpdateScan,
    [switch]$RunMaintenance,
    [switch]$InstallTestDriver
)

$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne 'Win32NT') {
    throw 'This smoke test requires Windows.'
}
if (($RunMaintenance -or $InstallTestDriver) -and ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted')) {
    throw 'Native maintenance tests require a disposable GitHub-hosted runner.'
}

function Assert-Result {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

$repo = Split-Path -Parent $PSScriptRoot
foreach ($script in (Get-ChildItem -LiteralPath $repo -Filter '*.ps1' -File)) {
    $tokens = $null
    $parseErrors = $null
    $null = [System.Management.Automation.Language.Parser]::ParseFile(
        $script.FullName, [ref]$tokens, [ref]$parseErrors)
    Assert-Result ($parseErrors.Count -eq 0) ("{0}: {1}" -f $script.Name, ($parseErrors -join ', '))
}
Write-Host "Toolkit scripts parsed in PowerShell $($PSVersionTable.PSVersion)."

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('ToolkitSmoke_' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $tempRoot
try {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    try {
        $listener.Start()
        $port = $listener.LocalEndpoint.Port
        $configPath = Join-Path $tempRoot 'Infrastructure[1].json'
        $exportPath = Join-Path $tempRoot 'Triage[1].json'
        '[{"Name":"Loopback fixture","Host":"127.0.0.1","Port":' + $port + '}]' |
            Set-Content -LiteralPath $configPath -Encoding UTF8

        & (Join-Path $repo 'Invoke-NetTriage.ps1') -NonInteractive -SkipPublicProbes `
            -CoreInfrastructurePath $configPath -TargetDestination '127.0.0.1' -TargetPorts $port `
            -PingCount 1 -ExportPath $exportPath -RetainCount 0

        $triage = Get-Content -LiteralPath $exportPath -Raw | ConvertFrom-Json
        Assert-Result ($triage.CoreInfrastructure.Count -eq 1 -and $triage.CoreInfrastructure[0].Success) 'Configured TCP probe failed.'
        Assert-Result ($triage.Target.Ports.Count -eq 1 -and $triage.Target.Ports[0].Success) 'Single-target TCP probe failed.'
        Assert-Result ($triage.Target.Route.InterfaceIndex -gt 0 -and $triage.Target.Route.RemoteAddress -eq '127.0.0.1' -and -not $triage.Target.Route.Error) 'The native route lookup did not identify the loopback destination.'
        Assert-Result ($triage.CoreInfrastructure[0].ResolvedAddress -eq '127.0.0.1' -and $triage.CoreInfrastructure[0].Route.InterfaceIndex -gt 0) 'Core checks must identify the address and route they tested.'
        Assert-Result (-not $triage.ExternalIP -and -not $triage.Latency.DNS_ProbeName) 'Built-in public probes were enabled.'
        Assert-Result (Test-Path -LiteralPath ([System.IO.Path]::ChangeExtension($exportPath, 'txt'))) 'Text summary is missing.'

        $defaultPath = Join-Path $tempRoot 'DefaultRoute.json'
        & (Join-Path $repo 'Invoke-NetTriage.ps1') -NonInteractive -SkipPublicProbes `
            -CoreInfrastructurePath $configPath -PingCount 1 -ExportPath $defaultPath -RetainCount 0
        $default = Get-Content -LiteralPath $defaultPath -Raw | ConvertFrom-Json
        Assert-Result (-not $default.Network.Route.Error -and $default.Network.Route.InterfaceIndex -gt 0) 'The native default route lookup failed.'
        Assert-Result ($default.Network.Route.Selection -in @('DefaultIPv4', 'DefaultIPv6')) 'A target-free run must identify its default route policy.'
        if ($default.Network.Gateway) {
            Assert-Result ($default.Latency.Gateway.Target -eq $default.Network.Gateway) 'Gateway latency did not use the selected route.'
        }
        if ($default.Network.DNS.Count -gt 0) {
            Assert-Result ($default.Latency.DNS.Target -eq $default.Network.DNS[0]) 'DNS-server latency did not use the selected interface.'
        }

        $listener.Stop()
        $afterPath = Join-Path $tempRoot 'TriageAfter.json'
        & (Join-Path $repo 'Invoke-NetTriage.ps1') -NonInteractive -SkipPublicProbes `
            -CoreInfrastructurePath $configPath -TargetDestination '127.0.0.1' -TargetPorts $port `
            -PingCount 1 -ExportPath $afterPath -RetainCount 0
        $comparisonPath = Join-Path $tempRoot 'NativeComparison.json'
        & (Join-Path $repo 'Compare-NetTriage.ps1') $exportPath $afterPath -Quiet -ExportPath $comparisonPath | Out-Null
        $comparison = Get-Content -LiteralPath $comparisonPath -Raw | ConvertFrom-Json
        $tcpChanges = @($comparison.Checks | Where-Object { $_.Category -in @('Core', 'Target') })
        Assert-Result ($tcpChanges.Count -eq 2 -and @($tcpChanges | Where-Object { $_.Change -ne 'Regressed' }).Count -eq 0) 'The native before-and-after comparison missed the stopped TCP listener.'
        Write-Host 'NetTriage native round-trip comparison passed.'
    }
    finally { $listener.Stop() }
    Write-Host 'NetTriage loopback and export checks passed.'

    & {
        # Keep these guards in the dry-run scope.
        function ipconfig.exe { throw 'Unexpected network step in a cleanup-only run.' }
        function dism.exe { throw 'Unexpected DISM invocation during WhatIf.' }
        function sfc.exe { throw 'Unexpected SFC invocation during WhatIf.' }
        function shutdown.exe { throw 'Unexpected reboot invocation during WhatIf.' }

        $dryRunPath = Join-Path $tempRoot 'TuneUpDryRun'
        $summary = & (Join-Path $repo 'Invoke-EndpointTuneUp.ps1') -Phase Cleanup -SkipTempCleanup `
            -DeepClean -Reboot -WhatIf -NonInteractive -Quiet -LogDirectory $dryRunPath
        Assert-Result (-not (Test-Path -LiteralPath $dryRunPath)) 'Tune-up WhatIf created an audit directory.'
        Assert-Result ($summary -is [string] -and $summary -match 'Failed steps\s+: none') 'Tune-up WhatIf failed.'
        Assert-Result ($summary -match 'Skipped steps\s+: .*DISM component-store cleanup.*Reboot \(shutdown /r\)') 'Tune-up WhatIf omitted expected skipped steps.'
    }
    Write-Host 'Endpoint Tune-Up phase selection and dry-run checks passed.'

    & {
        function ipconfig.exe {
            $arguments = $args -join ' '
            if ($arguments -notin @('/all', '/flushdns', '/registerdns')) { throw "Unexpected ipconfig action $arguments" }
            $global:LASTEXITCODE = 0
            'Fixture network state'
        }
        function netsh.exe { throw 'RemoteSafe invoked netsh.' }
        function nbtstat.exe { throw 'RemoteSafe invoked nbtstat.' }
        function Restart-NetAdapter { throw 'RemoteSafe restarted an adapter.' }
        function Get-NetAdapterPowerManagement { throw 'RemoteSafe entered NIC power management.' }
        function shutdown.exe { throw 'RemoteSafe invoked shutdown.' }
        $remotePath = Join-Path $tempRoot 'RemoteSafe.json'
        $null = & (Join-Path $repo 'Invoke-EndpointTuneUp.ps1') -Phase Network -RemoteSafe -Reboot -Force `
            -NonInteractive -Quiet -LogDirectory $tempRoot -ReportPath $remotePath -LogRetentionDays 0
        $remote = Get-Content -LiteralPath $remotePath -Raw | ConvertFrom-Json
        Assert-Result (-not $remote.FatalError -and $remote.FailedSteps.Count -eq 0) 'RemoteSafe invoked a prohibited operation.'
        Assert-Result ($remote.NetworkSafety.State -in @('StaticDetected', 'NoManualAddresses')) 'The native IP preflight could not classify this runner.'
        $protected = @($remote.Steps | Where-Object { $_.Error -eq 'Skipped by -RemoteSafe' })
        Assert-Result ($protected.Count -eq 9) 'RemoteSafe must skip every disruptive network step and the requested reboot.'
        Assert-Result (@($remote.Steps | Where-Object { $_.Phase -eq 'Network' -and $_.Status -eq 'Success' }).Count -eq 4) 'RemoteSafe should retain network snapshots and DNS cache operations.'
    }
    Write-Host 'RemoteSafe entry-point policy checks passed.'

    if ($RunMaintenance) {
        $maintenancePath = Join-Path $tempRoot 'Maintenance.json'
        & (Join-Path $repo 'Invoke-EndpointTuneUp.ps1') -Phase Cleanup -SkipTempCleanup `
            -DeepClean -NonInteractive -Quiet -LogDirectory $tempRoot -ReportPath $maintenancePath -LogRetentionDays 0
        $maintenance = Get-Content -LiteralPath $maintenancePath -Raw | ConvertFrom-Json
        Assert-Result (-not $maintenance.FatalError -and $maintenance.FailedSteps.Count -eq 0) 'Native maintenance reported a failure.'
        $completed = @($maintenance.Steps | Where-Object { $_.Status -eq 'Success' })
        Assert-Result ($completed.Count -eq 2 -and @($completed | Where-Object { $_.Phase -ne 'Cleanup' }).Count -eq 0) 'Native maintenance ran unexpected steps.'
        Write-Host 'Native DISM cleanup and SFC checks passed.'
    }

    if ($IncludeWindowsUpdateScan) {
        $updatePath = Join-Path $tempRoot 'Update[1].json'
        & (Join-Path $repo 'Invoke-UpdateSystem.ps1') -ScanOnly -SkipBiosRouting `
            -LogDirectory $tempRoot -ReportPath $updatePath
        $update = Get-Content -LiteralPath $updatePath -Raw | ConvertFrom-Json
        Assert-Result ([bool]$update.System.OS) 'The updater did not report the Windows OS.'
        Assert-Result ($update.WindowsUpdate.ScanStatus -in @('Succeeded', 'Partial', 'Failed')) 'The updater did not record a scan result.'
        Assert-Result ($update.WindowsUpdate.InstallStatus -eq 'NotRequested' -and -not $update.RebootRequired) 'Scan-only requested installation or reboot.'
        if ($update.WindowsUpdate.ScanStatus -eq 'Failed') {
            Assert-Result ($update.Errors.Count -gt 0) 'The failed Windows Update scan had no diagnostic.'
            Write-Warning "The Windows Update source returned a scan failure: $($update.Errors -join ', ')"
        }
        else {
            Write-Host "Windows Update scan status: $($update.WindowsUpdate.ScanStatus). Applicable updates: $($update.WindowsUpdate.Found)."
        }
        if ($InstallTestDriver) {
            $candidate = @($update.WindowsUpdate.Updates | Where-Object {
                $_.Title -like 'Microsoft Corporation AudioProcessingObject Driver Update (*)' -and $_.UpdateId
            } | Select-Object -First 1)
            if ($candidate.Count -eq 1 -and $update.WindowsUpdate.ScanStatus -eq 'Succeeded') {
                & (Join-Path $repo 'Invoke-UpdateSystem.ps1') -AutoInstall -NonInteractive -SkipBiosRouting `
                    -UpdateId $candidate[0].UpdateId -LogDirectory $tempRoot -ReportPath $updatePath
                $installed = Get-Content -LiteralPath $updatePath -Raw | ConvertFrom-Json
                Assert-Result ($installed.WindowsUpdate.InstallStatus -eq 'Succeeded' -and $installed.WindowsUpdate.Updates.Count -eq 1) 'The selected native driver installation failed.'
                Assert-Result ($installed.WindowsUpdate.Updates[0].UpdateId -eq $candidate[0].UpdateId) 'The installation report identifies a different update.'
                Write-Host "Native driver installation passed. Reboot required: $($installed.RebootRequired)."
            }
            else { Write-Warning 'The known audio driver was unavailable. Native driver installation was skipped.' }
        }
    }
}
finally {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force
}
