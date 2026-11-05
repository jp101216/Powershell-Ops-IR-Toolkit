#Requires -Version 5.1
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repo = Split-Path -Parent $PSScriptRoot
foreach ($source in @(
    @{ File = 'Invoke-NetTriage.ps1'; Functions = @('Resolve-DiagnosticTarget', 'Get-DiagnosticRoute', 'Get-VpnEvidence', 'Test-TcpPort', 'Test-ResolvedTcpPort') }
    @{ File = 'Invoke-EndpointTuneUp.ps1'; Functions = @('Get-NetworkResetSafety', 'Invoke-Step', 'Add-SkippedStep') }
)) {
    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        (Join-Path $repo $source.File), [ref]$tokens, [ref]$errors)
    if ($errors) { throw ($errors -join ', ') }
    foreach ($definition in $ast.EndBlock.Statements | Where-Object { $_ -is [System.Management.Automation.Language.FunctionDefinitionAst] }) {
        if ($definition.Name -in $source.Functions) {
            . ([scriptblock]::Create($definition.Extent.Text))
        }
    }
}
function Assert-Result {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

$global:ToolkitNetworkFixture = @{
    Routes = @(); Interfaces = @(); Adapters = @(); Addresses = @()
    Services = @('vpnagent'); AdapterError = $false; AddressError = $false
    DnsInterface = $null; Actions = 0
}
function Find-NetRoute {
    [CmdletBinding()] param([string]$RemoteIPAddress)
    [pscustomobject]@{ IPAddress = '10.20.0.5'; InterfaceIndex = 42 }
    [pscustomobject]@{
        InterfaceIndex = 42; InterfaceAlias = 'VPN'; NextHop = '10.20.0.1'
        DestinationPrefix = '10.0.0.0/8'; RouteMetric = 1; InterfaceMetric = 10
    }
}
function Get-NetRoute {
    [CmdletBinding()] param([string[]]$DestinationPrefix)
    $global:ToolkitNetworkFixture.Routes
}
function Get-NetIPInterface {
    [CmdletBinding()] param()
    $global:ToolkitNetworkFixture.Interfaces
}
function Get-DnsClientServerAddress {
    [CmdletBinding()] param([int]$InterfaceIndex)
    $global:ToolkitNetworkFixture.DnsInterface = $InterfaceIndex
    [pscustomobject]@{ ServerAddresses = @('10.20.0.53', 'fe80::53') }
}
function Get-Service {
    [CmdletBinding()] param([string[]]$Name)
    foreach ($service in $Name) {
        if ($service -in $global:ToolkitNetworkFixture.Services) { [pscustomobject]@{ Status = 'Running' } }
    }
}
function Get-Process {
    [CmdletBinding()] param([string[]]$Name)
}
function Get-NetAdapter {
    [CmdletBinding()] param([switch]$IncludeHidden)
    if ($global:ToolkitNetworkFixture.AdapterError) { throw 'Fixture adapter error' }
    $global:ToolkitNetworkFixture.Adapters
}
function Get-NetIPAddress {
    [CmdletBinding()] param([int]$InterfaceIndex, [string]$Type)
    if ($global:ToolkitNetworkFixture.AddressError) { throw 'Fixture address error' }
    $global:ToolkitNetworkFixture.Addresses | Where-Object { -not $InterfaceIndex -or $_.InterfaceIndex -eq $InterfaceIndex }
}
function Write-Log {
    param([AllowEmptyString()][string]$Message, [string]$Level)
}

try {
    $resolved = Resolve-DiagnosticTarget '::1'
    Assert-Result ($resolved.Address -eq '::1' -and -not $resolved.Error) 'IPv6 literal resolution failed.'
    $route = Get-DiagnosticRoute '10.22.0.8'
    Assert-Result ($route.InterfaceIndex -eq 42 -and $route.LocalAddress -eq '10.20.0.5') 'Destination route or source was selected incorrectly.'
    Assert-Result ($global:ToolkitNetworkFixture.DnsInterface -eq 42 -and $route.DNSServers[1] -eq 'fe80::53%42') 'DNS must use the selected interface and scope link-local IPv6 addresses.'
    & {
        function Test-TcpPort {
            param([string]$ComputerName, [int]$Port, [int]$TimeoutMs)
            [pscustomobject]@{ Success = ($ComputerName -eq '192.0.2.10'); LatencyMs = 1; Error = 'Fixture refusal' }
        }
        $resolution = [pscustomobject]@{ Addresses = @('2001:db8::1', '192.0.2.10'); Error = $null }
        $probe = Test-ResolvedTcpPort -Resolution $resolution -Port 443 -TimeoutMs 1000
        Assert-Result ($probe.Success -and $probe.Attempts.Count -eq 2 -and $probe.Route.RemoteAddress -eq '192.0.2.10') 'Multi-address fallback must report the route for the successful address.'
    }
    if ([System.Net.Sockets.Socket]::OSSupportsIPv6) {
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::IPv6Loopback, 0)
        try {
            $listener.Start()
            $probe = Test-TcpPort -ComputerName '::1' -Port $listener.LocalEndpoint.Port -TimeoutMs 1000
            Assert-Result $probe.Success 'IPv6 TCP probing failed.'
        }
        finally { $listener.Stop() }
    }
    $global:ToolkitNetworkFixture.Interfaces = @(
        [pscustomobject]@{ InterfaceIndex = 1; AddressFamily = 'IPv4'; ConnectionState = 'Disconnected' }
        [pscustomobject]@{ InterfaceIndex = 2; AddressFamily = 'IPv4'; ConnectionState = 'Connected' }
        [pscustomobject]@{ InterfaceIndex = 3; AddressFamily = 'IPv4'; ConnectionState = 'Connected' }
    )
    $global:ToolkitNetworkFixture.Routes = @(
        [pscustomobject]@{ InterfaceIndex = 1; InterfaceAlias = 'Down'; AddressFamily = 'IPv4'; DestinationPrefix = '0.0.0.0/0'; NextHop = '192.0.2.1'; RouteMetric = 1; InterfaceMetric = 1 }
        [pscustomobject]@{ InterfaceIndex = 2; InterfaceAlias = 'High interface metric'; AddressFamily = 'IPv4'; DestinationPrefix = '0.0.0.0/0'; NextHop = '192.0.2.2'; RouteMetric = 1; InterfaceMetric = 100 }
        [pscustomobject]@{ InterfaceIndex = 3; InterfaceAlias = 'Preferred'; AddressFamily = 'IPv4'; DestinationPrefix = '0.0.0.0/0'; NextHop = '192.0.2.3'; RouteMetric = 20; InterfaceMetric = 1 }
    )
    $route = Get-DiagnosticRoute
    Assert-Result ($route.InterfaceIndex -eq 3 -and $route.Selection -eq 'DefaultIPv4') 'Default routing must consider connection state and both route and interface metrics.'
    $global:ToolkitNetworkFixture.Routes = @()
    $route = Get-DiagnosticRoute
    Assert-Result ([bool]$route.Error -and $null -eq $route.InterfaceIndex) 'Missing routes must remain unavailable.'
    $global:ToolkitNetworkFixture.Interfaces = @([pscustomobject]@{ InterfaceIndex = 7; AddressFamily = 'IPv6'; ConnectionState = 'Connected' })
    $global:ToolkitNetworkFixture.Routes = @([pscustomobject]@{
        InterfaceIndex = 7; InterfaceAlias = 'IPv6'; AddressFamily = 'IPv6'
        DestinationPrefix = '::/0'; NextHop = 'fe80::1'; RouteMetric = 10; InterfaceMetric = 5
    })
    $route = Get-DiagnosticRoute
    Assert-Result ($route.InterfaceIndex -eq 7 -and $route.Selection -eq 'DefaultIPv6') 'IPv6 default route fallback failed.'

    $vpn = Get-VpnEvidence
    Assert-Result ($vpn.Clients[0].Running -and -not $vpn.Clients[0].TunnelObserved -and $vpn.Tunnels.Count -eq 0) 'A running VPN service must not imply a tunnel.'
    $global:ToolkitNetworkFixture.Services += 'ZSATunnel'
    $global:ToolkitNetworkFixture.Adapters = @(
        [pscustomobject]@{ ifIndex = 42; Name = 'Cisco'; InterfaceDescription = 'Cisco AnyConnect Virtual Adapter'; Status = 'Up' }
        [pscustomobject]@{ ifIndex = 43; Name = 'Zscaler'; InterfaceDescription = 'Zscaler Virtual Adapter'; Status = 'Up' }
        [pscustomobject]@{ ifIndex = 44; Name = 'Other'; InterfaceDescription = 'WireGuard Tunnel'; Status = 'Up' }
    )
    $global:ToolkitNetworkFixture.Addresses = @(
        [pscustomobject]@{ InterfaceIndex = 42; IPAddress = '10.20.0.5'; AddressState = 'Preferred'; SkipAsSource = $false; PrefixOrigin = 'Other' }
        [pscustomobject]@{ InterfaceIndex = 43; IPAddress = '169.254.1.5'; AddressState = 'Preferred'; SkipAsSource = $false; PrefixOrigin = 'WellKnown' }
        [pscustomobject]@{ InterfaceIndex = 44; IPAddress = 'fd00::5'; AddressState = 'Preferred'; SkipAsSource = $false; PrefixOrigin = 'Manual' }
    )
    $vpn = Get-VpnEvidence
    Assert-Result ($vpn.Tunnels.Count -eq 2 -and $vpn.Clients[0].TunnelObserved -and -not $vpn.Clients[1].TunnelObserved) 'Tunnel evidence must match its provider and include usable IPv6 addresses.'
    $global:ToolkitNetworkFixture.AdapterError = $true
    $vpn = Get-VpnEvidence
    Assert-Result ($vpn.Errors.Count -eq 1 -and $vpn.Summary -match 'incomplete') 'An adapter-query failure must be visible.'

    $safety = Get-NetworkResetSafety
    Assert-Result ($safety.State -eq 'StaticDetected' -and $safety.StaticAddresses[0].IPAddress -eq 'fd00::5') 'Manual IPv6 addresses must protect stack resets.'
    $global:ToolkitNetworkFixture.Addresses = @([pscustomobject]@{ InterfaceIndex = 2; InterfaceAlias = 'Ethernet'; IPAddress = '192.0.2.10'; AddressFamily = 'IPv4'; PrefixOrigin = 'Dhcp' })
    $safety = Get-NetworkResetSafety
    Assert-Result ($safety.State -eq 'NoManualAddresses') 'DHCP configuration was misclassified.'
    $global:ToolkitNetworkFixture.AddressError = $true
    $safety = Get-NetworkResetSafety
    Assert-Result ($safety.State -eq 'Unknown' -and [bool]$safety.Error) 'Failed IP inspection must protect stack resets.'

    $Phase = @('Network')
    $RemoteSafe = $true
    $script:CurrentPhase = 'Network'
    $script:NetworkSafety = [pscustomobject]@{ State = 'NoManualAddresses' }
    $script:StepResults = New-Object System.Collections.Generic.List[object]
    $script:StepFailures = New-Object System.Collections.Generic.List[string]
    $script:SkippedSteps = New-Object System.Collections.Generic.List[string]
    $action = { $global:ToolkitNetworkFixture.Actions++ }
    Invoke-Step 'Disruptive action' -DisruptsNetwork -Action $action -Confirm:$false
    Assert-Result ($global:ToolkitNetworkFixture.Actions -eq 0 -and $script:StepResults[0].Error -match 'RemoteSafe') 'RemoteSafe allowed a disruptive action.'
    $script:CurrentPhase = 'Summary'
    Invoke-Step 'Reboot' -DisruptsNetwork -Action $action -Confirm:$false
    Assert-Result ($global:ToolkitNetworkFixture.Actions -eq 0) 'RemoteSafe allowed a reboot.'
    $script:CurrentPhase = 'Network'
    $RemoteSafe = $false
    foreach ($state in @('StaticDetected', 'Unknown')) {
        $script:NetworkSafety.State = $state
        Invoke-Step 'Stack reset' -ResetsNetworkStack -Action $action -Confirm:$false
    }
    Assert-Result ($global:ToolkitNetworkFixture.Actions -eq 0) 'Protected stack resets executed.'
    $script:NetworkSafety.State = 'NoManualAddresses'
    Invoke-Step 'Permitted reset' -ResetsNetworkStack -Action $action -Confirm:$false
    Assert-Result ($global:ToolkitNetworkFixture.Actions -eq 1 -and $script:StepFailures.Count -eq 0) 'A permitted action failed.'
    Write-Host "Network policy tests passed in PowerShell $($PSVersionTable.PSVersion)."
}
finally { Remove-Variable -Name ToolkitNetworkFixture -Scope Global }
