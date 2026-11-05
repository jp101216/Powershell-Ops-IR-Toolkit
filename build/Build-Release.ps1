#Requires -Version 5.1
[CmdletBinding()]
param([string]$OutputDirectory)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$version = (Get-Content -LiteralPath (Join-Path $repo 'VERSION') -Raw).Trim()
if ($version -notmatch '^\d+\.\d+\.\d+$') { throw 'VERSION must contain a numeric major.minor.patch version.' }
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $repo 'dist' }
$OutputDirectory = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDirectory)
[System.IO.Directory]::CreateDirectory($OutputDirectory) | Out-Null
$name = "Powershell-Ops-IR-Toolkit-v$version"
$staging = Join-Path $OutputDirectory ([guid]::NewGuid().ToString('N'))
$payload = Join-Path $staging $name
$archive = Join-Path $OutputDirectory ($name + '.zip')
$manifest = Join-Path $OutputDirectory 'SHA256SUMS.txt'
$files = @(
    'Compare-NetTriage.ps1', 'Invoke-EndpointTuneUp.ps1', 'Invoke-NetTriage.ps1', 'Invoke-UpdateSystem.ps1',
    'README.md', 'CHANGELOG.md', 'LICENSE', 'VERSION', 'CoreInfrastructure.example.json'
)
try {
    [System.IO.Directory]::CreateDirectory($payload) | Out-Null
    foreach ($file in $files) {
        $source = Join-Path $repo $file
        if ($file -like '*.ps1' -and (Get-Content -LiteralPath $source -Raw) -notmatch [regex]::Escape("Version $version")) {
            throw "Version mismatch in $file."
        }
        Copy-Item -LiteralPath $source -Destination (Join-Path $payload $file)
    }
    $hashes = foreach ($file in ($files | Sort-Object)) {
        $hash = (Get-FileHash -LiteralPath (Join-Path $payload $file) -Algorithm SHA256).Hash.ToLowerInvariant()
        "$hash  $file"
    }
    [System.IO.File]::WriteAllLines((Join-Path $payload 'SHA256SUMS.txt'), [string[]]$hashes,
        (New-Object System.Text.UTF8Encoding($false)))
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    if (Test-Path -LiteralPath $archive) { Remove-Item -LiteralPath $archive -Force }
    [System.IO.Compression.ZipFile]::CreateFromDirectory($staging, $archive)
    $archiveHash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    [System.IO.File]::WriteAllText($manifest, "$archiveHash  $name.zip`n", (New-Object System.Text.UTF8Encoding($false)))
    Write-Output $archive
    Write-Output $manifest
}
finally {
    if (Test-Path -LiteralPath $staging) { Remove-Item -LiteralPath $staging -Recurse -Force }
}
