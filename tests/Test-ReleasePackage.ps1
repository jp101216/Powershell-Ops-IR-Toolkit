#Requires -Version 5.1
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$root = Join-Path ([System.IO.Path]::GetTempPath()) ('PackageTest_' + [guid]::NewGuid().ToString('N'))
try {
    $outputs = @(& (Join-Path $repo 'build/Build-Release.ps1') -OutputDirectory $root)
    if ($outputs.Count -ne 2) { throw 'Expected an archive and checksum manifest.' }
    $archiveHash = (Get-FileHash -LiteralPath $outputs[0] -Algorithm SHA256).Hash.ToLowerInvariant()
    if ((Get-Content -LiteralPath $outputs[1] -Raw) -notmatch "^$archiveHash  ") { throw 'Archive checksum mismatch.' }
    $extract = Join-Path $root 'extracted'
    [System.IO.Compression.ZipFile]::ExtractToDirectory($outputs[0], $extract)
    $payload = @(Get-ChildItem -LiteralPath $extract -Directory)
    if ($payload.Count -ne 1) { throw 'Expected one release directory.' }
    $files = @(Get-ChildItem -LiteralPath $payload[0].FullName -File)
    if ($files.Count -ne 10) { throw 'Unexpected release payload.' }
    foreach ($line in (Get-Content -LiteralPath (Join-Path $payload[0].FullName 'SHA256SUMS.txt'))) {
        $parts = $line -split '  ', 2
        if ($parts.Count -ne 2) { throw 'Malformed payload checksum.' }
        $hash = (Get-FileHash -LiteralPath (Join-Path $payload[0].FullName $parts[1]) -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($hash -ne $parts[0]) { throw "Checksum mismatch for $($parts[1])." }
    }
    Write-Host 'Release package and payload checksums verified.'
    $global:LASTEXITCODE = 0
}
finally {
    if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force }
}
