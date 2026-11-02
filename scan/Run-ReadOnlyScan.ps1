[CmdletBinding()]
param([string]$OutputDirectory = (Join-Path $PSScriptRoot ('Scan-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))), [string]$ConfigRoot)
$ErrorActionPreference = 'Stop'
$outputFull = [IO.Path]::GetFullPath($OutputDirectory)
if (-not (Test-Path -LiteralPath $outputFull)) { [void](New-Item -ItemType Directory -Path $outputFull) }
& (Join-Path $PSScriptRoot 'Collect-WindowsNetwork.ps1') -OutputPath (Join-Path $outputFull 'windows-network.json')
$pythonExe = $null
$prefix = @()
foreach ($candidate in @('python','python3','py')) {
    $command = Get-Command $candidate -ErrorAction SilentlyContinue
    if (-not $command) { continue }
    # Skip Microsoft Store aliases; never launch an installer.
    if ($command.Source -match '\\Microsoft\\WindowsApps\\') { continue }
    $testPrefix = @()
    if ($candidate -eq 'py') { $testPrefix = @('-3') }
    try {
        & $command.Source @testPrefix -B -c 'import sys; sys.exit(0 if sys.version_info >= (3,9) else 1)' 2>$null
        if ($LASTEXITCODE -eq 0) { $pythonExe=$command.Source; $prefix=$testPrefix; break }
    } catch { }
}
if (-not $pythonExe) {
    Write-Output 'Windows report saved. Python 3.9+ unavailable; ask source Codex to locate its existing Python runtime. Do not treat Clash scan as complete.'
    exit 2
}
$arguments = @('-B', (Join-Path $PSScriptRoot 'collect_clash.py'), '--output', (Join-Path $outputFull 'clash-policy.json'), '--windows-report', (Join-Path $outputFull 'windows-network.json'))
if ($ConfigRoot) { $arguments += @('--config-root', $ConfigRoot) }
& $pythonExe @prefix @arguments
if ($LASTEXITCODE -ne 0) { Write-Output 'Clash scan incomplete. Inspect the non-sensitive status and correct the discovered config root.'; exit 3 }
Write-Output ('Read-only scan completed: ' + $outputFull)
Write-Output 'Source Codex must also complete browser/UI, actual log matching, configuration syntax and manual Claude usability checks described in README.md.'
