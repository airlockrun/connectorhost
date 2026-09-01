#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$BinaryPath = (Join-Path $PSScriptRoot "airlock-host.exe")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$resolvedBinary = (Resolve-Path -LiteralPath $BinaryPath -ErrorAction Stop).ProviderPath
if ([System.IO.Path]::GetExtension($resolvedBinary) -ne ".exe") {
    throw "BinaryPath must name an .exe file"
}

if (-not $PSCmdlet.ShouldProcess($resolvedBinary, "Install the AirlockHost Windows service")) {
    return
}

$statusOutput = & $resolvedBinary service status 2>$null
$statusExitCode = $LASTEXITCODE
if ($statusExitCode -ne 0) {
    throw "airlock-host service status failed with exit code $statusExitCode"
}
$wasInstalled = $statusOutput -notmatch '^not-installed'
$wasRunning = $statusOutput -match '^(running|start-pending)'

& $resolvedBinary service install | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "airlock-host service install failed with exit code $LASTEXITCODE"
}

$installedBinary = Join-Path $env:ProgramFiles "Airlock\airlock-host.exe"
if (-not $wasInstalled -or $wasRunning) {
    if ($wasRunning) {
        & $installedBinary service stop | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "airlock-host service stop failed with exit code $LASTEXITCODE"
        }
    }
    & $installedBinary service start | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "airlock-host service start failed with exit code $LASTEXITCODE"
    }
} else {
    Write-Host "The AirlockHost service was updated and remains stopped."
    Write-Host "Start it when ready:"
    Write-Host "  & `"$installedBinary`" service start"
    return
}

Write-Host "The AirlockHost service is installed and running."
Write-Host "Complete the explicit enrollment flow:"
Write-Host "  & `"$installedBinary`" enroll --airlock https://airlock.example"
