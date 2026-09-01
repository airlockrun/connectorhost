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

& $resolvedBinary service install
if ($LASTEXITCODE -ne 0) {
    throw "airlock-host service install failed with exit code $LASTEXITCODE"
}

$installedBinary = Join-Path $env:ProgramFiles "Airlock\airlock-host.exe"
Write-Host "The AirlockHost service is installed but not started."
Write-Host "Complete the explicit enrollment flow:"
Write-Host "  & `"$installedBinary`" service start"
Write-Host "  & `"$installedBinary`" service enroll --airlock https://airlock.example"
