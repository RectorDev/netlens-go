$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "NetLens capture needs Administrator privileges. Re-open PowerShell as Administrator and run this script again."
}

Push-Location $projectRoot
try {
    if (-not (Test-Path ".\WinDivert.dll") -or -not (Test-Path ".\WinDivert64.sys")) {
        & "$PSScriptRoot\setup-windivert.ps1"
    }

    $exe = if (Test-Path ".\netlens-gui.exe") { ".\netlens-gui.exe" } elseif (Test-Path ".\netlens.exe") { ".\netlens.exe" } else { $null }
    if (-not $exe) {
        throw "No NetLens executable was found in $projectRoot. Run .\scripts\build-windows.ps1 first."
    }

    Write-Host "Starting NetLens desktop inspector..."
    Write-Host "HTTPS CA trust is now managed from Settings inside the NetLens UI."
    Start-Process -FilePath (Join-Path $projectRoot $exe.TrimStart('.\')) -WorkingDirectory $projectRoot
}
finally {
    Pop-Location
}
