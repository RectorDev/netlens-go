$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
Push-Location $projectRoot
try {
    & "$PSScriptRoot\setup-windivert.ps1"
    & "$PSScriptRoot\setup-webview-deps.ps1"

    go test ./...
    if ($LASTEXITCODE -ne 0) { throw "go test failed" }
    go vet ./...
    if ($LASTEXITCODE -ne 0) { throw "go vet failed" }

    $env:GOOS = "windows"
    $env:GOARCH = "amd64"
    $env:CGO_ENABLED = "0"

    go build -trimpath -ldflags="-s -w" -o netlens.exe ./cmd/netlens
    if ($LASTEXITCODE -ne 0) { throw "console build failed" }
    go build -trimpath -ldflags="-s -w -H windowsgui" -o netlens-gui.exe ./cmd/netlens
    if ($LASTEXITCODE -ne 0) { throw "GUI build failed" }

    Write-Host "Built:"
    Write-Host "  $projectRoot\netlens.exe      (console/debug build)"
    Write-Host "  $projectRoot\netlens-gui.exe  (desktop build)"
    Write-Host "Keep WinDivert.dll and WinDivert64.sys beside the executable."
    Write-Host "Run PowerShell as Administrator, then .\scripts\setup-and-start.ps1"
}
finally {
    Pop-Location
}
