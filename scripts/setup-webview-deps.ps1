$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$webviewCommit = "56598839c808a2340edee99204db479f410e9bf4"

Push-Location $projectRoot
try {
    Write-Host "Ensuring pinned WebView2 Go dependency is available..."
    go get "github.com/jchv/go-webview2@$webviewCommit"
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to download github.com/jchv/go-webview2. Internet access is required for the first source build."
    }
    go mod tidy
    if ($LASTEXITCODE -ne 0) { throw "go mod tidy failed" }
}
finally {
    Pop-Location
}
