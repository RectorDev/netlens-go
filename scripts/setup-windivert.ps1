$ErrorActionPreference = "Stop"
$version = "2.2.2"
$projectRoot = Split-Path -Parent $PSScriptRoot
$zip = Join-Path $env:TEMP "WinDivert-$version.zip"
$url = "https://github.com/basil00/WinDivert/releases/download/v$version/WinDivert-$version-A.zip"
$tmp = Join-Path $env:TEMP "NetLens-WinDivert"

Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "Downloading official WinDivert $version runtime..."
Invoke-WebRequest -Uri $url -OutFile $zip
Expand-Archive -Path $zip -DestinationPath $tmp -Force

$src = Join-Path $tmp "WinDivert-$version-A\x64"
Copy-Item (Join-Path $src "WinDivert.dll") -Destination (Join-Path $projectRoot "WinDivert.dll") -Force
Copy-Item (Join-Path $src "WinDivert64.sys") -Destination (Join-Path $projectRoot "WinDivert64.sys") -Force
Write-Host "WinDivert.dll and WinDivert64.sys copied to $projectRoot"
