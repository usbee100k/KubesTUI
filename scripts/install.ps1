# Install KubesTUI on Windows (current user, no admin rights needed).
#
#   irm https://raw.githubusercontent.com/usbee100k/KubesTUI/main/scripts/install.ps1 | iex
#
# A homelabCD bootstrap node serves this same script on your LAN
# ("Share KubesTUI with a Workstation"), with the download address below
# pointing at the node instead of GitHub.

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'   # much faster Invoke-WebRequest

$base = if ($env:KUBESTUI_BASE) { $env:KUBESTUI_BASE } else { 'https://github.com/usbee100k/KubesTUI/releases/latest/download' }

$arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'amd64' }
$name = "kubestui-windows-$arch.exe"
$dir  = Join-Path $env:LOCALAPPDATA 'KubesTUI'
$exe  = Join-Path $dir 'kubestui.exe'
$tmp  = "$exe.download"

New-Item -ItemType Directory -Force -Path $dir | Out-Null

Write-Host "Downloading $name from $base ..."
Invoke-WebRequest -UseBasicParsing -Uri "$base/$name" -OutFile $tmp

# Verify the checksum before installing.
$sums = (Invoke-WebRequest -UseBasicParsing -Uri "$base/SHA256SUMS").Content
if ($sums -is [byte[]]) { $sums = [Text.Encoding]::UTF8.GetString($sums) }
$want = $null
foreach ($line in ($sums -split "`n")) {
    $parts = $line.Trim() -split '\s+'
    if ($parts.Count -ge 2 -and $parts[1].TrimStart('*') -eq $name) { $want = $parts[0].ToLower() }
}
$got = (Get-FileHash -Algorithm SHA256 -Path $tmp).Hash.ToLower()
if (-not $want -or $want -ne $got) {
    Remove-Item -Force $tmp
    throw "Checksum mismatch for $name (expected $want, got $got). Nothing was installed."
}

Move-Item -Force $tmp $exe
Write-Host "Checksum OK. Installed $exe"

# Put it on the user's PATH (new terminals pick it up).
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if (-not (($userPath -split ';') -contains $dir)) {
    [Environment]::SetEnvironmentVariable('Path', ($userPath.TrimEnd(';') + ";$dir"), 'User')
    Write-Host "Added $dir to your PATH."
}
if (-not (($env:Path -split ';') -contains $dir)) { $env:Path += ";$dir" }

Write-Host ""
Write-Host "Done. Run:  kubestui"
Write-Host "Then choose 'Connect a new cluster' and enter a control plane's IP."
