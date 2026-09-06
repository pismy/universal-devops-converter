<#
.SYNOPSIS
    Install udc (universal-devops-converter) on Windows.

.DESCRIPTION
    Detects the architecture, resolves a release, downloads the matching
    archive, verifies its SHA-256 checksum and installs the binary.

.PARAMETER Version
    Release tag to install (e.g. v1.2.3). Defaults to the latest release.

.PARAMETER InstallDir
    Directory to install into. Defaults to $env:LOCALAPPDATA\Programs\udc.

.PARAMETER NoVerify
    Skip checksum verification (not recommended).

.EXAMPLE
    irm https://raw.githubusercontent.com/pismy/universal-devops-converter/main/install.ps1 | iex

.EXAMPLE
    .\install.ps1 -Version v1.2.3 -InstallDir C:\tools
#>
[CmdletBinding()]
param(
    [string]$Version = $(if ($env:UDC_VERSION) { $env:UDC_VERSION } else { 'latest' }),
    [string]$InstallDir = $env:UDC_INSTALL_DIR,
    [switch]$NoVerify
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Repo = 'pismy/universal-devops-converter'
$Bin = 'udc'

function Write-Step { param([string]$Message) Write-Host $Message -ForegroundColor Cyan }

# --- platform ---------------------------------------------------------------

$arch = switch ($env:PROCESSOR_ARCHITECTURE) {
    'AMD64' { 'amd64' }
    'ARM64' { 'arm64' }
    default { throw "Unsupported architecture '$($env:PROCESSOR_ARCHITECTURE)'." }
}
$archive = "$Bin-windows-$arch.zip"

# --- resolve the release ----------------------------------------------------

# TLS 1.2 is not the default on Windows PowerShell 5.1, and github.com refuses
# anything older.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

if ($Version -eq 'latest') {
    Write-Step "Resolving the latest release of $Repo..."
    $headers = @{ 'User-Agent' = 'udc-install' }
    if ($env:GITHUB_TOKEN) { $headers['Authorization'] = "Bearer $env:GITHUB_TOKEN" }
    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -Headers $headers
    $tag = $release.tag_name
    if (-not $tag) { throw "Could not resolve the latest release of $Repo." }
} else {
    $tag = $Version
}
Write-Step "Installing $Bin $tag (windows/$arch)"

$baseUrl = "https://github.com/$Repo/releases/download/$tag"

# --- install directory ------------------------------------------------------

if (-not $InstallDir) {
    $InstallDir = Join-Path $env:LOCALAPPDATA "Programs\$Bin"
}
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

# --- download, verify, unpack ----------------------------------------------

$temp = Join-Path ([IO.Path]::GetTempPath()) ([Guid]::NewGuid().ToString())
New-Item -ItemType Directory -Force -Path $temp | Out-Null
try {
    $archivePath = Join-Path $temp $archive
    Write-Step "Downloading $baseUrl/$archive"
    Invoke-WebRequest -Uri "$baseUrl/$archive" -OutFile $archivePath -UseBasicParsing

    if (-not $NoVerify) {
        $checksumPath = "$archivePath.sha256"
        try {
            Invoke-WebRequest -Uri "$baseUrl/$archive.sha256" -OutFile $checksumPath -UseBasicParsing
            $expected = ((Get-Content $checksumPath -Raw).Trim() -split '\s+')[0]
            $actual = (Get-FileHash -Path $archivePath -Algorithm SHA256).Hash.ToLower()
            if ($actual -ne $expected.ToLower()) {
                throw "Checksum mismatch (expected $expected, got $actual)."
            }
            Write-Step 'Checksum verified.'
        } catch [Net.WebException] {
            Write-Warning "No published checksum for $archive, skipping verification."
        }
    }

    Expand-Archive -Path $archivePath -DestinationPath $temp -Force
    $binary = Join-Path $temp "$Bin.exe"
    if (-not (Test-Path $binary)) { throw "$Bin.exe not found in $archive." }
    Copy-Item -Path $binary -Destination (Join-Path $InstallDir "$Bin.exe") -Force
} finally {
    Remove-Item -Recurse -Force $temp -ErrorAction SilentlyContinue
}

$installed = Join-Path $InstallDir "$Bin.exe"
Write-Step "Installed $installed"

# Persist the directory on the user's PATH when it is not already there.
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if ($userPath -notlike "*$InstallDir*") {
    [Environment]::SetEnvironmentVariable('Path', "$userPath;$InstallDir", 'User')
    Write-Warning "Added $InstallDir to your user PATH. Restart your shell to pick it up."
}

& $installed --version
