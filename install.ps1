# One-command native installer for the NetTact Agent on Windows.
[CmdletBinding()]
param(
    [string]$ServerUrl,
    [string]$Token,
    [string]$Version = "latest",
    [string]$DownloadBase = "https://d.nettact.org/agent",
    [switch]$AutoUpdate,
    [switch]$UpdateOnly
)

$ErrorActionPreference = "Stop"

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run PowerShell as Administrator, then run this command again."
}
if (-not [Environment]::Is64BitOperatingSystem) {
    throw "NetTact Agent currently requires 64-bit Windows."
}
if (-not $UpdateOnly) {
    if (-not $ServerUrl -or -not $Token) {
        throw "ServerUrl and Token are required."
    }
    if ($ServerUrl.Contains("`n") -or $ServerUrl.Contains("`r") -or
        $Token.Contains("`n") -or $Token.Contains("`r")) {
        throw "ServerUrl and Token must each be a single line."
    }
}
if ($AutoUpdate -and $Version -ne "latest") {
    throw "AutoUpdate cannot be combined with a pinned Version."
}

$installDir = Join-Path $env:ProgramFiles "NetTact"
$configDir = Join-Path $env:ProgramData "NetTact"
$dataDir = Join-Path $configDir "agent-data"
$binary = Join-Path $installDir "nettact-agent.exe"
$configFile = Join-Path $configDir "agent.yaml"
$tokenFile = Join-Path $configDir "enroll.token"
$asset = "nettact-agent-windows-amd64.exe"
if ($Version -eq "latest") {
    $downloadUrl = "$DownloadBase/$asset"
} else {
    $downloadUrl = "$DownloadBase/$Version/$asset"
}

New-Item -ItemType Directory -Force $installDir, $configDir, $dataDir | Out-Null
$tempBinary = Join-Path ([IO.Path]::GetTempPath()) ([IO.Path]::GetRandomFileName())
try {
    Write-Host "==> Downloading NetTact Agent for windows/amd64"
    Invoke-WebRequest -UseBasicParsing -Uri $downloadUrl -OutFile $tempBinary
    if ($UpdateOnly -and (Test-Path $binary)) {
        $currentHash = (Get-FileHash -Algorithm SHA256 $binary).Hash
        $newHash = (Get-FileHash -Algorithm SHA256 $tempBinary).Hash
        if ($currentHash -eq $newHash) {
            Write-Host "==> Agent is already up to date."
            return
        }
    }
    Stop-ScheduledTask -TaskName "NetTact Agent" -ErrorAction SilentlyContinue
    Get-Process -Name "nettact-agent" -ErrorAction SilentlyContinue | Stop-Process -Force
    Copy-Item -Force $tempBinary $binary
} finally {
    Remove-Item -Force -ErrorAction SilentlyContinue $tempBinary
}

if ($UpdateOnly) {
    Start-ScheduledTask -TaskName "NetTact Agent"
    Write-Host "==> Agent updated and restarted."
    return
}

$utf8NoBom = [Text.UTF8Encoding]::new($false)
[IO.File]::WriteAllText($tokenFile, $Token, $utf8NoBom)
$serverJson = ConvertTo-Json $ServerUrl -Compress
$dataJson = ConvertTo-Json $dataDir -Compress
$tokenJson = ConvertTo-Json $tokenFile -Compress
$config = "server_url: $serverJson`ndata_dir: $dataJson`nenroll_token_file: $tokenJson`n"
[IO.File]::WriteAllText($configFile, $config, $utf8NoBom)

# Restrict configuration, token and state to Administrators and SYSTEM.
& icacls.exe $configDir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Failed to secure $configDir"
}

$taskName = "NetTact Agent"
$action = New-ScheduledTaskAction -Execute $binary -Argument "--config `"$configFile`""
$trigger = New-ScheduledTaskTrigger -AtStartup
$taskPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero)
Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $taskPrincipal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName $taskName
Start-Sleep -Seconds 2

if (-not (Get-Process -Name "nettact-agent" -ErrorAction SilentlyContinue)) {
    throw "The Agent did not stay running. Check Task Scheduler > '$taskName' for the startup result."
}

if ($AutoUpdate) {
    $installer = Join-Path $installDir "install.ps1"
    Invoke-WebRequest -UseBasicParsing -Uri "$DownloadBase/install.ps1" -OutFile $installer
    $updateAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$installer`" -UpdateOnly"
    $updateTrigger = New-ScheduledTaskTrigger -Daily -At "3:00 AM"
    Register-ScheduledTask -TaskName "NetTact Agent Update" -Action $updateAction -Trigger $updateTrigger -Principal $taskPrincipal -Settings $settings -Force | Out-Null
    Write-Host "==> Daily automatic updates enabled."
}

Write-Host "==> Agent installed and running. It should appear in the NetTact console within seconds."
