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

# Start the Agent once in the foreground so configuration and enrollment errors
# reach the operator. Task Scheduler discards the process's stdout/stderr, and
# the Agent reports every startup failure there, so a failure under the task
# alone is undiagnosable. This is the Windows counterpart to the journalctl
# dump install.sh does. A successful run persists the agent identity in
# $dataDir, so the scheduled task below reuses it.
Write-Host "==> Verifying configuration and enrolling"
$outLog = Join-Path ([IO.Path]::GetTempPath()) "nettact-agent-preflight.out"
$errLog = Join-Path ([IO.Path]::GetTempPath()) "nettact-agent-preflight.err"
# The Agent persists its identity the moment enrollment succeeds, so that file
# appearing is a positive confirmation. "Still alive after N seconds" is not: the
# enrollment POST has its own 30s HTTP timeout (internal/enroll), so an Agent
# blocked against a black-holed server looks exactly like a healthy one until
# that timeout fires and it exits with the real error. The grace period below
# therefore has to outlast that timeout, and on a re-install (identity already on
# disk, so the Agent resumes instead of enrolling) surviving it is all we have.
$credentialFile = Join-Path $dataDir "agent.json"
$hadCredential = Test-Path $credentialFile
try {
    $preflight = Start-Process -FilePath $binary -ArgumentList "--config `"$configFile`"" `
        -NoNewWindow -PassThru -RedirectStandardOutput $outLog -RedirectStandardError $errLog
    $verified = $false
    $graceDeadline = (Get-Date).AddSeconds(45)
    while ((Get-Date) -lt $graceDeadline) {
        if ($preflight.HasExited) {
            break
        }
        if (-not $hadCredential -and (Test-Path $credentialFile)) {
            $verified = $true
            break
        }
        Start-Sleep -Milliseconds 250
    }
    if (-not $verified -and -not $preflight.HasExited) {
        $verified = $true
    }
    if (-not $verified) {
        Write-Host ""
        Write-Host "The Agent exited instead of staying up. Its output was:"
        $output = @(Get-Content $errLog, $outLog -ErrorAction SilentlyContinue)
        if ($output.Count -eq 0) {
            Write-Host "    (the Agent produced no output)"
        }
        foreach ($line in $output) {
            Write-Host "    $line"
        }
        throw "The Agent could not start. See its output above."
    }
    Stop-Process -Id $preflight.Id -Force -ErrorAction SilentlyContinue
    $preflight.WaitForExit(10000) | Out-Null
} finally {
    Remove-Item -Force -ErrorAction SilentlyContinue $outLog, $errLog
}

$taskName = "NetTact Agent"
$action = New-ScheduledTaskAction -Execute $binary -Argument "--config `"$configFile`""
$trigger = New-ScheduledTaskTrigger -AtStartup
$taskPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
# A monitoring agent must keep running on battery, so override both power
# defaults (New-ScheduledTaskSettingsSet sets them to $true).
$settings = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $taskPrincipal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName $taskName

# Start-ScheduledTask only queues the launch; the service starts the process out
# of band, and a cold first run of an unsigned binary can sit behind an
# antivirus scan for well over a second. Poll instead of assuming a fixed wait.
# One sighting is not enough either: the preflight above ran as the installing
# administrator, so a failure specific to the SYSTEM task context shows up as a
# process that appears and then dies. Require it to still be there after a short
# dwell, and keep polling if it is not — the task restarts on its own, and only
# never reaching a stable sighting is an install failure.
$deadline = (Get-Date).AddSeconds(60)
$dwellSeconds = 3
$running = $false
while ((Get-Date) -lt $deadline) {
    if (Get-Process -Name "nettact-agent" -ErrorAction SilentlyContinue) {
        Start-Sleep -Seconds $dwellSeconds
        if (Get-Process -Name "nettact-agent" -ErrorAction SilentlyContinue) {
            $running = $true
            break
        }
    }
    Start-Sleep -Milliseconds 500
}
if (-not $running) {
    $info = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction SilentlyContinue
    if ($info) {
        Write-Host ("Task '{0}' last result: 0x{1:X8} (last run {2})" -f $taskName, $info.LastTaskResult, $info.LastRunTime)
    }
    throw "The Agent started correctly in the foreground but did not stay running under Task Scheduler > '$taskName'."
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
