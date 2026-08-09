# One-command native installer for the NetTact Agent on Windows.
[CmdletBinding()]
param(
    [string]$ServerUrl,
    [string]$Token,
    [string]$Version = "latest",
    [string]$DownloadBase = "https://d.nettact.org/agent",
    # Comma-separated local permission policy, or the literal "none". This
    # REPLACES the Agent's built-in default set rather than adding to it; omit it
    # to keep the default. The NetTact console's Agent page generates a
    # ready-made value. Wildcards are not accepted.
    [string]$Permissions,
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
    # The console shows this command with a placeholder token until one is
    # generated, and it is copied and run in that state often enough to be worth
    # naming: enrollment would answer 401 several steps from here, after the
    # download, the service install and the identity wipe, and the machine would
    # be left with an agent that enrolls nowhere. Say what actually went wrong,
    # before anything on this host is touched.
    if ($Token -eq "<enrollment-token>") {
        throw "The -Token value is still the console's placeholder, so no enrollment token was ever generated. In the NetTact console open Agents -> Add agent, click 'Generate token', then copy this command again from that page."
    }
    if ($ServerUrl.Contains("`n") -or $ServerUrl.Contains("`r") -or
        $Token.Contains("`n") -or $Token.Contains("`r")) {
        throw "ServerUrl and Token must each be a single line."
    }
}
if ($AutoUpdate -and $Version -ne "latest") {
    throw "AutoUpdate cannot be combined with a pinned Version."
}

# Normalize and validate the permission policy up front: the Agent rejects an
# unsatisfiable policy at startup, and discovering that after the scheduled task
# is registered is a worse experience than failing here. Whitespace is stripped
# rather than rejected so a value pasted out of the console still works.
$permissionList = @()
$permissionsNone = $false
if ($Permissions) {
    $Permissions = ($Permissions -replace '\s', '')
    if (-not $Permissions) {
        throw 'Permissions needs a value (use "none" for an empty grant).'
    }
    if ($Permissions.Contains("*") -or $Permissions -ieq "all") {
        throw 'Permissions does not accept wildcards; list explicit permissions or "none".'
    }
    if ($Permissions -ieq "none") {
        $permissionsNone = $true
    } else {
        $permissionList = @($Permissions.Split(",") | Where-Object { $_ })
        # A value of only separators would emit a `permissions:` key with no
        # children, which the Agent reads as "not configured" and answers with the
        # full built-in DEFAULT grant — the opposite of the restriction that was
        # asked for, and silently.
        if ($permissionList.Count -eq 0) {
            throw 'Permissions lists no permissions; pass explicit ids or "none" for an empty grant.'
        }
    }
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

# A full install REPLACES any previous installation outright. The previous
# scheduled tasks go away (including the update task — if -AutoUpdate is not on
# this command line, the machine must not keep updating), and the Agent's
# identity and queued telemetry are wiped so it re-enrolls with the token passed
# HERE. Resuming the old identity would silently ignore that token, and a stale
# credential (agent deleted in the console, server moved) breaks startup in ways
# that look like network failures. The wipe is also what gives the verification
# below its positive signal: a full install always produces a fresh enrollment.
Unregister-ScheduledTask -TaskName "NetTact Agent" -Confirm:$false -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName "NetTact Agent Update" -Confirm:$false -ErrorAction SilentlyContinue
Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $installDir "install.ps1")
if (Test-Path $dataDir) {
    Remove-Item -Recurse -Force $dataDir
}
New-Item -ItemType Directory -Force $dataDir | Out-Null

$utf8NoBom = [Text.UTF8Encoding]::new($false)
[IO.File]::WriteAllText($tokenFile, $Token, $utf8NoBom)
$serverJson = ConvertTo-Json $ServerUrl -Compress
$dataJson = ConvertTo-Json $dataDir -Compress
$tokenJson = ConvertTo-Json $tokenFile -Compress
$config = "server_url: $serverJson`ndata_dir: $dataJson`nenroll_token_file: $tokenJson`n"
# Emit the permission policy as a YAML block list, or the literal `none` scalar
# for an empty grant. Omitting the key entirely (no -Permissions) leaves the Agent
# on its built-in default set — an empty list would instead mean "grant nothing",
# which is a very different install.
if ($permissionsNone) {
    $config += "permissions: none`n"
} elseif ($permissionList.Count -gt 0) {
    $config += "permissions:`n"
    foreach ($perm in $permissionList) {
        $config += "  - " + (ConvertTo-Json $perm -Compress) + "`n"
    }
}
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
# dump install.sh does.
#
# The data dir was wiped above, so this run always enrolls fresh — and the Agent
# persists its identity (agent.json) the moment enrollment succeeds, so that
# file appearing is positive proof the server was reachable and the token
# accepted. Nothing weaker counts as success: "still alive after N seconds"
# would pass an Agent stuck against an unreachable server. The deadline outlasts
# the enrollment POST's 30s HTTP timeout (internal/enroll), so a black-holed
# server surfaces as the Agent exiting with the real error, which is shown. A
# successful run leaves the identity in $dataDir for the scheduled task below.
Write-Host "==> Verifying server connectivity and enrolling"
$outLog = Join-Path ([IO.Path]::GetTempPath()) "nettact-agent-preflight.out"
$errLog = Join-Path ([IO.Path]::GetTempPath()) "nettact-agent-preflight.err"
$credentialFile = Join-Path $dataDir "agent.json"
try {
    $preflight = Start-Process -FilePath $binary -ArgumentList "--config `"$configFile`"" `
        -NoNewWindow -PassThru -RedirectStandardOutput $outLog -RedirectStandardError $errLog
    $enrolled = $false
    $deadline = (Get-Date).AddSeconds(60)
    while ((Get-Date) -lt $deadline) {
        if (Test-Path $credentialFile) {
            $enrolled = $true
            break
        }
        if ($preflight.HasExited) {
            break
        }
        Start-Sleep -Milliseconds 250
    }
    # agent.json is written non-atomically; give the write a moment to finish
    # before the writer is stopped, or the scheduled task could inherit a
    # truncated credential.
    if ($enrolled) {
        Start-Sleep -Seconds 1
    }
    # Stop it before reading the logs (releases the redirect handles); on
    # success the scheduled task below resumes from the saved identity.
    if (-not $preflight.HasExited) {
        Stop-Process -Id $preflight.Id -Force -ErrorAction SilentlyContinue
        $preflight.WaitForExit(10000) | Out-Null
    }
    if (-not $enrolled) {
        Write-Host ""
        Write-Host "INSTALL FAILED: the Agent could not enroll with $ServerUrl. Its output was:"
        $output = @(Get-Content $errLog, $outLog -ErrorAction SilentlyContinue)
        if ($output.Count -eq 0) {
            Write-Host "    (the Agent produced no output — is $ServerUrl reachable from this machine?)"
        }
        foreach ($line in $output) {
            Write-Host "    $line"
        }
        Write-Host "Nothing was left running. Fix the problem, then generate a token in the console (for a reinstall of this machine, open the Agent in the console and choose Reinstall) and run the install command again."
        throw "Installation failed: the Agent could not enroll. See its output above."
    }
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
    throw "INSTALL FAILED: the Agent enrolled correctly in the foreground but did not stay running under Task Scheduler > '$taskName'."
}

if ($AutoUpdate) {
    $installer = Join-Path $installDir "install.ps1"
    Invoke-WebRequest -UseBasicParsing -Uri "$DownloadBase/install.ps1" -OutFile $installer
    $updateAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$installer`" -UpdateOnly"
    $updateTrigger = New-ScheduledTaskTrigger -Daily -At "3:00 AM"
    Register-ScheduledTask -TaskName "NetTact Agent Update" -Action $updateAction -Trigger $updateTrigger -Principal $taskPrincipal -Settings $settings -Force | Out-Null
    Write-Host "==> Daily automatic updates enabled."
}

Write-Host "==> SUCCESS: Agent enrolled and running. It should appear in the NetTact console within seconds."
