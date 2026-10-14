<#
.SYNOPSIS
    WarRoom preflight: launch all four agents, then verify all four are
    listening before you fire an incident.

.DESCRIPTION
    The agents log to stdout only, so this script owns the redirection: it
    clears each agent's stale .log, launches the four mains from the repo venv
    (.venv313, else .venv -- see -Python), and
    polls the fresh logs for the "running Band agent loop" line. It will not
    give the green light until every agent has reached its Band loop without
    crashing -- so you never fire into a half-empty room again.

    Readiness for an agent = its process is alive AND its log shows
    "running Band agent loop" AND no Traceback / [ERROR] / [CRITICAL] appeared.
    "Ready" means the agent is up and listening for @mentions.

.PARAMETER Headless
    Run the four agents as hidden background processes (logs to file only),
    instead of opening four visible terminal windows.

.PARAMETER Check
    Don't launch anything -- just run the readiness scan against the current
    logs/PIDs and print the status table. This is the "are all 4 connected?"
    one-liner. Exit code 0 if all ready, 1 otherwise.

.PARAMETER Stop
    Stop all agents started by a previous run (kills the recorded process trees).

.PARAMETER Force
    Launch even if a previous run's PID file still has live processes (stops
    them first).

.PARAMETER TimeoutSec
    How long to wait for all four to become ready. Default 90.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\run_all.ps1
        Opens four agent windows, waits, prints the green light + fire command.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\run_all.ps1 -Check
        Just answer "are all 4 connected?" against the running set.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\run_all.ps1 -Stop
#>
[CmdletBinding()]
param(
    [switch]$Headless,
    [switch]$Check,
    [switch]$Stop,
    [switch]$Force,
    [int]$TimeoutSec = 90,
    # Override the Commander's model for this run. The Commander defaults to the
    # cheap claude-haiku-4-5, which is flaky at the action-execution phase (it can
    # loop on sign-offs instead of calling its action tools). Pass
    # -CommanderModel claude-sonnet-4-6 for a decisive, hands-off execution at
    # higher cost. Sets COMMANDER_MODEL for the launched Commander process.
    [string]$CommanderModel = "",
    # Override Triage's model for this run. Triage's context is tiny (just the
    # alert), so a stronger model here is cheap and reliably completes the
    # multi-step setup (create one room, add everyone, brief). Pass
    # -TriageModel claude-sonnet-4-6. Sets TRIAGE_MODEL for the Triage process.
    [string]$TriageModel = "",
    # CyberRescue: interpreter to launch the agents with. Default resolution is
    # -Python, then $env:CYBERRESCUE_PYTHON, then .venv313 (the verified env),
    # then .venv (original WarRoom layout) -- see scripts\Resolve-RepoPython.ps1.
    [string]$Python = "",
    # CyberRescue: skip the offline preflight (python -m cyberrescue.live
    # preflight) that otherwise must pass before anything is launched.
    [switch]$SkipPreflight,
    # CyberRescue: by default, if any agent FAILS during startup every agent this
    # run launched is stopped (no half-started room). Pass to leave them up.
    [switch]$KeepOnFailure
)

$ErrorActionPreference = "Stop"

# --- paths ---------------------------------------------------------------
$Repo    = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$PidFile = Join-Path $Repo ".run_all.pids"
. (Join-Path $PSScriptRoot "Resolve-RepoPython.ps1")
$PythonExe = $null   # resolved only when launching (-Stop / -Check never need it)

# name -> module ; order = recruitment order (Triage first, Commander last)
$Agents = [ordered]@{
    "triage"       = "agents.triage.main"
    "threat_intel" = "agents.threat_intel.main"
    "compliance"   = "agents.compliance.main"
    "commander"    = "agents.commander.main"
}

$ReadySignal = "running Band agent loop"
$FaultMarkers = @("Traceback (most recent call last)", "[CRITICAL]", "[ERROR]")

function LogPath([string]$name) { Join-Path $Repo "$name.log" }

# --- PID file helpers ----------------------------------------------------
function Read-Pids {
    $map = @{}
    if (Test-Path $PidFile) {
        foreach ($line in Get-Content $PidFile) {
            if ($line -match '^\s*(\w+)\s*=\s*(\d+)\s*$') { $map[$Matches[1]] = [int]$Matches[2] }
        }
    }
    return $map
}

function Write-Pids([hashtable]$map) {
    $lines = foreach ($k in $map.Keys) { "$k=$($map[$k])" }
    Set-Content -Path $PidFile -Value $lines -Encoding ascii
}

function Test-Alive([int]$procId) {
    if (-not $procId) { return $false }
    try { $null = Get-Process -Id $procId -ErrorAction Stop; return $true }
    catch { return $false }
}

# --- stop ----------------------------------------------------------------
function Stop-All {
    $map = Read-Pids
    if ($map.Count -eq 0) { Write-Host "[run_all] no recorded agents to stop." -ForegroundColor Yellow; return }
    foreach ($name in $map.Keys) {
        $procId = $map[$name]
        if (Test-Alive $procId) {
            # /T kills the child python under a launched powershell window too.
            & taskkill /PID $procId /T /F *> $null
            Write-Host "[run_all] stopped $name (pid $procId)" -ForegroundColor DarkGray
        }
    }
    Remove-Item $PidFile -ErrorAction SilentlyContinue
    Write-Host "[run_all] all agents stopped." -ForegroundColor Green
}

# --- readiness scan ------------------------------------------------------
function Get-AgentStatus([string]$name, [int]$procId) {
    $log = LogPath $name
    $alive = Test-Alive $procId
    $text = ""
    if (Test-Path $log) { $text = Get-Content $log -Raw -ErrorAction SilentlyContinue }
    if ($null -eq $text) { $text = "" }

    $fault = $false
    foreach ($m in $FaultMarkers) { if ($text.Contains($m)) { $fault = $true; break } }
    $reachedLoop = $text.Contains($ReadySignal)

    # FAILED only makes sense for an agent THIS run launched (has a PID): it
    # started and then crashed/faulted. With no recorded PID it's simply DOWN.
    $launched = ($procId -ne 0)
    if ($launched -and ($fault -or (-not $alive))) { $state = "FAILED" }
    elseif ($alive -and $reachedLoop)              { $state = "READY" }
    elseif ($alive)                                { $state = "STARTING" }
    else                                           { $state = "DOWN" }

    [pscustomobject]@{ Agent = $name; Pid = $procId; State = $state }
}

function Show-Status([object[]]$rows) {
    Write-Host ""
    Write-Host ("  {0,-14} {1,-8} {2}" -f "AGENT", "PID", "STATE")
    Write-Host ("  {0,-14} {1,-8} {2}" -f "-----", "---", "-----")
    foreach ($r in $rows) {
        $color = switch ($r.State) {
            "READY"    { "Green" }
            "STARTING" { "Yellow" }
            "FAILED"   { "Red" }
            default    { "DarkGray" }
        }
        Write-Host ("  {0,-14} {1,-8} {2}" -f $r.Agent, $r.Pid, $r.State) -ForegroundColor $color
    }
    Write-Host ""
}

function Invoke-Check {
    $map = Read-Pids
    $rows = foreach ($name in $Agents.Keys) {
        $procId = 0; if ($map.ContainsKey($name)) { $procId = $map[$name] }
        Get-AgentStatus $name $procId
    }
    Show-Status $rows
    $notReady = @($rows | Where-Object { $_.State -ne "READY" })
    if ($notReady.Count -eq 0) {
        Write-Host "[run_all] All 4 connected and listening." -ForegroundColor Green
        return $true
    }
    Write-Host "[run_all] Not all agents are ready (see table)." -ForegroundColor Yellow
    foreach ($r in ($notReady | Where-Object { $_.State -eq "FAILED" })) {
        $log = LogPath $r.Agent
        Write-Host "  --- last lines of $($r.Agent).log ---" -ForegroundColor DarkGray
        if (Test-Path $log) { Get-Content $log -Tail 6 | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray } }
    }
    return $false
}

# --- launch --------------------------------------------------------------
function Start-All {
    $resolved = Resolve-RepoPython -Repo $Repo -Explicit $Python
    $script:PythonExe = $resolved.Path
    Write-Host "[run_all] python: $PythonExe (from $($resolved.Source))" -ForegroundColor Cyan

    # CyberRescue: offline preflight (no network / LLM calls). Launch nothing
    # unless every check passes -- a missing key or placeholder UUID would
    # otherwise surface as one crashed agent in a half-started room.
    if (-not $SkipPreflight) {
        Write-Host "[run_all] preflight: $PythonExe -m cyberrescue.live preflight" -ForegroundColor Cyan
        & $PythonExe -m cyberrescue.live preflight
        if ($LASTEXITCODE -ne 0) {
            throw "preflight failed (exit $LASTEXITCODE) -- nothing was launched. Fix the FAIL lines above, or pass -SkipPreflight."
        }
    }

    # Per-run Commander model override (e.g. claude-sonnet-4-6 for decisive
    # execution). Child processes inherit this env var from Start-Process.
    if ($CommanderModel) {
        $env:COMMANDER_MODEL = $CommanderModel
        Write-Host "[run_all] Commander model override: $CommanderModel" -ForegroundColor Cyan
    }
    if ($TriageModel) {
        $env:TRIAGE_MODEL = $TriageModel
        Write-Host "[run_all] Triage model override: $TriageModel" -ForegroundColor Cyan
    }

    $existing = Read-Pids
    $liveLeft = @($existing.Keys | Where-Object { Test-Alive $existing[$_] })
    if ($liveLeft.Count -gt 0) {
        if ($Force) { Stop-All }
        else { throw "A previous run is still alive ($($liveLeft -join ', ')). Re-run with -Stop, or -Force to relaunch." }
    }

    $map = @{}
    foreach ($name in $Agents.Keys) {
        $module = $Agents[$name]
        $log = LogPath $name
        Set-Content -Path $log -Value "" -Encoding utf8   # clear stale log -> readiness scans this run only

        if ($Headless) {
            $err = "$log.err"
            $p = Start-Process -FilePath $PythonExe `
                -ArgumentList @("-u", "-m", $module) `
                -WorkingDirectory $Repo `
                -WindowStyle Hidden -PassThru `
                -RedirectStandardOutput $log `
                -RedirectStandardError $err
            $map[$name] = $p.Id
        }
        else {
            # Visible window per agent (the demo's four-framework-logs shot),
            # teeing each agent's output to console AND its .log file.
            $inner = "& '$PythonExe' -u -m $module 2>&1 | Tee-Object -FilePath '$log'"
            $p = Start-Process -FilePath "powershell" `
                -ArgumentList @("-NoExit", "-Command", $inner) `
                -WorkingDirectory $Repo -PassThru
            $map[$name] = $p.Id
        }
        Write-Host "[run_all] launched $name (pid $($map[$name]))" -ForegroundColor Cyan
    }
    Write-Pids $map
    return $map
}

# --- main ----------------------------------------------------------------
if ($Stop)  { Stop-All; exit 0 }
if ($Check) { if (Invoke-Check) { exit 0 } else { exit 1 } }

$null = Start-All

Write-Host ""
Write-Host "[run_all] waiting up to $TimeoutSec s for all four to start listening..." -ForegroundColor Cyan
$deadline = (Get-Date).AddSeconds($TimeoutSec)
$allReady = $false
while ((Get-Date) -lt $deadline) {
    $map = Read-Pids
    $rows = foreach ($name in $Agents.Keys) { Get-AgentStatus $name $map[$name] }
    if (@($rows | Where-Object { $_.State -eq "FAILED" }).Count -gt 0) { break }
    if (@($rows | Where-Object { $_.State -ne "READY" }).Count -eq 0) { $allReady = $true; break }
    Start-Sleep -Milliseconds 1500
}

$ok = Invoke-Check
if ($ok) {
    Write-Host "[run_all] GREEN LIGHT. Fire the incident with:" -ForegroundColor Green
    Write-Host "    & '$PythonExe' -m injector.inject_alert INC-C" -ForegroundColor Green
    Write-Host "  (or paste the alert into the room, @-picking Triage)." -ForegroundColor DarkGray
    exit 0
}
else {
    # CyberRescue: safe partial shutdown. A crashed agent means the room would
    # run with a missing participant, so stop every agent this run launched.
    $map = Read-Pids
    $rows = foreach ($name in $Agents.Keys) { Get-AgentStatus $name $map[$name] }
    $failed = @($rows | Where-Object { $_.State -eq "FAILED" })
    if ($failed.Count -gt 0 -and -not $KeepOnFailure) {
        Write-Host "[run_all] $($failed.Count) agent(s) FAILED -- stopping all launched agents (logs kept; -KeepOnFailure to leave them up)." -ForegroundColor Red
        Stop-All
    }
    Write-Host "[run_all] Do NOT fire yet -- fix the agents above, or re-check with:" -ForegroundColor Yellow
    Write-Host "    powershell -ExecutionPolicy Bypass -File scripts\run_all.ps1 -Check" -ForegroundColor Yellow
    exit 1
}
