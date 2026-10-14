<#
.SYNOPSIS
    CyberRescue-AI OFFLINE demo: detection -> investigation -> response plan ->
    Core authorization -> SIMULATED execution -> audit verification + anchoring.

.DESCRIPTION
    Everything runs locally against a fresh SQLite Core in a NEW output folder
    outside the repository (default: %TEMP%\cyberrescue-ca3-demo-<timestamp>).
    No network, no LLM, no Band, no API keys. Data is the committed SYNTHETIC
    telemetry for scenario A (incident INC-C-2026-0042). Every response action
    is SIMULATED; nothing touches a real host.

    This demo does NOT show live LLM agent collaboration. For that, see
    docs\ca3\07-live-demo-runbook.md.

    Each step prints its real CLI output; the script stops at the first command
    whose exit code is not the expected one. Outputs written to the folder:
      transcript.txt   full console transcript of this run
      case.html        investigation case (static HTML)
      plan.json/.html  advisory response plan
      execution.json   simulated execution report (recorded in the Core)
      anchor\*.json    signed checkpoint of all audit chain heads
      key\anchor.key   demo-only anchor key (kept in a separate sub-folder)

.PARAMETER OutDir
    Output folder. Must not exist yet (a demo never overwrites earlier evidence).

.PARAMETER Pause
    Wait for Enter between steps (for presenting live).

.PARAMETER Python
    Interpreter to use (default: .venv313, then .venv; see Resolve-RepoPython.ps1).

.PARAMETER SkipEvaluation
    Skip step 0 (the ground-truth evaluation run).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\demo_offline.ps1
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\demo_offline.ps1 -Pause
#>
[CmdletBinding()]
param(
    [string]$OutDir = "",
    [switch]$Pause,
    [string]$Python = "",
    [switch]$SkipEvaluation
)

$ErrorActionPreference = "Stop"
$Repo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
. (Join-Path $PSScriptRoot "Resolve-RepoPython.ps1")
$Py = Resolve-RepoPython -Repo $Repo -Explicit $Python

if (-not $OutDir) {
    $OutDir = Join-Path $env:TEMP ("cyberrescue-ca3-demo-" + (Get-Date -Format "yyyyMMdd-HHmmss"))
}
if (Test-Path -LiteralPath $OutDir) { throw "OutDir '$OutDir' already exists; choose a new folder." }
$full = [System.IO.Path]::GetFullPath($OutDir)
if ($full.StartsWith($Repo, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "OutDir must be outside the repository (demo databases and keys never go in Git)."
}
New-Item -ItemType Directory -Path $full | Out-Null
New-Item -ItemType Directory -Path (Join-Path $full "key") | Out-Null
New-Item -ItemType Directory -Path (Join-Path $full "anchor") | Out-Null
$OutDir = $full
$Transcript = Join-Path $OutDir "transcript.txt"

# Isolate this run: its own Core DB and gate log; never the repo default.
$env:CYBERRESCUE_DB_PATH = Join-Path $OutDir "demo.db"
$env:CYBERRESCUE_GATE_LOG = Join-Path $OutDir "gate_log.jsonl"
$env:PYTHONIOENCODING = "utf-8"
Remove-Item Env:CYBERRESCUE_ANCHOR_KEY_FILE -ErrorAction SilentlyContinue

function Say([string]$text, [string]$color = "Gray") {
    Write-Host $text -ForegroundColor $color
    Add-Content -LiteralPath $Transcript -Value $text -Encoding utf8
}

function Step([string]$title) {
    if ($Pause) { Write-Host ""; Read-Host "  [Enter] for: $title" | Out-Null }
    Say ""
    Say ("=" * 78) "DarkCyan"
    Say "  $title" "Cyan"
    Say ("=" * 78) "DarkCyan"
}

# Run the repo Python with args; echo + transcript the output; check exit code.
function Py {
    param([string[]]$PyArgs, [int[]]$Expect = @(0), [switch]$Quiet)
    Say ("PS> python " + ($PyArgs -join " ")) "Yellow"
    $old = $ErrorActionPreference; $ErrorActionPreference = "Continue"
    $out = & $Py.Path @PyArgs 2>&1 | ForEach-Object { "$_" }
    $code = $LASTEXITCODE
    $ErrorActionPreference = $old
    foreach ($line in $out) {
        Add-Content -LiteralPath $Transcript -Value $line -Encoding utf8
        if (-not $Quiet) { Write-Host $line }
    }
    Say "  (exit code $code)" "DarkGray"
    if ($Expect -notcontains $code) {
        Say "[demo] UNEXPECTED exit code $code (expected $($Expect -join '/')). Stopping." "Red"
        exit 1
    }
    return ,$out
}

function ActorId([string[]]$out) {
    foreach ($l in $out) { if ($l -match '^\[core\] actor ([0-9a-f]{32})') { return $Matches[1] } }
    throw "could not parse actor id from: $out"
}

Say "CyberRescue-AI offline demo  --  OFFLINE / SYNTHETIC DATA / SIMULATED ACTIONS" "Green"
Say "  started:   $((Get-Date).ToString('o'))"
Say "  python:    $($Py.Path)  (from $($Py.Source))"
Say "  git:       $(git -C $Repo rev-parse --short HEAD 2>$null)"
Say "  output:    $OutDir"
Say "  NOTE: no LLM, no Band, no network. This does not demonstrate live agent collaboration."

if (-not $SkipEvaluation) {
    Step "0. Ground-truth evaluation (whole pipeline in a throw-away Core)"
    Py @("-m", "cyberrescue.evaluation", "run", "--scenario", "A", "--investigation",
         "--response", "--execution", "--accountability") | Out-Null
}

Step "1. Core database, asset inventory, incident INC-C (from the mock alert)"
Py @("-m", "cyberrescue.core", "init") | Out-Null
Py @("-m", "cyberrescue.core", "seed-assets") | Out-Null
Py @("-m", "cyberrescue.telemetry", "open-incident", "--scenario", "A") | Out-Null

Step "2. Ingest synthetic telemetry as hashed evidence"
$collector = ActorId (Py @("-m", "cyberrescue.core", "register-actor", "--kind", "system",
                             "--role", "collector", "--name", "synthetic collector"))
Py @("-m", "cyberrescue.telemetry", "ingest", "--scenario", "A", "--collector", $collector) | Out-Null

Step "3. Deterministic DETECTION + correlation (findings persisted to the Core)"
$detector = ActorId (Py @("-m", "cyberrescue.core", "register-actor", "--kind", "system",
                            "--role", "detector", "--name", "detection engine"))
Py @("-m", "cyberrescue.detection", "run", "--incident", "INC-C", "--persist",
     "--detector", $detector) | Out-Null

Step "4. INVESTIGATION (read-only): scope, gaps, case export"
Py @("-m", "cyberrescue.investigation", "scope", "--incident", "INC-C") | Out-Null
Py @("-m", "cyberrescue.investigation", "gaps", "--incident", "INC-C") | Out-Null
Py @("-m", "cyberrescue.investigation", "case", "--incident", "INC-C", "--format", "html",
     "--out", (Join-Path $OutDir "case.html")) | Out-Null

Step "5. RESPONSE PLAN (advisory: proposes steps, requests nothing)"
$planJson = Join-Path $OutDir "plan.json"
Py @("-m", "cyberrescue.response", "plan", "--incident", "INC-C", "--format", "json",
     "--out", $planJson) | Out-Null
Py @("-m", "cyberrescue.response", "plan", "--incident", "INC-C", "--format", "html",
     "--out", (Join-Path $OutDir "plan.html")) | Out-Null
$plan = Get-Content -LiteralPath $planJson -Raw -Encoding utf8 | ConvertFrom-Json
Say ("  plan {0}: {1} steps, {2} human decision points" -f $plan.plan_id, $plan.steps.Count,
     $plan.decision_points.Count) "Green"
foreach ($s in $plan.steps) {
    $unmet = if ($s.preview.unmet_rules) { $s.preview.unmet_rules -join "," } else { "-" }
    Say ("    {0}  {1,-20} {2,-28} preview={3} unmet={4}" -f $s.step_id, $s.action,
         ("{0}:{1}" -f $s.target.kind, $s.target.value), $s.preview.outcome_if_requested, $unmet)
}
foreach ($d in $plan.decision_points) {
    Say ("    DECISION  {0,-20} -> human decision; never executed by the system" -f $d.action)
}

Step "6. CORE AUTHORIZATION: Commander requests every step; the policy engine decides"
$commander = ActorId (Py @("-m", "cyberrescue.core", "register-actor", "--kind", "agent",
                             "--role", "commander", "--name", "Commander (offline demo)"))
$ciso = ActorId (Py @("-m", "cyberrescue.core", "register-actor", "--kind", "human",
                        "--role", "ciso", "--name", "Demo CISO (operator)"))

# `core request` exits 0 for every recorded decision; the outcome is in its
# first line ("[core] ALLOW|REQUIRE_APPROVAL|DENY: ..."), so assert on that.
function Assert-Outcome([string[]]$out, [string[]]$allowed) {
    $outcome = $null
    foreach ($l in $out) {
        if ($l -match '^\[core\] (ALLOW|REQUIRE_APPROVAL|DENY):') { $outcome = $Matches[1]; break }
    }
    if (-not $outcome) { Say "[demo] no policy decision in output. Stopping." "Red"; exit 1 }
    if ($allowed -notcontains $outcome) {
        Say "[demo] UNEXPECTED policy outcome $outcome (expected $($allowed -join '/')). Stopping." "Red"
        exit 1
    }
}

function Request-Step($s, [string[]]$allowed) {
    $a = @("-m", "cyberrescue.core", "request", "--incident", "INC-C", "--action", $s.action,
           "--requester", $commander, "--plan-step", $s.step_id)
    if ($s.target.kind -eq "host") { $a += @("--asset", $s.target.value) }
    Assert-Outcome (Py $a) $allowed
}

Say "  6a. first pass -- no human approval yet; P5-flagged steps must NOT be allowed:" "Green"
foreach ($s in $plan.steps) {
    if ($s.preview.unmet_rules -contains "P5") { Request-Step $s @("REQUIRE_APPROVAL") }
    else { Request-Step $s @("ALLOW") }
}

Say "  6b. a tier-3 destructive action is refused (legal hold + tier-3 rule):" "Green"
Assert-Outcome (Py @("-m", "cyberrescue.core", "request", "--incident", "INC-C",
    "--action", "wipe_host", "--asset", "srv-db-01", "--requester", $commander)) @("REQUIRE_APPROVAL", "DENY")

Say "  6c. the CISO approves only the containment steps the policy flagged (P5):" "Green"
foreach ($s in $plan.steps) {
    if ($s.preview.unmet_rules -contains "P5") {
        Py @("-m", "cyberrescue.core", "approve", "--incident", "INC-C", "--action", $s.action,
             "--asset", $s.target.value, "--approver", $ciso,
             "--reason", "offline demo: CISO approves proposed containment") | Out-Null
    }
}
Say "  6d. Commander re-requests the steps that were still pending:" "Green"
foreach ($s in $plan.steps) {
    if ($s.preview.unmet_rules -contains "P5") { Request-Step $s @("ALLOW") }
}

Step "7. SIMULATED EXECUTION of authorized steps, recorded in the Core (SIMULATION ONLY)"
$executor = ActorId (Py @("-m", "cyberrescue.core", "register-actor", "--kind", "system",
                            "--role", "executor", "--name", "simulated executor"))
$report = Join-Path $OutDir "execution.json"
Py @("-m", "cyberrescue.execution", "simulate", "--plan", $planJson, "--record",
     "--recorder", $executor, "--format", "json", "--out", $report) | Out-Null
Py @("-m", "cyberrescue.execution", "verify", "--report", $report, "--plan", $planJson) | Out-Null
Py @("-m", "cyberrescue.core", "show", "--incident", "INC-C") | Out-Null

Step "8. AUDIT: verify hash chains, sign an external anchor, verify against it"
$key = Join-Path $OutDir "key\anchor.key"
$anchor = Join-Path $OutDir "anchor\checkpoint.json"
Py @("-m", "cyberrescue.core", "verify") | Out-Null
Py @("-m", "cyberrescue.core", "anchor-keygen", "--out", $key) | Out-Null
Py @("-m", "cyberrescue.core", "anchor", "--out", $anchor, "--key-file", $key) | Out-Null
Py @("-m", "cyberrescue.core", "verify", "--anchor", $anchor, "--key-file", $key) | Out-Null

Step "9. TAMPER TEST on a COPY of the database (the demo DB itself is untouched)"
$copy = Join-Path $OutDir "tampered-copy.db"
Copy-Item -LiteralPath $env:CYBERRESCUE_DB_PATH -Destination $copy
$tamper = @'
import sqlite3, sys
c = sqlite3.connect(sys.argv[1])
c.execute("DROP TRIGGER audit_events_no_update")
uid, = c.execute("SELECT uid FROM audit_events WHERE event_type='ACTION_EXECUTED' "
                 "ORDER BY seq LIMIT 1").fetchone()
c.execute("UPDATE audit_events SET payload = replace(payload, 'simulated', 'SIMULATED-EDIT') "
          "WHERE uid = ?", (uid,))
c.commit()
print(f"[tamper] edited payload of audit event {uid} directly in SQLite (attacker with file access)")
'@
$tamperPy = Join-Path $OutDir "tamper.py"
Set-Content -LiteralPath $tamperPy -Value $tamper -Encoding utf8
Py @($tamperPy, $copy) | Out-Null
Say "  expected: verify FAILS (exit 1) on the tampered copy" "Green"
Py @("-m", "cyberrescue.core", "--db", $copy, "verify") -Expect @(1) | Out-Null
Py @("-m", "cyberrescue.core", "--db", $copy, "verify", "--anchor", $anchor,
     "--key-file", $key) -Expect @(1) | Out-Null

Say ""
Say "[demo] COMPLETE -- every step returned its expected exit code." "Green"
Say "[demo] Evidence folder: $OutDir" "Green"
Say "[demo] Open: case.html, plan.html; transcript.txt holds the full console log." "Green"
exit 0
