<#
.SYNOPSIS
    Shared helper: pick the repository's Python interpreter.

.DESCRIPTION
    Dot-source this file, then call Resolve-RepoPython. Resolution order:

      1. an explicit -Explicit path (a script's -Python parameter);
      2. $env:CYBERRESCUE_PYTHON;
      3. <repo>\.venv313\Scripts\python.exe  (the verified CyberRescue environment);
      4. <repo>\.venv\Scripts\python.exe     (original WarRoom layout).

    An explicit path or env value that does not exist is an error -- it is never
    silently replaced by a different interpreter. Returns a pscustomobject with
    Path and Source so callers can print which interpreter (and why) they use.
#>

function Resolve-RepoPython {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Repo,
        [string]$Explicit = ""
    )
    if ($Explicit) {
        if (-not (Test-Path -LiteralPath $Explicit -PathType Leaf)) {
            throw "Python not found at -Python '$Explicit'."
        }
        return [pscustomobject]@{ Path = (Resolve-Path -LiteralPath $Explicit).Path; Source = "-Python parameter" }
    }
    if ($env:CYBERRESCUE_PYTHON) {
        if (-not (Test-Path -LiteralPath $env:CYBERRESCUE_PYTHON -PathType Leaf)) {
            throw "Python not found at CYBERRESCUE_PYTHON='$($env:CYBERRESCUE_PYTHON)'."
        }
        return [pscustomobject]@{ Path = (Resolve-Path -LiteralPath $env:CYBERRESCUE_PYTHON).Path; Source = "CYBERRESCUE_PYTHON" }
    }
    foreach ($venv in @(".venv313", ".venv")) {
        $candidate = Join-Path $Repo "$venv\Scripts\python.exe"
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return [pscustomobject]@{ Path = $candidate; Source = $venv }
        }
    }
    throw "No repository Python found (looked for .venv313 and .venv under $Repo). " +
          "Create one, or pass -Python / set CYBERRESCUE_PYTHON."
}
