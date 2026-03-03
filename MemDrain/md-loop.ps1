# md-loop.ps1
# Runs md.exe -all from this script's folder every 5 seconds
# - no console spam (stdout/stderr redirected to nul)
# - avoids runspace crash (no async output handlers)
# - optional timeout + idle priority to reduce hitching

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

$IntervalMs = 5000
$TimeoutMs  = 4000   # kill md.exe if it runs longer than this
$workDir    = $PSScriptRoot
$tool       = Join-Path $workDir 'md.exe'

if (-not (Test-Path $tool)) { throw "md.exe not found at: $tool" }

$cmd = $env:ComSpec
if (-not $cmd) { $cmd = "$env:windir\System32\cmd.exe" }

# Build once
$psi = [System.Diagnostics.ProcessStartInfo]::new()
$psi.FileName = $cmd
$psi.WorkingDirectory = $workDir
$psi.UseShellExecute = $false
$psi.CreateNoWindow = $true

# /d disables AutoRun to reduce surprises on stripped systems
$quotedTool = '"' + $tool + '"'
$psi.Arguments = "/d /c $quotedTool -all 1>nul 2>nul"

function Run-MDOnce {
    $p = [System.Diagnostics.Process]::new()
    $p.StartInfo = $psi
    if (-not $p.Start()) { return }

    try { $p.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::Idle } catch {}

    if (-not $p.WaitForExit($TimeoutMs)) {
        try { $p.Kill() } catch {}
        try { $p.WaitForExit() | Out-Null } catch {}
    }
    $p.Close()
}

$sw = [System.Diagnostics.Stopwatch]::StartNew()
$next = 0L

while ($true) {
    $next += $IntervalMs
    try { Run-MDOnce } catch {}

    $rem = $next - $sw.ElapsedMilliseconds
    if ($rem -gt 0) { Start-Sleep -Milliseconds $rem }
    else { $next = $sw.ElapsedMilliseconds }
}