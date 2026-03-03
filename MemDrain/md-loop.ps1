# md-loop.ps1 (smooth launcher + optional responsiveness tweaks)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

# --- knobs ---
$IntervalMs      = 5000
$TimeoutMs       = 4500          # kill md.exe if it exceeds this (raise if you want it to finish more often)
$Priority        = 'Idle'        # Idle (least hitch) or BelowNormal (more effect)
$PinToLastCore   = $true
$UseBgMode       = $true         # background mode lowers I/O priority

$workDir = $PSScriptRoot
$tool    = Join-Path $workDir 'md.exe'
if (-not (Test-Path $tool)) { throw "md.exe not found at: $tool" }

# Win32 background mode flag
Add-Type -Namespace Win32 -Name Native -MemberDefinition @"
using System;
using System.Runtime.InteropServices;
public static class Native {
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool SetPriorityClass(IntPtr hProcess, uint dwPriorityClass);
  public const uint PROCESS_MODE_BACKGROUND_BEGIN = 0x00100000;
}
"@ | Out-Null

$cmd = $env:ComSpec
if (-not $cmd) { $cmd = "$env:windir\System32\cmd.exe" }

$psi = [System.Diagnostics.ProcessStartInfo]::new()
$psi.FileName = $cmd
$psi.WorkingDirectory = $workDir
$psi.UseShellExecute = $false
$psi.CreateNoWindow = $true

# /d disables AutoRun; redirect output to nul so no spam and no pipe-draining overhead
$quotedTool = '"' + $tool + '"'
$psi.Arguments = "/d /c $quotedTool -all 1>nul 2>nul"

function Start-MD {
    $p = [System.Diagnostics.Process]::new()
    $p.StartInfo = $psi
    if (-not $p.Start()) { return $null }

    try { $p.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::$Priority } catch {}

    if ($UseBgMode) {
        try { [Win32.Native]::SetPriorityClass($p.Handle, [Win32.Native]::PROCESS_MODE_BACKGROUND_BEGIN) | Out-Null } catch {}
    }

    if ($PinToLastCore) {
        try {
            $n = [Environment]::ProcessorCount
            if ($n -ge 2 -and $n -le 63) {
                $mask = [IntPtr](1L -shl ($n - 1))  # last core
                $p.ProcessorAffinity = $mask
            }
        } catch {}
    }

    return $p
}

$sw = [System.Diagnostics.Stopwatch]::StartNew()
$next = 0L

while ($true) {
    $next += $IntervalMs

    $p = $null
    try {
        $p = Start-MD
        if ($p) {
            if (-not $p.WaitForExit($TimeoutMs)) {
                try { $p.Kill() } catch {}
                try { $p.WaitForExit() | Out-Null } catch {}
            }
            $p.Close()
        }
    } catch {}

    $rem = $next - $sw.ElapsedMilliseconds
    if ($rem -gt 0) { Start-Sleep -Milliseconds $rem } else { $next = $sw.ElapsedMilliseconds }
}