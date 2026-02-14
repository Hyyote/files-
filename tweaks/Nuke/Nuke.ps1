#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Unified OS-Level Amputation Script
    Merges: DiagnosticRemoval + WER Stub Replacement + Task Manager Removal
            + .NET/WCF Feature Disable + Post-Boot Service Recovery

.DESCRIPTION
    Phase  1: Service Deletion (diagnostic, telemetry, per-user templates)
    Phase  2: Binary Removal (diagnostic hosts, PCA, SgrmBroker, CDP, perf tools, etc.)
    Phase  3: Scheduled Task Purge
    Phase  4: ETW Autologger Session Kill (expanded: EventLog sessions, PerfTrack, etc.)
    Phase  5: Event Log + ETW Infrastructure Nuke (WINEVT, Autologger, GlobalLogger)
    Phase  6: Per-User Service Template Neutering
    Phase  7: Compatibility Engine Cleanup
    Phase  8: Artifact Purge
    Phase  9: WER Registry Nuke
    Phase 10: WER Binary Removal + Stub DLL Deployment
    Phase 11: WER Kernel Driver Disable + Report Store Cleanup
    Phase 12: Task Manager Removal
    Phase 13: .NET / WCF / WAS Feature Disable (DISM, expanded)
    Phase 14: Tracing Infrastructure Registry Nuke (WPP, FTH, SQM, kernel perf)
    Phase 15: .NET / CLR Tracing Disable (ETW providers, NGEN, telemetry env vars)
    Phase 16: Performance Counter Cleanup
    Phase 17: Event Log File Purge (.evtx + ETL + system logs)
    Phase 18: Post-Boot Service Recovery (audiosrv + DHCP via service)

.NOTES
    - Run from an elevated PowerShell prompt or via the .bat launcher
    - Place compiled wer.dll (x64) and wer32.dll (x86) next to this script
    - Reboot required after execution
    - NO BACKUPS ARE CREATED. THIS IS IRREVERSIBLE.
#>

param(
    [string]$StubDllPath = "$PSScriptRoot\wer.dll",
    [string]$Stub32DllPath = "$PSScriptRoot\wer32.dll"
)

$ErrorActionPreference = "Continue"
Set-StrictMode -Version Latest

# ============================================================================
#  Logging
# ============================================================================

$LogFile = "$PSScriptRoot\nuke_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$timestamp] [$Level] $Message"
    Write-Host $entry -ForegroundColor $(switch ($Level) {
        "ERROR" { "Red" }
        "WARN"  { "Yellow" }
        "OK"    { "Green" }
        "PHASE" { "Cyan" }
        default { "White" }
    })
    Add-Content -Path $LogFile -Value $entry
}

# ============================================================================
#  Helpers
# ============================================================================

function Take-Ownership {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return $false }
    $null = cmd /c "takeown /f `"$Path`" >nul 2>&1"
    $null = cmd /c "icacls `"$Path`" /grant Administrators:F >nul 2>&1"
    $null = cmd /c "icacls `"$Path`" /grant SYSTEM:F >nul 2>&1"
    return $true
}

function Remove-Binary {
    param([string]$Path, [string]$Label)
    if (-not (Test-Path $Path)) {
        Write-Log "  [skip] $Label -- not found: $Path"
        return
    }

    Take-Ownership $Path | Out-Null

    try {
        $procName = [System.IO.Path]::GetFileNameWithoutExtension($Path)
        Get-Process -Name $procName -ErrorAction SilentlyContinue | ForEach-Object {
            Write-Log "  Killing $($_.Name) (PID $($_.Id))"
            Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
            Start-Sleep -Milliseconds 300
        }
        Remove-Item $Path -Force -ErrorAction Stop
        Write-Log "  [del] $Label -- $Path" "OK"
    } catch {
        $null = cmd /c "del /f /q `"$Path`" >nul 2>&1"
        if (Test-Path $Path) {
            $pendingKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
            $pending = @()
            $existingProps = Get-ItemProperty -Path $pendingKey -ErrorAction SilentlyContinue
            if ($existingProps -and ($existingProps.PSObject.Properties.Name -contains "PendingFileRenameOperations")) {
                $pending = @($existingProps.PendingFileRenameOperations)
            }
            $pending += "\??\$Path"
            $pending += ""
            Set-ItemProperty -Path $pendingKey -Name "PendingFileRenameOperations" -Value $pending -Type MultiString -Force
            Write-Log "  [reboot] $Label -- scheduled for deletion: $Path" "WARN"
        } else {
            Write-Log "  [del] $Label -- $Path (fallback)" "OK"
        }
    }
}

function Delete-Service {
    param([string]$Name)
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($svc) {
        if ($svc.Status -ne "Stopped") {
            Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue
            Start-Sleep -Milliseconds 500
        }
        $null = cmd /c "sc.exe delete `"$Name`" >nul 2>&1"
        if ($LASTEXITCODE -eq 0) {
            Write-Log "  [del] Service: $Name" "OK"
        } else {
            Write-Log "  [fail] Service: $Name -- sc delete returned $LASTEXITCODE" "WARN"
        }
    } else {
        Write-Log "  [skip] Service: $Name -- not found"
    }
}

function Remove-ScheduledTaskSafe {
    param([string]$TaskPath)
    $null = cmd /c "schtasks /Change /TN `"$TaskPath`" /Disable >nul 2>&1"
    $null = cmd /c "schtasks /Delete /TN `"$TaskPath`" /F >nul 2>&1"
    if ($LASTEXITCODE -eq 0) {
        Write-Log "  [del] Task: $TaskPath" "OK"
    } else {
        Write-Log "  [skip] Task: $TaskPath -- not found"
    }
}

function Stop-ProcessByPath {
    param([string]$Path)
    $name = [System.IO.Path]::GetFileNameWithoutExtension($Path)
    Get-Process -Name $name -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Log "  Killing process: $($_.Name) (PID $($_.Id))"
        Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 500
    }
}

# ============================================================================
#  Preflight
# ============================================================================

Write-Log "=== Unified OS Amputation Starting ===" "PHASE"
Write-Log "Log: $LogFile"

$hasWerStub64 = Test-Path $StubDllPath
$hasWerStub32 = Test-Path $Stub32DllPath

if (-not $hasWerStub64) {
    Write-Log "x64 stub wer.dll not found at: $StubDllPath" "WARN"
    Write-Log "WER stub deployment will be SKIPPED. Apps calling WER may hang." "WARN"
}
if (-not $hasWerStub32) {
    Write-Log "x86 stub wer32.dll not found at: $Stub32DllPath" "WARN"
    Write-Log "32-bit WER stub deployment will be skipped." "WARN"
}

# ============================================================================
#  Phase 1: Service Deletion (Diagnostic + Telemetry)
# ============================================================================

Write-Log ""
Write-Log "=== Phase 1: Service Deletion ===" "PHASE"
Write-Log "Deleting services entirely (not just disabling)..."

$servicesToDelete = @(
    "DPS",
    "WdiServiceHost",
    "WdiSystemHost",
    "PcaSvc",
    "CDPSvc",
    "DeviceAssociationBrokerSvc",
    "SgrmBroker",
    "SgrmAgent",
    "diagsvc",
    "diagnosticshub.standardcollector.service",
    "MapsBroker",
    "lfsvc",
    "wercplsupport",
    "TabletInputService",
    "TrkWks",
    "iphlpsvc",
    "PhoneSvc",
    "RetailDemo",
    "WerSvc",
    # Additional tracing/logging services
    "DiagTrack",                  # Connected User Experiences and Telemetry
    "GraphicsPerfSvc",            # Graphics performance monitor
    "Ndu",                        # Network Data Usage Monitoring
    "dmwappushservice",           # WAP Push Message Routing (MDM telemetry)
    "DmEnrollmentSvc",            # Device Management Enrollment
    "FileTrace",                  # File Trace MiniFilter service
    "PerfHost",                   # Performance Counter DLL Host service
    "pla",                        # Performance Logs & Alerts
    "SstpSvc",                    # Secure Socket Tunneling Protocol (SSTP)
    "WbioSrvc",                   # Windows Biometric Service
    "wisvc",                      # Windows Insider Service
    "WpcMonSvc"                   # Parental Controls
)

foreach ($svc in $servicesToDelete) {
    Delete-Service $svc
}

$perUserTemplates = @(
    "CDPUserSvc",
    "DeviceAssociationBrokerSvc",
    "PimIndexMaintenanceSvc",
    "UnistoreSvc",
    "UserDataSvc",
    "WpnUserService",
    "DevicesFlowUserSvc",
    "PrintWorkflowUserSvc",
    "MessagingService",
    "OneSyncSvc",
    "CaptureService",
    "cbdhsvc"
)

Write-Log ""
Write-Log "Deleting per-user service templates..."

foreach ($template in $perUserTemplates) {
    Delete-Service $template
    $instances = Get-Service -Name "${template}_*" -ErrorAction SilentlyContinue
    foreach ($inst in $instances) {
        Delete-Service $inst.Name
    }
}

# ============================================================================
#  Phase 2: Binary Removal (Diagnostic)
# ============================================================================

Write-Log ""
Write-Log "=== Phase 2: Binary Removal (Diagnostic) ===" "PHASE"
Write-Log "Removing diagnostic executables and service DLLs..."

$diagBinaries = @(
    @{ Path = "$env:SystemRoot\System32\DiagSvcs\DiagnosticsHub.StandardCollector.Service.exe"; Label = "DiagHub Collector" },
    @{ Path = "$env:SystemRoot\System32\DiagSvcs\DiagnosticsHub.StandardCollector.Proxy.dll"; Label = "DiagHub Proxy" },
    @{ Path = "$env:SystemRoot\System32\diaghost.exe"; Label = "Diagnostic Host" },
    @{ Path = "$env:SystemRoot\System32\dps.dll"; Label = "DPS Service DLL" },
    @{ Path = "$env:SystemRoot\System32\pcasvc.dll"; Label = "PCA Service DLL" },
    @{ Path = "$env:SystemRoot\System32\pcaui.exe"; Label = "PCA UI" },
    @{ Path = "$env:SystemRoot\System32\pcaui.dll"; Label = "PCA UI DLL" },
    @{ Path = "$env:SystemRoot\System32\SgrmBroker.exe"; Label = "SgrmBroker" },
    @{ Path = "$env:SystemRoot\System32\SgrmAgent.exe"; Label = "SgrmAgent" },
    @{ Path = "$env:SystemRoot\System32\CDPSvc.dll"; Label = "CDP Service DLL" },
    @{ Path = "$env:SystemRoot\System32\DasHost.exe"; Label = "Device Association Host" },
    @{ Path = "$env:SystemRoot\System32\MapsBroker.dll"; Label = "Maps Broker DLL" },
    @{ Path = "$env:SystemRoot\System32\wercplsupport.dll"; Label = "WER CPL Support" },
    @{ Path = "$env:SystemRoot\System32\CompatTelRunner.exe"; Label = "Compat Telemetry Runner" },
    @{ Path = "$env:SystemRoot\System32\devicecensus.exe"; Label = "Device Census" },
    @{ Path = "$env:SystemRoot\System32\utc.dll"; Label = "DiagTrack UTC DLL" },
    @{ Path = "$env:SystemRoot\System32\InventoryAgent.dll"; Label = "Inventory Agent" },
    # Performance / tracing CLI tools (NTLite removes component but binaries may survive)
    @{ Path = "$env:SystemRoot\System32\logman.exe"; Label = "Logman (perf trace CLI)" },
    @{ Path = "$env:SystemRoot\System32\tracerpt.exe"; Label = "Trace Report" },
    @{ Path = "$env:SystemRoot\System32\typeperf.exe"; Label = "TypePerf (counter monitor)" },
    @{ Path = "$env:SystemRoot\System32\relog.exe"; Label = "Relog (perf log converter)" },
    @{ Path = "$env:SystemRoot\System32\wpr.exe"; Label = "Windows Performance Recorder" },
    @{ Path = "$env:SystemRoot\System32\wprui.exe"; Label = "WPR UI" },
    @{ Path = "$env:SystemRoot\System32\wevtutil.exe"; Label = "Event Log CLI (dead after Phase 5)" },
    @{ Path = "$env:SystemRoot\System32\perfhost.exe"; Label = "Perf Counter DLL Host" },
    @{ Path = "$env:SystemRoot\System32\perfmon.exe"; Label = "Performance Monitor" },
    # Diagnostic tools
    @{ Path = "$env:SystemRoot\System32\psr.exe"; Label = "Steps Recorder" },
    @{ Path = "$env:SystemRoot\System32\mdsched.exe"; Label = "Memory Diagnostic Scheduler" },
    @{ Path = "$env:SystemRoot\System32\msdt.exe"; Label = "Support Diagnostic Tool" },
    @{ Path = "$env:SystemRoot\System32\mdm.exe"; Label = "Machine Debug Manager" },
    @{ Path = "$env:SystemRoot\System32\MRT.exe"; Label = "Malicious Software Removal Tool" },
    @{ Path = "$env:SystemRoot\System32\sdclt.exe"; Label = "Backup and Restore" },
    @{ Path = "$env:SystemRoot\System32\wsreset.exe"; Label = "Store Reset" },
    @{ Path = "$env:SystemRoot\System32\systemreset.exe"; Label = "System Reset" },
    @{ Path = "$env:SystemRoot\System32\dwm.exe.log"; Label = "DWM log file" },
    # DiagTrack binaries
    @{ Path = "$env:SystemRoot\System32\diagtrack.dll"; Label = "DiagTrack DLL" },
    @{ Path = "$env:SystemRoot\System32\diagtrackrunner.exe"; Label = "DiagTrack Runner" },
    # Reliability
    @{ Path = "$env:SystemRoot\System32\RacEngn.dll"; Label = "Reliability Analysis Engine" },
    @{ Path = "$env:SystemRoot\System32\RACAgent.exe"; Label = "Reliability Analysis Agent" }
)

foreach ($item in $diagBinaries) {
    Remove-Binary -Path $item.Path -Label $item.Label
}

# ============================================================================
#  Phase 3: Scheduled Task Purge
# ============================================================================

Write-Log ""
Write-Log "=== Phase 3: Scheduled Task Purge ===" "PHASE"
Write-Log "Removing latency-relevant scheduled tasks..."

$tasksToRemove = @(
    "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",
    "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver",
    "\Microsoft\Windows\MemoryDiagnostic\ProcessMemoryDiagnosticEvents",
    "\Microsoft\Windows\MemoryDiagnostic\RunFullMemoryDiagnostic",
    "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem",
    "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
    "\Microsoft\Windows\Application Experience\PcaPatchDbTask",
    "\Microsoft\Windows\Application Experience\ProgramDataUpdater",
    "\Microsoft\Windows\Application Experience\StartupAppTask",
    "\Microsoft\Windows\Application Experience\AitAgent",
    "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
    "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
    "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask",
    "\Microsoft\Windows\Autochk\Proxy",
    "\Microsoft\Windows\Device Information\Device",
    "\Microsoft\Windows\Device Information\Device User",
    "\Microsoft\Windows\CloudExperienceHost\CreateObjectTask",
    "\Microsoft\Windows\Feedback\Siuf\DmClient",
    "\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload",
    "\Microsoft\Windows\FileHistory\File History (maintenance mode)",
    "\Microsoft\Windows\Flighting\FeatureConfig\ReconcileFeatures",
    "\Microsoft\Windows\Flighting\FeatureConfig\UsageDataFlushing",
    "\Microsoft\Windows\Flighting\FeatureConfig\UsageDataReporting",
    "\Microsoft\Windows\Flighting\OneSettings\RefreshCache",
    "\Microsoft\Windows\Location\Notifications",
    "\Microsoft\Windows\Location\WindowsActionDialog",
    "\Microsoft\Windows\Maps\MapsToastTask",
    "\Microsoft\Windows\Maps\MapsUpdateTask",
    "\Microsoft\Windows\Diagnosis\Scheduled",
    "\Microsoft\Windows\Diagnosis\RecommendedTroubleshootingScanner",
    "\Microsoft\Windows\PI\Sqm-Tasks",
    "\Microsoft\Windows\PushToInstall\LoginCheck",
    "\Microsoft\Windows\PushToInstall\Registration",
    "\Microsoft\Windows\Setup\SetupCleanupTask",
    "\Microsoft\Windows\Setup\SnappyOOBECleanup",
    "\Microsoft\Windows\System Guard\VerifiedAccess_AtLogin",
    "\Microsoft\Windows\System Guard\VerifiedAccess_Periodic",
    "\Microsoft\Windows\Wininet\CacheTask",
    "\Microsoft\Windows\Work Folders\Work Folders Logon Synchronization",
    "\Microsoft\Windows\Work Folders\Work Folders Maintenance Work",
    "\Microsoft\Windows\Workplace Join\Automatic-Device-Join",
    "\Microsoft\Windows\Workplace Join\Recovery-Check",
    "\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance",
    "\Microsoft\Windows\Windows Defender\Windows Defender Cleanup",
    "\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan",
    "\Microsoft\Windows\Windows Defender\Windows Defender Verification",
    "\Microsoft\Windows\Clip\License Validation",
    "\Microsoft\Windows\Speech\SpeechModelDownloadTask",
    "\Microsoft\Windows\Speech\HeardActivityLookback",
    "\Microsoft\Windows\International\Synchronize Language Settings",
    "\Microsoft\Windows\Management\Provisioning\Cellular",
    "\Microsoft\Windows\Management\Provisioning\Logon",
    "\Microsoft\Windows\Windows Error Reporting\QueueReporting"
)

foreach ($task in $tasksToRemove) {
    Remove-ScheduledTaskSafe $task
}

Write-Log ""
Write-Log "Sweeping for remaining diagnostic/telemetry tasks..."

$sweepPatterns = @(
    "Compat", "Ceip", "Telemetry", "DiagTrack", "Consolidator",
    "DeviceCensus", "Sqm", "Feedback", "Flighting", "WER", "WerTask", "Error Reporting"
)

$taskListRaw = cmd /c "schtasks /Query /FO CSV /NH 2>nul"
if ($taskListRaw) {
    $taskListRaw | ForEach-Object {
        $fields = $_ -split '","'
        if ($fields.Count -ge 1) {
            $taskFullName = $fields[0].Trim('"')
            foreach ($pattern in $sweepPatterns) {
                if ($taskFullName -match $pattern -and $taskFullName -notin $tasksToRemove) {
                    Remove-ScheduledTaskSafe $taskFullName
                    break
                }
            }
        }
    }
}

# ============================================================================
#  Phase 4: ETW Autologger Session Kill
# ============================================================================

Write-Log ""
Write-Log "=== Phase 4: ETW Autologger Session Kill ===" "PHASE"
Write-Log "Disabling non-essential autologger sessions..."

$autologgersToKill = @(
    "AppModel",
    "CloudExperienceHostOobe",
    "DiagLog",
    "Diagtrack-Listener",
    "LwtNetLog",
    "Microsoft-Windows-Setup",
    "NtfsLog",
    "RadioMgr",
    "ReadyBoot",
    "SetupPlatformTel",
    "SpoolerLogger",
    "SQMLogger",
    "UBPM",
    "WdiContextLog",
    "WiFiSession",
    "WiFiDriverIHVSession",
    "WiFiDriverIHVSessionRepro",
    "Circular Kernel Context Logger",
    "FaceRecoTel",
    "FaceUnlock",
    "MeasuredBoot",
    "RdrLog",
    "Tpm",
    "TileStore",
    "WFP-IPsec Diagnostics",
    "WindowsUpdate-Diagnostics",
    "AutoLogger-Diagtrack-Listener",
    "DefenderApiLogger",
    "DefenderAuditLogger",
    "WerFaultTraceSession",
    "WerConsentTraceSession",
    # Additional logging sessions
    "EventLog-System",            # System event log writer
    "EventLog-Application",       # Application event log writer
    "EventLog-Security",          # Security event log writer
    "NetCore",                    # .NET Core runtime tracing
    "PerfTrack",                  # Performance tracking
    "CldFlt",                     # Cloud Files mini-filter tracing
    "ScreenOnPowerStudyTraceSession", # Power study telemetry
    "StorLog",                    # Storage logging
    "IOLOGGER",                   # I/O logging
    "WindowsUpdate",              # Windows Update tracing
    "WinPhoneCritical",           # Phone telemetry (leftover)
    "AIT",                        # Application Impact Telemetry
    "SecurityHealthService",      # Defender health tracing
    "Microsoft-Windows-Diagtrack-Listener", # DiagTrack alternate name
    "BioEnrollment"               # Biometric enrollment tracing
)

$autoLoggerRoot = "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger"

foreach ($session in $autologgersToKill) {
    $sessionPath = "$autoLoggerRoot\$session"
    if (Test-Path $sessionPath) {
        Set-ItemProperty -Path $sessionPath -Name "Start" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
        $providers = Get-ChildItem $sessionPath -ErrorAction SilentlyContinue
        $providerCount = 0
        foreach ($provider in $providers) {
            Remove-Item $provider.PSPath -Recurse -Force -ErrorAction SilentlyContinue
            $providerCount++
        }
        Write-Log "  [kill] $session (disabled + $providerCount providers removed)" "OK"
    } else {
        Write-Log "  [skip] $session -- not found"
    }
}

Write-Log ""
Write-Log "Sweeping for remaining diagnostic autologgers..."

Get-ChildItem $autoLoggerRoot -ErrorAction SilentlyContinue | ForEach-Object {
    $name = $_.PSChildName
    if ($name -match "Diag|Telemetry|Census|SQM|Ceip|Feedback|WER|Wer" -and $name -notin $autologgersToKill) {
        Set-ItemProperty -Path $_.PSPath -Name "Start" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
        $providers = Get-ChildItem $_.PSPath -ErrorAction SilentlyContinue
        foreach ($p in $providers) {
            Remove-Item $p.PSPath -Recurse -Force -ErrorAction SilentlyContinue
        }
        Write-Log "  [kill] $name (sweep)" "OK"
    }
}

Write-Log ""
Write-Log "Purging WER ETW provider GUIDs from autologger sessions..."

$werEtwProviders = @(
    "{E46EEAD8-0C54-4489-9898-8FA79D059E0E}",
    "{CC79CF77-70D9-4082-9B52-23F3A3E92FE4}",
    "{1377561D-9312-452C-AD13-C4A1C9C906E0}",
    "{3E0D88DE-AE5C-438A-BB1C-C2E627F8AECB}"
)

foreach ($guid in $werEtwProviders) {
    Get-ChildItem $autoLoggerRoot -ErrorAction SilentlyContinue | ForEach-Object {
        Get-ChildItem $_.PSPath -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_.PSChildName -eq $guid) {
                Remove-Item $_.PSPath -Recurse -Force -ErrorAction SilentlyContinue
                Write-Log "  Removed ETW provider $guid from $($_.PSParentPath | Split-Path -Leaf)"
            }
        }
    }
}

# ============================================================================
#  Phase 5: Event Log + ETW Infrastructure Nuke
# ============================================================================

Write-Log ""
Write-Log "=== Phase 5: Event Log + ETW Infrastructure Nuke ===" "PHASE"
Write-Log "Deleting WINEVT channels/publishers and WMI logger infrastructure..."

$infrastructureKeys = @(
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels"; Label = "WINEVT Channels" },
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers"; Label = "WINEVT Publishers" },
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger"; Label = "WMI Autologger" },
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\GlobalLogger"; Label = "WMI GlobalLogger" }
)

foreach ($key in $infrastructureKeys) {
    if (Test-Path $key.Path) {
        try {
            Remove-Item $key.Path -Recurse -Force -ErrorAction Stop
            Write-Log "  [del] $($key.Label) -- $($key.Path)" "OK"
        } catch {
            $regPath = $key.Path -replace 'HKLM:\\', 'HKLM\'
            $null = cmd /c "reg delete `"$regPath`" /f >nul 2>&1"
            if ($LASTEXITCODE -eq 0) {
                Write-Log "  [del] $($key.Label) -- $($key.Path) (via reg.exe)" "OK"
            } else {
                Write-Log "  [warn] $($key.Label) -- partial deletion, some subkeys may be locked" "WARN"
            }
        }
    } else {
        Write-Log "  [skip] $($key.Label) -- not found"
    }
}

# ============================================================================
#  Phase 6: Per-User Service Template Neutering
# ============================================================================

Write-Log ""
Write-Log "=== Phase 6: Per-User Service Template Neutering ===" "PHASE"
Write-Log "Removing per-user service template DLLs..."

$perUserBinaries = @(
    @{ Path = "$env:SystemRoot\System32\CDPUserSvc.dll"; Label = "CDPUserSvc DLL" },
    @{ Path = "$env:SystemRoot\System32\PimIndexMaintenanceSvc.dll"; Label = "PIM Index DLL" },
    @{ Path = "$env:SystemRoot\System32\UnistoreSvc.dll"; Label = "Unified Store DLL" },
    @{ Path = "$env:SystemRoot\System32\UserDataSvc.dll"; Label = "User Data DLL" },
    @{ Path = "$env:SystemRoot\System32\WpnUserService.dll"; Label = "Push Notification DLL" },
    @{ Path = "$env:SystemRoot\System32\DevicesFlowUserSvc.dll"; Label = "Devices Flow DLL" },
    @{ Path = "$env:SystemRoot\System32\cbdhsvc.dll"; Label = "Clipboard User DLL" },
    @{ Path = "$env:SystemRoot\System32\CaptureService.dll"; Label = "Capture Service DLL" },
    @{ Path = "$env:SystemRoot\System32\MessagingService.dll"; Label = "Messaging Service DLL" }
)

foreach ($item in $perUserBinaries) {
    Remove-Binary -Path $item.Path -Label $item.Label
}

# ============================================================================
#  Phase 7: Compatibility Engine Cleanup
# ============================================================================

Write-Log ""
Write-Log "=== Phase 7: Compatibility Engine Cleanup ===" "PHASE"
Write-Log "Purging compatibility databases and shim cache..."

$shimCachePath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache"
$shimProps = Get-ItemProperty -Path $shimCachePath -ErrorAction SilentlyContinue
if ($shimProps -and ($shimProps.PSObject.Properties.Name -contains "AppCompatCache")) {
    Remove-ItemProperty -Path $shimCachePath -Name "AppCompatCache" -Force -ErrorAction SilentlyContinue
    Write-Log "  [del] AppCompatCache shim cache purged" "OK"
}

$layersPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers"
if (Test-Path $layersPath) {
    Remove-Item $layersPath -Recurse -Force -ErrorAction SilentlyContinue
    Write-Log "  [del] AppCompatFlags\Layers cleared" "OK"
}

$compatStorePaths = @(
    "$env:ProgramData\Microsoft\Windows\AppRepository\Packages\*compat*",
    "$env:SystemRoot\AppPatch\sysmain.sdb"
)

foreach ($p in $compatStorePaths) {
    $items = Get-Item $p -ErrorAction SilentlyContinue
    foreach ($item in $items) {
        Take-Ownership $item.FullName | Out-Null
        Remove-Item $item.FullName -Force -ErrorAction SilentlyContinue
        Write-Log "  [del] $($item.FullName)" "OK"
    }
}

$appraiserDir = "$env:SystemRoot\System32\appraiser"
if (Test-Path $appraiserDir) {
    $null = cmd /c "takeown /f `"$appraiserDir`" /r /d y >nul 2>&1"
    $null = cmd /c "icacls `"$appraiserDir`" /grant Administrators:F /t >nul 2>&1"
    Remove-Item $appraiserDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Log "  [del] Appraiser directory" "OK"
}

# ============================================================================
#  Phase 8: Artifact Purge
# ============================================================================

Write-Log ""
Write-Log "=== Phase 8: Artifact Purge ===" "PHASE"
Write-Log "Cleaning leftover data stores and caches..."

$artifactPaths = @(
    "$env:ProgramData\Microsoft\Diagnosis",
    "$env:ProgramData\Microsoft\Windows\Sqm",
    "$env:ProgramData\Microsoft\Windows\Setup\Telemetry",
    "$env:ProgramData\Microsoft\Windows\Appraiser",
    "$env:ProgramData\Microsoft\Windows\ConnectedDevicesPlatform",
    "$env:ProgramData\Microsoft\Windows\DeviceCensus",
    "$env:ProgramData\Microsoft\Windows\Maps",
    "$env:ProgramData\Microsoft\Windows\Location",
    "$env:ProgramData\Microsoft\Windows\PushNotifications",
    "$env:ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger",
    "$env:ProgramData\Microsoft\SiufData",
    "$env:SystemRoot\Prefetch\ReadyBoot\*.fx",
    "$env:SystemRoot\LiveKernelReports",
    "$env:SystemRoot\Minidump",
    "$env:SystemRoot\MEMORY.DMP",
    "$env:ProgramData\Microsoft\Windows\WER",
    "$env:LOCALAPPDATA\Microsoft\Windows\WER",
    "$env:LOCALAPPDATA\CrashDumps"
)

foreach ($path in $artifactPaths) {
    $items = @()
    if ($path -match '\*') {
        $items = Get-Item $path -ErrorAction SilentlyContinue
    } elseif (Test-Path $path) {
        $items = @(Get-Item $path)
    }

    foreach ($item in $items) {
        try {
            if ($item.PSIsContainer) {
                Remove-Item $item.FullName -Recurse -Force -ErrorAction Stop
            } else {
                Remove-Item $item.FullName -Force -ErrorAction Stop
            }
            Write-Log "  [del] $($item.FullName)" "OK"
        } catch {
            Write-Log "  [warn] Could not clean: $($item.FullName)" "WARN"
        }
    }
}

Write-Log ""
Write-Log "Cleaning per-user artifacts..."

$userProfiles = Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -notin @("Public", "Default", "Default User", "All Users") }

$perUserArtifacts = @(
    "AppData\Local\ConnectedDevicesPlatform",
    "AppData\Local\Diagnostics",
    "AppData\Local\Microsoft\Windows\Diagnosis",
    "AppData\Local\Microsoft\Windows\1033\StructuredQuerySchema.bin",
    "AppData\Local\Microsoft\Windows\WebCache",
    "AppData\Local\Microsoft\Windows\Explorer\thumbcache_*.db",
    "AppData\Local\Microsoft\Windows\WER",
    "AppData\Local\CrashDumps"
)

foreach ($profile in $userProfiles) {
    foreach ($relPath in $perUserArtifacts) {
        $fullPath = Join-Path $profile.FullName $relPath
        $items = Get-Item $fullPath -ErrorAction SilentlyContinue
        foreach ($item in $items) {
            try {
                if ($item.PSIsContainer) {
                    Remove-Item $item.FullName -Recurse -Force -ErrorAction Stop
                } else {
                    Remove-Item $item.FullName -Force -ErrorAction Stop
                }
                Write-Log "  [del] $($item.FullName)" "OK"
            } catch { }
        }
    }
}

# ============================================================================
#  Phase 9: WER Registry Nuke
# ============================================================================

Write-Log ""
Write-Log "=== Phase 9: WER Registry Nuke ===" "PHASE"
Write-Log "Applying WER disable policies..."

$werRegPaths = @(
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting"; Name = "Disabled"; Value = 1; Type = "DWord" },
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting"; Name = "DontShowUI"; Value = 1; Type = "DWord" },
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting"; Name = "DontSendAdditionalData"; Value = 1; Type = "DWord" },
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting"; Name = "LoggingDisabled"; Value = 1; Type = "DWord" },
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting"; Name = "AutoApproveOSDumps"; Value = 0; Type = "DWord" },
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Consent"; Name = "DefaultConsent"; Value = 0; Type = "DWord" },
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Consent"; Name = "DefaultOverrideBehavior"; Value = 1; Type = "DWord" },
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl"; Name = "CrashDumpEnabled"; Value = 0; Type = "DWord" },
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl"; Name = "EnableLogFile"; Value = 0; Type = "DWord" },
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl"; Name = "AutoReboot"; Value = 1; Type = "DWord" },
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps"; Name = "DumpCount"; Value = 0; Type = "DWord" },
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps"; Name = "DumpType"; Value = 0; Type = "DWord" },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting"; Name = "Disabled"; Value = 1; Type = "DWord" },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting"; Name = "DontSendAdditionalData"; Value = 1; Type = "DWord" },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting"; Name = "DontShowUI"; Value = 1; Type = "DWord" },
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug"; Name = "Auto"; Value = "1"; Type = "String" }
)

foreach ($reg in $werRegPaths) {
    if (-not (Test-Path $reg.Path)) {
        New-Item -Path $reg.Path -Force | Out-Null
    }
    Set-ItemProperty -Path $reg.Path -Name $reg.Name -Value $reg.Value -Type $reg.Type -Force
    Write-Log "  Set: $($reg.Path)\$($reg.Name) = $($reg.Value)"
}

$aeDebugPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug"
$aeDebugProps = Get-ItemProperty -Path $aeDebugPath -ErrorAction SilentlyContinue
if ($aeDebugProps -and ($aeDebugProps.PSObject.Properties.Name -contains "Debugger")) {
    if ($aeDebugProps.Debugger -match "WerFault") {
        Remove-ItemProperty -Path $aeDebugPath -Name "Debugger" -Force -ErrorAction SilentlyContinue
        Write-Log "  Removed AeDebug WerFault debugger entry." "OK"
    }
}

$aeDebugWow = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\AeDebug"
if (Test-Path $aeDebugWow) {
    $aeDebugWowProps = Get-ItemProperty -Path $aeDebugWow -ErrorAction SilentlyContinue
    if ($aeDebugWowProps -and ($aeDebugWowProps.PSObject.Properties.Name -contains "Debugger")) {
        if ($aeDebugWowProps.Debugger -match "WerFault") {
            Remove-ItemProperty -Path $aeDebugWow -Name "Debugger" -Force -ErrorAction SilentlyContinue
            Write-Log "  Removed WOW64 AeDebug WerFault debugger entry." "OK"
        }
    }
}

Write-Log "WER registry policies applied." "OK"

# ============================================================================
#  Phase 10: WER Binary Removal + Stub Deployment
# ============================================================================

Write-Log ""
Write-Log "=== Phase 10: WER Binary Removal + Stub Deployment ===" "PHASE"

$werProcesses = @("WerFault", "WerFaultSecure", "wermgr")
foreach ($proc in $werProcesses) {
    Stop-ProcessByPath "$env:SystemRoot\System32\$proc.exe"
}

$werBinaries = @(
    @{ Path = "$env:SystemRoot\System32\WerFault.exe"; Label = "WerFault x64" },
    @{ Path = "$env:SystemRoot\System32\WerFaultSecure.exe"; Label = "WerFaultSecure x64" },
    @{ Path = "$env:SystemRoot\System32\wermgr.exe"; Label = "wermgr x64" },
    @{ Path = "$env:SystemRoot\System32\werui.dll"; Label = "werui x64" },
    @{ Path = "$env:SystemRoot\System32\wersvc.dll"; Label = "wersvc x64" },
    @{ Path = "$env:SystemRoot\System32\wer.dll"; Label = "wer.dll x64 (original)" },
    @{ Path = "$env:SystemRoot\SysWOW64\WerFault.exe"; Label = "WerFault x86" },
    @{ Path = "$env:SystemRoot\SysWOW64\WerFaultSecure.exe"; Label = "WerFaultSecure x86" },
    @{ Path = "$env:SystemRoot\SysWOW64\wermgr.exe"; Label = "wermgr x86" },
    @{ Path = "$env:SystemRoot\SysWOW64\wer.dll"; Label = "wer.dll x86 (original)" },
    @{ Path = "$env:SystemRoot\SysWOW64\werui.dll"; Label = "werui x86" }
)

foreach ($item in $werBinaries) {
    Remove-Binary -Path $item.Path -Label $item.Label
}

Write-Log ""
Write-Log "Deploying WER stub DLLs..."

if ($hasWerStub64) {
    $sys32Target = "$env:SystemRoot\System32\wer.dll"
    try {
        Copy-Item $StubDllPath $sys32Target -Force -ErrorAction Stop
        Write-Log "  [deploy] x64 stub: $sys32Target" "OK"
    } catch {
        Write-Log "  [warn] Failed to deploy x64 stub, scheduling reboot copy: $_" "WARN"
        $tempStub = "$env:SystemRoot\Temp\wer_stub64_$(Get-Random).dll"
        Copy-Item $StubDllPath $tempStub -Force
        $pendingKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
        $pending = (Get-ItemProperty -Path $pendingKey -Name "PendingFileRenameOperations" -ErrorAction SilentlyContinue).PendingFileRenameOperations
        if (-not $pending) { $pending = @() }
        $pending += "\??\$tempStub"
        $pending += "\??\$sys32Target"
        Set-ItemProperty -Path $pendingKey -Name "PendingFileRenameOperations" -Value $pending -Type MultiString -Force
    }
}

if ($hasWerStub32 -and (Test-Path "$env:SystemRoot\SysWOW64")) {
    $wow64Target = "$env:SystemRoot\SysWOW64\wer.dll"
    try {
        Copy-Item $Stub32DllPath $wow64Target -Force -ErrorAction Stop
        Write-Log "  [deploy] x86 stub: $wow64Target" "OK"
    } catch {
        Write-Log "  [warn] Failed to deploy x86 stub, scheduling reboot copy: $_" "WARN"
        $tempStub32 = "$env:SystemRoot\Temp\wer_stub32_$(Get-Random).dll"
        Copy-Item $Stub32DllPath $tempStub32 -Force
        $pendingKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
        $pending = (Get-ItemProperty -Path $pendingKey -Name "PendingFileRenameOperations" -ErrorAction SilentlyContinue).PendingFileRenameOperations
        if (-not $pending) { $pending = @() }
        $pending += "\??\$tempStub32"
        $pending += "\??\$wow64Target"
        Set-ItemProperty -Path $pendingKey -Name "PendingFileRenameOperations" -Value $pending -Type MultiString -Force
    }
}

# ============================================================================
#  Phase 11: WER Kernel Driver Disable
# ============================================================================

Write-Log ""
Write-Log "=== Phase 11: WER Kernel Driver Disable ===" "PHASE"

$driverSvcPath = "HKLM:\SYSTEM\CurrentControlSet\Services\WerKernel"
if (Test-Path $driverSvcPath) {
    Set-ItemProperty -Path $driverSvcPath -Name "Start" -Value 4 -Type DWord -Force
    Set-ItemProperty -Path $driverSvcPath -Name "ErrorControl" -Value 0 -Type DWord -Force
    Write-Log "  werkernel: Start=4 (Disabled), ErrorControl=0 (Ignore)" "OK"
} else {
    Write-Log "  werkernel service entry not found." "WARN"
}

Write-Log ""
Write-Log "Disabling WER optional feature..."
try {
    $werFeature = Get-WindowsOptionalFeature -Online -FeatureName "Windows-Error-Reporting" -ErrorAction SilentlyContinue
    if ($werFeature -and $werFeature.State -eq "Enabled") {
        Disable-WindowsOptionalFeature -Online -FeatureName "Windows-Error-Reporting" -NoRestart -ErrorAction Stop | Out-Null
        Write-Log "  Disabled Windows-Error-Reporting optional feature." "OK"
    }
} catch {
    Write-Log "  Optional feature not found or already disabled." "WARN"
}

# ============================================================================
#  Phase 12: Task Manager Removal
# ============================================================================

Write-Log ""
Write-Log "=== Phase 12: Task Manager Removal ===" "PHASE"

$taskmgrPath = "$env:SystemRoot\System32\Taskmgr.exe"
if (Test-Path $taskmgrPath) {
    Take-Ownership $taskmgrPath | Out-Null

    Get-Process -Name "Taskmgr" -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Log "  Killing Taskmgr (PID $($_.Id))"
        Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 300
    }

    try {
        Remove-Item $taskmgrPath -Force -ErrorAction Stop
        Write-Log "  [del] Taskmgr.exe" "OK"
    } catch {
        $pendingKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
        $pending = @()
        $existingProps = Get-ItemProperty -Path $pendingKey -ErrorAction SilentlyContinue
        if ($existingProps -and ($existingProps.PSObject.Properties.Name -contains "PendingFileRenameOperations")) {
            $pending = @($existingProps.PendingFileRenameOperations)
        }
        $pending += "\??\$taskmgrPath"
        $pending += ""
        Set-ItemProperty -Path $pendingKey -Name "PendingFileRenameOperations" -Value $pending -Type MultiString -Force
        Write-Log "  [reboot] Taskmgr.exe scheduled for deletion" "WARN"
    }
} else {
    Write-Log "  [skip] Taskmgr.exe -- not found"
}

# ============================================================================
#  Phase 13: .NET / WCF Feature Disable (DISM)
# ============================================================================

Write-Log ""
Write-Log "=== Phase 13: .NET / WCF Feature Disable ===" "PHASE"
Write-Log "Disabling .NET and WCF features via DISM..."

$featuresToDisable = @(
    "NetFx3",
    "NetFx4-AdvSrvs",
    "WCF-Services45",
    "WCF-TCP-PortSharing45",
    # Additional WCF sub-features (belt-and-suspenders -- NTLite sets offline but ensure online)
    "WCF-HTTP-Activation",
    "WCF-HTTP-Activation45",
    "WCF-MSMQ-Activation45",
    "WCF-Pipe-Activation45",
    "WCF-NonHTTP-Activation",
    "WCF-TCP-Activation45",
    # .NET extended features
    "NetFx4Extended-ASPNET45",
    # Legacy frameworks
    "Windows-Identity-Foundation",
    # PowerShell 2.0 engine (security liability, nothing needs it with 5.1+)
    "MicrosoftWindowsPowerShellV2Root",
    "MicrosoftWindowsPowerShellV2",
    # Windows Process Activation Service (WAS) sub-features
    "WAS-WindowsActivationService",
    "WAS-ProcessModel",
    "WAS-ConfigurationAPI",
    "WAS-NetFxEnvironment"
)

foreach ($feature in $featuresToDisable) {
    Write-Log "  Disabling: $feature"
    $result = cmd /c "dism /online /disable-feature /featurename:$feature /norestart 2>&1"
    if ($LASTEXITCODE -eq 0) {
        Write-Log "  [disabled] $feature" "OK"
    } elseif ($result -match "does not exist") {
        Write-Log "  [skip] $feature -- not present on this build"
    } else {
        Write-Log "  [warn] $feature -- DISM returned $LASTEXITCODE" "WARN"
    }
}

# ============================================================================
#  Phase 14: Tracing Infrastructure Registry Nuke
# ============================================================================

Write-Log ""
Write-Log "=== Phase 14: Tracing Infrastructure Registry Nuke ===" "PHASE"
Write-Log "Removing WPP/software tracing config, diagnostics perf, WMI security..."

# WPP Software Tracing configuration tree
$tracingPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Tracing"
if (Test-Path $tracingPath) {
    try {
        Remove-Item $tracingPath -Recurse -Force -ErrorAction Stop
        Write-Log "  [del] WPP Tracing tree" "OK"
    } catch {
        $null = cmd /c "reg delete `"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Tracing`" /f >nul 2>&1"
        if ($LASTEXITCODE -eq 0) {
            Write-Log "  [del] WPP Tracing tree (via reg.exe)" "OK"
        } else {
            Write-Log "  [warn] WPP Tracing tree -- partial deletion" "WARN"
        }
    }
}

# Boot/shutdown trace control
$diagPerfPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Diagnostics\Performance"
if (Test-Path $diagPerfPath) {
    # Disable boot trace
    Set-ItemProperty -Path $diagPerfPath -Name "BootTraceDiagnosticEnabled" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $diagPerfPath -Name "ShutdownTraceDiagnosticEnabled" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
    Write-Log "  [set] Boot/Shutdown trace diagnostics disabled" "OK"
}

# NOTE: WMI\Security is intentionally NOT deleted here.
# It sits under HKLM\SYSTEM\CurrentControlSet\Control\WMI which the user confirmed
# causes black screen / BSOD if the parent is deleted. Only Autologger and GlobalLogger
# subkeys are safe to delete (handled in Phase 5).

# Disable fault-tolerant heap (FTH) monitoring -- logs every crash for "learning"
$fthPath = "HKLM:\SOFTWARE\Microsoft\FTH"
if (Test-Path $fthPath) {
    Set-ItemProperty -Path $fthPath -Name "Enabled" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
    Write-Log "  [set] Fault Tolerant Heap (FTH) monitoring disabled" "OK"
}

# Disable SQM (Software Quality Metrics) client
$sqmPath = "HKLM:\SOFTWARE\Microsoft\SQMClient\Windows"
if (Test-Path $sqmPath) {
    Set-ItemProperty -Path $sqmPath -Name "CEIPEnable" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $sqmPath -Name "SqmLogFileSize" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
    Write-Log "  [set] SQM Client disabled" "OK"
}

# Disable Application Telemetry
$appTelPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"
if (-not (Test-Path $appTelPath)) { New-Item -Path $appTelPath -Force | Out-Null }
Set-ItemProperty -Path $appTelPath -Name "AITEnable" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $appTelPath -Name "DisableInventory" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $appTelPath -Name "DisablePCA" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $appTelPath -Name "DisableUAR" -Value 1 -Type DWord -Force
Write-Log "  [set] Application telemetry/PCA/UAR disabled via policy" "OK"

# Disable Kernel Perf Trace
$kernelTracePath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"
if (Test-Path $kernelTracePath) {
    Set-ItemProperty -Path $kernelTracePath -Name "PerfLogging" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
    Write-Log "  [set] Kernel performance logging disabled" "OK"
}

# ============================================================================
#  Phase 15: .NET / CLR Tracing Disable
# ============================================================================

Write-Log ""
Write-Log "=== Phase 15: .NET / CLR Tracing Disable ===" "PHASE"
Write-Log "Disabling .NET runtime ETW providers and performance counters..."

# Disable CLR ETW globally
$dotnetFwPath = "HKLM:\SOFTWARE\Microsoft\.NETFramework"
if (Test-Path $dotnetFwPath) {
    Set-ItemProperty -Path $dotnetFwPath -Name "ETWEnabled" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
    Write-Log "  [set] .NET Framework ETWEnabled = 0" "OK"
}

# Also for WOW64 .NET
$dotnetFwWowPath = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework"
if (Test-Path $dotnetFwWowPath) {
    Set-ItemProperty -Path $dotnetFwWowPath -Name "ETWEnabled" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
    Write-Log "  [set] .NET Framework WOW64 ETWEnabled = 0" "OK"
}

# Disable .NET CLR ETW providers via registry
# These are the main CLR event source GUIDs
$dotnetEtwProviders = @(
    @{ Guid = "{E13C0D23-CCBC-4E12-931B-D9CC2EEE27E4}"; Name = "DotNETRuntime" },
    @{ Guid = "{A669021C-C450-4609-A035-5AF59AF4DF18}"; Name = "DotNETRuntimeRundown" },
    @{ Guid = "{763FD754-7086-4DFE-95EB-C01A46FAF4CA}"; Name = "DotNETRuntimeStress" },
    @{ Guid = "{2E5DBA47-A3D2-4D16-8EE0-6671FFDCD7B5}"; Name = "DotNETRuntimePrivate" }
)

foreach ($provider in $dotnetEtwProviders) {
    $provRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\$($provider.Guid)"
    if (Test-Path $provRegPath) {
        Remove-Item $provRegPath -Recurse -Force -ErrorAction SilentlyContinue
        Write-Log "  [del] ETW publisher: $($provider.Name) ($($provider.Guid))" "OK"
    }
    # Also check autologger sessions for these providers
    $autoLoggerRoot2 = "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger"
    if (Test-Path $autoLoggerRoot2) {
        Get-ChildItem $autoLoggerRoot2 -ErrorAction SilentlyContinue | ForEach-Object {
            $subKey = Join-Path $_.PSPath $provider.Guid
            if (Test-Path $subKey) {
                Remove-Item $subKey -Recurse -Force -ErrorAction SilentlyContinue
                Write-Log "  [del] CLR ETW provider $($provider.Name) from $($_.PSChildName)"
            }
        }
    }
}

# Disable NGEN service (native image compilation tracing + background activity)
$ngenSvc = Get-Service -Name "clr_optimization_v4.0.30319_64" -ErrorAction SilentlyContinue
if ($ngenSvc) {
    Stop-Service -Name $ngenSvc.Name -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($ngenSvc.Name)" -Name "Start" -Value 4 -Type DWord -Force -ErrorAction SilentlyContinue
    Write-Log "  [set] NGEN x64 service disabled" "OK"
}
$ngenSvc32 = Get-Service -Name "clr_optimization_v4.0.30319_32" -ErrorAction SilentlyContinue
if ($ngenSvc32) {
    Stop-Service -Name $ngenSvc32.Name -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($ngenSvc32.Name)" -Name "Start" -Value 4 -Type DWord -Force -ErrorAction SilentlyContinue
    Write-Log "  [set] NGEN x86 service disabled" "OK"
}

# Disable .NET Telemetry environment variable for all future processes
[System.Environment]::SetEnvironmentVariable("DOTNET_CLI_TELEMETRY_OPTOUT", "1", "Machine")
[System.Environment]::SetEnvironmentVariable("COMPlus_EnableDiagnostics", "0", "Machine")
Write-Log "  [set] DOTNET_CLI_TELEMETRY_OPTOUT=1 (machine)" "OK"
Write-Log "  [set] COMPlus_EnableDiagnostics=0 (machine)" "OK"

# ============================================================================
#  Phase 16: Performance Counter Cleanup
# ============================================================================

Write-Log ""
Write-Log "=== Phase 16: Performance Counter Cleanup ===" "PHASE"
Write-Log "Removing orphaned performance counter registrations..."

# Remove Performance subkeys from services that no longer exist or are disabled
$perfOrphans = @(
    "BITS", "DiagTrack", "Dnscache", "LanmanServer", "LanmanWorkstation",
    "lfsvc", "MapsBroker", "PcaSvc", "SgrmBroker", "WerSvc",
    "WdiServiceHost", "WdiSystemHost", "DPS"
)

foreach ($svcName in $perfOrphans) {
    $perfSubkey = "HKLM:\SYSTEM\CurrentControlSet\Services\$svcName\Performance"
    if (Test-Path $perfSubkey) {
        Remove-Item $perfSubkey -Recurse -Force -ErrorAction SilentlyContinue
        Write-Log "  [del] Perf counters: $svcName" "OK"
    }
}

# Disable global performance counter collection
$perfDisablePath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib"
if (Test-Path $perfDisablePath) {
    Set-ItemProperty -Path $perfDisablePath -Name "Disable Performance Counters" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
    Write-Log "  [set] Global performance counter collection disabled" "OK"
}

# ============================================================================
#  Phase 17: Event Log File Purge
# ============================================================================

Write-Log ""
Write-Log "=== Phase 17: Event Log File Purge ===" "PHASE"
Write-Log "Clearing and removing .evtx log files..."

# Clear all event logs first (in case service is still running)
try {
    Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            [System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog($_.LogName)
        } catch { }
    }
    Write-Log "  Cleared all event logs via API" "OK"
} catch {
    Write-Log "  [warn] Event log clear via API failed (may already be nuked)" "WARN"
}

# Delete .evtx files
$evtxDir = "$env:SystemRoot\System32\winevt\Logs"
if (Test-Path $evtxDir) {
    Take-Ownership $evtxDir | Out-Null
    $null = cmd /c "takeown /f `"$evtxDir`" /r /d y >nul 2>&1"
    $null = cmd /c "icacls `"$evtxDir`" /grant Administrators:F /t >nul 2>&1"
    $evtxFiles = Get-ChildItem $evtxDir -Filter "*.evtx" -ErrorAction SilentlyContinue
    $evtxCount = 0
    foreach ($f in $evtxFiles) {
        Remove-Item $f.FullName -Force -ErrorAction SilentlyContinue
        $evtxCount++
    }
    Write-Log "  [del] $evtxCount .evtx files from winevt\Logs" "OK"
}

# Also clear ETL log files from diagnostics directories
$etlDirs = @(
    "$env:SystemRoot\System32\LogFiles\WMI",
    "$env:SystemRoot\System32\LogFiles\Srt",
    "$env:ProgramData\Microsoft\Diagnosis\ETLLogs",
    "$env:SystemRoot\Logs\CBS",
    "$env:SystemRoot\Logs\DISM",
    "$env:SystemRoot\Logs\MoSetup",
    "$env:SystemRoot\Logs\NetSetup",
    "$env:SystemRoot\Logs\DPX",
    "$env:SystemRoot\Panther"
)

foreach ($dir in $etlDirs) {
    if (Test-Path $dir) {
        $files = Get-ChildItem $dir -Recurse -Include "*.etl","*.log","*.txt","*.xml" -ErrorAction SilentlyContinue
        $count = 0
        foreach ($f in $files) {
            Remove-Item $f.FullName -Force -ErrorAction SilentlyContinue
            $count++
        }
        if ($count -gt 0) {
            Write-Log "  [del] $count log files from $dir" "OK"
        }
    }
}

# ============================================================================
#  Phase 18: Post-Boot Service Recovery (audiosrv + DHCP)
# ============================================================================

Write-Log ""
Write-Log "=== Phase 18: Post-Boot Service Recovery ===" "PHASE"
Write-Log "Installing service recovery for audiosrv + Dhcp..."

# SYSTEM-level service that restarts broken services at boot (no Task Scheduler needed)
$svcRecoveryScript = @'
@echo off
:: Runs as SYSTEM via service -- no UAC prompt, no Task Scheduler
timeout /t 10 /nobreak >nul
net stop audiosrv /y >nul 2>&1
net start audiosrv >nul 2>&1
net stop Dhcp /y >nul 2>&1
net start Dhcp >nul 2>&1
'@

$svcRecoveryPath = "$env:SystemRoot\PostBootRecoverySvc.cmd"
Set-Content -Path $svcRecoveryPath -Value $svcRecoveryScript -Force -Encoding ASCII
Write-Log "  Created recovery script: $svcRecoveryPath"

# Remove existing service if present
$null = cmd /c "sc.exe stop PostBootRecovery >nul 2>&1"
$null = cmd /c "sc.exe delete PostBootRecovery >nul 2>&1"

# Create delayed-auto service (runs as SYSTEM before logon)
$null = cmd /c "sc.exe create PostBootRecovery binPath= `"cmd.exe /c $svcRecoveryPath`" type= own start= delayed-auto error= ignore >nul 2>&1"

if ($LASTEXITCODE -eq 0) {
    Write-Log "  [OK] PostBootRecovery service created (delayed-auto, runs as SYSTEM)" "OK"
} else {
    # Fallback: HKLM Run key with self-elevating wrapper
    Write-Log "  [warn] Service creation failed, falling back to Run key..." "WARN"

    $elevatedRecoveryScript = @'
@echo off
net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -WindowStyle Hidden -Command "Start-Process '%~f0' -Verb RunAs -WindowStyle Hidden"
    exit /b
)
timeout /t 8 /nobreak >nul
net stop audiosrv /y >nul 2>&1
net start audiosrv >nul 2>&1
net stop Dhcp /y >nul 2>&1
net start Dhcp >nul 2>&1
'@

    $recoveryPath = "$env:SystemRoot\PostBootRecovery.cmd"
    Set-Content -Path $recoveryPath -Value $elevatedRecoveryScript -Force -Encoding ASCII
    $runKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    Set-ItemProperty -Path $runKeyPath -Name "PostBootRecovery" -Value $recoveryPath -Type String -Force
    Write-Log "  [set] HKLM Run\PostBootRecovery (fallback with UAC flash)" "OK"
}

# ============================================================================
#  Summary
# ============================================================================

Write-Log ""
Write-Log "=== Unified Amputation Complete ===" "PHASE"
Write-Log ""
Write-Log "Log: $LogFile"
Write-Log ""

$logContent = Get-Content $LogFile -ErrorAction SilentlyContinue
$delCount = ($logContent | Select-String "\[del\]").Count
$rebootCount = ($logContent | Select-String "\[reboot\]").Count
$deployCount = ($logContent | Select-String "\[deploy\]").Count
$disabledCount = ($logContent | Select-String "\[disabled\]").Count
$skipCount = ($logContent | Select-String "\[skip\]").Count
$warnCount = ($logContent | Select-String "\[warn\]").Count

Write-Log "Deleted:    $delCount items" "OK"
Write-Log "Deployed:   $deployCount stubs" "OK"
Write-Log "Disabled:   $disabledCount features" "OK"
Write-Log "Reboot-del: $rebootCount items" "WARN"
Write-Log "Skipped:    $skipCount items"
Write-Log "Warnings:   $warnCount items"
Write-Log ""
Write-Log "REBOOT REQUIRED" "WARN"
Write-Log ""

$reboot = Read-Host "Reboot now? (y/N)"
if ($reboot -eq "y" -or $reboot -eq "Y") {
    Write-Log "Rebooting..."
    Restart-Computer -Force
}
