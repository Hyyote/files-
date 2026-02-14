# Unified OS Amputation Kit
**Run with NSudo System privileges.**

Merged from: **DiagnosticRemoval** + **WER Stub** + additional optimizations.

**No backups are created. No restore points. This is irreversible.**

## What It Does

| Phase | Description |
|-------|-------------|
| 1 | Delete diagnostic/telemetry services (DPS, PcaSvc, CDPSvc, WerSvc, DiagTrack, Ndu, etc.) + per-user templates |
| 2 | Remove diagnostic + tracing binaries (DiagHub, PCA, SgrmBroker, CDP, logman, tracerpt, wpr, perfhost, MRT, etc.) |
| 3 | Purge scheduled tasks (diagnostics, telemetry, feedback, compat, WER) |
| 4 | Kill ETW autologger sessions (expanded: EventLog-System/App/Security, PerfTrack, CldFlt, StorLog, etc.) |
| 5 | Event Log + ETW Infrastructure Nuke (WINEVT Channels, Publishers, Autologger tree, GlobalLogger) |
| 6 | Remove per-user service template DLLs |
| 7 | Compatibility engine cleanup (shim cache, appraiser, SDB files) |
| 8 | Artifact purge (crash dumps, WER reports, telemetry data, per-user caches) |
| 9 | WER registry nuke (all policies disabled, crash dumps off, AeDebug cleaned) |
| 10 | WER binary removal + stub wer.dll deployment (x64 + x86) |
| 11 | WER kernel driver disable (werkernel.sys) + optional feature |
| 12 | Task Manager deletion (Taskmgr.exe) |
| 13 | .NET / WCF / WAS feature disable via DISM (expanded: all WCF sub-features, PowerShell v2, WAS, WIF) |
| 14 | Tracing infrastructure registry nuke (WPP tree, FTH, SQM, AppCompat telemetry, kernel perf logging) |
| 15 | .NET / CLR tracing disable (ETW providers, NGEN service, DOTNET_CLI_TELEMETRY_OPTOUT, COMPlus_EnableDiagnostics) |
| 16 | Performance counter cleanup (orphaned perf keys, global collection disable) |
| 17 | Event log file purge (.evtx files + ETL logs + CBS/DISM/Setup logs) |
| 18 | Post-boot service recovery for audiosrv + DHCP (works without Task Scheduler) |

## Files

| File | Purpose |
|------|---------|
| `Nuke.bat` | Launcher (self-elevates) |
| `Nuke.ps1` | Main script (18 phases) |
| `wer.dll` | Pre-compiled x64 WER stub |
| `wer32.dll` | Pre-compiled x86 WER stub |
| `wer_stub.c` | Stub source (not needed at runtime) |
| `wer_stub.def` | Stub exports (not needed at runtime) |

## Usage

1. Extract the zip
2. Run `Nuke.bat`
3. Reboot when prompted

## What's New (vs previous version)

**Phase 1 additions:** DiagTrack, GraphicsPerfSvc, Ndu, dmwappushservice, DmEnrollmentSvc, FileTrace, PerfHost, pla, SstpSvc, WbioSrvc, wisvc, WpcMonSvc

**Phase 2 additions:** logman.exe, tracerpt.exe, typeperf.exe, relog.exe, wpr.exe, wprui.exe, wevtutil.exe, perfhost.exe, perfmon.exe, psr.exe, mdsched.exe, msdt.exe, mdm.exe, MRT.exe, sdclt.exe, wsreset.exe, systemreset.exe, diagtrack.dll, diagtrackrunner.exe, RacEngn.dll, RACAgent.exe

**Phase 4 additions:** EventLog-System/Application/Security, NetCore, PerfTrack, CldFlt, ScreenOnPowerStudyTraceSession, StorLog, IOLOGGER, WindowsUpdate, WinPhoneCritical, AIT, SecurityHealthService, BioEnrollment

**Phase 13 expansion:** WCF-HTTP-Activation, WCF-HTTP-Activation45, WCF-MSMQ-Activation45, WCF-Pipe-Activation45, WCF-NonHTTP-Activation, WCF-TCP-Activation45, NetFx4Extended-ASPNET45, Windows-Identity-Foundation, MicrosoftWindowsPowerShellV2Root, MicrosoftWindowsPowerShellV2, WAS-WindowsActivationService, WAS-ProcessModel, WAS-ConfigurationAPI, WAS-NetFxEnvironment

**New Phase 14:** WPP software tracing tree removal, boot/shutdown trace disable, WMI security cleanup, FTH disable, SQM disable, AppCompat telemetry policy, kernel perf logging disable

**New Phase 15:** .NET ETWEnabled=0, CLR ETW provider GUID removal (DotNETRuntime, DotNETRuntimeRundown, DotNETRuntimeStress, DotNETRuntimePrivate), NGEN service disable, DOTNET_CLI_TELEMETRY_OPTOUT=1, COMPlus_EnableDiagnostics=0

**New Phase 16:** Orphaned performance counter subkey removal, global perf counter collection disable

**New Phase 17:** .evtx file deletion, ETL log cleanup, CBS/DISM/Setup/Panther log purge

## Post-Boot Service Recovery

Since Task Scheduler is broken on certain builds, the script installs a **delayed-auto service** (`PostBootRecovery`) that runs as SYSTEM at boot. It waits 10 seconds, then restarts `audiosrv` and `Dhcp`.

To remove the recovery mechanism later:
```
sc.exe stop PostBootRecovery
sc.exe delete PostBootRecovery
del C:\Windows\PostBootRecoverySvc.cmd
```
