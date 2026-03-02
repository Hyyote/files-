
@echo Disable Firewall
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" /v "DisableNotifications" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" /v "DoNotAllowExceptions" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" /v "EnableFirewall" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" /v "DisableNotifications" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" /v "DoNotAllowExceptions" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" /v "EnableFirewall" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /v "DisableNotifications" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /v "DoNotAllowExceptions" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /v "EnableFirewall" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /f >nul 2>&1
reg delete "HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /f >nul 2>&1


@echo Disable Power Savings on Drives.
for /f "tokens=*" %%i in ('reg query "HKLM\SYSTEM\CurrentControlSet\Enum" /s /f "StorPort"^| findstr "StorPort"') do reg add "%%i" /v "EnableIdlePowerManagement" /t REG_DWORD /d "0" /f >nul 2>&1

:: Disable MMCSS
reg add "HKLM\SYSTEM\CurrentControlSet\Services\MMCSS" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d 4294967295 /f >nul 2>&1

@echo Services
reg add "HKLM\SYSTEM\CurrentControlSet\Services\acpipagr" /v Start /t REG_DWORD /d 4 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AcpiPmi" /v Start /t REG_DWORD /d 4 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\acpitime" /v Start /t REG_DWORD /d 4 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\bam" /v Start /t REG_DWORD /d 4 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\dam" /v Start /t REG_DWORD /d 4 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service" /v Start /t REG_DWORD /d 4 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\diagtrack" /v Start /t REG_DWORD /d 4 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\diagsvc" /v Start /t REG_DWORD /d 4 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\dps" /v Start /t REG_DWORD /d 4 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\dusmsvc" /v Start /t REG_DWORD /d 4 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DSSvc" /v Start /t REG_DWORD /d 4 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\GpuEnergyDrv" /v Start /t REG_DWORD /d 4 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\intelpmt" /v Start /t REG_DWORD /d 4 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\kdnic" /v Start /t REG_DWORD /d 4 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\McpManagementService" /v Start /t REG_DWORD /d 4 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\pcasvc" /v Start /t REG_DWORD /d 4 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\pla" /v Start /t REG_DWORD /d 4 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\PrintDeviceConfigurationService" /v Start /t REG_DWORD /d 4 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\PrintNotify" /v Start /t REG_DWORD /d 4 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\PrintScanBrokerService" /v Start /t REG_DWORD /d 4 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\printworkflowusersvc" /v Start /t REG_DWORD /d 4 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\PRM" /v Start /t REG_DWORD /d 4 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\spooler" /v Start /t REG_DWORD /d 4 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\stisvc" /v Start /t REG_DWORD /d 4 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\svsvc" /v Start /t REG_DWORD /d 4 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Telemetry" /v Start /t REG_DWORD /d 4 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\troubleshootingsvc" /v Start /t REG_DWORD /d 4 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\usbprint" /v Start /t REG_DWORD /d 4 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WdiServiceHost" /v Start /t REG_DWORD /d 4 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WdiSystemHost" /v Start /t REG_DWORD /d 4 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Wecsvc" /v Start /t REG_DWORD /d 4 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\wercplsupport" /v Start /t REG_DWORD /d 4 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WerSvc" /v Start /t REG_DWORD /d 4 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WmiAcpi" /v Start /t REG_DWORD /d 4 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\wmiApSrv" /v Start /t REG_DWORD /d 4 /f >nul 2>&1


@echo Disable UAC
reg add "HKLM\SYSTEM\CurrentControlSet\Services\luafv" /v "Start" /t REG_DWORD /d 4 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "PromptOnSecureDesktop" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ValidateAdminCodeSignatures" /t REG_DWORD /d 0 /f >nul 2>&1


@echo Configure Power Path
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "EnergySaverState" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "EmiPollingInterval" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "EventProcessorEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "EnergyEstimationEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "EmiTelemetryActivePollingInterval" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "EmiTelemetryCsPollingInterval" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "PmiPollingInterval" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "AllowAudioToEnableExecutionRequiredPowerRequests" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "AllowSystemRequiredPowerRequests" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "AlwaysComputeQosHints" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "Class1InitialUnparkCount" /t REG_DWORD /d "64" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "CoalescingFlushInterval" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "CustomizeDuringSetup" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DeepIoCoalescingEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DisableDisplayBurstOnPowerSourceChange" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DisableInboxPepGeneratedConstraints" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DisableVsyncLatencyUpdate" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DripsSwHwDivergenceEnableLiveDump" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "EnableInputSuppression" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "EnforceAusterityMode" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "IdleProcessorsRequireQosManagement" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "IgnoreCsComplianceCheck" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "IpiLastClockOwnerDisable" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LidReliabilityState" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "PerfCalculateActualUtilization" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "PerfCheckTimerImplementation" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "PoFxSystemIrpWaitForReportDevicePowered" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "StandbyConnectivityGracePeriod" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "TimerRebaseThresholdOnDripsExit" /t REG_DWORD /d "60" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "TtmEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "Win32kCalloutWatchdogTimeoutSeconds" /t REG_DWORD /d "0" /f >nul 2>&1


@echo Disable Write Cache Buffer Flashing
for /f "delims=" %%k in ('reg Query HKLM\SYSTEM\CurrentControlSet\Enum /f "{4d36e967-e325-11ce-bfc1-08002be10318}" /d /s ^| find "HKEY"') do (
    reg add "%%k\Device Parameters\Disk" /v "UserWriteCacheSetting" /t REG_DWORD /d 0 /f >nul 2>&1
)


@echo Error Reporting
reg add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d "1" /f >nul 2>&1


@echo Disable GameBar
reg add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\GameBar" /v "GamePanelStartupTipIndex" /t REG_DWORD /d "3" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\GameBar" /v "ShowStartupPanel" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\GameBar" /v "UseNexusForGameBarEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Gaming.GameBar.PresenceServer.Internal.PresenceWriter" /v "ActivationType" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" /v "value" /t REG_DWORD /d "0" /f >nul 2>&1


@echo Variables to Disable Telemetry
setx POWERSHELL_TELEMETRY_OPTOUT 1 >nul 2>&1
setx DOTNET_CLI_TELEMETRY_OPTOUT 1 >nul 2>&1


@echo Game Mode
reg add "HKCU\SOFTWARE\Microsoft\MediaPlayer\Preferences" /v "UsageTracking" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\GameBar" /v "AllowAutoGameMode" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\GameBar" /v "AutoGameModeEnabled" /t REG_DWORD /d 0 /f >nul 2>&1


@echo Disable Timer Coalescing
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v "TimerCoalescing" /t REG_BINARY /d 0000000000000000000000000000000000000000000000000000000000000000 /f >nul 2>&1


@echo Disable USB Powersavings
powershell.exe -command "Get-WmiObject MSPower_DeviceEnable -Namespace root\wmi | ForEach-Object { $_.enable = $false; $_.psbase.put(); }" >nul 2>&1
powershell -ExecutionPolicy Bypass -Command "iex ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('aWYgKC1ub3QgKFtTZWN1cml0eS5QcmluY2lwYWwuV2luZG93c1ByaW5jaXBhbF0gW1NlY3VyaXR5LlByaW5jaXBhbC5XaW5kb3dzSWRlbnRpdHldOjpHZXRDdXJyZW50KCkpLklzSW5Sb2xlKFtTZWN1cml0eS5QcmluY2lwYWwuV2luZG93c0J1aWx0SW5Sb2xlXSAiQWRtaW5pc3RyYXRvciIpKSB7DQogICAgU3RhcnQtUHJvY2VzcyBwb3dlcnNoZWxsICItRmlsZSBgIiRQU0NvbW1hbmRQYXRoYCIiIC1WZXJiIFJ1bkFzDQogICAgZXhpdA0KfQ0KDQpmdW5jdGlvbiBEaXNhYmxlLVVTQlBvd2VyTWFuYWdlbWVudCB7DQogICAgcGFyYW0gKA0KICAgICAgICBbc3RyaW5nXSRDbGFzc05hbWUNCiAgICApDQoNCiAgICAkaHVicyA9IEdldC1XbWlPYmplY3QgLUNsYXNzICRDbGFzc05hbWUNCiAgICAkcG93ZXJNZ210ID0gR2V0LVdtaU9iamVjdCAtQ2xhc3MgTVNQb3dlcl9EZXZpY2VFbmFibGUgLU5hbWVzcGFjZSByb290XHdtaQ0KDQogICAgZm9yZWFjaCAoJHAgaW4gJHBvd2VyTWdtdCkgew0KICAgICAgICAkSU4gPSAkcC5JbnN0YW5jZU5hbWUuVG9VcHBlcigpDQogICAgICAgIGZvcmVhY2ggKCRoIGluICRodWJzKSB7DQogICAgICAgICAgICAkUE5QREkgPSAkaC5QTlBEZXZpY2VJRA0KICAgICAgICAgICAgaWYgKCRJTiAtbGlrZSAiKiRQTlBESSoiKSB7DQogICAgICAgICAgICAgICAgV3JpdGUtSG9zdCAiaW5mbzogY29uZmlndXJpbmcgJElOIg0KICAgICAgICAgICAgICAgICRwLmVuYWJsZSA9ICRGYWxzZQ0KICAgICAgICAgICAgICAgICRwLnBzYmFzZS5wdXQoKSB8IE91dC1OdWxsDQogICAgICAgICAgICB9DQogICAgICAgIH0NCiAgICB9DQp9DQpEaXNhYmxlLVVTQlBvd2VyTWFuYWdlbWVudCAtQ2xhc3NOYW1lICdXaW4zMl9VU0JDb250cm9sbGVyJw0KRGlzYWJsZS1VU0JQb3dlck1hbmFnZW1lbnQgLUNsYXNzTmFtZSAnV2luMzJfVVNCQ29udHJvbGxlckRldmljZScNCkRpc2FibGUtVVNCUG93ZXJNYW5hZ2VtZW50IC1DbGFzc05hbWUgJ1dpbjMyX1VTQkh1YicNCg==')))" >nul 2>&1
set "REG_PATH=HKLM\SYSTEM\CurrentControlSet\Control\usbflags"
for /f "tokens=*" %%i in ('reg query "%REG_PATH%" 2^>nul ^| findstr /r "[0-9A-F]\{12\}"') do (
    set "DEVICE_KEY=%%i"
    
    for /f "tokens=*" %%a in ("!DEVICE_KEY:%REG_PATH%\=!") do (
        set "DEVICE_ID=%%a"
        
        echo !DEVICE_ID! | findstr /r /c:"^[0-9A-F]\{12\}$" >nul 2>&1
        if !errorlevel! EQU 0 ( 
            reg add "%REG_PATH%\!DEVICE_ID!" /v "DisableLPM" /t REG_DWORD /d "1" /f >nul 2>&1
        )
    )
)
set "USB_ENUM_PATH=HKLM\SYSTEM\CurrentControlSet\Enum\USB" >nul 2>&1
for /f "tokens=*" %%d in ('reg query "%USB_ENUM_PATH%" 2^>nul') do (
    set "DEVICE_PATH=%%d"
    
    for /f "tokens=*" %%i in ('reg query "!DEVICE_PATH!" 2^>nul') do (
        set "INSTANCE_PATH=%%i"
        
            reg query "!INSTANCE_PATH!\Device Parameters" >nul 2>&1
            if !errorlevel! EQU 0 (
                reg add "!INSTANCE_PATH!\Device Parameters" /v "AllowIdleIrpInD3" /t REG_DWORD /d "0" /f >nul 2>&1
                reg add "!INSTANCE_PATH!\Device Parameters" /v "DeviceSelectiveSuspended" /t REG_DWORD /d "0" /f >nul 2>&1
                reg add "!INSTANCE_PATH!\Device Parameters" /v "IdleTimeoutPeriodInMilliSec" /t REG_DWORD /d "0" /f >nul 2>&1
                reg add "!INSTANCE_PATH!\Device Parameters" /v "EnhancedPowerManagementEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
                reg add "!INSTANCE_PATH!\Device Parameters" /v "EnhancedPowerManagementUseMonitor" /t REG_DWORD /d "0" /f >nul 2>&1
                reg add "!INSTANCE_PATH!\Device Parameters" /v "SelectiveSuspendEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
                reg add "!INSTANCE_PATH!\Device Parameters" /v "SelectiveSuspendTimeout" /t REG_DWORD /d "0" /f >nul 2>&1
                reg add "!INSTANCE_PATH!\Device Parameters" /v "SuppressInputInCS" /t REG_DWORD /d "0" /f >nul 2>&1
                reg add "!INSTANCE_PATH!\Device Parameters" /v "SystemInputSuppressionEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
                
                reg query "!INSTANCE_PATH!\Device Parameters\Wdf" >nul 2>&1
                if !errorlevel! EQU 0 (
                    reg add "!INSTANCE_PATH!\Device Parameters\Wdf" /v "IdleInWorkingState" /t REG_DWORD /d "0" /f >nul 2>&1
                    reg add "!INSTANCE_PATH!\Device Parameters\Wdf" /v "SleepstudyState" /t REG_DWORD /d "0" /f >nul 2>&1
                    reg add "!INSTANCE_PATH!\Device Parameters\Wdf" /v "WdfDefaultIdleInWorkingState" /t REG_DWORD /d "0" /f >nul 2>&1
                    reg add "!INSTANCE_PATH!\Device Parameters\Wdf" /v "WdfDirectedPowerTransitionChildrenOptional" /t REG_DWORD /d "0" /f >nul 2>&1
                    reg add "!INSTANCE_PATH!\Device Parameters\Wdf" /v "WdfDirectedPowerTransitionEnable" /t REG_DWORD /d "0" /f >nul 2>&1
                    reg add "!INSTANCE_PATH!\Device Parameters\Wdf" /v "WdfUseWdfTimerForPofx" /t REG_DWORD /d "0" /f >nul 2>&1
                )
            )
        )
    )
    set "ROOT_HUB_PATH=HKLM\SYSTEM\CurrentControlSet\Enum\USB\ROOT_HUB30" >nul 2>&1
    if exist "%ROOT_HUB_PATH%" (
        for /f "tokens=*" %%r in ('reg query "%ROOT_HUB_PATH%" 2^>nul') do (
            set "HUB_PATH=%%r"
            reg add "!HUB_PATH!\Device Parameters\Wdf" /v "IdleInWorkingState" /t REG_DWORD /d "0" /f >nul 2>&1
            reg add "!HUB_PATH!\Device Parameters\Wdf" /v "SleepstudyState" /t REG_DWORD /d "0" /f >nul 2>&1
            reg add "!HUB_PATH!\Device Parameters\Wdf" /v "WdfDefaultIdleInWorkingState" /t REG_DWORD /d "0" /f >nul 2>&1
            reg add "!HUB_PATH!\Device Parameters\Wdf" /v "WdfDirectedPowerTransitionChildrenOptional" /t REG_DWORD /d "0" /f >nul 2>&1
            reg add "!HUB_PATH!\Device Parameters\Wdf" /v "WdfDirectedPowerTransitionEnable" /t REG_DWORD /d "0" /f >nul 2>&1
            reg add "!HUB_PATH!\Device Parameters\Wdf" /v "WdfUseWdfTimerForPofx" /t REG_DWORD /d "0" /f >nul 2>&1
        )
    )
for %%i in (
	"EnhancedPowerManagementEnabled"
	"AllowIdleIrpInD3"
	"DeviceSelectiveSuspended"
	"DeviceResetNotificationEnabled"
	"SelectiveSuspendEnabled"
	"WaitWakeEnabled"
	"D3ColdSupported"
	"DisableD3Cold"
	"WdfDirectedPowerTransitionEnable"
	"EnableIdlePowerManagement"
	"IdleInWorkingState"
	"IdleTimeoutInMS"
	"MinimumIdleTimeoutInMS"
	"EnableHIPM"
	"EnableHDDParking"
	"EnableDIPM"
) do (
    for /f "delims=" %%k in ('reg query "HKLM\SYSTEM\CurrentControlSet\Enum" /s /f "%%~i" ^| findstr "HK"') do (
        reg add "%%k" /v "%%~i" /t reg_dword /d 0 /f >nul 2>&1
    )
)


@echo Disable Power Management
for %%i in (
	"DisableIdlePowerManagement"
	"DisableRuntimePowerManagement"
) do (
    for /f "delims=" %%k in ('reg query "HKLM\SYSTEM\CurrentControlSet\Enum" /s /f "%%~i" ^| findstr "HK"') do (
        reg add "%%k" /v "%%~i" /t reg_dword /d 1 /f >nul 2>&1
    )
)


@echo USB Flags
reg add "HKLM\SYSTEM\CurrentControlSet\Control\usbflags" /v "DisableHCS0Idle" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\usbflags" /v "Allow64KLowOrFullSpeedControlTransfers" /t REG_DWORD /d "1" /f >nul 2>&1


@echo Wake On Input
reg add "HKLM\SYSTEM\Input" /v "WakeOnInputDeviceTypes" /t REG_DWORD /d "0" /f >nul 2>&1


@echo Wdf
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Wdf" /v "WdfGlobalLogsDisabled" /t REG_DWORD /d "1" /f >nul 2>&1


@echo Tagged Energy
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy" /v "DisableTaggedEnergyLogging" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy" /v "TelemetryMaxApplication" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy" /v "TelemetryMaxTagPerApplication" /t REG_DWORD /d "0" /f >nul 2>&1


@echo Broker Infrastructure
reg add "HKLM\SYSTEM\CurrentControlSet\Services\BrokerInfrastructure\Parameters" /v "ActivityCheckTimerLowPowerPeriodMs" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\BrokerInfrastructure\Parameters" /v "ActivityCheckTimerPeriodMs" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\BrokerInfrastructure\Parameters" /v "AlternateCancellationTimeout" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\BrokerInfrastructure\Parameters" /v "DisableTriggerCoalescing" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\BrokerInfrastructure\Parameters" /v "DefaultTriggerCoalescingTime" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\BrokerInfrastructure\Parameters" /v "EnergyBudgetDisabled" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\BrokerInfrastructure\Parameters" /v "EnergyBudgetBgTaskPercentage" /t REG_DWORD /d "100" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\BrokerInfrastructure\Parameters" /v "EnergyBudgetClearDebtOnFg" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\BrokerInfrastructure\Parameters" /v "EnergyBudgetDebtCancellationDisabled" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\BrokerInfrastructure\Parameters" /v "EnergyBudgetInfiniteOnFg" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\BrokerInfrastructure\Parameters" /v "GlobalCoalesceMaxAdditionalTasksPerWake" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\BrokerInfrastructure\Parameters" /v "GlobalCoalesceMaxEarlyFireWindowMs" /t REG_DWORD /d "0" /f >nul 2>&1

@echo Sticky Keys
reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "506" /f >nul 2>&1

@echo Svc Host Split Threshold
reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "4294967295" /f >nul 2>&1

@echo Power Throtting
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f >nul 2>&1

@echo Hibernation
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "AllowHibernate" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HiberbootEnabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabledDefault" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateChecksummingEnabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "SkipHibernateMemoryMapValidation" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HiberFileSizePercent" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "EnableMinimalHiberFile" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\ForceHibernateDisabled" /v "Policy" /t REG_DWORD /d 1 /f >nul 2>&1
powercfg -h off


@echo Disable Sleep Study
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "SleepStudyDisabled" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "SleepStudyDeviceAccountingLevel" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "SleepstudyAccountingEnabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Wdf" /v "WdfGlobalSleepStudyDisabled" /t REG_DWORD /d "1" /f >nul 2>&1
wevtutil.exe set-log "Microsoft-Windows-SleepStudy/Diagnostic" /e:false >nul 2>&1
wevtutil.exe set-log "Microsoft-Windows-Kernel-Processor-Power/Diagnostic" /e:false >nul 2>&1
wevtutil.exe set-log "Microsoft-Windows-UserModePowerService/Diagnostic" /e:false >nul 2>&1
icacls "C:\Windows\System32\SleepStudy" /remove:g SYSTEM >nul 2>&1
icacls "C:\Windows\System32\SleepStudy" /remove:g Administrators >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Wdf" /v "WdfGlobalSleepStudyDisabled" /t REG_DWORD /d "1" /f >nul 2>&1


@echo Disable Modern Standby
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "PlatformAoAcOverride" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "PlatformRoleOverride" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MSDisabled" /t REG_DWORD /d 1 /f >nul 2>&1


@echo Kernel
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "TimerCheckFlags" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "SerializeTimerExpiration" /t REG_DWORD /d 2 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableControlFlowGuardXfg" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableExceptionChainValidation" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "HyperStartDisabled" /t REG_DWORD /d 1 /f >nul 2>&1
:: reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "ThreadDpcEnable" /t REG_DWORD /d "0" /f >nul 2>&1


@echo Configuration Manager
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Configuration Manager" /v "BugcheckRecoveryEnabled" /t REG_DWORD /d 0 /f >nul 2>&1


@echo Power
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "WatchdogResumeTimeout" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "WatchdogSleepTimeout" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "Win32CalloutWatchdogBugcheckEnabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "IdleScanInterval" /t REG_DWORD /d 0 /f >nul 2>&1


@echo I/O System
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "DisableDiskCounters" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "IoAllowLoadCrashDumpDriver" /t REG_DWORD /d 0 /f >nul 2>&1



@echo Memory Path config
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettings" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "536870915" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d "536870915" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePagingExecutive" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePageCombining" /t REG_DWORD /d 1 /f >nul 2>&1



@echo Edge
reg add "HKLM\Software\Policies\Microsoft\Windows\EdgeUI" /v "DisableMFUTracking" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\Software\Policies\Microsoft\MicrosoftEdge\Main" /v "AllowPrelaunch" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\Software\Microsoft\EdgeUpdate" /v "DoNotUpdateToEdgeWithChromium" /t REG_DWORD /d "0" /f >nul 2>&1


@echo Background Apps 
reg add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsRunInBackground" /t REG_DWORD /d "2" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BackgroundAppGlobalToggle" /t REG_DWORD /d "0" /f >nul 2>&1


@echo Remove Shortcut Text
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\NamingTemplates" /v "ShortcutNameTemplate" /t REG_SZ /d "\"%s.lnk\"" /f >nul 2>&1


@echo Show Hidden Files and File Extensions
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d "0" /f >nul 2>&1


@echo Remove SendTo Context Menu
reg delete "HKCR\AllFilesystemObjects\shellex\ContextMenuHandlers\SendTo" /f >nul 2>&1
reg delete "HKCR\UserLibraryFolder\shellex\ContextMenuHandlers\SendTo" /f >nul 2>&1


@echo Block Cast To Device
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" /v "{7AD84985-87B4-4a16-BE58-8B72A5B390F7}" /t REG_SZ /d "" /f >nul 2>&1


@echo Remove Extract All Context Menu
reg delete "HKCR\CompressedFolder\ShellEx\ContextMenuHandlers\{b8cdcb65-b1bf-4b42-9428-1dfdb7ee92af}" /f >nul 2>&1
reg delete "HKCR\SystemFileAssociations\.zip\ShellEx\ContextMenuHandlers\{b8cdcb65-b1bf-4b42-9428-1dfdb7ee92af}" /f >nul 2>&1


@echo Disable Location Sensors
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableSensors" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableWindowsLocationProvider" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocationScripting" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocation" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\FindMyDevice" /v "AllowFindMyDevice" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\FindMyDevice" /v "LocationSyncEnabled" /t REG_DWORD /d "0" /f >nul 2>&1


@echo Remove Give Access To Context Menu
reg delete "HKCR\*\shellex\ContextMenuHandlers\Sharing" /f >nul 2>&1
reg delete "HKCR\Directory\Background\shellex\ContextMenuHandlers\Sharing" /f >nul 2>&1
reg delete "HKCR\Directory\shellex\ContextMenuHandlers\Sharing" /f >nul 2>&1
reg delete "HKCR\Drive\shellex\ContextMenuHandlers\Sharing" /f >nul 2>&1
reg delete "HKCR\LibraryFolder\background\shellex\ContextMenuHandlers\Sharing" /f >nul 2>&1
reg delete "HKCR\UserLibraryFolder\shellex\ContextMenuHandlers\Sharing" /f >nul 2>&1


@echo Remove Include in Library Context Menu
reg delete "HKCR\Folder\ShellEx\ContextMenuHandlers\Library Location" /f >nul 2>&1


@echo Disable Map Network Drive/Disconnect Network Drive
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoNetConnectDisconnect" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoNetConnectDisconnect" /t REG_DWORD /d "1" /f >nul 2>&1


@echo Remove New RTF
reg delete "HKCR\.rtf\ShellNew" /f >nul 2>&1


@echo Remove Previous Versions
reg delete "HKCR\AllFilesystemObjects\shellex\PropertySheetHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}" /f >nul 2>&1
reg delete "HKCR\CLSID\{450D8FBA-AD25-11D0-98A8-0800361B1103}\shellex\PropertySheetHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}" /f >nul 2>&1
reg delete "HKCR\Directory\shellex\PropertySheetHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}" /f >nul 2>&1
reg delete "HKCR\Drive\shellex\PropertySheetHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}" /f >nul 2>&1
reg delete "HKCR\AllFilesystemObjects\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}" /f >nul 2>&1
reg delete "HKCR\CLSID\{450D8FBA-AD25-11D0-98A8-0800361B1103}\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}" /f >nul 2>&1
reg delete "HKCR\Directory\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}" /f >nul 2>&1
reg delete "HKCR\Drive\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}" /f >nul 2>&1
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "NoPreviousVersionsPage" /f >nul 2>&1
reg delete "HKCU\SOFTWARE\Policies\Microsoft\PreviousVersions" /v "DisableLocalPage" /f >nul 2>&1


@echo Search Settings
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" /v "IsAADCloudSearchEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" /v "IsDeviceSearchHistoryEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" /v "IsMSACloudSearchEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" /v "SafeSearchMode" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "EnableDynamicContentInWSB" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "DisableSearchBoxSuggestions" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" /v "IsDynamicSearchBoxEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "SaveZoneInformation" /t REG_DWORD /d "1" /f >nul 2>&1


@echo Lightning
reg add "HKCU\Software\Microsoft\Lighting" /v "AmbientLightingEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Lighting" /v "ControlledByForegroundApp" /t REG_DWORD /d "0" /f >nul 2>&1


@echo Mouse Control Panel
reg add "HKCU\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "0" /f >nul 2>&1
reg add "HKCU\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d "0" /f >nul 2>&1
reg add "HKCU\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d "0" /f >nul 2>&1
reg add "HKCU\Control Panel\Mouse" /v "RawMouseThrottleEnabled" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKCU\Control Panel\Mouse" /v "RawMouseThrottleForced" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKCU\Control Panel\Mouse" /v "RawMouseThrottleDuration" /t REG_DWORD /d 20 /f >nul 2>&1
reg add "HKCU\Control Panel\Mouse" /v "RawMouseThrottleLeeway" /t REG_DWORD /d 0 /f >nul 2>&1


@echo Sync
reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSync" /t REG_DWORD /d "2" /f >nul 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSyncUserOverride" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableSyncOnPaidNetwork" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v "Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /v "Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /v "Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /v "Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync" /v "SyncPolicy" /t REG_DWORD /d "5" /f >nul 2>&1


@echo Disable Wake on Input
reg add "HKLM\SYSTEM\Input" /v "WakeOnInputDeviceTypes" /t REG_DWORD /d "0" /f >nul 2>&1


@echo Rebuild Performance Counters
lodctr /r >nul 2>&1
lodctr /r >nul 2>&1
winmgmt /resyncperf >nul 2>&1


@echo Network
for /f %%a in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}" /v "*SpeedDuplex" /s ^| findstr  "HKEY"') do (
    for /f %%i in ('reg query "%%a" /v "*ReceiveBuffers" ^| findstr "HKEY"') do (
        reg add "%%i" /v "*ReceiveBuffers" /t REG_SZ /d "2048" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "*TransmitBuffers" ^| findstr "HKEY"') do (
        reg add "%%i" /v "*TransmitBuffers" /t REG_SZ /d "1024" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "EnablePME" ^| findstr "HKEY"') do (
        reg add "%%i" /v "EnablePME" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "*DeviceSleepOnDisconnect" ^| findstr "HKEY"') do (
        reg add "%%i" /v "*DeviceSleepOnDisconnect" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "*EEE" ^| findstr "HKEY"') do (
        reg add "%%i" /v "*EEE" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "*ModernStandbyWoLMagicPacket" ^| findstr "HKEY"') do (
        reg add "%%i" /v "*ModernStandbyWoLMagicPacket" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "*SelectiveSuspend" ^| findstr "HKEY"') do (
        reg add "%%i" /v "*SelectiveSuspend" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "*WakeOnMagicPacket" ^| findstr "HKEY"') do (
        reg add "%%i" /v "*WakeOnMagicPacket" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "*WakeOnPattern" ^| findstr "HKEY"') do (
        reg add "%%i" /v "*WakeOnPattern" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "AutoPowerSaveModeEnabled" ^| findstr "HKEY"') do (
        reg add "%%i" /v "AutoPowerSaveModeEnabled" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "*DeviceSleepOnDisconnect" ^| findstr "HKEY"') do (
        reg add "%%i" /v "*DeviceSleepOnDisconnect" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "EEELinkAdvertisement" ^| findstr "HKEY"') do (
        reg add "%%i" /v "EEELinkAdvertisement" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "EeePhyEnable" ^| findstr "HKEY"') do (
        reg add "%%i" /v "EeePhyEnable" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "EnableGreenEthernet" ^| findstr "HKEY"') do (
        reg add "%%i" /v "EnableGreenEthernet" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "EnableModernStandby" ^| findstr "HKEY"') do (
        reg add "%%i" /v "EnableModernStandby" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "GigaLite" ^| findstr "HKEY"') do (
        reg add "%%i" /v "GigaLite" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "PnPCapabilities" ^| findstr "HKEY"') do (
        reg add "%%i" /v "PnPCapabilities" /t REG_DWORD /d "24" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "PowerDownPll" ^| findstr "HKEY"') do (
        reg add "%%i" /v "PowerDownPll" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "PowerSavingMode" ^| findstr "HKEY"') do (
        reg add "%%i" /v "PowerSavingMode" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "ReduceSpeedOnPowerDown" ^| findstr "HKEY"') do (
        reg add "%%i" /v "ReduceSpeedOnPowerDown" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "S5WakeOnLan" ^| findstr "HKEY"') do (
        reg add "%%i" /v "S5WakeOnLan" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "SavePowerNowEnabled" ^| findstr "HKEY"') do (
        reg add "%%i" /v "SavePowerNowEnabled" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "ULPMode" ^| findstr "HKEY"') do (
        reg add "%%i" /v "ULPMode" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "WakeOnLink" ^| findstr "HKEY"') do (
        reg add "%%i" /v "WakeOnLink" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "WakeOnSlot" ^| findstr "HKEY"') do (
        reg add "%%i" /v "WakeOnSlot" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "WakeUpModeCap" ^| findstr "HKEY"') do (
        reg add "%%i" /v "WakeUpModeCap" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "WaitAutoNegComplete" ^| findstr "HKEY"') do (
        reg add "%%i" /v "WaitAutoNegComplete" /t REG_SZ /d "0" /f
    )
    for /f %%i in ('reg query "%%a" /v "*FlowControl" ^| findstr "HKEY"') do (
        reg add "%%i" /v "*FlowControl" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "WolShutdownLinkSpeed" ^| findstr "HKEY"') do (
        reg add "%%i" /v "WolShutdownLinkSpeed" /t REG_SZ /d "2" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "WakeOnMagicPacketFromS5" ^| findstr "HKEY"') do (
        reg add "%%i" /v "WakeOnMagicPacketFromS5" /t REG_SZ /d "2" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "WolShutdownLinkSpeed" ^| findstr "HKEY"') do (
        reg add "%%i" /v "WolShutdownLinkSpeed" /t REG_SZ /d "2" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "*PMNSOffload" ^| findstr "HKEY"') do (
        reg add "%%i" /v "*PMNSOffload" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "*PMARPOffload" ^| findstr "HKEY"') do (
        reg add "%%i" /v "*PMARPOffload" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "*NicAutoPowerSaver" ^| findstr "HKEY"') do (
        reg add "%%i" /v "*NicAutoPowerSaver" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "*PMWiFiRekeyOffload" ^| findstr "HKEY"') do (
        reg add "%%i" /v "*PMWiFiRekeyOffload" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "EnablePowerManagement" ^| findstr "HKEY"') do (
        reg add "%%i" /v "EnablePowerManagement" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "ForceWakeFromMagicPacketOnModernStandby" ^| findstr "HKEY"') do (
        reg add "%%i" /v "ForceWakeFromMagicPacketOnModernStandby" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "WakeFromS5" ^| findstr "HKEY"') do (
        reg add "%%i" /v "WakeFromS5" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "WakeOn" ^| findstr "HKEY"') do (
        reg add "%%i" /v "WakeOn" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "OBFFEnabled" ^| findstr "HKEY"') do (
        reg add "%%i" /v "OBFFEnabled" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "DMACoalescing" ^| findstr "HKEY"') do (
        reg add "%%i" /v "DMACoalescing" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "EnableSavePowerNow" ^| findstr "HKEY"') do (
        reg add "%%i" /v "EnableSavePowerNow" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "EnableD0PHYFlexibleSpeed" ^| findstr "HKEY"') do (
        reg add "%%i" /v "EnableD0PHYFlexibleSpeed" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "EnablePHYWakeUp" ^| findstr "HKEY"') do (
        reg add "%%i" /v "EnablePHYWakeUp" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "EnablePHYFlexibleSpeed" ^| findstr "HKEY"') do (
        reg add "%%i" /v "EnablePHYFlexibleSpeed" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "AllowAllSpeedsLPLU" ^| findstr "HKEY"') do (
        reg add "%%i" /v "AllowAllSpeedsLPLU" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "*EnableDynamicPowerGating" ^| findstr "HKEY"') do (
        reg add "%%i" /v "*EnableDynamicPowerGating" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "EnableD3ColdInS0" ^| findstr "HKEY"') do (
        reg add "%%i" /v "EnableD3ColdInS0" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "LatencyToleranceReporting" ^| findstr "HKEY"') do (
        reg add "%%i" /v "LatencyToleranceReporting" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "EnableAspm" ^| findstr "HKEY"') do (
        reg add "%%i" /v "EnableAspm" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "LTROBFF" ^| findstr "HKEY"') do (
        reg add "%%i" /v "LTROBFF" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "S0MgcPkt" ^| findstr "HKEY"') do (
        reg add "%%i" /v "S0MgcPkt" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "*TCPChecksumOffloadIPv4" ^| findstr "HKEY"') do (
        reg add "%%i" /v "*TCPChecksumOffloadIPv4" /t REG_SZ /d "3" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "*TCPChecksumOffloadIPv6" ^| findstr "HKEY"') do (
        reg add "%%i" /v "*TCPChecksumOffloadIPv6" /t REG_SZ /d "3" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "*TCPConnectionOffloadIPv4" ^| findstr "HKEY"') do (
        reg add "%%i" /v "*TCPConnectionOffloadIPv4" /t REG_SZ /d "3" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "*TCPConnectionOffloadIPv6" ^| findstr "HKEY"') do (
        reg add "%%i" /v "*TCPConnectionOffloadIPv6" /t REG_SZ /d "3" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "*TCPUDPChecksumOffloadIPv4" ^| findstr "HKEY"') do (
        reg add "%%i" /v "*TCPUDPChecksumOffloadIPv4" /t REG_SZ /d "3" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "*TCPUDPChecksumOffloadIPv6" ^| findstr "HKEY"') do (
        reg add "%%i" /v "*TCPUDPChecksumOffloadIPv6" /t REG_SZ /d "3" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "*UDPChecksumOffloadIPv4" ^| findstr "HKEY"') do (
        reg add "%%i" /v "*UDPChecksumOffloadIPv4" /t REG_SZ /d "3" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "*UDPChecksumOffloadIPv6" ^| findstr "HKEY"') do (
        reg add "%%i" /v "*UDPChecksumOffloadIPv6" /t REG_SZ /d "3" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "*UdpRsc" ^| findstr "HKEY"') do (
        reg add "%%i" /v "*UdpRsc" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "**UsoIPv4" ^| findstr "HKEY"') do (
        reg add "%%i" /v "*UsoIPv4" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "*UsoIPv6" ^| findstr "HKEY"') do (
        reg add "%%i" /v "*UsoIPv6" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "*RscIPv6" ^| findstr "HKEY"') do (
        reg add "%%i" /v "*RscIPv6" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "*RscIPv4" ^| findstr "HKEY"') do (
        reg add "%%i" /v "*RscIPv4" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "*IPsecOffloadV2IPv4" ^| findstr "HKEY"') do (
        reg add "%%i" /v "*IPsecOffloadV2IPv4" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "*IPsecOffloadV2" ^| findstr "HKEY"') do (
        reg add "%%i" /v "*IPsecOffloadV2" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "*IPsecOffloadV1IPv4" ^| findstr "HKEY"') do (
        reg add "%%i" /v "*IPsecOffloadV1IPv4" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "*LsoV1IPv4" ^| findstr "HKEY"') do (
        reg add "%%i" /v "*LsoV1IPv4" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "*LsoV2IPv4" ^| findstr "HKEY"') do (
        reg add "%%i" /v "*LsoV2IPv4" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "*LsoV2IPv6" ^| findstr "HKEY"') do (
        reg add "%%i" /v "*LsoV2IPv6" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "*IPChecksumOffloadIPv4" ^| findstr "HKEY"') do (
        reg add "%%i" /v "*IPChecksumOffloadIPv4" /t REG_SZ /d "3" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "WakeFromPowerOff" ^| findstr "HKEY"') do (
        reg add "%%i" /v "WakeFromPowerOff" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "LogLinkStateEvent" ^| findstr "HKEY"') do (
        reg add "%%i" /v "LogLinkStateEvent" /t REG_SZ /d "16" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "*InterruptModeration" ^| findstr "HKEY"') do (
        reg add "%%i" /v "*InterruptModeration" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "ITR" ^| findstr "HKEY"') do (
        reg add "%%i" /v "ITR" /t REG_SZ /d "0" /f >nul 2>&1
    )
) >nul 2>&1


@echo Int Delays
for %%a in (TxIntDelay TxAbsIntDelay RxIntDelay RxAbsIntDelay) do (
    for /f "delims=" %%b in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}" /s /f "*SpeedDuplex" ^| findstr "HKEY"') do (
        reg add "%%b" /v "%%a" /t REG_SZ /d "0" /f >nul 2>&1
    )
)


@echo Network Binding
powershell Disable-NetAdapterBinding -Name "Ethernet" -ComponentID ms_lldp; Disable-NetAdapterBinding -Name "Ethernet" -ComponentID ms_msclient; Disable-NetAdapterBinding -Name "Ethernet" -ComponentID ms_lltdio; Disable-NetAdapterBinding -Name "Ethernet" -ComponentID ms_implat; Disable-NetAdapterBinding -Name "Ethernet" -ComponentID ms_rspndr; Disable-NetAdapterBinding -Name "Ethernet" -ComponentID ms_server >nul 2>&1


@echo Network Coalescing
powershell Set-NetOffloadGlobalSetting -ReceiveSegmentCoalescing Enable >nul 2>&1
powershell Set-NetOffloadGlobalSetting -PacketCoalescingFilter Disable >nul 2>&1


@echo BBr2
netsh int ipv6 set gl loopbacklargemtu=disable >nul 2>&1
netsh int ipv4 set gl loopbacklargemtu=disable >nul 2>&1
netsh int tcp set supplemental Template=Internet CongestionProvider=bbr2 >nul 2>&1
netsh int tcp set supplemental Template=Datacenter CongestionProvider=bbr2 >nul 2>&1
netsh int tcp set supplemental Template=Compat CongestionProvider=bbr2 >nul 2>&1
netsh int tcp set supplemental Template=DatacenterCustom CongestionProvider=bbr2 >nul 2>&1
netsh int tcp set supplemental Template=InternetCustom CongestionProvider=bbr2 >nul 2>&1


@echo Netsh Configuration
netsh int udp set global uro=disabled >nul 2>&1
netsh int tcp set global timestamps=disabled >nul 2>&1
netsh int tcp set security mpp=disabled >nul 2>&1
netsh int tcp set security profiles=disabled >nul 2>&1
netsh int ipv6 6to4 set state disabled >nul 2>&1
netsh int teredo set state disabled >nul 2>&1
netsh int isatap set state disabled >nul 2>&1
netsh int tcp set heuristics disabled >nul 2>&1
netsh int tcp set heuristics wsh=disabled >nul 2>&1


@echo NDIS
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NDIS\Parameters" /v "TrackNblOwner" /t REG_DWORD /d "0" /f >nul 2>&1


@echo Configure QoS Packet Scheduler
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" /v "NonBestEffortLimit" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" /v "TimerResolution" /t REG_DWORD /d 1 /f >nul 2>&1


@echo Disable Nagle Algorithm
for /f "tokens=*" %%A in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" 2^>nul') do (
	reg add "%%A" /v "TcpAckFrequency" /t REG_DWORD /d "1" /f >nul 2>&1
	reg add "%%A" /v "TcpDelAckTicks" /t REG_DWORD /d "0" /f >nul 2>&1
	reg add "%%A" /v "TCPNoDelay" /t REG_DWORD /d "1" /f >nul 2>&1
)

@echo NetBios
for /f "tokens=*" %%B in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces" 2^>nul') do (
	reg add "%%B" /v "NetbiosOptions" /t REG_DWORD /d "2" /f >nul 2>&1
)


@echo Ntfs
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsDisable8dot3NameCreation" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsDisableVolsnapHints" /t REG_DWORD /d "1" /f >nul 2>&1


@echo FlushDns
ipconfig /flushdns >nul 2>&1


@echo Disable Wake Devices
for /f "tokens=*" %%a in ('powercfg /devicequery wake_armed 2^>nul') do powercfg /devicedisablewake "%%a" >nul 2>&1



chcp 437 >nul 2>&1 & powershell -nop -noni -exec bypass -c %* >nul 2>&1 & chcp 65001 >nul 2>&1


for %%R in (
    "HKLM\SYSTEM\CurrentControlSet\Enum\SCSI"
    "HKLM\SYSTEM\CurrentControlSet\Enum\PCI"
) do (
    for /f "tokens=*" %%i in ('reg query %%R ^| findstr "HKEY"') do (
        for /f "tokens=*" %%a in ('reg query "%%i" ^| findstr "HKEY"') do (
            reg add "%%a\Device Parameters\Disk" /v "CacheIsPowerProtected" /t REG_DWORD /d 1 /f >nul 2>&1
            reg add "%%a\Device Parameters\Disk" /v "UserWriteCacheSetting" /t REG_DWORD /d 1 /f >nul 2>&1
            reg add "%%a\Device Parameters\Disk" /v "WriteCacheBufferFlushing" /t REG_DWORD /d 0 /f >nul 2>&1
        )
    )
)

REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger" /f

:: Prevent the Software Protection service attempting to register a restart every 30s

REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform" /v "InactivityShutdownDelay" /t REG_DWORD /d "4294967295" /f
