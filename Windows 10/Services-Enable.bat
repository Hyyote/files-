
@echo off
REM Set drive letter to target
set "DRIVE_LETTER=C"

if not "%DRIVE_LETTER%" == "C" (
    reg load "tempSYSTEM" "%DRIVE_LETTER%:\Windows\System32\config\SYSTEM"
    if not %errorlevel% == 0 (echo error: failed to load SYSTEM hive && pause && exit /b 1)
    set "HIVE=tempSYSTEM\ControlSet001"
) else (
    set "HIVE=SYSTEM\CurrentControlSet"
)

reg query "HKLM\%HIVE%" > nul 2>&1 || echo error: hive not exists or is unloaded && pause && exit /b 1

REN "%DRIVE_LETTER%:\Windows\System32\ctfmon.exee" "ctfmon.exe"
REN "%DRIVE_LETTER%:\Windows\System32\backgroundTaskHost.exee" "backgroundTaskHost.exe"
REN "%DRIVE_LETTER%:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\TextInputHost.exee" "TextInputHost.exe"
reg.exe add "HKLM\%HIVE%\Control\Class\{4d36e967-e325-11ce-bfc1-08002be10318}" /v "LowerFilters" /t REG_MULTI_SZ /d "EhStorClass" /f
reg.exe add "HKLM\%HIVE%\Control\Class\{4d36e96c-e325-11ce-bfc1-08002be10318}" /v "UpperFilters" /t REG_MULTI_SZ /d "ksthunk" /f
reg.exe add "HKLM\%HIVE%\Control\Class\{6bdd1fc6-810f-11d0-bec7-08002be2092f}" /v "UpperFilters" /t REG_MULTI_SZ /d "ksthunk" /f
reg.exe add "HKLM\%HIVE%\Control\Class\{71a27cdd-812a-11d0-bec7-08002be2092f}" /v "LowerFilters" /t REG_MULTI_SZ /d "fvevol\0iorate\0rdyboost" /f
reg.exe add "HKLM\%HIVE%\Control\Class\{ca3e7ab9-b4c3-4ae6-8251-579ef933890f}" /v "UpperFilters" /t REG_MULTI_SZ /d "ksthunk" /f
reg.exe add "HKLM\%HIVE%\Services\AarSvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\acpipagr" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\afunix" /v "Start" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\%HIVE%\Services\AJRouter" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\ALG" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\amdgpio2" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\AppIDSvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\AppMgmt" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\AppReadiness" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\AppVClient" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\%HIVE%\Services\AssignedAccessManagerSvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\AsyncMac" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\autotimesvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\AxInstSV" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\bam" /v "Start" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\%HIVE%\Services\BcastDVRUserService" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\BDESVC" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\Beep" /v "Start" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\%HIVE%\Services\BFE" /v "Start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\%HIVE%\Services\bfs" /v "Start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\%HIVE%\Services\bindflt" /v "Start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\%HIVE%\Services\BITS" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\BluetoothUserService" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\bowser" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\BTAGService" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\BthAvctpSvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\bthserv" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\CaptureService" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\cbdhsvc" /v "Start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\%HIVE%\Services\CDPSvc" /v "Start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\%HIVE%\Services\CDPUserSvc" /v "Start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\%HIVE%\Services\cdrom" /v "Start" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\%HIVE%\Services\CertPropSvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\CimFS" /v "Start" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\%HIVE%\Services\CldFlt" /v "Start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\%HIVE%\Services\CLFS" /v "Start" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\%HIVE%\Services\ClipSVC" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\CloudBackupRestoreSvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\cloudidsvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\CompositeBus" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\COMSysApp" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\ConsentUxUserSvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\CredentialEnrollmentManagerUserSvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\CscService" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\dcsvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\defragsvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\DeviceAssociationBrokerSvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\DeviceAssociationService" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\DeviceInstall" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\DevicePickerUserSvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\DevicesFlowUserSvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\DevQueryBroker" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\Dfsc" /v "Start" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\%HIVE%\Services\diagnosticshub.standardcollector.service" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\diagsvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\DiagTrack" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\%HIVE%\Services\DialogBlockingService" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\%HIVE%\Services\DispBrokerDesktopSvc" /v "Start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\%HIVE%\Services\DisplayEnhancementService" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\DmEnrollmentSvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\dmwappushservice" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\Dnscache" /v "Start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\%HIVE%\Services\DoSvc" /v "Start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\%HIVE%\Services\dot3svc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\DPS" /v "Start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\%HIVE%\Services\DsmSvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\DsSvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\DusmSvc" /v "Start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\%HIVE%\Services\EapHost" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\edgeupdate" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\%HIVE%\Services\edgeupdatem" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\%HIVE%\Services\EFS" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\EhStorClass" /v "Start" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\%HIVE%\Services\embeddedmode" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\EntAppSvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\EventSystem" /v "Start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\%HIVE%\Services\fdPHost" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\FDResPub" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\fhsvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\FontCache" /v "Start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\%HIVE%\Services\FontCache3.0.0.0" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\FrameServer" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\fvevol" /v "Start" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\%HIVE%\Services\GameInputSvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\GPIOClx0101" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\GraphicsPerfSvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\HvHost" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\icssvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\IKEEXT" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\InstallService" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\IntelPMT" /v "Start" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\%HIVE%\Services\InventorySvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\iorate" /v "Start" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\%HIVE%\Services\iphlpsvc" /v "Start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\%HIVE%\Services\IpxlatCfgSvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\kdnic" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\KeyIso" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\KSecPkg" /v "Start" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\%HIVE%\Services\ksthunk" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\KtmRm" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\LanmanServer" /v "Start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\%HIVE%\Services\LanmanWorkstation" /v "Start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\%HIVE%\Services\lfsvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\LicenseManager" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\lltdio" /v "Start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\%HIVE%\Services\lltdsvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\lmhosts" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\luafv" /v "Start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\%HIVE%\Services\LxpSvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\MapsBroker" /v "Start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\%HIVE%\Services\McpManagementService" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\MessagingService" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\MicrosoftEdgeElevationService" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\%HIVE%\Services\MixedRealityOpenXRSvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\mpsdrv" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\mpssvc" /v "Start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\%HIVE%\Services\mrxsmb" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\mrxsmb20" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\MSDTC" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\MSiSCSI" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\MsKeyboardFilter" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\%HIVE%\Services\MsLldp" /v "Start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\%HIVE%\Services\MsSecCore" /v "Start" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\%HIVE%\Services\MsSecFlt" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\MSTEE" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\NaturalAuthentication" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\NcaSvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\NcbService" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\NcdAutoSetup" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\NdisCap" /v "Start" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\%HIVE%\Services\NdisVirtualBus" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\NdisWan" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\Ndu" /v "Start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\%HIVE%\Services\NetBIOS" /v "Start" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\%HIVE%\Services\NetBT" /v "Start" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\%HIVE%\Services\Netlogon" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\NetTcpPortSharing" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\%HIVE%\Services\NgcCtnrSvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\NgcSvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\NPSMSvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\npsvctrig" /v "Start" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\%HIVE%\Services\OneSyncSvc" /v "Start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\%HIVE%\Services\p2pimsvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\p2psvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\P9RdrService" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\PcaSvc" /v "Start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\%HIVE%\Services\PEAUTH" /v "Start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\%HIVE%\Services\PeerDistSvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\PenService" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\perceptionsimulation" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\PerfHost" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\PhoneSvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\PimIndexMaintenanceSvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\pla" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\PNRPAutoReg" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\PNRPsvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\PolicyAgent" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\PptpMiniport" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\PrintNotify" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\PrintWorkflowUserSvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\PRM" /v "Start" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\%HIVE%\Services\PushToInstall" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\QWAVE" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\RasAgileVpn" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\RasAuto" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\Rasl2tp" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\RasMan" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\RasPppoe" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\RasSstp" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\rdbss" /v "Start" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\%HIVE%\Services\rdpbus" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\rdyboost" /v "Start" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\%HIVE%\Services\RemoteAccess" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\%HIVE%\Services\RemoteRegistry" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\%HIVE%\Services\RetailDemo" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\RmSvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\RpcLocator" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\rspndr" /v "Start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\%HIVE%\Services\SamSs" /v "Start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\%HIVE%\Services\SCardSvr" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\ScDeviceEnum" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\Schedule" /v "Start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\%HIVE%\Services\SCPolicySvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\SDRSVC" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\%HIVE%\Services\SEMgrSvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\SENS" /v "Start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\%HIVE%\Services\Sense" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\%HIVE%\Services\SensorDataService" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\SensorService" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\SensrSvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\SessionEnv" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\SgrmAgent" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\%HIVE%\Services\SgrmBroker" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\%HIVE%\Services\SharedAccess" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\SharedRealitySvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\ShellHWDetection" /v "Start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\%HIVE%\Services\shpamsvc" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\%HIVE%\Services\smphost" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\SmsRouter" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\SNMPTrap" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\spaceport" /v "Start" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\%HIVE%\Services\spectrum" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\Spooler" /v "Start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\%HIVE%\Services\srv2" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\srvnet" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\SSDPSRV" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\ssh-agent" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\%HIVE%\Services\SstpSvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\StiSvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\storflt" /v "Start" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\%HIVE%\Services\storqosflt" /v "Start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\%HIVE%\Services\StorSvc" /v "Start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\%HIVE%\Services\svsvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\swprv" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\SysMain" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\%HIVE%\Services\TapiSrv" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\tcpipreg" /v "Start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\%HIVE%\Services\TermService" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\Themes" /v "Start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\%HIVE%\Services\TieringEngineService" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\TimeBrokerSvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\TokenBroker" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\TrkWks" /v "Start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\%HIVE%\Services\TroubleshootingSvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\tunnel" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\tzautoupdate" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\%HIVE%\Services\UEFI" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\UevAgentService" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\%HIVE%\Services\umbus" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\UmRdpService" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\UnistoreSvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\upnphost" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\UserDataSvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\UsoSvc" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\%HIVE%\Services\VacSvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\VaultSvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\vdrvroot" /v "Start" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\%HIVE%\Services\vds" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\Vid" /v "Start" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\%HIVE%\Services\vmicguestinterface" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\vmicheartbeat" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\vmickvpexchange" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\vmicrdv" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\vmicshutdown" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\vmictimesync" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\vmicvmsession" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\vmicvss" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\VSS" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\W32Time" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\WaaSMedicSvc" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\%HIVE%\Services\WalletService" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\wanarp" /v "Start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\%HIVE%\Services\wanarpv6" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\WarpJITSvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\wbengine" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\WbioSrvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\wcifs" /v "Start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\%HIVE%\Services\wcncsvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\WdiServiceHost" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\WdiSystemHost" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\WdNisSvc" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\%HIVE%\Services\WebClient" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\webthreatdefsvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\webthreatdefusersvc" /v "Start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\%HIVE%\Services\Wecsvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\WEPHOSTSVC" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\wercplsupport" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\WerSvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\WFDSConMgrSvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\WiaRpc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\WinDefend" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\%HIVE%\Services\WindowsTrustedRT" /v "Start" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\%HIVE%\Services\WindowsTrustedRTProxy" /v "Start" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\%HIVE%\Services\WinHttpAutoProxySvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\WinRM" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\wisvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\wlidsvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\wlpasvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\WManSvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\WmiAcpi" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\wmiApSrv" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\Wof" /v "Start" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\%HIVE%\Services\WpcMonSvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\WPDBusEnum" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\WpnService" /v "Start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\%HIVE%\Services\WpnUserService" /v "Start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\%HIVE%\Services\wscsvc" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\%HIVE%\Services\WSearch" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\%HIVE%\Services\wuauserv" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\WwanSvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\XblAuthManager" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\XblGameSave" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\XboxGipSvc" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\%HIVE%\Services\XboxNetApiSvc" /v "Start" /t REG_DWORD /d "3" /f
shutdown /r /f /t 0
