@ECHO OFF
SETLOCAL ENABLEEXTENSIONS ENABLEDELAYEDEXPANSION
cd /D "%~dp0"

IF EXIST "C:\Windows\system32\adminrightstest" (
rmdir C:\Windows\system32\adminrightstest >NUL 2>&1
)
mkdir C:\Windows\system32\adminrightstest >NUL 2>&1
if %errorlevel% neq 0 (
POWERSHELL "Start-Process \"%~nx0\" -Verb RunAs"
if !errorlevel! neq 0 (
POWERSHELL "Start-Process '%~nx0' -Verb RunAs"
if !errorlevel! neq 0 (
ECHO You should run this script as Admin in order to allow system changes
ECHO The tweaker will now exit
pause
exit
)
)
exit
)
rmdir C:\Windows\system32\adminrightstest >NUL 2>&1

ECHO Preparation...
ECHO Enabling and starting required services

SC CONFIG Winmgmt start= auto >NUL 2>&1 
SC CONFIG TrustedInstaller start= demand >NUL 2>&1
SC CONFIG AppInfo start= demand >NUL 2>&1
SC CONFIG DeviceInstall start= demand >NUL 2>&1
SC START Winmgmt >NUL 2>&1
SC START TrustedInstaller >NUL 2>&1
SC START AppInfo >NUL 2>&1
SC START DeviceInstall >NUL 2>&1
SC START Dhcp >NUL 2>&1

:: Automatically setting static ip while DHCP is enabled
if "%INTERFACE%"=="" for /f "tokens=3,*" %%i in ('netsh int show interface^|find "Connected"') do set INTERFACE=%%j
if "%IP%"=="" for /f "tokens=3 delims=: " %%i in ('netsh int ip show config name^="%INTERFACE%" ^| findstr "IP Address" ^| findstr [0-9]') do set IP=%%i
if "%MASK%"=="" for /f "tokens=2 delims=()" %%i in ('netsh int ip show config name^="%INTERFACE%" ^| findstr /r "(.*)"') do for %%j in (%%i) do set MASK=%%j
if "%GATEWAY%"=="" for /f "tokens=3 delims=: " %%i in ('netsh int ip show config name^="%INTERFACE%" ^| findstr "Default" ^| findstr [0-9]') do set GATEWAY=%%i
set DNS1=156.154.70.22
set DNS2=8.8.4.4
netsh int ipv4 set address name="%INTERFACE%" static %IP% %MASK% %GATEWAY% >NUL 2>&1
netsh int ipv4 set dns name="%INTERFACE%" static %DNS1% primary >NUL 2>&1
netsh int ipv4 add dns name="%INTERFACE%" %DNS2% index=2 >NUL 2>&1
:: Restart adapter
netsh int set interface name="%INTERFACE%" admin="disabled" && netsh int set interface name="%INTERFACE%" admin="enabled" >NUL 2>&1

ECHO Execution Policy to Unrestricted...
POWERSHELL "Set-ExecutionPolicy -ExecutionPolicy Unrestricted" >NUL 2>&1

ECHO Unlocking SILK Smoothness...
REG ADD "HKLM\System\CurrentControlSet\Services\nvlddmkm\FTS" /v "EnableRID61684" /t REG_DWORD /d "1" /f >NUL 2>&1

ECHO Removing Kernel Blacklist...
REG DELETE "HKLM\System\CurrentControlSet\Control\GraphicsDrivers\BlockList\Kernel" /va /reg:64 /f >NUL 2>&1

ECHO Disabling Mitigations...
POWERSHELL "ForEach($v in (Get-Command -Name \"Set-ProcessMitigation\").Parameters[\"Disable\"].Attributes.ValidValues){Set-ProcessMitigation -System -Disable $v.ToString() -ErrorAction SilentlyContinue}"  >NUL 2>&1

ECHO Disabling RAM compression...
POWERSHELL Disable-MMAgent -MemoryCompression -ApplicationPreLaunch -ErrorAction SilentlyContinue >NUL 2>&1

ECHO Disabling Hibernation...
powercfg -h OFF >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Control\Power" /v "HibernateEnabled" /t REG_DWORD /d "0" /f >NUL 2>&1

ECHO Disabling User Account Control...
REG ADD "HKLM\System\CurrentControlSet\Services\Appinfo" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableVirtualization" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableInstallerDetection" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "PromptOnSecureDesktop" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableSecureUIAPaths" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "ValidateAdminCodeSignatures" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableUIADesktopToggle" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorUser" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "FilterAdministratorToken" /t REG_DWORD /d "0" /f >NUL 2>&1

ECHO Disabling Windows Defender...
REG ADD "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableIOAVProtection" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableOnAccessProtection" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableRoutinelyTakingAction" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\Software\WOW6432Node\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\Software\WOW6432Node\Policies\Microsoft\Windows Defender" /v "DisableRoutinelyTakingAction" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\Software\WOW6432Node\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d "0" /f >NUL 2>&1
REG DELETE "HKLM\Software\Microsoft\Windows NT\CurrentVersion\SPP\Clients" /f >NUL 2>&1

ECHO Disabling Windows Update...
REG ADD "HKLM\Software\Microsoft\WindowsUpdate\UpdatePolicy\PolicyState" /v "BranchReadinessLevel" /t REG_SZ /d "CB" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\WindowsUpdate\UpdatePolicy\PolicyState" /v "DeferFeatureUpdates" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\WindowsUpdate\UpdatePolicy\PolicyState" /v "DeferQualityUpdates" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\WindowsUpdate\UpdatePolicy\PolicyState" /v "ExcludeWUDrivers" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\WindowsUpdate\UpdatePolicy\PolicyState" /v "FeatureUpdatesDeferralInDays" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\WindowsUpdate\UpdatePolicy\PolicyState" /v "IsDeferralIsActive" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\WindowsUpdate\UpdatePolicy\PolicyState" /v "IsWUfBConfigured" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\WindowsUpdate\UpdatePolicy\PolicyState" /v "IsWUfBDualScanActive" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\WindowsUpdate\UpdatePolicy\PolicyState" /v "PolicySources" /t REG_DWORD /d "2" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "BranchReadinessLevel" /t REG_DWORD /d "16" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "DeferFeatureUpdates" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "DeferFeatureUpdatesPeriodInDays" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "ManagePreviewBuilds" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "ManagePreviewBuildsPolicyValue" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "PauseFeatureUpdatesStartTime" /t REG_SZ /d "" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "DetectionFrequency" /t REG_DWORD /d "20" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "DetectionFrequencyEnabled" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "EnableFeaturedSoftware" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\PolicyManager\current\device\Update" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\PolicyManager\default\Update" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\PolicyManager\default\Update\ExcludeWUDriversInQualityUpdate" /v "value" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\WindowsUpdate\UX\Settings" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\DriverSearching" /v "SearchOrderConfig" /t REG_DWORD /d "0" /f >NUL 2>&1

ECHO Enabling Windows Components...
dism /online /enable-feature /featurename:DesktopExperience /all /norestart >NUL 2>&1
dism /online /enable-feature /featurename:LegacyComponents /all /norestart >NUL 2>&1
dism /online /enable-feature /featurename:DirectPlay /all /norestart >NUL 2>&1
dism /online /enable-feature /featurename:NetFx4-AdvSrvs /all /norestart >NUL 2>&1
dism /online /enable-feature /featurename:NetFx3 /all /norestart >NUL 2>&1

ECHO Enabling AL HRTF...
ECHO hrtf ^= true > "%appdata%\alsoft.ini"
ECHO hrtf ^= true > "C:\ProgramData\alsoft.ini"

ECHO Disabling IoLatencyCap...
FOR /F "eol=E" %%a in ('REG QUERY "HKLM\System\CurrentControlSet\Services" /S /F "IoLatencyCap"^| FINDSTR /V "IoLatencyCap"') DO (
REG ADD "%%a" /v "IoLatencyCap" /t REG_DWORD /d "0" /f >NUL 2>&1
FOR /F "tokens=*" %%z IN ("%%a") DO (
SET STR=%%z
SET STR=!STR:HKLM\System\CurrentControlSet\services\=!
SET STR=!STR:\Parameters=!
)
)

ECHO Disabling HIPM and DIPM...
FOR /F "eol=E" %%a in ('REG QUERY "HKLM\System\CurrentControlSet\Services" /S /F "EnableHIPM"^| FINDSTR /V "EnableHIPM"') DO (
REG ADD "%%a" /v "EnableHIPM" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "%%a" /v "EnableDIPM" /t REG_DWORD /d "0" /f >NUL 2>&1
FOR /F "tokens=*" %%z IN ("%%a") DO (
SET STR=%%z
SET STR=!STR:HKLM\System\CurrentControlSet\Services\=!
)
)

ECHO Disabling StartMenuExperienceHost.exe...
taskkill /f /im explorer.exe
taskkill /f /im StartMenuExperienceHost.exe
taskkill /f /im runtimebroker.exe
cd C:\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy
takeown /f "StartMenuExperienceHost.exe"
icacls "C:\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe" /grant Administrators:F
ren StartMenuExperienceHost.exe StartMenuExperienceHost.old
cd C:\Windows\System32
takeown /f "runtimebroker.exe"
icacls "C:\Windows\System32\RuntimeBroker.exe" /grant Administrators:F
ren runtimebroker.exe runtimebroker.old
start explorer.exe
)
)

ECHO Disabling all CdpUserSvcs...
FOR /F "eol=E" %%a in ('REG QUERY "HKLM\System\CurrentControlSet\Services" /F "cdpusersvc"') DO (
REG ADD "%%a" /F /V "Start" /T REG_DWORD /d 4 >NUL 2>&1
FOR /F "tokens=*" %%z IN ("%%a") DO (
SET STR=%%z
SET STR=!STR:HKLM\System\CurrentControlSet\services\=!
)
)

ECHO Removing adapters off QoS Service...
FOR /F %%a in ('REG QUERY "HKLM\System\CurrentControlSet\Services\Psched\Parameters\Adapters"') DO ( 
REG DELETE %%a /F >NUL 2>&1
FOR /F "tokens=*" %%z IN ("%%a") DO (
SET STR=%%z
SET STR=!STR:HKLM\System\CurrentControlSet\Services\Psched\Parameters\Adapters\=!
)
)

ECHO Disabling QoS and NdisCap...
FOR /F "tokens=3*" %%I IN ('REG QUERY "HKLM\Software\Microsoft\Windows NT\CurrentVersion\NetworkCards" /F "ServiceName" /S^| FINDSTR /I /L "ServiceName"') DO (
FOR /F %%a IN ('REG QUERY "HKLM\System\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}" /F "%%I" /D /E /S^| FINDSTR /I /L "\\Class\\"') DO SET "REGPATH=%%a"
FOR /F "tokens=3*" %%n in ('REG QUERY "!REGPATH!" /V "FilterList"') DO SET newFilterList=%%n
SET newFilterList=!newFilterList:-{B5F4D659-7DAA-4565-8E41-BE220ED60542}=!
SET newFilterList=!newFilterList:-{430BDADD-BAB0-41AB-A369-94B67FA5BE0A}=!
REG QUERY !REGPATH! /V "FilterList" | FINDSTR /I "{B5F4D659-7DAA-4565-8E41-BE220ED60542} {430BDADD-BAB0-41AB-A369-94B67FA5BE0A}" >NUL 2>&1
IF NOT ERRORLEVEL 1 (
REG ADD !REGPATH! /F /V "FilterList" /T REG_MULTI_SZ /d "!newFilterList!" >NUL 2>&1
)
)

ECHO Disabling USB Hub idle...
FOR /F %%a in ('WMIC PATH Win32_USBHub GET DeviceID^| FINDSTR /L "VID_"') DO (
REG ADD "HKLM\System\CurrentControlSet\Enum\%%a\Device Parameters" /v "EnhancedPowerManagementEnabled" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Enum\%%a\Device Parameters" /v "AllowIdleIrpInD3" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Enum\%%a\Device Parameters" /v "DeviceSelectiveSuspended" /t REG_DWORD /d "0" /f >NUL 2>&1	
REG ADD "HKLM\System\CurrentControlSet\Enum\%%a\Device Parameters" /v "SelectiveSuspendEnabled" /t REG_DWORD /d "0" /f >NUL 2>&1	
REG ADD "HKLM\System\CurrentControlSet\Enum\%%a\Device Parameters" /v "SelectiveSuspendOn" /t REG_DWORD /d "0" /f >NUL 2>&1	
REG ADD "HKLM\System\CurrentControlSet\Enum\%%a\Device Parameters" /v "fid_D1Latency" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Enum\%%a\Device Parameters" /v "fid_D2Latency" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Enum\%%a\Device Parameters" /v "fid_D3Latency" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Control\usbflags" /v "fid_D1Latency" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Control\usbflags" /v "fid_D2Latency" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Control\usbflags" /v "fid_D3Latency" /t REG_DWORD /d "0" /f >NUL 2>&1
)

ECHO Disabling StorPort idle...
FOR /F "tokens=*" %%a in ('REG QUERY "HKLM\System\CurrentControlSet\Enum" /S /F "StorPort"^| FINDSTR /E "StorPort"') DO (
REG ADD "%%a" /v "EnableIdlePowerManagement" /t REG_DWORD /d "0" /f >NUL 2>&1
FOR /F "tokens=*" %%z IN ("%%a") DO (
SET STR=%%z
SET STR=!STR:HKLM\System\CurrentControlSet\Enum\=!
SET STR=!STR:\Device Parameters\StorPort=!
)
)

IF EXIST "%WinDir%\Resources\Themes\aero\aerolite.msstyles" (
powershell "$content = [System.IO.File]::ReadAllText('%WinDir%\Resources\Themes\aero.theme').Replace('%ResourceDir%\Themes\Aero\Aero.msstyles','%ResourceDir%\Themes\Aero\Aerolite.msstyles'); [System.IO.File]::WriteAllText('%WinDir%\Resources\Themes\aerolite.theme', $content)" >NUL 2>&1
ECHO Installing Aero Lite Theme
IF EXIST "%WinDir%\Resources\Themes\light.theme" (
powershell "$content = [System.IO.File]::ReadAllText('%WinDir%\Resources\Themes\light.theme').Replace('%ResourceDir%\Themes\Aero\Aero.msstyles','%ResourceDir%\Themes\Aero\Aerolite.msstyles'); [System.IO.File]::WriteAllText('%WinDir%\Resources\Themes\lightlite.theme', $content)" >NUL 2>&1 
ECHO Installing Light Lite Theme
)
)

ECHO Preparing system for Process Explorer...
IF EXIST "%~dp0\procexp64.exe" REG ADD "HKLM\System\CurrentControlSet\Services\PCW" /v "Start" /t REG_DWORD /d "4" /f
IF EXIST "%~dp0\procexp64.exe" xcopy /S /Q /Y /F "%~dp0\procexp64.exe" "%WINDIR%"
IF EXIST "%~dp0\procexp64.exe" REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskmgr.exe" /v "Debugger" /t REG_SZ /d "%WINDIR%\procexp64.exe" /f
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "EulaAccepted" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "Windowplacement" /t REG_BINARY /d "2c0000000200000003000000ffffffffffffffffffffffffffffffff75030000110000009506000069020000" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "FindWindowplacement" /t REG_BINARY /d "2c00000000000000000000000000000000000000000000000000000096000000960000000000000000000000" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "SysinfoWindowplacement" /t REG_BINARY /d "2c00000000000000010000000000000000000000ffffffffffffffff28000000280000002b0300002b020000" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "PropWindowplacement" /t REG_BINARY /d "2c00000000000000000000000000000000000000000000000000000028000000280000000000000000000000" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "DllPropWindowplacement" /t REG_BINARY /d "2c00000000000000000000000000000000000000000000000000000028000000280000000000000000000000" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "UnicodeFont" /t REG_BINARY /d "080000000000000000000000000000009001000000000000000000004d00530020005300680065006c006c00200044006c00670000000000000000000000000000000000000000000000000000000000000000000000000000000000" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "Divider" /t REG_BINARY /d "531f0e151662ea3f" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "SavedDivider" /t REG_BINARY /d "531f0e151662ea3f" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "ProcessImageColumnWidth" /t REG_DWORD /d "261" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "ShowUnnamedHandles" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "ShowDllView" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "HandleSortColumn" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "HandleSortDirection" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "DllSortColumn" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "DllSortDirection" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "ProcessSortColumn" /t REG_DWORD /d "4294967295" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "ProcessSortDirection" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "HighlightServices" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "HighlightOwnProcesses" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "HighlightRelocatedDlls" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "HighlightJobs" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "HighlightNewProc" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "HighlightDelProc" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "HighlightImmersive" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "HighlightProtected" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "HighlightPacked" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "HighlightNetProcess" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "HighlightSuspend" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "HighlightDuration" /t REG_DWORD /d "1000" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "ShowCpuFractions" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "ShowLowerpane" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "ShowAllUsers" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "ShowProcessTree" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "SymbolWarningShown" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "HideWhenMinimized" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "AlwaysOntop" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "OneInstance" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "NumColumnSets" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "ConfirmKill" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "RefreshRate" /t REG_DWORD /d "1000" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "PrcessColumnCount" /t REG_DWORD /d "17" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "DllColumnCount" /t REG_DWORD /d "5" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "HandleColumnCount" /t REG_DWORD /d "2" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "DefaultProcPropPage" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "DefaultSysInfoPage" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "DefaultDllPropPage" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "DbgHelpPath" /t REG_SZ /d "C:\Windows\SYSTEM32\dbghelp.dll" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "SymbolPath" /t REG_SZ /d "" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "ColorPacked" /t REG_DWORD /d "16711808" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "ColorImmersive" /t REG_DWORD /d "15395328" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "ColorOwn" /t REG_DWORD /d "16765136" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "ColorServices" /t REG_DWORD /d "13684991" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "ColorRelocatedDlls" /t REG_DWORD /d "10551295" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "ColorGraphBk" /t REG_DWORD /d "15790320" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "ColorJobs" /t REG_DWORD /d "27856" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "ColorDelProc" /t REG_DWORD /d "4605695" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "ColorNewProc" /t REG_DWORD /d "4652870" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "ColorNet" /t REG_DWORD /d "10551295" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "ColorProtected" /t REG_DWORD /d "8388863" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "ShowHeatmaps" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "ColorSuspend" /t REG_DWORD /d "8421504" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "StatusBarColumns" /t REG_DWORD /d "13589" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "ShowAllCpus" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "ShowAllGpus" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "Opacity" /t REG_DWORD /d "100" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "GpuNodeUsageMask" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "GpuNodeUsageMask1" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "VerifySignatures" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "VirusTotalCheck" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "VirusTotalSubmitUnknown" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "ToolbarBands" /t REG_BINARY /d "0601000000000000000000004b00000001000000000000004b00000002000000000000004b00000003000000000000004b0000000400000000000000400000000500000000000000500000000600000000000000930400000700000000000000" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "UseGoogle" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "ShowNewProcesses" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "TrayCPUHistory" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "ShowIoTray" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "ShowNetTray" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "ShowDiskTray" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "ShowPhysTray" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "ShowCommitTray" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "ShowGpuTray" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "FormatIoBytes" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "StackWindowPlacement" /t REG_BINARY /d "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer" /v "ETWstandardUserWarning" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\DllColumnMap" /v "0" /t REG_DWORD /d "26" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\DllColumnMap" /v "1" /t REG_DWORD /d "42" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\DllColumnMap" /v "2" /t REG_DWORD /d "1033" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\DllColumnMap" /v "3" /t REG_DWORD /d "1111" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\DllColumnMap" /v "4" /t REG_DWORD /d "1670" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\DllColumns" /v "0" /t REG_DWORD /d "110" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\DllColumns" /v "1" /t REG_DWORD /d "180" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\DllColumns" /v "2" /t REG_DWORD /d "140" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\DllColumns" /v "3" /t REG_DWORD /d "300" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\DllColumns" /v "4" /t REG_DWORD /d "100" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\HandleColumnMap" /v "0" /t REG_DWORD /d "21" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\HandleColumnMap" /v "1" /t REG_DWORD /d "22" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\HandleColumns" /v "0" /t REG_DWORD /d "100" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\HandleColumns" /v "1" /t REG_DWORD /d "450" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumnMap" /v "0" /t REG_DWORD /d "3" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumnMap" /v "1" /t REG_DWORD /d "1055" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumnMap" /v "2" /t REG_DWORD /d "1650" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumnMap" /v "3" /t REG_DWORD /d "1065" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumnMap" /v "4" /t REG_DWORD /d "1200" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumnMap" /v "5" /t REG_DWORD /d "1092" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumnMap" /v "6" /t REG_DWORD /d "1340" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumnMap" /v "7" /t REG_DWORD /d "5" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumnMap" /v "8" /t REG_DWORD /d "1339" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumnMap" /v "9" /t REG_DWORD /d "1333" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumnMap" /v "10" /t REG_DWORD /d "1622" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumnMap" /v "11" /t REG_DWORD /d "1636" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumnMap" /v "12" /t REG_DWORD /d "1179" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumnMap" /v "13" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumnMap" /v "14" /t REG_DWORD /d "1060" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumnMap" /v "15" /t REG_DWORD /d "1063" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumnMap" /v "16" /t REG_DWORD /d "1670" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumnMap" /v "17" /t REG_DWORD /d "1653" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumnMap" /v "18" /t REG_DWORD /d "1653" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumnMap" /v "19" /t REG_DWORD /d "1653" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumns" /v "0" /t REG_DWORD /d "261" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumns" /v "1" /t REG_DWORD /d "35" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumns" /v "2" /t REG_DWORD /d "37" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumns" /v "3" /t REG_DWORD /d "52" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumns" /v "4" /t REG_DWORD /d "85" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumns" /v "5" /t REG_DWORD /d "80" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumns" /v "6" /t REG_DWORD /d "60" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumns" /v "7" /t REG_DWORD /d "39" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumns" /v "8" /t REG_DWORD /d "79" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumns" /v "9" /t REG_DWORD /d "65" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumns" /v "10" /t REG_DWORD /d "93" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumns" /v "11" /t REG_DWORD /d "76" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumns" /v "12" /t REG_DWORD /d "55" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumns" /v "13" /t REG_DWORD /d "31" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumns" /v "14" /t REG_DWORD /d "70" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumns" /v "15" /t REG_DWORD /d "70" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\ProcessColumns" /v "16" /t REG_DWORD /d "44" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Sysinternals\Process Explorer\VirusTotal" /v "VirusTotalTermsAccepted" /t REG_DWORD /d "1" /f >NUL 2>&1

ECHO Network tweaks, takes time...
NETSH winsock reset >NUL 2>&1
NETSH interface teredo set state disabled >NUL 2>&1
NETSH interface 6to4 set state disabled >NUL 2>&1
NETSH int isatap set state disable >NUL 2>&1
NETSH int ip set global neighborcachelimit=4096 >NUL 2>&1
NETSH int ip set global taskoffload=disabled >NUL 2>&1
NETSH int ip set global loopbackworkercount = %NUMBER_OF_PROCESSORS% >NUL 2>&1
NETSH int tcp set global autotuninglevel=disable >NUL 2>&1
NETSH int tcp set global chimney=disabled >NUL 2>&1
NETSH int tcp set global dca=enabled >NUL 2>&1
NETSH int tcp set global ecncapability=disabled >NUL 2>&1
NETSH int tcp set global netdma=enabled >NUL 2>&1
NETSH int tcp set global nonsackrttresiliency=disabled >NUL 2>&1
NETSH int tcp set global rsc=disabled >NUL 2>&1
NETSH int tcp set global rss=enabled >NUL 2>&1
NETSH int tcp set global timestamps=disabled >NUL 2>&1
NETSH int tcp set heuristics disabled >NUL 2>&1
NETSH int tcp set security mpp=disabled >NUL 2>&1
NETSH int tcp set security profiles=disabled >NUL 2>&1
NETSH int tcp set global initialRto=3000 >NUL 2>&1
NETSH int tcp set global maxsynretransmissions=2 >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableICMPRedirect" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "EnablePMTUDiscovery" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "Tcp1323Opts" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "GlobalMaxTcpWindowSize" /t REG_DWORD /d "5840" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpWindowSize" /t REG_DWORD /d "5840" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxConnectionsPerServer" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxUserPort" /t REG_DWORD /d "65534" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t REG_DWORD /d "32" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "EnablePMTUBHDetect" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "DisableTaskOffload" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "DefaultTTL" /t REG_DWORD /d "64" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "SackOpts" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxDupAcks" /t REG_DWORD /d "2" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\Winsock" /v "UseDelayedAcceptance" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\Winsock" /v "MaxSockAddrLength" /t REG_DWORD /d "16" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\Winsock" /v "MinSockAddrLength" /t REG_DWORD /d "16" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\MSMQ\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\Psched" /v "MaxOutstandingSends" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\Psched" /v "NonBestEffortLimit" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\Psched" /v "TimerResolution" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\Software\WOW6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MAXCONNECTIONSPER1_0SERVER" /v "explorer.exe" /t REG_DWORD /d "10" /f >NUL 2>&1
REG ADD "HKLM\Software\WOW6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MAXCONNECTIONSPER1_0SERVER" /v "iexplore.exe" /t REG_DWORD /d "10" /f >NUL 2>&1
REG ADD "HKLM\Software\WOW6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MAXCONNECTIONSPERSERVER" /v "explorer.exe" /t REG_DWORD /d "10" /f >NUL 2>&1
REG ADD "HKLM\Software\WOW6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MAXCONNECTIONSPERSERVER" /v "iexplore.exe" /t REG_DWORD /d "10" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "DnsPriority" /t REG_DWORD /d "6" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "HostsPriority" /t REG_DWORD /d "5" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "LocalPriority" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "NetbtPriority" /t REG_DWORD /d "7" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\AFD\Parameters" /v "DefaultReceiveWindow" /t REG_DWORD /d "16384" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\AFD\Parameters" /v "DefaultSendWindow" /t REG_DWORD /d "16384" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\AFD\Parameters" /v "DisableRawSecurity" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\AFD\Parameters" /v "DynamicSendBufferDisable" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\AFD\Parameters" /v "FastCopyReceiveThreshold" /t REG_DWORD /d "16384" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\AFD\Parameters" /v "FastSendDatagramThreshold" /t REG_DWORD /d "16384" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\AFD\Parameters" /v "IgnorePushBitOnReceives" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\AFD\Parameters" /v "NonBlockingSendSpecialBuffering" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\Tcpip6\Parameters" /v "DisabledComponents" /t REG_DWORD /d "255" /f >NUL 2>&1
for /f %%i in ('wmic path win32_networkadapter get GUID ^| findstr "{"') do REG ADD "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v TcpAckFrequency /t REG_DWORD /d 1 /f >NUL 2>&1
for /f %%i in ('wmic path win32_networkadapter get GUID ^| findstr "{"') do REG ADD "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v TcpDelAckTicks /t REG_DWORD /d 0 /f >NUL 2>&1
for /f %%i in ('wmic path win32_networkadapter get GUID ^| findstr "{"') do REG ADD "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v TCPNoDelay /t REG_DWORD /d 1 /f >NUL 2>&1

:: Adapter
for /f %%r in ('reg query "HKLM\SYSTEM\ControlSet001\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}" /f "PCI\VEN" /d /s^|Findstr HKEY') do (
REG ADD "%%r" /v "*EEE" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "%%r" /v "*FlowControl" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "%%r" /v "*InterruptModeration" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "%%r" /v "*JumboPacket" /t REG_SZ /d "1415" /f >NUL 2>&1
REG ADD "%%r" /v "*LsoV1IPv4" /t REG_SZ /d "1" /f >NUL 2>&1
REG ADD "%%r" /v "*LsoV2IPv4" /t REG_SZ /d "1" /f >NUL 2>&1
REG ADD "%%r" /v "*LsoV2IPv6" /t REG_SZ /d "1" /f >NUL 2>&1
REG ADD "%%r" /v "*ModernStandbyWoLMagicPacket" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "%%r" /v "*NumRssQueues" /t REG_SZ /d "1" /f >NUL 2>&1
REG ADD "%%r" /v "*PMARPOffload" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "%%r" /v "*PMNSOffload" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "%%r" /v "*PriorityVLANTag" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "%%r" /v "*ReceiveBuffers" /t REG_SZ /d "80" /f >NUL 2>&1
REG ADD "%%r" /v "*RSS" /t REG_SZ /d "1" /f >NUL 2>&1
REG ADD "%%r" /v "*RssBaseProcNumber" /t REG_SZ /d "1" /f >NUL 2>&1
REG ADD "%%r" /v "*RssMaxProcNumber" /t REG_SZ /d "1" /f >NUL 2>&1
REG ADD "%%r" /v "*SpeedDuplex" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "%%r" /v "*TCPChecksumOffloadIPv4" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "%%r" /v "*TCPChecksumOffloadIPv6" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "%%r" /v "*TransmitBuffers" /t REG_SZ /d "80" /f >NUL 2>&1
REG ADD "%%r" /v "*WakeOnMagicPacket" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "%%r" /v "*WakeOnPattern" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "%%r" /v "AdvancedEEE" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "%%r" /v "AutoDisableGigabit" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "%%r" /v "EEELinkAdvertisement" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "%%r" /v "EnableGreenEthernet" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "%%r" /v "EnablePME" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "%%r" /v "EnableTss" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "%%r" /v "GigaLite" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "%%r" /v "ITR" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "%%r" /v "LogLinkStateEvent" /t REG_SZ /d "51" /f >NUL 2>&1
REG ADD "%%r" /v "MasterSlave" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "%%r" /v "PowerSavingMode" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "%%r" /v "ReduceSpeedOnPowerDown" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "%%r" /v "S5WakeOnLan" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "%%r" /v "TxIntDelay" /t REG_SZ /d "5" /f >NUL 2>&1
REG ADD "%%r" /v "ULPMode" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "%%r" /v "WaitAutoNegComplete" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "%%r" /v "WakeOnLink" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "%%r" /v "WakeOnSlot" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "%%r" /v "WolShutdownLinkSpeed" /t REG_SZ /d "2" /f >NUL 2>&1
)

:: Core 2 Affinity
for /f %%n in ('wmic path win32_networkadapter get PNPDeviceID ^| findstr /L "VEN_"') do (
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Enum\%%n\Device Parameters\Interrupt Management\Affinity Policy" /v "AssignmentSetOverride" /t REG_BINARY /d "04" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Enum\%%n\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePolicy" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Enum\%%n\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MessageNumberLimit" /t REG_DWORD /d "256" /f >NUL 2>&1
)

POWERSHELL Set-NetTCPSetting -SettingName internet -ScalingHeuristics disabled -ErrorAction SilentlyContinue
POWERSHELL Set-NetTCPSetting -SettingName internet -MinRto 300 -ErrorAction SilentlyContinue
POWERSHELL Disable-NetAdapterEncapsulatedPacketTaskOffload -Name "*" -ErrorAction SilentlyContinue
POWERSHELL Disable-NetAdapterIPsecOffload -Name "*" -ErrorAction SilentlyContinue
POWERSHELL Disable-NetAdapterChecksumOffload -Name "*" -ErrorAction SilentlyContinue
POWERSHELL Disable-NetAdapterLso -Name "*" -ErrorAction SilentlyContinue
POWERSHELL Disable-NetAdapterRsc -Name "*" -ErrorAction SilentlyContinue
POWERSHELL Disable-NetAdapterIPsecOffload -Name "*" -ErrorAction SilentlyContinue
POWERSHELL Disable-NetAdapterPowerManagement -Name "*" -ErrorAction SilentlyContinue

:: Adapter bindings
POWERSHELL Disable-NetAdapterBinding -Name "*" -ComponentID ms_lldp -ErrorAction SilentlyContinue
:: Link-Layer Topology Discovery Mapper I/O Driver
POWERSHELL Disable-NetAdapterBinding -Name "*" -ComponentID ms_lltdio -ErrorAction SilentlyContinue
:: Client for Microsoft Networks
POWERSHELL Disable-NetAdapterBinding -Name "*" -ComponentID ms_msclient -ErrorAction SilentlyContinue
:: Microsoft LLDP Protocol Driver
POWERSHELL Disable-NetAdapterBinding -Name "*" -ComponentID ms_rspndr -ErrorAction SilentlyContinue
:: File and Printer Sharing for Microsoft Networks
POWERSHELL Disable-NetAdapterBinding -Name "*" -ComponentID ms_server -ErrorAction SilentlyContinue
:: Microsoft Network Adapter Multiplexor Protocol
POWERSHELL Disable-NetAdapterBinding -Name "*" -ComponentID ms_implat -ErrorAction SilentlyContinue

:: QoS Packet Scheduler
POWERSHELL Disable-NetAdapterQos -Name "*" -ErrorAction SilentlyContinue
POWERSHELL Disable-NetAdapterBinding -Name "*" -ComponentID ms_pacer -ErrorAction SilentlyContinue

:: Bindings that are not common
POWERSHELL Disable-NetAdapterBinding -Name "*" -ComponentID ms_pppoe -ErrorAction SilentlyContinue
POWERSHELL Disable-NetAdapterBinding -Name "*" -ComponentID ms_rdma_ndk -ErrorAction SilentlyContinue
POWERSHELL Disable-NetAdapterBinding -Name "*" -ComponentID ms_ndisuio -ErrorAction SilentlyContinue
POWERSHELL Disable-NetAdapterBinding -Name "*" -ComponentID ms_wfplwf_upper -ErrorAction SilentlyContinue
POWERSHELL Disable-NetAdapterBinding -Name "*" -ComponentID ms_wfplwf_lower -ErrorAction SilentlyContinue
POWERSHELL Disable-NetAdapterBinding -Name "*" -ComponentID ms_netbt -ErrorAction SilentlyContinue
POWERSHELL Disable-NetAdapterBinding -Name "*" -ComponentID ms_netbios -ErrorAction SilentlyContinue

:: Restarting Adapter
POWERSHELL Restart-NetAdapter -Name "Ethernet" -ErrorAction SilentlyContinue

ECHO Disabling Themes...
REG ADD "HKLM\System\CurrentControlSet\Services\Themes" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1

ECHO Disabling Drivers...
:: Preventing Errors
REG ADD "HKLM\System\CurrentControlSet\Services\Dhcp" /v "DependOnService" /t REG_MULTI_SZ /d "NSI\0Afd" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\hidserv" /v "DependOnService" /t REG_MULTI_SZ /d "" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\fvevol" /v "ErrorControl" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\LanmanServer" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Control\Class\{4d36e96c-e325-11ce-bfc1-08002be10318}" /v "UpperFilters" /t REG_MULTI_SZ /d "" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Control\Class\{4d36e967-e325-11ce-bfc1-08002be10318}" /v "LowerFilters" /t REG_MULTI_SZ /d "" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Control\Class\{4d36e967-e325-11ce-bfc1-08002be10318}" /v "LowerFilters" /t REG_MULTI_SZ /d "" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Control\Class\{6bdd1fc6-810f-11d0-bec7-08002be2092f}" /v "UpperFilters" /t REG_MULTI_SZ /d "" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Control\Class\{71a27cdd-812a-11d0-bec7-08002be2092f}" /v "LowerFilters" /t REG_MULTI_SZ /d "" /f >NUL 2>&1

:: ACPI Devices driver
REG ADD "HKLM\System\CurrentControlSet\Services\AcpiDev" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Charge Arbitration Driver
REG ADD "HKLM\System\CurrentControlSet\Services\CAD" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Windows Cloud Files Filter Driver
REG ADD "HKLM\System\CurrentControlSet\Services\CldFlt" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Windows sandboxing and encryption filter
REG ADD "HKLM\System\CurrentControlSet\Services\FileCrypt" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: GPU Energy Driver
REG ADD "HKLM\System\CurrentControlSet\Services\GpuEnergyDrv" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: WAN Miniport (PPTP)
REG ADD "HKLM\System\CurrentControlSet\Services\PptpMiniport" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Remote Application Programming Interface (RAPI)
REG ADD "HKLM\System\CurrentControlSet\Services\RapiMgr" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: WAN Miniport (IKEv2)
REG ADD "HKLM\System\CurrentControlSet\Services\RasAgileVpn" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: WAN Miniport (L2TP)
REG ADD "HKLM\System\CurrentControlSet\Services\Rasl2tp" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: WAN Miniport (SSTP)
REG ADD "HKLM\System\CurrentControlSet\Services\RasSstp" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Remote Access IP ARP Driver
REG ADD "HKLM\System\CurrentControlSet\Services\Wanarp" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Remote Access IPv6 ARP Driver
REG ADD "HKLM\System\CurrentControlSet\Services\wanarpv6" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Related to windows defender
REG ADD "HKLM\System\CurrentControlSet\Services\Wdnsfltr" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: CTF Loader
REG ADD "HKLM\System\CurrentControlSet\Services\WcesComm" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Windows Container Isolation
REG ADD "HKLM\System\CurrentControlSet\Services\Wcifs" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Windows Container Name Virtualization
REG ADD "HKLM\System\CurrentControlSet\Services\Wcnfs" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Windows Trusted Execution Environment Class Extension
REG ADD "HKLM\System\CurrentControlSet\Services\WindowsTrustedRT" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Microsoft Windows Trusted Runtime Secure Service
REG ADD "HKLM\System\CurrentControlSet\Services\WindowsTrustedRTProxy" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1

:: Background Activity Moderator Driver (W10Default=1)
REG ADD "HKLM\System\CurrentControlSet\Services\bam" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: CNG Hardware Assist algorithm provider (W10Default=4) (W8Default=Empty)
REG ADD "HKLM\System\CurrentControlSet\Services\cnghwassist" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Disk I/O Rate Filter Driver (W10Default=0)
REG ADD "HKLM\System\CurrentControlSet\Services\iorate" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Security Events Component Minifilter (W10Default=0)
REG ADD "HKLM\System\CurrentControlSet\Services\mssecflt" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Tunnel Miniport Adapter Driver (W10Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\tunnel" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\tunnel" /v "ErrorControl" /t REG_DWORD /d "1" /f >NUL 2>&1
:: Virtual WiFi Filter Driver (W10Default=1)
REG ADD "HKLM\System\CurrentControlSet\Services\vwififlt" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: ACPI Processor Aggregator Driver (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\acpipagr" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: ACPI Power Meter Driver (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\AcpiPmi" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: ACPI Wake Alarm Driver (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\Acpitime" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Most useless driver to exist (W8Default=1)
REG ADD "HKLM\System\CurrentControlSet\Services\Beep" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: NT Lan Manager Datagram Receiver Driver (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\bowser" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: CD/DVD File System Reader (W8Default=4)
REG ADD "HKLM\System\CurrentControlSet\Services\cdfs" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: CD-ROM Driver / Cannot use programs like rufus (W8Default=1)
REG ADD "HKLM\System\CurrentControlSet\Services\cdrom" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Common Log / General-purpose logging service (W8Default=0)
REG ADD "HKLM\System\CurrentControlSet\Services\CLFS" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: (Compbatt for W7) (For laptops) - Microsoft ACPI Control Method Battery Driver (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\CmBatt" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Composite Bus Enumerator Driver (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\CompositeBus" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Console Driver (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\condrv" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Offline Files Driver (W8Default=1)
REG ADD "HKLM\System\CurrentControlSet\Services\CSC" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Desktop Activity Moderator Driver (W8Default=1)
REG ADD "HKLM\System\CurrentControlSet\Services\dam" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: DFS Namespace Client Driver (W8Default=1)
REG ADD "HKLM\System\CurrentControlSet\Services\dfsc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Enhanced Storage Filter Driver (W8Default=0)
REG ADD "HKLM\System\CurrentControlSet\Services\EhStorClass" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: FAT12/16/32 File System Driver (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\fastfat" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: File Information FS MiniFilter (W8Default=0)
REG ADD "HKLM\System\CurrentControlSet\Services\FileInfo" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: BitLocker Drive Encryption Filter Driver (W8Default=0)
REG ADD "HKLM\System\CurrentControlSet\Services\fvevol" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Kernel Debug Network Miniport NDIS 6.20 (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\kdnic" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Kernel Security Support Provider Interface Packages (W8Default=0)
REG ADD "HKLM\System\CurrentControlSet\Services\KSecPkg" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Link-Layer Topology Discovery Mapper I/O Driver (W8Default=2)
REG ADD "HKLM\System\CurrentControlSet\Services\lltdio" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: UAC File Virtualization (W8Default=2)
REG ADD "HKLM\System\CurrentControlSet\Services\luafv" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Modem Device Driver (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\Modem" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: The Networking-MPSSVC-Svc component is part of Windows Firewall (W8Default=2)
REG ADD "HKLM\System\CurrentControlSet\Services\MpsSvc" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Windows Defender Firewall Authorization Driver (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\mpsdrv" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: SMB MiniRedirector Wrapper and Engine (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\mrxsmb" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: SMB 1.x MiniRedirector (W8Default=2)
REG ADD "HKLM\System\CurrentControlSet\Services\Mrxsmb10" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: SMB 2.0 MiniRedirector (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\Mrxsmb20" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Disabling breaks laptop keyboards and PS2 keyboards (W8Default=0)
REG ADD "HKLM\System\CurrentControlSet\Services\msisadrv" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Link-Layer Discovery Protocol (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\MsLldp" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: System Management BIOS Driver (W8Default=1)
REG ADD "HKLM\System\CurrentControlSet\Services\mssmbios" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: NDIS Capture (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\NdisCap" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Remote Access NDIS TAPI Driver (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\NdisTapi" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Virtual Network Adapter Enumerator (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\NdisVirtualBus" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Remote Access NDIS WAN Driver (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\NdisWan" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: NDIS Proxy Driver  (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\Ndproxy" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Windows Network Data Usage Monitoring Driver (W8Default=2)
REG ADD "HKLM\System\CurrentControlSet\Services\Ndu" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: NetBIOS interface driver (W8Default=1) 
REG ADD "HKLM\System\CurrentControlSet\Services\NetBIOS" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Implements NetBios over TCP/IP (W8Default=1)
REG ADD "HKLM\System\CurrentControlSet\Services\NetBT" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Named pipe service trigger provider (W8Default=1)
REG ADD "HKLM\System\CurrentControlSet\Services\Npsvctrig" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Protected Environment Authentication and Authorization Export Driver (W8Default=2)
REG ADD "HKLM\System\CurrentControlSet\Services\PEAUTH" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: QoS Packet Scheduler (W8Default=1)
REG ADD "HKLM\System\CurrentControlSet\Services\Psched" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: QWAVE enhances AV streaming performance and reliability by ensuring network QoS for AV apps (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\QWAVEdrv" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Remote Access Auto Connection Driver (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\RasAcd" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Remote Access PPPOE Driver (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\RasPppoe" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Redirected Buffering Sub System (W8Default=1)
REG ADD "HKLM\System\CurrentControlSet\Services\rdbss" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Remote Desktop Device Redirector Bus Driver (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\rdpbus" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Usually already stripped in custom isos (W8Default=0)
REG ADD "HKLM\System\CurrentControlSet\Services\rdyboost" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Link-Layer Topology Discovery Responder (W8Default=2)
REG ADD "HKLM\System\CurrentControlSet\Services\rspndr" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Serial Mouse Driver / Needed for ps2 mice (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\sermouse" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Storage Spaces Driver (W8Default=0)
REG ADD "HKLM\System\CurrentControlSet\Services\spaceport" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Server SMB 2.xxx Driver (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\srv2" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Server network driver (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\Srvnet" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Central repository of Telephony data (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\TapiSrv" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: IPv6 Protocol Driver (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\Tcpip6" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6" /v "ErrorControl" /t REG_DWORD /d "1" /f >NUL 2>&1
:: TCP/IP registry compatibility driver (W8Default=2)
REG ADD "HKLM\System\CurrentControlSet\Services\tcpipreg" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: TDI translation driver (W8Default=1)
REG ADD "HKLM\System\CurrentControlSet\Services\tdx" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Trusted Platform Module (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\TPM" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Reads/Writes UDF 1.02,1.5,2.0x,2.5 disc formats, usually found on C/DVD discs (W8Default=4)
REG ADD "HKLM\System\CurrentControlSet\Services\udfs" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Can be disabled on UEFI. Bricks some systems (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\UEFI" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: UMBus Enumerator Driver (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\umbus" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Virtual Drive Root Enumerator file (W8Default=0)
REG ADD "HKLM\System\CurrentControlSet\Services\vdrvroot" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Hyper-V Virtualization Infrastructure Driver (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\Vid" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Volume Manager Driver (W8Default=0)
REG ADD "HKLM\System\CurrentControlSet\Services\Volmgrx" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Virtual Wireless Bus Driver (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\vwifibus" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Related to windows defender (W8Default=0)
REG ADD "HKLM\System\CurrentControlSet\Services\Wdboot" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Related to windows defender (W8Default=0)
REG ADD "HKLM\System\CurrentControlSet\Services\WdFilter" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Related to windows defender (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\WdNisDrv" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Windows defender (W8Default=2)
REG ADD "HKLM\System\CurrentControlSet\Services\WinDefend" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Microsoft Windows Management Interface for ACPI (W8Default=3)
REG ADD "HKLM\System\CurrentControlSet\Services\WmiAcpi" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: Winsock IFS Driver (W8Default=4)
REG ADD "HKLM\System\CurrentControlSet\Services\ws2ifsl" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: This can be disabled, but it breaks some functionality of the kernel. Null is required for piping thus for some programs to work, like wget and wsusoffline (W8Default=1)
REG ADD "HKLM\System\CurrentControlSet\Services\Null" /v "Start" /t REG_DWORD /d "1" /f >NUL 2>&1

:: Disable Core Parking
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "Attributes" /t Reg_DWORD /d "2" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMax" /t Reg_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMin" /t Reg_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318584" /v "Attributes" /t Reg_DWORD /d "2" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318584" /v "ValueMax" /t Reg_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318584" /v "ValueMin" /t Reg_DWORD /d "0" /f >NUL 2>&1

:: Decrease Mouse and KeyboardDataQueueSize
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" /v "MouseDataQueueSize" /t REG_DWORD /d "16" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" /v "SendOutputToAllPorts" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" /v "WppRecorder_UseTimeStamp" /t Reg_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" /v "KeyboardDataQueueSize" /t REG_DWORD /d "3" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" /v "MaximumPortsServiced" /t Reg_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" /v "SendOutputToAllPorts" /t Reg_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" /v "WppRecorder_UseTimeStamp" /t Reg_DWORD /d "0" /f >NUL 2>&1

:: Disable NTFS tunnelling
REG ADD "HKLM\SYSTEM\ControlSet001\Control\FileSystem" /v "MaximumTunnelEntries" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Control\FileSystem" /v "MaximumTunnelEntryAgeInSeconds" /t REG_DWORD /d "5" /f >NUL 2>&1

:: Disable Windows Modules Installer
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\TrustedInstaller" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1

:: Prevent the Software Protection service attempting to register a restart every 30s
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform" /v "InactivityShutdownDelay" /t REG_DWORD /d "4294967295" /f >NUL 2>&1

:: Build reg keys to configure event trace sessions
REG EXPORT "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger" "C:\ets-enable.reg"
>> "C:\ets-disable.reg" echo Windows Registry Editor Version 5.00 && >> "C:\ets-disable.reg" echo. && >> "C:\ets-disable.reg" echo [-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger]

:: Disable the creation of 8.3 character-length file names on FAT- and NTFS-formatted volumes
fsutil behavior set disable8dot3 1

:: Disable updates to the Last Access Time stamp
fsutil behavior set disablelastaccess 1

:: AMD GPU optimizations
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "EnableUlps_NA" /t REG_SZ /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "StutterMode" /t REG_SZ /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "EnableUlps_NB" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "ECCMODE" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_Force3DPerformanceMode" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_ForceHighDPMLevel" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisableAllClockGating" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisableAspmSWL1" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisableClkReqSupport" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisableCpPowerGating" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisableDrmdmaMGCG" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisableDrmdmaPowerGating" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisableDrmLightSleep" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisableDrmMGCG" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisableDynamicGfxMGPowerGating" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisableFBCForFullScreenApp" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisableFBCForXDMA" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisableFBCSupport" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisableForceUvdToSclk" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisableGDSPowerGating" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisableGfx3DCGCG" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisableGfx3DCGLS" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisableGfxCGPowerGating" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisableGfxCGTS" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisableGfxCGTS_LS" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisableGfxClockGating" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisableGfxCoarseGrainClockGating" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisableGfxCoarseGrainLightSleep" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisableGfxCpLightSleep" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisableGfxMediumGrainClockGating" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisableGfxMediumGrainLightSleep" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisableGFXPipelinePowerGating" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisableGfxMGCGPerfMon" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisableGfxPGCondClearStateWA" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisableGfxRlcLightSleep" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisableGmcPowerGating" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisableHdpLightSleep" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisableHdpMGClockGating" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisableLPTSupport" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisableLTR" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisableLTREnforcement" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisableLTRNoSnoopRequirement" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisableLTRSnoopRequirement" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisableLTRStrap" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisableMcLightSleep" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisableMcMGCG" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisablePowerGating" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisableRomMGCGClockGating" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisableSamuClockGating" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisableSamuLightSleep" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisableSAMUPowerGating" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisableSdmaMGCG" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisableSdmaMGLS" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisableStaticGfxMGPowerGating" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisableSysClockGating" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisableUVDPowerGating" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisableUVDPowerGatingDynamic" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisableVceClockGating" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisableVceLightSleep" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisableVCEPowerGating" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisableXdmaLightSleep" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisableXdmaPowerGating" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisableXdmaSclkGating" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "EnableAspmL0s" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "EnableAspmL1" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "EnableAspmL1SS" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "EnableSpreadSpectrum" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "EnableSysClockGatingThruSmu" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "EnableUlps" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "EnableUvdClockGating" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "EnableVcePllSpreadSpectrum" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "EnableVceSwClockGating" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PO_DisableClockGating" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_ACDCGpioDisabled" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_ACPDPM" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_DisableClockStretcher" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_DisableDBRamping" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_DisableDIDT" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_DisableDPM" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_DisableEDCLeakageController" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_DisableEngineTransition" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_DisableFFC" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_DisableLightSleep" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_DisableULPS" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_DisablePowerOptimization" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_EnablePowerSave" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_EnableLoadFalconSmcFirmware" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_EnablePowerContainment" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_EnableChillOptimization" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_EnablePowerOptimization" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_DisablePCIePerformanceRequest" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_EnableLongIdleBACOSupport" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_DisableULV" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_DisableMemoryTransition" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_DisableVoltageTransition" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DALDisableAzClockGating" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DalDisableFBCCompClkGate" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DaleAllowCCState" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DalEnableTiledDisplay" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DalPowerGatingLb" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DalPowerGatingPipe" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "KMD_BacoOnSingleGpu" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "KMD_DisableDxvaVPClockManagement" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_SclkDeepSleepDisable" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_GPUPowerDownEnabled" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_SclkDpmDisabled" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_PcieDpmDisabled" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_MMClockGatingEnabled" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_MclkDpmDisabled" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_LSCGDisable" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_ShadowPstateMode" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_UserBACOEnable" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_UMDPStateDisable" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_ThermalAutoThrottlingEnable" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_VRHotGpioDisabled" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_EnablePkgPwrTracking" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_EnablePerDPM" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_EnableMCLKOptimization" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_DisableVoltageIsland" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "KMD_EnableEventLog" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "KMD_EnableGpuMessage" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "KMD_EnableIoMmuGpuIsolation" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "KMD_EnableOPM2Interface" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "KMD_EnableVirtualDalSupport" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "ACGSupported" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DalAllowSelfRefreshControl" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisableAcpPowerGating" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "EnableAtomworkDebugger" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "EnableCPLIBLog" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "EnableDfDramScrub" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "EnableGfxClockGatingThruSmu" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "EnableGPUVirtulizationFeature" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "EnableLBPWSupport" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "EnablePllOffInL1" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "EnablePPSMSupport" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "IRQMgrDisableIHClockGating" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "CailDisableGdbSpmProgramming" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "CailDisableVbiosRegAccessDebug" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "CAILEnableACPIOptimization" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DalAllowNBPState" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DalAsicFIDLightSleep" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DalEnableLTTPR" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DalMPOSCLKDeepSleepIncrease" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisableAcpSupport" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisableBifLightSleep" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisableBifMGCG" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisableGCEDC" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisableRlcSmuPGHandshake" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisableSpuMGCG" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_BAMACOEnabled" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_CGCGDisable" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_DisableAVFS" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_DisableCAC" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_DisableMultiUVDStates" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_DisableOCLPowerOptimization" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_DisableMCDownLoadFeature" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_DisableODStateInDC" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_DisablePowerContainment" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_DisablePowerControl" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_DisablePPM" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_DisableShadowPstate" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_DisableThermalManagement" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_DisableSMUUVDHandshake" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_DisableSPLLShutdownSupport" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_DisableUVDClientMCTuning" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_DisableUVDVCEShutDown" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_DisableXDMANaturalDPM" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_EnableACPIOptimization" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_EnableBACOSupportFeature" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_isIcafeEnable" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_SAMUDPM" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_SclkThrottleLowNotification" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_UVDDPM" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_VCEDPM" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DalAllowCPUPStateSwitch" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DALExtraMCLatency" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DALExtraReorderingLatency" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_EnableHardwareThermalProtection" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DalLogEnable" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "KMD_ForceD3ColdSupport" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "KMD_ForceD3ColdAuxPowerSupport" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "KMD_DisableFBCRegion" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "KMD_DisableFBCMixedMode" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "KMD_EnableGuestHibernation" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "KMD_EnableMesLog" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "KMD_CpDebugDump" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "KMD_DisableCgOnShutdownOnly" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "KMD_ForceD3hotWhenD3coldSupported" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "KMD_ForceIpsForD3Cold" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_MemorySSEnabled" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_EngineSSEnabled" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_BreakOnAssert" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_BreakOnWarn" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisableKernelPowerInterface" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisableQuickGfxMGPowerGating" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "KMD_StandbyOptimization" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "MemoryBankDowngrade" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_MGCGCGTSSMDisable" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_MGCGDisable" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_ForceMCLKHigh" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DP_ForceSSEnable" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DalDPSkipPowerOff" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DalEnableHdcp22Debugging" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "KMD_EnableDebugVmid" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_AutoWattManDebug" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisableEarlySamuInit" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "KMD_EnableAcpLogging" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "KMD_EnableBigPageAppLogging" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "KMD_InjectWait3DIdle" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "KMD_EnableParaVirtualization" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_ThermalOutGpioDisabled" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DalPSRFeatureEnable" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "KMD_DisableDPD" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "KMD_EnableAllocStackTrace" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "KMD_EnableOPM2Interface" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "BankSwapDowngrade" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DalEnableDPMSTFeature" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DalForcePSR" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DalLimitModesOnSclk" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DalSendDPMSNotification" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DalStutterIgnoreFbcForNBp" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "KMD_DbgIntSupport" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "KMD_EnableUvdRTPM" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "KMD_RTPMEnabled" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_BACOSkipHardware" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_BACOSkipSMCInterrupt" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_BACOUseIOAccess" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "KMD_EnableKiqDbg" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "KMD_EnableContextBasedPowerManagement" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_ForceHwAvfsEn" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "KMD_DisableATIDBGPOST" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "KMD_LongIdleDetectOption" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "KMD_ForceTmzDisable" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DalLowVCEPerformance" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "EnableSpreadSpectrum" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_GeminiLCSSupportFeature" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_ODNFeatureEnable" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DalSceOledEnable" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DalSceEnable" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DalDisableFEC" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_GfxOffControl" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_EnableRaceToIdle" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisablePllOffInL1" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisableDfMGCG" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DisableMcMediumGrainClockGating" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "EnableswGCCGPG" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "EnableswGcLbpw" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "EnableswGCFakeCGPG" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "EnableswGCFakeCGCG" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "EnableVCNMemoryShutdown" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "EnableUmschSelfTest" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_EnableVPEPG" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "EnableVPECG" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "EnableVPEDpm" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PipeTilingDowngrade" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "GroupSizeDowngrade" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "RowTilingDowngrade" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "SampleSplitDowngrade" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "SMU_DisableMmhubPowerGating" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "SMU_DisableAthubPowerGating" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "SMU_DisableACG" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_SocclkDpmDisabled" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_EnableDummyPstateTable" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "SMU_EnableVCNPG" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "SMU_EnableJPEGPG" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "SMU_EnableISPPG" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "SMU_EnableMMHUBPG" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "SMU_EnableUMSCHPG" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "SMU_EnableVPEPG" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "SMU_EnableLSDMAPG" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "SMU_ConfigMALLPG" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DalDisableClockGating" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DalDisallowpstateChange" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DalDisableHubpPG" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DalDisableDscPG" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DalDisableDppPG" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DalDisableMpcOtgPG" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DalFineGrainClockGating" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DalMemLowPowerSupport" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "KMD_PXDPPEDynamicPowerStates" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "KMD_PXS3S4OptimizationSupport" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "KMD_WindowedModePowerManagement" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DalWirelessDisplayIdleSupport" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "KMD_LoopCountForIdle" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PipePowerGating" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "KMD_EnableVcnIdleTimer" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_EnableDynamicLTRSupport" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "PP_SkipQueryATPXPowerDown" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DalEnableOledEdpPowerUpOpt" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DalEnableIdleRegChecks" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DalReplayLowRefreshRateEnableOpt" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DalFeatureEnableUSB4PowerManagement" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DalPSRPowerOpt" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DalDisableIdlePowerOptimizations" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DalEnableFreesyncPowerOptimization" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DalDisable48MhzPwrDwn" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DalForceMaxDisplayClock" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DalRegKey_DisableMemLowPower" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "DalIgnoreDPRefClkSS" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /v "EnableVPEMemoryShutdown" /t REG_DWORD /d "0" /f > nul 2>&1

:: Dwm tweaks
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v DesktopHeapLogging /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v DwmInputUsesIoCompletionPort /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v EnableDwmInputProcessing /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\DWM" /v "EnableAeroPeek" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\DWM" /v "Blur" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\DWM" /v "CompositionPolicy" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\DWM" /v "Composition" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\DWM" /v "AlwaysHibernateThumbnails" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\DWM" /v "EnableWindowColorization" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\DWM" /v "AnimationAttributionEnabl"ed /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\DWM" /v "AnimationAttributionHashingEnabled" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\DWM" /v "OneCoreNoBootDWM" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\DWM" /v "ForceEffectMode" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\DWM" /v "DisallowComposition" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\DWM" /v "EnableShadow" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\DWM" /v "DisableHologramCompositor" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\DWM" /v "DisableProjectedShadows" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\DWM" /v "EnableDesktopOverlays" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\DWM\ExtendedComposition" /v "Compositor" /t REG_SZ /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\DWM\ExtendedComposition" /v "enableColorSeparation" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\DWM\ExtendedComposition" /v "ExclusiveModeFramerateAveragingPeriodMs" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\DWM\ExtendedComposition" /v "ExclusiveModeFramerateThresholdPercent" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\DWM\ExtendedComposition" /v "ForwardOnlyOnly" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\DWM\ExtendedComposition" /v "RemoveSRMeshInShell" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\DWM\ExtendedComposition" /v "SydneyDownsampleFilterKernelSize" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\DWM" /v "DWMWA_TRANSITIONS_FORCEDISABLED" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\DWM" /v "DisallowAnimations" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\DWM" /v "AnimationAttributionEnabled" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\DWM" /v "AnimationAttributionHashingEnabled" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\DWM" /v "DisableAccentGradient" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\DWM" /v "DisallowFlip3d" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\DWM" /v "Composition" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\DWM" /v "DisallowAnimations" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\DWM" /v "DisallowFlip3d" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v "DwmInputUsesIoCompletionPort" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v "EnableDwmInputProcessing" /t REG_DWORD /d "0" /f >NUL 2>&1

:: Miscellaneous
REG ADD "HKLM\SOFTWARE\Microsoft\Ole" /v "EnableDCOM" /t Reg_Sz /d N /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Microsoft\FTP" /v "Use PASV" /t Reg_Sz /d no /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Control\GraphicsDrivers\Configuration\BNQ7F58LAL04138SL0_2A_07E4_2E^E866752506E97B4D61FBA5E9F9717023\00\00" /v "Scaling" /t Reg_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RmPowerFeature" /t REG_DWORD /d "1413829973" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RmPowerFeature2" /t REG_DWORD /d "89478485" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RmEnableNoiseAwarePll" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "ReportAnalytics" /t Reg_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DisableTaskOffload" /t Reg_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "IRQ00Priority" /t Reg_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "IRQ08Priority" /t Reg_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "IRQ16Priority" /t Reg_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "IRQ23Priority" /t Reg_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "IRQ8Priority" /t Reg_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\TimeBrokerSvc" /v "Start" /t Reg_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager\Executive" /v "AdditionalCriticalWorkerThreads" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager\Executive" /v "AdditionalDelayedWorkerThreads" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager\Executive" /v "PriorityQuantumMatrix" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "PoolUsageMaximum" /t REG_DWORD /d "40" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Control\Power\Profile\Events\{54533251-82be-4824-96c1-47b60b740d00}\{0DA965DC-8FCF-4c0b-8EFE-8DD5E7BC959A}\{7E01ADEF-81E6-4e1b-8075-56F373584694}" /v "TimeLimitInSeconds" /t Reg_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability" /v "TimeStampInterval" /t Reg_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Ole" /v "LegacyImpersonationLevel" /t Reg_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows" /v "NonBestEffortLimit" /t Reg_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\cdrom" /v "AutoRun" /t Reg_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\NDIS\Parameters" /v "MaxNumRssCpus" /t Reg_DWORD /d "10" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\NDIS\Parameters" /v "MaxNumRssThreads" /t Reg_DWORD /d "20" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Control\GraphicsDrivers\Configuration\BNQ7F58LAL04138SL0_2A_07E4_2E^E866752506E97B4D61FBA5E9F9717023\00\00" /v "Rotation" /t Reg_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\ControlSet001\Control\GraphicsDrivers\Configuration\BNQ7F58LAL04138SL0_2A_07E4_2E^E866752506E97B4D61FBA5E9F9717023\00\00" /v "ScanlineOrdering" /t Reg_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control" /v "SvcHostSplitThresholdInKB" /t Reg_DWORD /d "33554432" /f >NUL 2>&1
REG ADD "HKCU\Control Panel\Input Method" /v "Show Status" /t Reg_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\mouhid\Parameters" /v "TreatAbsolutePointerAsAbsolute" /t Reg_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\mouhid\Parameters" /v "TreatAbsoluteAsRelative" /t Reg_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\Control Panel\Cursors" /v "CursorDeadzoneJumpingSetting" /t Reg_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableCursorSuppression" /t Reg_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\NDIS\Parameters" /v "CheckFwVersion" /t Reg_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\NDIS\Parameters" /v "RssBaseCpu" /t Reg_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\AUEP" /v "RSX_AUEPStatus" /t Reg_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnableUlps" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableDMACopy" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableBlockWrite" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "StutterMode" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PP_SclkDeepSleepDisable" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PP_ThermalAutoThrottlingEnable" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableDrmdmaPowerGating" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability" /v "TimeStampInterval" /t Reg_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\FTH" /v "Enabled" /t Reg_DWORD /d "4" /f >NUL 2>&1
REN C:\Windows\System32\BFE.DLL BFE.DLL.old >NUL 2>&1
REN C:\Windows\System32\ctfmon.exe ctfmon.exe.old >NUL 2>&1
REN C:\Windows\System32\CompPkgSrv.exe CompPkgServ.exe.old >NUL 2>&1
REN C:\Windows\System32\MoUsoCoreWorker.exe MoUseCoreWorker.exe.old >NUL 2>&1
REN C:\Windows\SysWOW64\wbem\WmiPrvSE.exe WmiPrvSE.exe.old >NUL 2>&1
REN C:\Windows\System32\wbem\WmiPrvSE.exe WmiPrvSE.exe.old >NUL 2>&1
REN C:\Windows\System32\wbem\WMIADAP.exe WMIADAP.exe.old >NUL 2>&1
REN C:\Windows\System32\ShellHost.exe ShellHost.exe.old >NUL 2>&1
fsutil behavior set allowextchar 0
fsutil behavior set Bugcheckoncorrupt 0
fsutil behavior set disablecompression 1
fsutil behavior set disableencryption 1
fsutil behavior set disablespotcorruptionhandling 1
fsutil behavior set quotanotify 10800
fsutil repair set C: 0
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager\Executive" /V "AdditionalCriticalWorkerThreads" /T REG_DWORD /d 0 /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager\Executive" /V "AdditionalDelayedWorkerThreads" /T REG_DWORD /d 0 /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /V "MaxWorkItems" /T REG_DWORD /d 512 /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" /V "MaxThreads" /T REG_DWORD /d 32 /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager\I/O System" /V "IoEnableSessionZeroAccessCheck" /T REG_DWORD /d 0 /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager\I/O System" /V "PassiveIntRealTimeWorkerCount" /T REG_DWORD /d 0 /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager\I/O System" /V "PassiveIntRealTimeWorkerPriority" /T REG_DWORD /d 0 /f >NUL 2>&1
BCDEDIT /set maxproc No >NUL 2>&1
BCDEDIT /set restrictapicluster 0 >NUL 2>&1

:: Disable unnecessary VMWare
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\vsock" /v "ErrorControl" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\vsock" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\hcmon" /v "ErrorControl" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\hcmon" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\vstor2-mntapi20-shared" /v "ErrorControl" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\vstor2-mntapi20-shared" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\VMUSBArbService" /v "ErrorControl" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\VMUSBArbService" /v "Start" /t REG_DWORD /d "3" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\VMwareHostd" /v "ErrorControl" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\VMwareHostd" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1

:: Disable DMA memory protection and cores isolation
REG ADD "HKLM\Software\Policies\Microsoft\FVE" /v "DisableExternalDMAUnderLock" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\DeviceGuard" /v "HVCIMATRequired" /t REG_DWORD /d "0" /f >NUL 2>&1

:: IFEO tweaked (Questionable)
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\audiodg.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "2" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\chkdsk.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\chkdsk.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "3" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\defrag.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\defrag.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\dism.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\dism.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\dwm.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\dwm.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "3" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\GameBar.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\GameBar.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\GameBarFT.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\GameBarFT.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\GameBarFTServer.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\GameBarFTServer.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe\PerfOptions" /v "PagePriority" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MicrosoftEdgeUpdate.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MicrosoftEdgeUpdate.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MRT.exe" /v "CFGOptions" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MRT.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MRT.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\mscorsvw.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\mscorsvw.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\msedge.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "3" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MsMpEng.exe" /v "CFGOptions" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MsMpEng.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MsMpEng.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ngen.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ngen.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ngentask.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ngentask.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ntoskrnl.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ntoskrnl.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "3" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SearchIndexer.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SearchIndexer.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\svchost.exe" /v "MinimumStackCommitInBytes" /t REG_DWORD /d "32768" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\svchost.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\TiWorker.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\TiWorker.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\TrustedInstaller.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\TrustedInstaller.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\UsoClient.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\UsoClient.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\usocoreworker.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\usocoreworker.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\wuauclt.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\wuauclt.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f >NUL 2>&1

:: ThreadPriority tweaks (Questionable)
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl\Parameters" /v "ThreadPriority" /t REG_DWORD /d "15" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\HDAudBus\Parameters" /v "ThreadPriority" /t REG_DWORD /d "15" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\HidUsb\Parameters" /v "ThreadPriority" /t REG_DWORD /d "15" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\kbdhid\Parameters" /v "ThreadPriority" /t REG_DWORD /d "15" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\monitor\Parameters" /v "ThreadPriority" /t REG_DWORD /d "15" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\mouhid\Parameters" /v "ThreadPriority" /t REG_DWORD /d "15" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\usbccgp\Parameters" /v "ThreadPriority" /t REG_DWORD /d "15" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\usbehci\Parameters" /v "ThreadPriority" /t REG_DWORD /d "15" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\usbhub\Parameters" /v "ThreadPriority" /t REG_DWORD /d "15" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\USBHUB3\Parameters" /v "ThreadPriority" /t REG_DWORD /d "15" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\usbohci\Parameters" /v "ThreadPriority" /t REG_DWORD /d "15" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\usbuhci\Parameters" /v "ThreadPriority" /t REG_DWORD /d "15" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\USBXHCI\Parameters" /v "ThreadPriority" /t REG_DWORD /d "15" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\NDIS\Parameters" /v "ThreadPriority" /t REG_DWORD /d "15" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "ThreadPriority" /t REG_DWORD /d "15" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "ThreadPriority" /t REG_DWORD /d "0" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Audiosrv\Parameters" /v "ThreadPriority" /t REG_DWORD /d "0" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\disk\Parameters" /v "ThreadPriority" /t REG_DWORD /d "0" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\iaStorAC\Parameters" /v "ThreadPriority" /t REG_DWORD /d "0" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\iaStorAVC\Parameters" /v "ThreadPriority" /t REG_DWORD /d "0" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Ntfs\Parameters" /v "ThreadPriority" /t REG_DWORD /d "0" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\storahci\Parameters" /v "ThreadPriority" /t REG_DWORD /d "0" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters" /v "ThreadPriority" /t REG_DWORD /d "0" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters" /v "ThreadPriority" /t REG_DWORD /d "0" /f >NUL 2>&1

:: DirectX tweaks (Questionable)
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "CreateGdiPrimaryOnSlaveGPU" /t REG_DWORD /d "1" /f NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "DriverSupportsCddDwmInterop" /t REG_DWORD /d "1" /f NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "DxgkCddSyncDxAccess" /t REG_DWORD /d "1" /f NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "DxgkCddSyncGPUAccess" /t REG_DWORD /d "1" /f NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "DxgkCddWaitForVerticalBlankEvent" /t REG_DWORD /d "1" /f NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "DxgkCreateSwapChain" /t REG_DWORD /d "1" /f NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "DxgkFreeGpuVirtualAddress" /t REG_DWORD /d "1" /f NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "DxgkOpenSwapChain" /t REG_DWORD /d "1" /f NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "DxgkShareSwapChainObject" /t REG_DWORD /d "1" /f NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "DxgkWaitForVerticalBlankEvent" /t REG_DWORD /d "1" /f NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "DxgkWaitForVerticalBlankEvent2" /t REG_DWORD /d "1" /f NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "SwapChainBackBuffer" /t REG_DWORD /d "1" /f NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "TdrResetFromTimeoutAsync" /t REG_DWORD /d "1" /f NUL 2>&1

:: Cursor tweaks (Questionable)
REG ADD "HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorMagnetism" /v "AttractionRectInsetInDIPS" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorMagnetism" /v "DistanceThresholdInDIPS" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorMagnetism" /v "MagnetismDelayInMilliseconds" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorMagnetism" /v "MagnetismUpdateIntervalInMilliseconds" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorMagnetism" /v "VelocityInDIPSPerSecond" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorSpeed" /v "CursorUpdateInterval" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorSpeed" /v "CursorSensitivity" /t REG_DWORD /d "2710" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorSpeed" /v "IRRemoteNavigationDelta" /t REG_DWORD /d "1" /f >NUL 2>&1

:: Disable Touch Input
REG ADD "HKCU\Software\Microsoft\Wisp\Touch" /v "TouchGate" /t REG_DWORD /d "0" /f >NUL 2>&1

:: Power settings
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "AwayModeEnabled" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "Class1InitialUnparkCount" /t REG_DWORD /d "100" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "CsEnabled" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DisableDynamicProcessorBoost" /t REG_DWORD /d 1 /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "EnergyEstimationEnabled" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "PerfCalculateActualUtilization" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "SleepReliabilityDetailedDiagnostics" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "EventProcessorEnabled" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "Class2InitialUnparkCount" /t REG_DWORD /d "100" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "EnergyEstimationDisabled" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "QosManagesIdleProcessors" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DisableVsyncLatencyUpdate" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DisableSensorWatchdog" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "ExitLatencyCheckEnabled" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceDefault" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceFSVP" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceIdleResiliency" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyTolerancePerfOverride" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceScreenOffIR" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceVSyncEnabled" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f >NUL 2>&1

:: Resource Management settings
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\HardCap0" /v "CapPercentage" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\HardCap0" /v "SchedulingType" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\Paused" /v "CapPercentage" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\Paused" /v "SchedulingType" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\SoftCapFull" /v "CapPercentage" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\SoftCapFull" /v "SchedulingType" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\SoftCapFullAboveNormal" /v "CapPercentage" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\SoftCapFullAboveNormal" /v "PriorityClass" /t REG_DWORD /d "32" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\SoftCapFullAboveNormal" /v "SchedulingType" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\SoftCapLow" /v "CapPercentage" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\SoftCapLow" /v "SchedulingType" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\SoftCapLowBackgroundBegin" /v "CapPercentage" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\SoftCapLowBackgroundBegin" /v "PriorityClass" /t REG_DWORD /d "32" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\SoftCapLowBackgroundBegin" /v "SchedulingType" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\UnmanagedAboveNormal" /v "CapPercentage" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\UnmanagedAboveNormal" /v "PriorityClass" /t REG_DWORD /d "32" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\UnmanagedAboveNormal" /v "SchedulingType" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Processor" /v "Capabilities" /t REG_DWORD /d "517734" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\IO\NoCap" /v "IOBandwidth" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "IoEnableSessionZeroAccessCheck" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\BackgroundDefault" /v "IsLowPriority" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\Frozen" /v "IsLowPriority" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\FrozenDNCS" /v "IsLowPriority" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\FrozenDNK" /v "IsLowPriority" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\FrozenPPLE" /v "IsLowPriority" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\Paused" /v "IsLowPriority" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\PausedDNK" /v "IsLowPriority" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\Pausing" /v "IsLowPriority" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\PrelaunchForeground" /v "IsLowPriority" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\ThrottleGPUInterference" /v "IsLowPriority" /t REG_DWORD /d "0" /f >NUL 2>&1

:: Kernel settings
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DpcWatchdogProfileOffset" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableExceptionChainValidation" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "KernelSEHOPEnabled" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MaximumSharedReadyQueueSize" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableAutoBoost" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DistributeTimers" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DpcTimeout" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "IdealDpcRate" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MaximumDpcQueueDepth" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MinimumDpcRate" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "ThreadDpcEnable" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "AdjustDpcThreshold" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DpcWatchdogPeriod" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "SeTokenSingletonAttributesConfig" /t REG_DWORD /d "3" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableTsx" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "ObUnsecureGlobalNames" /t REG_MULTI_SZ /d "netfxcustomperfcounters.1.0\0SharedPerfIPCBlock\0Cor_Private_IPCBlock\0Cor_Public_IPCBlock_" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DynamicDpcProtocol" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "SerializeTimerExpiration" /t REG_DWORD /d "2" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "InterruptSteeringDisabled" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DpcQueueDepth" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MaxDynamicTickDuration" /t REG_DWORD /d "10" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "ForceIdleGracePeriod" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MaximumDpcRate" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableBufferedIoInit" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "BufferSize" /t REG_DWORD /d "32" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "IoQueueWorkItem" /t REG_DWORD /d "32" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "IoQueueWorkItemToNode" /t REG_DWORD /d "32" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "IoQueueWorkItemEx" /t REG_DWORD /d "32" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "IoQueueThreadIrp" /t REG_DWORD /d "32" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "ExTryQueueWorkItem" /t REG_DWORD /d "32" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "IoEnqueueIrp" /t REG_DWORD /d "32" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "WatchdogResumeTimeout" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "IdleScanInterval" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "IdleDurationExpirationTimeout" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DelayCloseSize" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DelayDerefKCBLimit" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "WorkerFactoryThreadIdleTimeout" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "PassiveWatchdogTimeout" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "BugCheckUnexpectedInterrupts" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableLowQosTimerResolution" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableControlFlowGuardExportSuppression" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableControlFlowGuardXfg" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DpcCumulativeSoftTimeout" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DpcWatchdogProfileBufferSizeBytes" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "ForceForegroundBoostDecay" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "SplitLargeCaches" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "XMMIZeroingEnable" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "PriorityControl" /t REG_DWORD /d "50" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableOverlappedExecution" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "TimeIncrement" /t REG_DWORD /d "15" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "QuantumLength" /t REG_DWORD /d "20" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\Kernel DMA Protection" /v DeviceEnumerationPolicy /t REG_DWORD /d 0 /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection" /v DeviceEnumerationPolicy /t REG_DWORD /d 0 /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DebugPollInterval" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "KernelSEHOPEnabled" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationOptions" /t REG_BINARY /d "222222222222222222222222222222222222222222222222" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationAuditOptions" /t REG_BINARY /d "222222222222222222222222222222222222222222222222" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "UnlimitDpcQueue" /t REG_DWORD /d "1" /f >NUL 2>&1

:: Ghidra related to gpu (Questionable)
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "D3PCLatency" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "DisableWriteCombining" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "EnableRuntimePowerManagement" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "FlTransitionLatency" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "HwSchedMode" /t REG_DWORD /d "2" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "LOWLATENCY" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "Node3DLowLatency" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "PciLatencyTimerControl" /t REG_DWORD /d "32" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "PowerSavingTweaks" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "PrimaryPushBufferSize" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "RMDeepLlEntryLatencyUsec" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "RMDisablePostL2Compression" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "RmDisableRegistryCaching" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "TdrLevel" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "UseGpuTimer" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "D3PCLatency" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DisableWriteCombining" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "EnableRuntimePowerManagement" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "FlTransitionLatency" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "LOWLATENCY" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "Node3DLowLatency" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "PciLatencyTimerControl" /t REG_DWORD /d "32" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "PowerSavingTweaks" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "PrimaryPushBufferSize" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "RMDeepLlEntryLatencyUsec" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "RMDisablePostL2Compression" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "RmDisableRegistryCaching" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "UseGpuTimer" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "AdaptiveVsyncEnable" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "AllowDeepCStates" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "BuffersInFlight" /t REG_DWORD /d "128" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "D3PCLatency" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "DisableGDIAcceleration" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "DisablePFonDP" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "DisableWriteCombining" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "Disable_OverlayDSQualityEnhancement" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "EnableRuntimePowerManagement" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "FlTransitionLatency" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "LOWLATENCY" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "Node3DLowLatency" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "PciLatencyTimerControl" /t REG_DWORD /d "32" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "PowerSavingTweaks" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "PrimaryPushBufferSize" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "RMDeepLlEntryLatencyUsec" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "RMDisablePostL2Compression" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "RmDisableRegistryCaching" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "RmFbsrPagedDMA" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "UseGpuTimer" /t REG_DWORD /d "1" /f >NUL 2>&1
	
:: Force contiguous memory allocation in the DirectX Graphics Kernel (Questionable)
REG ADD "HKLM\System\CurrentControlSet\Control\GraphicsDrivers" /v "DpiMapIommuContiguous" /t REG_DWORD /d "1" /f >NUL 2>&1

:: Force contiguous memory allocation in the NVIDIA driver (Questionable)
REG ADD "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PreferSystemMemoryContiguous" /t REG_DWORD /d "1" /f >NUL 2>&1

:: Display tweaks (Questionable)
FOR /F "DELIMS=DesktopMonitor, " %%i in ('WMIC PATH Win32_DesktopMonitor GET DeviceID^| FINDSTR /L "DesktopMonitor"') DO (
	SET MonitorAmount=%%i
)
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v Display%MonitorAmount%_PipeOptimizationEnable /t REG_DWORD /d "1" /f >NUL 2>&1

:: Avalon tweaks (Questionable)
REG ADD "HKCU\SOFTWARE\Microsoft\Avalon.Graphics" /v "ClearTypeLevel" /t REG_DWORD /d "100" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Microsoft\Avalon.Graphics" /v "DisableHWAcceleration" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Microsoft\Avalon.Graphics" /v "EnhancedContrastLevel" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Microsoft\Avalon.Graphics" /v "GammaLevel" /t REG_DWORD /d "1600" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Microsoft\Avalon.Graphics" /v "GrayscaleEnhancedContrastLevel" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Microsoft\Avalon.Graphics" /v "MaxMultisampleSize" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Microsoft\Avalon.Graphics" /v "PixelStructure" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Microsoft\Avalon.Graphics" /v "TextContrastLevel" /t REG_DWORD /d "6" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Microsoft\Avalon.Graphics" /v "UseReferenceRasterizer" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Avalon.Graphics" /v "ClearTypeLevel" /t REG_DWORD /d "100" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Avalon.Graphics" /v "DisableHWAcceleration" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Avalon.Graphics" /v "EnhancedContrastLevel" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Avalon.Graphics" /v "GammaLevel" /t REG_DWORD /d "1600" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Avalon.Graphics" /v "GrayscaleEnhancedContrastLevel" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Avalon.Graphics" /v "MaxMultisampleSize" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Avalon.Graphics" /v "PixelStructure" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Avalon.Graphics" /v "TextContrastLevel" /t REG_DWORD /d "6" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Avalon.Graphics" /v "UseReferenceRasterizer" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\WOW6432Node\Microsoft\Avalon.Graphics" /v "ClearTypeLevel" /t REG_DWORD /d "100" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\WOW6432Node\Microsoft\Avalon.Graphics" /v "DisableHWAcceleration" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\WOW6432Node\Microsoft\Avalon.Graphics" /v "EnhancedContrastLevel" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\WOW6432Node\Microsoft\Avalon.Graphics" /v "GammaLevel" /t REG_DWORD /d "1600" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\WOW6432Node\Microsoft\Avalon.Graphics" /v "GrayscaleEnhancedContrastLevel" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\WOW6432Node\Microsoft\Avalon.Graphics" /v "MaxMultisampleSize" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\WOW6432Node\Microsoft\Avalon.Graphics" /v "PixelStructure" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\WOW6432Node\Microsoft\Avalon.Graphics" /v "TextContrastLevel" /t REG_DWORD /d "6" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\WOW6432Node\Microsoft\Avalon.Graphics" /v "UseReferenceRasterizer" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKU\.DEFAULT\SOFTWARE\Microsoft\Avalon.Graphics" /v "DisableHWAcceleration" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKU\.DEFAULT\SOFTWARE\Microsoft\Avalon.Graphics" /v "MaxMultisampleSize" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKU\.DEFAULT\SOFTWARE\Microsoft\Avalon.Graphics" /v "UseReferenceRasterizer" /t REG_DWORD /d "0" /f >NUL 2>&1

:: Direct3d tweaks (Questionable)
REG ADD "HKCU\SOFTWARE\Microsoft\Direct3D" /v "DisableVidMemVBs" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Microsoft\Direct3D" /v "FlipNoVsync" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Microsoft\Direct3D" /v "MMX Fast Path" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Microsoft\Direct3D\Drivers" /v "SoftwareOnly" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\SOFTWARE\Microsoft\DirectDraw" /v "EmulationOnly" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Direct3D" /v "DisableVidMemVBs" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Direct3D" /v "FlipNoVsync" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Direct3D" /v "MMX Fast Path" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Direct3D\Drivers" /v "SoftwareOnly" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\DirectDraw" /v "EmulationOnly" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\WOW6432Node\Microsoft\Direct3D" /v "DisableVidMemVBs" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\WOW6432Node\Microsoft\Direct3D" /v "FlipNoVsync" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\WOW6432Node\Microsoft\Direct3D" /v "MMX Fast Path" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\WOW6432Node\Microsoft\Direct3D\Drivers" /v "SoftwareOnly" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SOFTWARE\WOW6432Node\Microsoft\DirectDraw" /v "EmulationOnly" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKU\.DEFAULT\SOFTWARE\Microsoft\Direct3D" /v "DisableVidMemVBs" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKU\.DEFAULT\SOFTWARE\Microsoft\Direct3D" /v "FlipNoVsync" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKU\.DEFAULT\SOFTWARE\Microsoft\Direct3D" /v "MMX Fast Path" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKU\.DEFAULT\SOFTWARE\Microsoft\Direct3D\Drivers" /v "SoftwareOnly" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKU\.DEFAULT\SOFTWARE\Microsoft\DirectDraw" /v "EmulationOnly" /t REG_DWORD /d "0" /f >NUL 2>&1

:: Disable additional NTFS/ReFS mitigations
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager" /v "ProtectionMode" /t REG_DWORD /d "0" /f >NUL 2>&1

:: Specifies the Wake Policy of LPC controllers during activity for the best possible latency
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager" /v "AlpcWakePolicy" /t REG_DWORD /d "1" /f >NUL 2>&1

:: Drivers and the kernel can be paged to disk as needed
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePagingExecutive" /t REG_DWORD /d "1" /f >NUL 2>&1

:: Using big system memory caching to improve microstuttering
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d "1" /f >NUL 2>&1

:: GPU Optimizations
REG ADD "HKLM\System\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnablePreemption" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "VsyncIdleTimeout" /t REG_DWORD /d "0" /f >NUL 2>&1

:: Multimedia Profile
REG ADD "HKLM\System\CurrentControlSet\Services\MMCSS" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "10" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "10" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Affinity" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Background Only" /t REG_SZ /d "False" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Clock Rate" /t REG_DWORD /d "10000" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d "8" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d "6" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f >NUL 2>&1

:: Process Scheduling
REG ADD "HKLM\System\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "40" /f >NUL 2>&1

:: Minimizing the number of times the CPU is forced to perform the relatively power-costly operation of entering and exiting idle states
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager\Power" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager\kernel" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager\Executive" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Control\Power\ModernSleep" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Control\Power" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Control" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >NUL 2>&1

:: Settings based on current Windows Version
for /f "tokens=3*" %%A in ('reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion" /v "ProductName"') do set "WinVersion=%%A %%B"
ECHO %WinVersion% | find "Windows 7" > nul
if %errorlevel% equ 0 (
powercfg -attributes sub_processor 5d76a2ca-e8c0-402f-a133-2158492d58ad -ATTRIB_HIDE >NUL 2>&1
powercfg -setacvalueindex scheme_current sub_processor 5d76a2ca-e8c0-402f-a133-2158492d58ad 1 >NUL 2>&1
)
ECHO %WinVersion% | find "Windows 8.1" > nul
if %errorlevel% equ 0 (
:: Disabling mitigation (Windows 8.1)
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationOptions" /t REG_BINARY /d "00000000000000000000000000000000" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationAuditOptions" /t REG_BINARY /d "00000000000000000000000000000000" /f >NUL 2>&1
:: Manages power policy and power policy notification delivery / Bricks Windows 7
REG ADD "HKLM\System\CurrentControlSet\Services\Power" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: IDE Channel / Bricks Windows 7
REG ADD "HKLM\System\CurrentControlSet\Services\atapi" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
)
ECHO %WinVersion% | find "Windows 10" > nul
if %errorlevel% equ 0 (
:: Disabling mitigation (Windows 10)
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationOptions" /t REG_BINARY /d "22222222222222222002000000200000" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationAuditOptions" /t REG_BINARY /d "20000020202022220000000000000000" /f >NUL 2>&1
:: Manages power policy and power policy notification delivery / Bricks Windows 7
REG ADD "HKLM\System\CurrentControlSet\Services\Power" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
:: IDE Channel / Bricks Windows 7
REG ADD "HKLM\System\CurrentControlSet\Services\atapi" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
)

:: Disable Windows Help
taskkill /f /im HelpPane.exe
takeown /f %WinDir%\HelpPane.exe
icacls %WinDir%\HelpPane.exe /deny Everyone:(X)

ECHO BCD Params...
:: Disable synthetic timer
BCDEDIT /deletevalue useplatformclock >NUL 2>&1
:: Constantly pool interrupts, dynamic tick was implemented as a power saving feature for laptops
BCDEDIT /set disabledynamictick yes >NUL 2>&1
:: Disable synthetic tick
BCDEDIT /set useplatformtick No >NUL 2>&1
:: Disable Data Execution Prevention Security Feature
BCDEDIT /set nx AlwaysOff >NUL 2>&1
:: Disable Emergency Management Services
BCDEDIT /set ems No >NUL 2>&1
BCDEDIT /set bootems No >NUL 2>&1
:: Disable code integrity services
BCDEDIT /set integrityservices disable >NUL 2>&1
:: Disable TPM Boot Entropy policy Security Feature
BCDEDIT /set tpmbootentropy ForceDisable >NUL 2>&1
:: Change bootmenupolicy to be able to F8
BCDEDIT /set bootmenupolicy Legacy >NUL 2>&1
:: Disable kernel debugger
BCDEDIT /set debug No >NUL 2>&1
:: Disable Virtual Secure Mode from Hyper-V
BCDEDIT /set hypervisorlaunchtype Off >NUL 2>&1
:: Disable the Controls the loading of Early Launch Antimalware (ELAM) drivers
BCDEDIT /set disableelamdrivers Yes >NUL 2>&1
:: Disable some of the kernel memory mitigations, gamers dont use SGX under any possible circumstance
BCDEDIT /set isolatedcontext No >NUL 2>&1
BCDEDIT /set allowedinmemorysettings 0x0 >NUL 2>&1
:: Disable DMA memory protection and cores isolation
BCDEDIT /set vm No >NUL 2>&1
BCDEDIT /set vsmlaunchtype Off >NUL 2>&1
:: Disable X2Apic and enable Memory Mapping for PCI-E devices
:: (for the best results enable MSI mode for all devices using MSI utility)
BCDEDIT /set x2apicpolicy Disable >NUL 2>&1
BCDEDIT /set configaccesspolicy Default >NUL 2>&1
BCDEDIT /set MSI Default >NUL 2>&1
BCDEDIT /set usephysicaldestination No >NUL 2>&1
BCDEDIT /set usefirmwarepcisettings No >NUL 2>&1
BCDEDIT /set tscsyncpolicy Legacy >NUL 2>&1
BCDEDIT /set useplatformclock False >NUL 2>&1
BCDEDIT /set uselegacyapicmode Yes >NUL 2>&1
BCDEDIT /set sos no >NUL 2>&1
BCDEDIT /set pae ForceDisable >NUL 2>&1

ECHO Importing registry...
:: Disable SmartScreen
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v SmartScreenEnabled /t REG_SZ /d "Off" /f > NUL 2>&1

:: Disable Content Evaluation
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v ContentEvaluation /t REG_DWORD /d "0" /f > NUL 2>&1

:: Disable Timeline
REG ADD "HKLM\Software\Policies\Microsoft\Windows\System" /v "EnableActivityFeed" /t REG_DWORD /d "0" /f > NUL 2>&1

:: Disable power throttling (Windows 10)
REG ADD "HKLM\System\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f >NUL 2>&1

:: Disable FSO Globally and GameDVR (Windows 10)
REG ADD "HKCU\Software\Microsoft\GameBar" /v "ShowStartupPanel" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\Software\Microsoft\GameBar" /v "GamePanelStartupTipIndex" /t REG_DWORD /d "3" /f >NUL 2>&1
REG ADD "HKCU\Software\Microsoft\GameBar" /v "AllowAutoGameMode" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\Software\Microsoft\GameBar" /v "AutoGameModeEnabled" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\Software\Microsoft\GameBar" /v "UseNexusForGameBarEnabled" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehaviorMode" /t REG_DWORD /d "2" /f >NUL 2>&1
REG ADD "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehavior" /t REG_DWORD /d "2" /f >NUL 2>&1
REG ADD "HKCU\System\GameConfigStore" /v "GameDVR_HonorUserFSEBehaviorMode" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\System\GameConfigStore" /v "GameDVR_DXGIHonorFSEWindowsCompatible" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKCU\System\GameConfigStore" /v "GameDVR_EFSEFeatureFlags" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\System\GameConfigStore" /v "GameDVR_DSEBehavior" /t REG_DWORD /d "2" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" /v "value" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKU\.DEFAULT\Software\Microsoft\GameBar" /v "AutoGameModeEnabled" /t REG_DWORD /d "0" /f >NUL 2>&1
REG DELETE "HKCU\System\GameConfigStore\Children" /f >NUL 2>&1
REG DELETE "HKCU\System\GameConfigStore\Parents" /f >NUL 2>&1

:: Hide Language Bar
REG ADD "HKCU\Software\Microsoft\CTF\LangBar" /v "ShowStatus" /t REG_DWORD /d "3" /f >NUL 2>&1
REG ADD "HKCU\Software\Microsoft\CTF\LangBar" /v "ExtraIconsOnMinimized" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKCU\Software\Microsoft\CTF\LangBar" /v "Transparency" /t REG_DWORD /d "255" /f >NUL 2>&1
REG ADD "HKCU\Software\Microsoft\CTF\LangBar" /v "Label" /t REG_DWORD /d "0" /f >NUL 2>&1

:: Turn Off Enhance Pointer Precision
REG ADD "HKU\.DEFAULT\Control Panel\Mouse" /v "MouseHoverTime" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "HKU\.DEFAULT\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "HKU\.DEFAULT\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "HKU\.DEFAULT\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "HKCU\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "HKCU\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "HKCU\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "HKCU\Control Panel\Mouse" /v "MouseSensitivity" /t REG_SZ /d "10" /f >NUL 2>&1

:: Control Panel tweaks
REG ADD "HKU\.DEFAULT\Control Panel\Desktop" /v "ForegroundLockTimeout" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKU\.DEFAULT\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "HKU\.DEFAULT\Control Panel\Desktop" /v "MouseWheelRouting" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKU\.DEFAULT\Control Panel\Mouse" /v "Beep" /t REG_SZ /d "No" /f >NUL 2>&1
REG ADD "HKU\.DEFAULT\Control Panel\Mouse" /v "ExtendedSounds" /t REG_SZ /d "No" /f >NUL 2>&1
REG ADD "HKU\.DEFAULT\Control Panel\Sound" /v "Beep" /t REG_SZ /d "no" /f >NUL 2>&1
REG ADD "HKU\.DEFAULT\Control Panel\Sound" /v "ExtendedSounds" /t REG_SZ /d "no" /f >NUL 2>&1

:: Disable Acessibility keys
REG ADD "HKU\.DEFAULT\Control Panel\Accessibility\HighContrast" /v "Flags" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "HKU\.DEFAULT\Control Panel\Accessibility\Keyboard Response" /v "Flags" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "HKU\.DEFAULT\Control Panel\Accessibility\MouseKeys" /v "Flags" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "HKU\.DEFAULT\Control Panel\Accessibility\SoundSentry" /v "Flags" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "HKU\.DEFAULT\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "HKU\.DEFAULT\Control Panel\Accessibility\TimeOut" /v "Flags" /t REG_SZ /d "0" /f >NUL 2>&1
REG ADD "HKU\.DEFAULT\Control Panel\Accessibility\ToggleKeys" /v "Flags" /t REG_SZ /d "0" /f >NUL 2>&1

:: Enable All Folders in Explorer Navigation Panel
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "NavPaneShowAllFolders" /t REG_DWORD /d "1" /f >NUL 2>&1

:: Disable automatic folder type discovery
REG ADD "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags\AllFolders\Shell" /v "FolderType" /t REG_SZ /d "NotSpecified" /f >NUL 2>&1
REG DELETE "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags" /f >NUL 2>&1

:: Disable shortcut text for shortcuts
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "link" /t REG_BINARY /d "00000000" /f >NUL 2>&1

:: Disable Mouse Keys Keyboard Shortcut
REG ADD "HKCU\Control Panel\Accessibility\MouseKeys" /v "Flags" /t REG_SZ /d "186" /f >NUL 2>&1
REG ADD "HKCU\Control Panel\Accessibility\MouseKeys" /v "MaximumSpeed" /t REG_SZ /d "40" /f >NUL 2>&1
REG ADD "HKCU\Control Panel\Accessibility\MouseKeys" /v "TimeToMaximumSpeed" /t REG_SZ /d "3000" /f >NUL 2>&1

:: Disable Data Execution Prevention
REG ADD "HKLM\Software\Policies\Microsoft\Windows\Explorer" /v "NoDataExecutionPrevention" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\System" /v "DisableHHDEP" /t REG_DWORD /d "1" /f >NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d "0" /f >NUL 2>&1

:: Disable automatic maintenance
REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v "MaintenanceDisabled" /t REG_DWORD /d "1" /f >NUL 2>&1

:: Disable fast startup
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d "0" /f >NUL 2>&1

:: Disable Sleep study
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "SleepStudyDisabled" /t REG_DWORD /d "1" /f >NUL 2>&1
for %a in ("SleepStudy" "Kernel-Processor-Power" "UserModePowerService") do (wevtutil sl Microsoft-Windows-%~a/Diagnostic /e:false)

:: Disable aero shake
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DisallowShaking" /t REG_DWORD /d "1" /f >NUL 2>&1

:: Disable downloads blocking
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "SaveZoneInformation" /t REG_DWORD /d "1" /f >NUL 2>&1

:: Disable malicious software removal tool from installing
REG ADD "HKLM\Software\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d "1" /f >NUL 2>&1

:: Windows update never notify and never install
REG ADD "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "AUOptions" /t REG_DWORD /d "2" /f >NUL 2>&1

:: Disable error reporting
REG ADD "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f >NUL 2>&1

:: Menu show delay
REG ADD "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f >NUL 2>&1

:: Show BSOD details instead of the sad smiley
REG ADD "HKLM\System\CurrentControlSet\Control\CrashControl" /v "DisplayParameters" /t REG_DWORD /d "1" /f >NUL 2>&1

:: Disable action center
REG ADD "HKCU\Software\Policies\Microsoft\Windows\Explorer" /v "DisableNotificationCenter" /t REG_DWORD /d "1" /f >NUL 2>&1

:: Disable jump lists
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackDocs" /t REG_DWORD /d "0" /f >NUL 2>&1

:: Disable search history
REG ADD "HKCU\Software\Policies\Microsoft\Windows\Explorer" /v "DisableSearchBoxSuggestions" /t REG_DWORD /d "1" /f >NUL 2>&1

:: Disable administrative shares
REG ADD "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "AutoShareWks" /t REG_DWORD /d "0" /f >NUL 2>&1

:: Disable Keyboard Hotkeys
REG ADD "HKCU\Keyboard Layout\Toggle" /v "Language Hotkey" /t REG_SZ /d "3" /f >NUL 2>&1
REG ADD "HKCU\Keyboard Layout\Toggle" /v "Hotkey" /t REG_SZ /d "3" /f >NUL 2>&1
REG ADD "HKCU\Keyboard Layout\Toggle" /v "Layout Hotkey" /t REG_SZ /d "3" /f >NUL 2>&1

:: Turn Off Sleep And Lock In Power Options
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" /v "ShowSleepOption" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" /v "ShowLockOption" /t REG_DWORD /d "0" /f >NUL 2>&1

:: Sound Communications Do Nothing
REG ADD "HKCU\Software\Microsoft\Multimedia\Audio" /v "UserDuckingPreference" /t REG_DWORD /d "3" /f >NUL 2>&1

:: Disable Store And Display Recently Opened Programs In The Start Menu
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackProgs" /t REG_DWORD /d "0" /f >NUL 2>&1

:: Speed Up Start Time
REG ADD "HKCU\AppEvents\Schemes" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DelayedDesktopSwitchTimeout" /t REG_DWORD /d "0" /f >NUL 2>&1

:: Disable Network Notification Icon
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "HideSCANetwork" /t REG_DWORD /d "1" /f >NUL 2>&1
REG DELETE "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "HideSCANetwork" /f >NUL 2>&1

:: Disable Startup Sound
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\BootAnimation" /v "DisableStartupSound" /t REG_DWORD /d "1" /f >NUL 2>&1

:: Small Start Menu Icons
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_LargeMFUIcons" /t REG_DWORD /d "0" /f >NUL 2>&1

:: Black Background
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Background" /v "OEMBackground" /t REG_DWORD /d "1" /f >NUL 2>&1

:: System properties - performance options - adjust for best performance
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v "VisualFXSetting" /t REG_DWORD /d "2" /f >NUL 2>&1

:: Disable KB4524752 Support Notifications
REG ADD "HKLM\Software\Policies\Microsoft\Windows\Gwx" /v "DisableGwx" /t REG_DWORD /d "1" /f >NUL 2>&1

:: Disable KB4524752 Support Notifications
REG ADD "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "DisableOSUpgrade" /t REG_DWORD /d "1" /f >NUL 2>&1

:: Disable Maintenance
REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v "MaintenanceDisabled" /t REG_DWORD /d "1" /f >NUL 2>&1

:: Disable Prefetcher and Superfetch
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\SysMain" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1

:: Show all icons and notifications on the taskbar
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "EnableAutoTray" /t REG_DWORD /d "0" /f >NUL 2>&1 >NUL 2>&1

:: Disable Consumer experiences from Microsoft
REG ADD "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d "1" /f >NUL 2>&1

:: Disable WPP Software Tracing Logs
REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\WUDF" /v "LogEnable" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\WUDF" /v "LogLevel" /t REG_DWORD /d "0" /f >NUL 2>&1

:: Turn off Microsoft Peer-to-Peer Networking Services
REG ADD "HKLM\Software\Policies\Microsoft\Peernet" /v "Disabled" /t REG_DWORD /d "0" /f >NUL 2>&1

:: Turn off Data Execution Prevention
REG ADD "HKLM\Software\Policies\Microsoft\Internet Explorer\Main" /v "DEPOff" /t REG_DWORD /d "1" /f >NUL 2>&1

:: Display highly detailed status messages
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "VerboseStatus" /t REG_DWORD /d "1" /f >NUL 2>&1

:: Trick to make system Startup faster
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /v "StartupDelayInMSec" /t REG_DWORD /d "0" /f >NUL 2>&1

:: Turn off Pen feedback
REG ADD "HKLM\Software\Policies\Microsoft\TabletPC" /v "TurnOffPenFeedback" /t REG_DWORD /d "1" /f >NUL 2>&1

:: Making menu more responsive
REG ADD "HKU\.DEFAULT\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f >NUL 2>&1

:: Disable Remote Assistance Connections
REG ADD "HKLM\System\CurrentControlSet\Control\Remote Assistance" /v "fAllowToGetHelp" /t REG_DWORD /d "0" /f >NUL 2>&1

:: Disable Telemetry
REG ADD "HKCU\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d "1" /f > NUL 2>&1
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f > NUL 2>&1
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "0" /f > NUL 2>&1
REG ADD "HKCU\Software\Policies\Microsoft\Windows\Explorer" /v "DisableNotificationCenter" /t REG_DWORD /d "1" /f > NUL 2>&1
REG ADD "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /v "value" /t REG_DWORD /d "0" /f > NUL 2>&1
REG ADD "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /v "value" /t REG_DWORD /d "0" /f > NUL 2>&1
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DownloadMode" /t REG_DWORD /d "0" /f > NUL 2>&1
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\ImmersiveShell" /v "UseActionCenterExperience" /t REG_DWORD /d "0" /f > NUL 2>&1
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f > NUL 2>&1
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "HideSCAHealth" /t REG_DWORD /d "1" /f > NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d "1" /f > NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f > NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\EnhancedStorageDevices" /v "TCGSecurityActivationDisabled" /t REG_DWORD /d "0" /f > NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSyncNGSC" /t REG_DWORD /d "1" /f > NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\safer\codeidentifiers" /v "authenticodeenabled" /t REG_DWORD /d "0" /f > NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSync" /t REG_DWORD /d "2" /f > NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSyncUserOverride" /t REG_DWORD /d "1" /f > NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d "1" /f > NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f > NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "AllowIndexingEncryptedStoresOrItems" /t REG_DWORD /d "0" /f > NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d "0" /f > NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "AlwaysUseAutoLangDetection" /t REG_DWORD /d "0" /f > NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d "0" /f > NUL 2>&1
REG ADD "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d "1" /f > NUL 2>&1
REG ADD "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f > NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d "0" /f > NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger" /v "Start" /t REG_DWORD /d "0" /f > NUL 2>&1
ECHO "" > C:\ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl >NUL 2>&1

:: Remove Metadata Tracking
REG DELETE "HKLM\Software\Microsoft\Windows\CurrentVersion\Device Metadata" /f > NUL 2>&1

:: Remove Storage Sense
REG DELETE "HKCU\Software\Microsoft\Windows\CurrentVersion\StorageSense" /f > NUL 2>&1

:: Remove Firewall Rules
REG DELETE "HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /f >NUL 2>&1

:: Disable power saving for every device
POWERSHELL "Get-WmiObject MSPower_DeviceEnable -Namespace root\wmi | ForEach-Object { $_.enable = $false; $_.psbase.put(); }" >NUL 2>&1

:: Force refresh rate, replace the value with your own
Reg.exe add "HKLM\SOFTWARE\Microsoft\DirectDraw" /v "ForceRefreshRate" /t REG_DWORD /d "240" /f
Reg.exe add "HKLM\SOFTWARE\WOW6432Node\Microsoft\DirectDraw" /v "ForceRefreshRate" /t REG_DWORD /d "240" /f

:: C1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\943c8cb6-6f93-4227-ad87-e9a3feec08d1" /v "Attributes" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DCSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DCSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Processor" /v "AllowPepPerfStates" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Processor" /v "Cstates" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Processor" /v "Capabilities" /t REG_DWORD /d "516198" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HighPerformance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HighestPerformance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MinimumThrottlePercent" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumThrottlePercent" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumPerformancePercent" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "Class1InitialUnparkCount" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "InitialUnparkCount" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumPerformancePercent" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" /v "fDisablePowerManagement" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PDC\Activators\Default\VetoPolicy" /v "EA:EnergySaverEngaged" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PDC\Activators\28\VetoPolicy" /v "EA:PowerStateDischarging" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Misc" /v "DeviceIdlePolicy" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "PerfEnergyPreference" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "PerfEnergyPreference" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPMinCores" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPMaxCores" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPMinCores1" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPMaxCores1" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CpLatencyHintUnpark1" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPDistribution" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CpLatencyHintUnpark" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "MaxPerformance1" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "MaxPerformance" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPDistribution1" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPHEADROOM" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\PowerCfg\GlobalPowerPolicy" /v "Policies" /t REG_BINARY /d "01000000020000000100000000000000020000000000000000000000000000002c0100003232030304000000040000000000000000000000840300002c01000000000000840300000001646464640000" /f
Reg.exe add "HKCU\Control Panel\PowerCfg\GlobalPowerPolicy" /v "Policies" /t REG_BINARY /d "01000000020000000100000000000000020000000000000000000000000000002c0100003232030304000000040000000000000000000000840300002c01000000000000840300000001646464640000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Processor" /v "Cstates" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Processor" /v "Capabilities" /t REG_DWORD /d "516198" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HighPerformance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HighestPerformance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MinimumThrottlePercent" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumThrottlePercent" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumPerformancePercent" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "Class1InitialUnparkCount" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "InitialUnparkCount" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumPerformancePercent" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPHEADROOM" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPCONCURRENCY" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "ProccesorThrottlingEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleThreshold" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdle" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuLatencyTimer" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuSlowdown" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "DedicatedSegmentSize" /t REG_DWORD /d "1298" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "Threshold" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuDebuggingEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "ProccesorLatencyThrottlingEnabled" /t REG_DWORD /d "0" /f

:: C4
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubDelay" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubInterval" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubPower" /t REG_DWORD /d "18" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubThreshold" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubType" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValue" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueMaximum" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueMinimum" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueStep" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDefault" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueCurrent" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValuePrevious" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueNext" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueLast" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueFirst" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueCount" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueIndex" /t REG_DWORD /d "42" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueName" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDescription" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDisabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueVisible" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueHidden" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueReadOnly" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueReadnv11" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValuenv11Only" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueExecute" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueNoExecute" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueSystem" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueUser" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubPower" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDisabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubPower" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueCustom" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueAuto" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueManual" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueAutomatic" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDisabledByDefault" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueEnabledByDefault" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDefaultEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDefaultDisabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDefaultAuto" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDefaultManual" /t REG_DWORD /d "0" /f

:: Disable preemption
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnablePreemption" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "GPUPreemptionLevel" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnableAsyncMidBufferPreemption" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnableMidGfxPreemptionVGPU" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnableMidBufferPreemptionForHighTdrTimeout" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnableSCGMidBufferPreemption" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "PerfAnalyzeMidBufferPreemption" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnableMidGfxPreemption" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnableMidBufferPreemption" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnableCEPreemption" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "DisableCudaContextPreemption" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "DisablePreemptionOnS3S4" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "ComputePreemptionLevel" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "DisablePreemption" /t REG_DWORD /d "1" /f

:: USB thread priority
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\usbxhci\Parameters" /v "ThreadPriority" /t REG_DWORD /d "31" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\USBHUB3\Parameters" /v "ThreadPriority" /t REG_DWORD /d "31" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Parameters" /v "ThreadPriority" /t REG_DWORD /d "31" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\NDIS\Parameters" /v "ThreadPriority" /t REG_DWORD /d "31" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl\Parameters" /v "ThreadPriority" /t REG_DWORD /d "15" /f

:: DirectX
Reg.exe add "HKLM\SOFTWARE\Microsoft\DirectDraw" /v "DisableAGPSupport" /t Reg_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Wow6432Node\Microsoft\DirectDraw" /v "DisableAGPSupport" /t Reg_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\DirectDraw" /v "UseNonLocalVidMem" /t Reg_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Wow6432Node\Microsoft\DirectDraw" /v "UseNonLocalVidMem" /t Reg_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Direct3D" /v "UseNonLocalVidMem" /t Reg_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Direct3D" /v "UseNonLocalVidMem" /t Reg_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\DirectDraw" /v "DisableDDSCAPSInDDSD" /t Reg_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Wow6432Node\Microsoft\DirectDraw" /v "DisableDDSCAPSInDDSD" /t Reg_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\DirectDraw" /v "EmulationOnly" /t Reg_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Wow6432Node\Microsoft\DirectDraw" /v "EmulationOnly" /t Reg_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\DirectDraw" /v "EmulatePointSprites" /t Reg_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Wow6432Node\Microsoft\DirectDraw" /v "EmulatePointSprites" /t Reg_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Direct3D\Drivers" /v "ForceRgbRasterizer" /t Reg_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Direct3D\Drivers" /v "ForceRgbRasterizer" /t Reg_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\DirectDraw" /v "EmulateStateBlocks" /t Reg_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Wow6432Node\Microsoft\DirectDraw" /v "EmulateStateBlocks" /t Reg_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Direct3D" /v "EnableDebugging" /t Reg_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Direct3D" /v "FullDebug" /t Reg_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Direct3D" /v "DisableDM" /t Reg_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Direct3D" /v "EnableMultimonDebugging" /t Reg_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Direct3D" /v "LoadDebugRuntime" /t Reg_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Direct3D\Drivers" /v "EnumReference" /t Reg_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Direct3D\Drivers" /v "EnumReference" /t Reg_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Direct3D\Drivers" /v "EnumSeparateMMX" /t Reg_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Direct3D\Drivers" /v "EnumSeparateMMX" /t Reg_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Direct3D\Drivers" /v "EnumRamp" /t Reg_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Direct3D\Drivers" /v "EnumRamp" /t Reg_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Direct3D\Drivers" /v "EnumNullDevice" /t Reg_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Direct3D\Drivers" /v "EnumNullDevice" /t Reg_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Direct3D" /v "FewVertices" /t Reg_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Direct3D" /v "FewVertices" /t Reg_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\DirectDraw" /v "DisableMMX" /t Reg_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Wow6432Node\Microsoft\DirectDraw" /v "DisableMMX" /t Reg_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Direct3D" /v "DisableMMX" /t Reg_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Direct3D" /v "DisableMMX" /t Reg_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Direct3D" /v "MMX Fast Path" /t Reg_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Direct3D" /v "MMX Fast Path" /t Reg_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Direct3D" /v "MMXFastPath" /t Reg_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Direct3D" /v "MMXFastPath" /t Reg_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Direct3D" /v "UseMMXForRGB" /t Reg_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Direct3D" /v "UseMMXForRGB" /t Reg_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Direct3D\Drivers" /v "UseMMXForRGB" /t Reg_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Direct3D\Drivers" /v "UseMMXForRGB" /t Reg_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Direct3D\Drivers" /v "EnumSeparateMMX" /t Reg_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Direct3D\Drivers" /v "EnumSeparateMMX" /t Reg_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\DirectDraw" /v "ForceNoSysLock" /t Reg_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Wow6432Node\Microsoft\DirectDraw" /v "ForceNoSysLock" /t Reg_DWORD /d "0" /f

Reg.exe add "HKLM\SOFTWARE\Microsoft\Direct3D" /v "DisableVidMemVBs" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Direct3D" /v "MMX Fast Path" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Direct3D" /v "FlipNoVsync" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Direct3D\Drivers" /v "SoftwareOnly" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "DpiMapIommuContiguous" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "HwSchedMode" /t REG_DWORD /d "2" /f

Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "MonitorLatencyTolerance" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "MonitorRefreshLatencyTolerance" /t REG_DWORD /d "0" /f

:: Disable NIC power savings
Reg.exe add "%%n" /v "AutoPowerSaveModeEnabled" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "AutoDisableGigabit" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "AdvancedEEE" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "DisableDelayedPowerUp" /t REG_SZ /d "2" /f
Reg.exe add "%%n" /v "*EEE" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "EEE" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "EnablePME" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "EEELinkAdvertisement" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "EnableGreenEthernet" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "EnableSavePowerNow" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "EnablePowerManagement" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "EnableDynamicPowerGating" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "EnableConnectedPowerGating" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "EnableWakeOnLan" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "GigaLite" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "NicAutoPowerSaver" /t REG_SZ /d "2" /f
Reg.exe add "%%n" /v "PowerDownPll" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "PowerSavingMode" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "ReduceSpeedOnPowerDown" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "S5NicKeepOverrideMacAddrV2" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "S5WakeOnLan" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "ULPMode" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "WakeOnDisconnect" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "*WakeOnMagicPacket" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "*WakeOnPattern" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "WakeOnLink" /t REG_SZ /d "0" /f
Reg.exe add "%%n" /v "WolShutdownLinkSpeed" /t REG_SZ /d "2" /f

:: General GPU
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Background Only" /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "BackgroundPriority" /t REG_DWORD /d "24" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "GPU Priority" /t REG_DWORD /d "18" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Scheduling Category" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "SFIO Priority" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Latency Sensitive" /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "TdrLevel" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "TdrDebugMode" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "VsyncIdleTimeout" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "TdrDebugMode" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "TdrLevel" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\CurrentControlSet\Services\VxD\BIOS" /v "AGPConcur" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\System\CurrentControlSet\Services\VxD\BIOS" /v "CPUPriority" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\System\CurrentControlSet\Services\VxD\BIOS" /v "FastDRAM" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\System\CurrentControlSet\Services\VxD\BIOS" /v "PCIConcur" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\System\CurrentControlSet\Control\GraphicsDrivers" /v TdrLevel /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\System\CurrentControlSet\Control\GraphicsDrivers" /v TdrDelay /t REG_DWORD /d 60 /f

:: AMD GPU
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "KMD_DeLagEnabled" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "KMD_EnableComputePreemption" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\DAL2_DATA__2_0\DisplayPath_4\EDID_D109_78E9\Option" /v "ProtectionControl" /t REG_BINARY /d "0100000001000000" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PP_DisableVoltageIsland" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PP_GPUPowerDownEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnableVceSwClockGating" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnableUvdClockGating" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableVCEPowerGating" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableUVDPowerGatingDynamic" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisablePowerGating" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableSAMUPowerGating" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableFBCForFullScreenApp" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableFBCSupport" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableEarlySamuInit" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PP_GPUPowerDownEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableDrmdmaPowerGating" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PP_SclkDeepSleepDisable" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PP_ThermalAutoThrottlingEnable" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PP_ActivityTarget" /t REG_DWORD /d "30" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PP_ODNFeatureEnable" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnableUlps" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "GCOOPTION_DisableGPIOPowerSaveMode" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PP_AllGraphicLevel_DownHyst" /t REG_DWORD /d "20" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PP_AllGraphicLevel_UpHyst" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "KMD_FRTEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableDMACopy" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableBlocknv11" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PP_ODNFeatureEnable" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "KMD_MaxUVDSessions" /t REG_DWORD /d "32" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DalAllowDirectMemoryAccessTrig" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DalAllowDPrefSwitchingForGLSync" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "WmAgpMaxIdleClk" /t REG_DWORD /d "32" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PP_MCLKStutterModeThreshold" /t REG_DWORD /d "4096" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "StutterMode" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "TVEnableOverscan" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\Dwm" /v "OverlayTestMode" /t REG_DWORD /d "5" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "MLF" /t REG_BINARY /d "3000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "EQAA" /t REG_BINARY /d "3000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "PowerState" /t REG_BINARY /d "3000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "AreaAniso_DEF" /t REG_SZ /d "8" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "SurfaceFormatReplacements_DEF" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "Main3D_DEF" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "AnisoType_DEF" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "AnisoDegree_DEF" /t REG_SZ /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "ForceTripleBuffering" /t REG_BINARY /d "3000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "ForceTripleBuffering_DEF" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "TextureOpt_DEF" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "TextureLod_DEF" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "TruformMode_DEF" /t REG_SZ /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "LodAdj" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "ForceZBufferDepth_DEF" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "Tessellation_OPTION_DEF" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "NoOSPowerOptions" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "ForceZBufferDepth" /t REG_BINARY /d "3100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "ForceZBufferDepth_DEF" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "Tessellation_DEF" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "Main3D" /t REG_BINARY /d "3100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "AnisoType" /t REG_BINARY /d "32000000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "AnisotropyOptimise" /t REG_BINARY /d "3100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "TrilinearOptimise" /t REG_BINARY /d "3100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "AnisoDegree" /t REG_BINARY /d "3400" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "TextureLod" /t REG_BINARY /d "31000000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "TextureOpt" /t REG_BINARY /d "31000000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "TextureOpt_DEF" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "TruformMode_NA" /t REG_BINARY /d "3200" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "Tessellation_OPTION" /t REG_BINARY /d "3200" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "Tessellation" /t REG_BINARY /d "3100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "Main3D_SET" /t REG_BINARY /d "302031203220332034203500" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "ForceZBufferDepth_SET" /t REG_BINARY /d "3020313620323400" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "FlipQueueSize" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "SurfaceFormatReplacements" /t REG_BINARY /d "3000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "TFQ" /t REG_BINARY /d "3200" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "TFQ_DEF" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "ZFormats_NA" /t REG_BINARY /d "3100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "PowerState" /t REG_BINARY /d "3000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "AntiStuttering" /t REG_BINARY /d "3000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "TurboSync" /t REG_BINARY /d "3000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "HighQualityAF" /t REG_BINARY /d "3300" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "ShaderCache" /t REG_BINARY /d "3200" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "ForceZBufferDepth" /t REG_BINARY /d "3100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "ForceZBufferDepth_DEF" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "Tessellation_DEF" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "Main3D" /t REG_BINARY /d "3100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "AnisoType" /t REG_BINARY /d "32000000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "AnisotropyOptimise" /t REG_BINARY /d "3100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "TrilinearOptimise" /t REG_BINARY /d "3100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "AnisoDegree" /t REG_BINARY /d "3400" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "TextureLod" /t REG_BINARY /d "31000000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "TextureOpt" /t REG_BINARY /d "31000000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "TextureOpt_DEF" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "TruformMode_NA" /t REG_BINARY /d "3200" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "Tessellation_OPTION" /t REG_BINARY /d "3200" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "Tessellation" /t REG_BINARY /d "3100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "Main3D_SET" /t REG_BINARY /d "302031203220332034203500" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "ForceZBufferDepth_SET" /t REG_BINARY /d "3020313620323400" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "FlipQueueSize" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "SurfaceFormatReplacements" /t REG_BINARY /d "3000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "TFQ" /t REG_BINARY /d "3200" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "TFQ_DEF" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "ZFormats_NA" /t REG_BINARY /d "3100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "PowerState" /t REG_BINARY /d "3000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "AntiStuttering" /t REG_BINARY /d "3000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "TurboSync" /t REG_BINARY /d "3000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "HighQualityAF" /t REG_BINARY /d "3300" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "ShaderCache" /t REG_BINARY /d "3200" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnableUlps" /t REG_DWORD /d "0" /f

:: Latency tolerance
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "ExitLatency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "ExitLatencyCheckEnabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "Latency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceDefault" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceFSVP" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyTolerancePerfOverride" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceScreenOffIR" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceVSyncEnabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "RtlCapabilityCheckLatency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "QosManagesIdleProcessors" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DisableVsyncLatencyUpdate" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DisableSensorWatchdog" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "InterruptSteeringDisabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LowLatencyScalingPercentage" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HighPerformance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HighestPerformance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MinimumThrottlePercent" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumThrottlePercent" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumPerformancePercent" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "InitialUnparkCount" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultD3TransitionLatencyActivelyUsed" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultD3TransitionLatencyIdleLongTime" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultD3TransitionLatencyIdleMonitorOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultD3TransitionLatencyIdleNoContext" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultD3TransitionLatencyIdleShortTime" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultD3TransitionLatencyIdleVeryLongTime" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultLatencyToleranceIdle0" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultLatencyToleranceIdle0MonitorOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultLatencyToleranceIdle1" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultLatencyToleranceIdle1MonitorOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultLatencyToleranceMemory" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultLatencyToleranceNoContext" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultLatencyToleranceNoContextMonitorOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultLatencyToleranceOther" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultLatencyToleranceTimerPeriod" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultMemoryRefreshLatencyToleranceActivelyUsed" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultMemoryRefreshLatencyToleranceMonitorOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultMemoryRefreshLatencyToleranceNoContext" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "Latency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MiracastPerfTrackGraphicsLatency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MonitorLatencyTolerance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MonitorRefreshLatencyTolerance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "TransitionLatency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DisableVsyncLatencyUpdate" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DisableSensorWatchdog" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "InterruptSteeringDisabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "ExitLatency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "ExitLatencyCheckEnabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "Latency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceDefault" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceFSVP" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyTolerancePerfOverride" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceScreenOffIR" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceVSyncEnabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "RtlCapabilityCheckLatency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LowLatencyScalingPercentage" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaxIAverageGraphicsLatencyInOneBucket" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultD3TransitionLatencyActivelyUsed" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultD3TransitionLatencyIdleLongTime" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultD3TransitionLatencyIdleMonitorOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultD3TransitionLatencyIdleNoContext" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultD3TransitionLatencyIdleShortTime" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultD3TransitionLatencyIdleVeryLongTime" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultLatencyToleranceIdle0" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultLatencyToleranceIdle0MonitorOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultLatencyToleranceIdle1" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultLatencyToleranceIdle1MonitorOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultLatencyToleranceMemory" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultLatencyToleranceNoContext" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultLatencyToleranceNoContextMonitorOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultLatencyToleranceOther" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultLatencyToleranceTimerPeriod" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultMemoryRefreshLatencyToleranceActivelyUsed" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultMemoryRefreshLatencyToleranceMonitorOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultMemoryRefreshLatencyToleranceNoContext" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaxIAverageGraphicsLatencyInOneBucket" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "Latency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MiracastPerfTrackGraphicsLatency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MonitorLatencyTolerance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MonitorRefreshLatencyTolerance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "TransitionLatency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "MonitorLatencyTolerance" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "MonitorRefreshLatencyTolerance" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MonitorLatencyTolerance" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MonitorRefreshLatencyTolerance" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "RMDisablePostL2Compression" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "RmDisableRegistryCaching" /t REG_DWORD /d "1" /f

:: USB power savings off
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%u\Device Parameters" /v SelectiveSuspendOn /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%u\Device Parameters" /v SelectiveSuspendEnabled /t REG_BINARY /d 00 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%u\Device Parameters" /v EnhancedPowerManagementEnabled /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%u\Device Parameters" /v AllowIdleIrpInD3 /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%u\Device Parameters\WDF" /v IdleInWorkingState /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%u\Device Parameters" /v SelectiveSuspendOn /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%u\Device Parameters" /v SelectiveSuspendEnabled /t REG_BINARY /d 00 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%u\Device Parameters" /v EnhancedPowerManagementEnabled /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%u\Device Parameters" /v AllowIdleIrpInD3 /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%u\Device Parameters\WDF" /v IdleInWorkingState /t REG_DWORD /d 0 /f
reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "EnhancedPowerManagementEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "AllowIdleIrpInD3" /t REG_DWORD /d "0" /f
reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "EnableSelectiveSuspend" /t REG_DWORD /d "0" /f
reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "DeviceSelectiveSuspended" /t REG_DWORD /d "0" /f
reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "SelectiveSuspendEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "SelectiveSuspendOn" /t REG_DWORD /d "0" /f
reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "D3ColdSupported" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%u\Device Parameters" /v SelectiveSuspendOn /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%u\Device Parameters" /v SelectiveSuspendEnabled /t REG_BINARY /d 00 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%u\Device Parameters\WDF" /v IdleInWorkingState /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Enum\%%u\Device Parameters\WDF" /v IdleInWorkingState /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "EnhancedPowerManagementEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "AllowIdleIrpInD3" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "DeviceSelectiveSuspended" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "SelectiveSuspendEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "SelectiveSuspendOn" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "fid_D1Latency" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "fid_D2Latency" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "fid_D3Latency" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Enum\%%u\Device Parameters\WDF" /v IdleInWorkingState /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "EnhancedPowerManagementEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "AllowIdleIrpInD3" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "DeviceSelectiveSuspended" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "SelectiveSuspendEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "SelectiveSuspendOn" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Enum\%%u\Device Parameters\WDF" /v IdleInWorkingState /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "EnhancedPowerManagementEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "AllowIdleIrpInD3" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "DeviceSelectiveSuspended" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "SelectiveSuspendEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "SelectiveSuspendOn" /t REG_DWORD /d "0" /f

Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\HardCap0" /v "CapPercentage" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\HardCap0" /v "SchedulingType" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\Paused" /v "CapPercentage" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\Paused" /v "SchedulingType" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\SoftCapFull" /v "CapPercentage" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\SoftCapFull" /v "SchedulingType" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\SoftCapLow" /v "CapPercentage" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\SoftCapLow" /v "SchedulingType" /t REG_DWORD /d "0" /f

Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\BackgroundDefault" /v "IsLowPriority" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\Frozen" /v "IsLowPriority" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\FrozenDNCS" /v "IsLowPriority" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\FrozenDNK" /v "IsLowPriority" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\FrozenPPLE" /v "IsLowPriority" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\Paused" /v "IsLowPriority" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\PausedDNK" /v "IsLowPriority" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\Pausing" /v "IsLowPriority" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\PrelaunchForeground" /v "IsLowPriority" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\ThrottleGPUInterference" /v "IsLowPriority" /t REG_DWORD /d "0" /f

Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Critical" /v "BasePriority" /t REG_DWORD /d "82" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Critical" /v "OverTargetPriority" /t REG_DWORD /d "50" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\CriticalNoUi" /v "BasePriority" /t REG_DWORD /d "82" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\CriticalNoUi" /v "OverTargetPriority" /t REG_DWORD /d "50" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\EmptyHostPPLE" /v "BasePriority" /t REG_DWORD /d "82" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\EmptyHostPPLE" /v "OverTargetPriority" /t REG_DWORD /d "50" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\High" /v "BasePriority" /t REG_DWORD /d "82" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\High" /v "OverTargetPriority" /t REG_DWORD /d "50" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Low" /v "BasePriority" /t REG_DWORD /d "82" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Low" /v "OverTargetPriority" /t REG_DWORD /d "50" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Lowest" /v "BasePriority" /t REG_DWORD /d "82" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Lowest" /v "OverTargetPriority" /t REG_DWORD /d "50" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Medium" /v "BasePriority" /t REG_DWORD /d "82" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Medium" /v "OverTargetPriority" /t REG_DWORD /d "50" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\MediumHigh" /v "BasePriority" /t REG_DWORD /d "82" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\MediumHigh" /v "OverTargetPriority" /t REG_DWORD /d "50" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\StartHost" /v "BasePriority" /t REG_DWORD /d "82" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\StartHost" /v "OverTargetPriority" /t REG_DWORD /d "50" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\VeryHigh" /v "BasePriority" /t REG_DWORD /d "82" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\VeryHigh" /v "OverTargetPriority" /t REG_DWORD /d "50" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\VeryLow" /v "BasePriority" /t REG_DWORD /d "82" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\VeryLow" /v "OverTargetPriority" /t REG_DWORD /d "50" /f

Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\IO\NoCap" /v "IOBandwidth" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Memory\NoCap" /v "CommitLimit" /t REG_DWORD /d "4294967295" /f
Reg.exe add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Memory\NoCap" /v "CommitTarget" /t REG_DWORD /d "4294967295" /f

REG DELETE HKEY_LOCAL_MACHINE\COMPONENTS\DerivedData\Components\wow64_wininet.etw_31bf3856ad364e35_10.0.18362.1_none_2f8560056c01225c /F >NUL 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\COMPONENTS\DerivedData\VersionedIndex\10.0.18362.30 (WinBuild.160101.0800)\ComponentFamilies\amd64_wininet.etw_31bf3856ad364e35_none_7e553f52ba809ea7" /F >NUL 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\COMPONENTS\DerivedData\VersionedIndex\10.0.18362.30 (WinBuild.160101.0800)\ComponentFamilies\wow64_wininet.etw_31bf3856ad364e35_none_88a9e9a4eee160a2" /F >NUL 2>&1
REG DELETE HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WinINet/UsageLog /F >NUL 2>&1
REG DELETE HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WinINet/WebSocket /F >NUL 2>&1
REG DELETE HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WinINet-Capture/Analytic /F >NUL 2>&1
REG DELETE HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WinINet-Config/ProxyConfigChanged /F >NUL 2>&1
REG DELETE HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\{5402e5ea-1bdd-4390-82be-e108f1e634f5} /F >NUL 2>&1
REG DELETE HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\{a70ff94f-570b-4979-ba5c-e59c9feab61b} /F >NUL 2>&1
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{4B79A419-F671-47D7-B001-888A456864AE}" /F >NUL 2>&1
REG DELETE HKEY_LOCAL_MACHINE\COMPONENTS\DerivedData\Components\amd64_wininet.etw_31bf3856ad364e35_10.0.18362.1_none_2530b5b337a06061 /F >NUL 2>&1
REG DELETE HKEY_LOCAL_MACHINE\Software\Classes\AppID\{3eb3c877-1f16-487c-9050-104dbcd66683} /F >NUL 2>&1
REG DELETE HKEY_LOCAL_MACHINE\Software\Classes\AppID\{F9717507-6651-4EDB-BFF7-AE615179BCCF} /F >NUL 2>&1
REG DELETE HKEY_LOCAL_MACHINE\Software\Classes\CLSID\{0358b920-0ac7-461f-98f4-58e32cd89148} /F >NUL 2>&1
REG DELETE HKEY_LOCAL_MACHINE\Software\Classes\CLSID\{057EEE47-2572-4AA1-88D7-60CE2149E33C} /F >NUL 2>&1
REG DELETE HKEY_LOCAL_MACHINE\Software\Classes\CLSID\{c39ee728-d419-4bd4-a3ef-eda059dbd935} /F >NUL 2>&1
REG DELETE HKEY_LOCAL_MACHINE\Software\Classes\Interface\{a168aadc-1674-49da-ad4f-4f27df8760d0} /F >NUL 2>&1
REG DELETE HKEY_LOCAL_MACHINE\Software\Classes\Interface\{B06B0CE5-689B-4AFD-B326-0A08A1A647AF} /F >NUL 2>&1
REG DELETE HKEY_LOCAL_MACHINE\Software\Classes\WinInetBroker.WinInetBroker /F >NUL 2>&1
REG DELETE HKEY_LOCAL_MACHINE\Software\Classes\WinInetBroker.WinInetBroker.1 /F >NUL 2>&1
REG DELETE HKEY_LOCAL_MACHINE\Software\Classes\WinInetCache.WinInetCache /F >NUL 2>&1
REG DELETE HKEY_LOCAL_MACHINE\Software\Classes\WinInetCache.WinInetCache.1 /F >NUL 2>&1
REG DELETE HKEY_LOCAL_MACHINE\Software\Classes\Wow6432Node\CLSID\{0358b920-0ac7-461f-98f4-58e32cd89148} /F >NUL 2>&1
REG DELETE HKEY_LOCAL_MACHINE\Software\Classes\Wow6432Node\CLSID\{057EEE47-2572-4AA1-88D7-60CE2149E33C} /F >NUL 2>&1
REG DELETE HKEY_LOCAL_MACHINE\Software\Classes\Wow6432Node\CLSID\{c39ee728-d419-4bd4-a3ef-eda059dbd935} /F >NUL 2>&1
REG DELETE HKEY_LOCAL_MACHINE\Software\Classes\Wow6432Node\Interface\{a168aadc-1674-49da-ad4f-4f27df8760d0} /F >NUL 2>&1
REG DELETE HKEY_LOCAL_MACHINE\Software\Classes\Wow6432Node\Interface\{B06B0CE5-689B-4AFD-B326-0A08A1A647AF} /F >NUL 2>&1
REG DELETE HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer\Capabilities\Roaming\WinInet /F >NUL 2>&1
REG DELETE HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{325B4FF1-5F84-4166-A23F-FB7825145862} /F >NUL 2>&1
REG DELETE HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Microsoft\Windows\Wininet /F >NUL 2>&1
REG DELETE HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\SideBySide\Winners\amd64_wininet.etw_31bf3856ad364e35_none_7e553f52ba809ea7 /F >NUL 2>&1
REG DELETE HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\SideBySide\Winners\wow64_wininet.etw_31bf3856ad364e35_none_88a9e9a4eee160a2 /F >NUL 2>&1
REG DELETE HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WinINet/Analytic /F >NUL 2>&1
REG DELETE HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\{43d1a55c-76d6-4f7e-995c-64c711e5cafe} /F >NUL 2>&1
REG DELETE HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Internet Explorer\Capabilities\Roaming\WinInet /F >NUL 2>&1
REG DELETE HKEY_LOCAL_MACHINE\System\ControlSet001\Control\Ubpm /F >NUL 2>&1
REG DELETE HKEY_LOCAL_MACHINE\System\ControlSet002\Control\Ubpm /F >NUL 2>&1
REG DELETE HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Wifi and Cortana Error /F >NUL 2>&1
REG DELETE HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\Wifi and Cortana Error /F >NUL 2>&1
DEL /F /Q C:\WINDOWS\WINSXS\MANIFESTS\amd64_wininet.etw_31bf3856ad364e35_10.0.18362.1_none_2530b5b337a06061.manifest >NUL 2>&1
DEL /F /Q C:\WINDOWS\WINSXS\MANIFESTS\wow64_wininet.etw_31bf3856ad364e35_10.0.18362.1_none_2f8560056c01225c.manifest >NUL 2>&1
REN C:\Windows\WinSxS\amd64_microsoft-windows-u..roundprocessmanager_31bf3856ad364e35_10.0.18362.1_none_38ad80f66ea09a5c\UBPM.DLL UBPM.DL >NUL 2>&1
REN C:\WINDOWS\SYSTEM32\UBPM.DLL UBPM.DL >NUL 2>&1
REN C:\WINDOWS\SYSTEM32\WHEALOGR.DLL WHEALOGR.DL >NUL 2>&1
REN C:\WINDOWS\SYSTEM32\CATSRV.DLL CATSRV.DL >NUL 2>&1
REN C:\WINDOWS\SYSTEM32\CATSRVPS.DLL CATSRVPS.DL >NUL 2>&1
REN C:\WINDOWS\SYSTEM32\CLBCATQ.DLL CLBCATQ.DL >NUL 2>&1
REN C:\WINDOWS\SYSTEM32\CATSRVUT.DLL CATSRVUT.DL >NUL 2>&1
REN C:\WINDOWS\SYSTEM32\COMSVCS.DLL COMSVCS.DL >NUL 2>&1
REN C:\WINDOWS\SYSTEM32\COLBACT.DLL COLBACT.DL >NUL 2>&1
REN C:\WINDOWS\SYSWOW64\UBPM.DLL UBPM.DL >NUL 2>&1
REN C:\WINDOWS\SYSWOW64\WHEALOGR.DLL WHEALOGR.DL >NUL 2>&1
REN C:\WINDOWS\SYSWOW64\CATSRV.DLL CATSRV.DL >NUL 2>&1
REN C:\WINDOWS\SYSWOW64\CATSRVPS.DLL CATSRVPS.DL >NUL 2>&1
REN C:\WINDOWS\SYSWOW64\CLBCATQ.DLL CLBCATQ.DL >NUL 2>&1
REN C:\WINDOWS\SYSWOW64\CATSRVUT.DLL CATSRVUT.DL >NUL 2>&1
REN C:\WINDOWS\SYSWOW64\COMSVCS.DLL COMSVCS.DL >NUL 2>&1
REN C:\WINDOWS\SYSWOW64\COLBACT.DLL COLBACT.DL >NUL 2>&1
REN C:\Windows\WinSxS\amd64_microsoft-windows-c..complus-runtime-qfe_31bf3856ad364e35_10.0.18362.1_none_3dc09e7cf5c741b9\CATSRV.DLL CATSRV.DL >NUL 2>&1
REN C:\Windows\WinSxS\amd64_microsoft-windows-c..complus-runtime-qfe_31bf3856ad364e35_10.0.18362.1_none_3dc09e7cf5c741b9\CATSRVUT.DLL CATSRVUT.DL >NUL 2>&1
REN C:\Windows\WinSxS\amd64_microsoft-windows-com-complus-runtime_31bf3856ad364e35_10.0.18362.1_none_2c282f0d51e9fc6a\CATSRVPS.DLL CATSRVPS.DL >NUL 2>&1
REN C:\Windows\WinSxS\wow64_microsoft-windows-c..complus-runtime-qfe_31bf3856ad364e35_10.0.18362.1_none_481548cf2a2803b4\CATSRV.DLL CATSRV.DL >NUL 2>&1
REN C:\Windows\WinSxS\wow64_microsoft-windows-c..fe-catsrvut-comsvcs_31bf3856ad364e35_10.0.18362.1_none_4f747f7b51772bd8\CATSRVPS.DLL CATSRVPS.DL >NUL 2>&1
REN C:\Windows\WinSxS\wow64_microsoft-windows-com-complus-runtime_31bf3856ad364e35_10.0.18362.1_none_367cd95f864abe65\CATSRVPS.DLL CATSRVPS.DL >NUL 2>&1
REN C:\Windows\WinSxS\amd64_microsoft-windows-c..complus-runtime-qfe_31bf3856ad364e35_10.0.18362.1_none_3dc09e7cf5c741b9\COLBACT.DLL COLBACT.DL >NUL 2>&1
REN C:\Windows\WinSxS\wow64_microsoft-windows-c..complus-runtime-qfe_31bf3856ad364e35_10.0.18362.1_none_481548cf2a2803b4\COLBACT.DLL COLBACT.DL >NUL 2>&1
REN C:\Windows\WinSxS\amd64_microsoft-windows-c..fe-catsrvut-comsvcs_31bf3856ad364e35_10.0.18362.1_none_451fd5291d1669dd\COMSVCS.DLL COMSVCS.DL >NUL 2>&1
REN C:\Windows\WinSxS\wow64_microsoft-windows-c..fe-catsrvut-comsvcs_31bf3856ad364e35_10.0.18362.1_none_4f747f7b51772bd8\COMSVCS.DLL COMSVCS.DL >NUL 2>&1
REN C:\Windows\WinSxS\amd64_microsoft-windows-c..fe-catsrvut-comsvcs_31bf3856ad364e35_10.0.18362.1_none_451fd5291d1669dd\CATSRVUT.DLL CATSRVUT.DL >NUL 2>&1
REN C:\Windows\WinSxS\wow64_microsoft-windows-c..fe-catsrvut-comsvcs_31bf3856ad364e35_10.0.18362.1_none_4f747f7b51772bd8\CATSRVUT.DLL CATSRVUT.DL >NUL 2>&1
REN C:\Windows\WinSxS\amd64_microsoft-windows-c..complus-runtime-qfe_31bf3856ad364e35_10.0.18362.1_none_3dc09e7cf5c741b9\CLBCATQ.DLL CLBCATQ.DL >NUL 2>&1
REN C:\Windows\WinSxS\wow64_microsoft-windows-c..complus-runtime-qfe_31bf3856ad364e35_10.0.18362.1_none_481548cf2a2803b4\CLBCATQ.DLL CLBCATQ.DL >NUL 2>&1
REN C:\Windows\WinSxS\wow64_microsoft-windows-thumbnailcache_31bf3856ad364e35_10.0.18362.1_none_1bcca0aacac057bf\THUMBCACHE.DLL THUMBCACHE.DL >NUL 2>&1
REN C:\Windows\WinSxS\amd64_microsoft-windows-thumbnailcache_31bf3856ad364e35_10.0.18362.1_none_1177f658965f95c4\THUMBCACHE.DLL THUMBCACHE.DL >NUL 2>&1
REN C:\WINDOWS\SYSTEM32\THUMBCACHE.DLL THUMBCACHE.DL >NUL 2>&1
REN C:\WINDOWS\SYSWOW64\THUMBCACHE.DLL THUMBCACHE.DL >NUL 2>&1
REN C:\WINDOWS\SYSTEM32\MS3DTHUMBNAILPROVIDER.DLL MS3DTHUMBNAILPROVIDER.DL >NUL 2>&1
REN C:\WINDOWS\SYSWOW64\MS3DTHUMBNAILPROVIDER.DLL MS3DTHUMBNAILPROVIDER.DL >NUL 2>&1
REN C:\WINDOWS\SYSWOW64\THUMBNAILEXTRACTIONHOST.EXE THUMBNAILEXTRACTIONHOST.EX >NUL 2>&1
REN C:\WINDOWS\SYSTEM32\THUMBNAILEXTRACTIONHOST.EXE THUMBNAILEXTRACTIONHOST.EX >NUL 2>&1
REN C:\Windows\WinSxS\amd64_microsoft-windows-p..ellextensionhandler_31bf3856ad364e35_10.0.18362.1_none_eef03df1208a56a5\MS3DTHUMBNAILPROVIDER.DLL MS3DTHUMBNAILPROVIDER.DL >NUL 2>&1
REN C:\Windows\WinSxS\wow64_microsoft-windows-thumbexthost_31bf3856ad364e35_10.0.18362.1_none_cd1f1327ef03e420\THUMBNAILEXTRACTIONHOST.EXE THUMBNAILEXTRACTIONHOST.EX >NUL 2>&1
REN C:\Windows\WinSxS\amd64_microsoft-windows-thumbexthost_31bf3856ad364e35_10.0.18362.1_none_c2ca68d5baa32225\THUMBNAILEXTRACTIONHOST.EXE THUMBNAILEXTRACTIONHOST.EX >NUL 2>&1
REN C:\Windows\WinSxS\wow64_microsoft-windows-p..ellextensionhandler_31bf3856ad364e35_10.0.18362.1_none_f944e84354eb18a0\MS3DTHUMBNAILPROVIDER.DLL MS3DTHUMBNAILPROVIDER.DL >NUL 2>&1
REN C:\WINDOWS\SYSTEM32\MOBSYNC.EXE MOBSYNC.EX >NUL 2>&1
REN C:\WINDOWS\SYSWOW64\MOBSYNC.EXE MOBSYNC.EX >NUL 2>&1
REN C:\Windows\WinSxS\amd64_microsoft-windows-mobsyncexe_31bf3856ad364e35_10.0.18362.1_none_c1ae4989d18d8cdd\MOBSYNC.EXE MOBSYNC.EX >NUL 2>&1
REN C:\Windows\WinSxS\wow64_microsoft-windows-mobsyncexe_31bf3856ad364e35_10.0.18362.1_none_cc02f3dc05ee4ed8\MOBSYNC.EXE MOBSYNC.EX >NUL 2>&1
REN C:\WINDOWS\SYSTEM32\SYNCCENTER.DLL SYNCCENTER.DL >NUL 2>&1
REN C:\WINDOWS\SYSWOW64\SYNCCENTER.DLL SYNCCENTER.DL >NUL 2>&1
REN C:\Windows\WinSxS\amd64_microsoft-windows-mobsync_31bf3856ad364e35_10.0.18362.1_none_c7cd16fcc69993cb\SYNCCENTER.DLL SYNCCENTER.DL >NUL 2>&1
REN C:\Windows\WinSxS\wow64_microsoft-windows-mobsync_31bf3856ad364e35_10.0.18362.1_none_d221c14efafa55c6\SYNCCENTER.DLL SYNCCENTER.DL >NUL 2>&1
REN C:\Windows\WinSxS\amd64_microsoft-windows-d..ommandline-adamsync_31bf3856ad364e35_10.0.18362.1_none_c4803cf49bd9a36f\adamsync.exe adamsync.ex >NUL 2>&1
REN C:\Windows\System32\Microsoft.Uev.SyncController.exe Microsoft.Uev.SyncController.ex >NUL 2>&1
REN C:\Windows\WinSxS\amd64_microsoft-windows-appmanagement-uevagent_31bf3856ad364e35_10.0.18362.1_none_cf09156b62331c1c\Microsoft.Uev.SyncController.exe Microsoft.Uev.SyncController.ex >NUL 2>&1
REN C:\Windows\System32\msfeedssync.exe msfeedssync.ex >NUL 2>&1
REN C:\Windows\SysWOW64\msfeedssync.exe msfeedssync.ex >NUL 2>&1
REN C:\Windows\WinSxS\amd64_microsoft-windows-ie-feedsbs_31bf3856ad364e35_11.0.18362.1_none_029cd9ddc2d4507c\msfeedssync.exe msfeedssync.ex >NUL 2>&1
REN C:\Windows\WinSxS\x86_microsoft-windows-ie-feedsbs_31bf3856ad364e35_11.0.18362.1_none_a67e3e5a0a76df46\msfeedssync.exe msfeedssync.ex >NUL 2>&1
REN C:\Windows\System32\SettingSyncHost.exe SettingSyncHost.ex >NUL 2>&1
REN C:\Windows\SysWOW64\SettingSyncHost.exe SettingSyncHost.ex >NUL 2>&1
REN C:\Windows\WinSxS\amd64_microsoft-windows-settingsynchost_31bf3856ad364e35_10.0.18362.1_none_52409c86a06208c5\SettingSyncHost.exe SettingSyncHost.ex >NUL 2>&1
REN C:\Windows\WinSxS\wow64_microsoft-windows-settingsynchost_31bf3856ad364e35_10.0.18362.1_none_5c9546d8d4c2cac0\SettingSyncHost.exe SettingSyncHost.ex >NUL 2>&1
REN C:\Windows\System32\SyncAppvPublishingServer.exe SyncAppvPublishingServer.ex >NUL 2>&1
REN C:\Windows\WinSxS\amd64_microsoft-windows-a..nagement-appvclient_31bf3856ad364e35_10.0.18362.1_none_9ecfe716455f6af7\SyncAppvPublishingServer.exe SyncAppvPublishingServer.ex >NUL 2>&1
REN C:\Windows\System32\SyncHost.exe SyncHost.ex >NUL 2>&1
REN C:\Windows\SysWOW64\SyncHost.exe SyncHost.ex >NUL 2>&1
REN C:\Windows\WinSxS\amd64_microsoft-windows-synchost_31bf3856ad364e35_10.0.18362.1_none_3bde7d1479cad5c3\SyncHost.exe SyncHost.ex >NUL 2>&1
REN C:\Windows\WinSxS\wow64_microsoft-windows-synchost_31bf3856ad364e35_10.0.18362.1_none_46332766ae2b97be\SyncHost.exe SyncHost.ex >NUL 2>&1
REN C:\Windows\System32\tzsync.exe tzsync.ex >NUL 2>&1
REN C:\Windows\WinSxS\amd64_microsoft-windows-timezone-sync_31bf3856ad364e35_10.0.18362.1_none_618e5fdf9d8d43cf\tzsync.exe tzsync.ex >NUL 2>&1
c:\windows\system32\logman stop "nt kernel logger" -ets >NUL 2>&1
c:\windows\system32\logman stop phetrundownlogger -ets >NUL 2>&1
c:\windows\system32\logman stop phetkernellogger -ets >NUL 2>&1
c:\windows\system32\logman stop usernotpresenttracesession -ets >NUL 2>&1
c:\windows\system32\logman stop ubpm -ets >NUL 2>&1
c:\windows\system32\logman stop msdtc_trace_session -ets >NUL 2>&1
c:\windows\system32\logman stop eventlog-security -ets >NUL 2>&1
c:\windows\system32\logman stop eventlog-application -ets >NUL 2>&1
c:\windows\system32\logman stop eventlog-system -ets >NUL 2>&1
c:\windows\system32\logman stop LwtNetLog -ets >NUL 2>&1
c:\windows\system32\logman stop NetCore -ets >NUL 2>&1
c:\windows\system32\logman stop NtfsLog -ets >NUL 2>&1
c:\windows\system32\logman stop RadioMgr -ets >NUL 2>&1
c:\windows\system32\logman stop WiFiSession -ets >NUL 2>&1
c:\windows\system32\logman stop "steam event tracing" -ets >NUL 2>&1
c:\windows\system32\logman stop scm -ets >NUL 2>&1
c:\windows\system32\logman stop audio -ets >NUL 2>&1
c:\windows\system32\logman stop sqmlogger -ets >NUL 2>&1
c:\windows\system32\logman stop readyboot -ets >NUL 2>&1
c:\windows\system32\logman stop wdicontextlog -ets >NUL 2>&1
c:\windows\system32\logman stop aiteventlog -ets >NUL 2>&1
c:\windows\system32\logman stop diaglog -ets >NUL 2>&1
c:\windows\system32\logman stop eventlog-system -ets >NUL 2>&1
c:\windows\system32\logman stop "circular kernel context logger" -ets >NUL 2>&1
c:\windows\system32\logman stop msmppssession7 -ets >NUL 2>&1
c:\windows\system32\logman stop wfp-diag -ets >NUL 2>&1
c:\windows\system32\logman stop energy-trace -ets >NUL 2>&1
c:\windows\system32\logman stop umstartup -ets >NUL 2>&1
c:\windows\system32\logman stop COM -ets >NUL 2>&1
c:\windows\system32\logman stop LogonUILog -ets >NUL 2>&1
c:\windows\system32\logman stop MpWppTracing-12312021-191912-00000003-ffffffff -ets >NUL 2>&1
c:\windows\system32\logman stop "Microsoft-Windows-Rdp-Graphics-RdpIdd-Trace Trace" -ets >NUL 2>&1
c:\windows\system32\logman stop "SHS-07092022-024750-7-3f" -ETS >NUL 2>&1
c:\windows\system32\logman stop "MpWppTracing-20220709-024352-00000003-ffffffff" -ets >NUL 2>&1
c:\windows\system32\logman stop Diagtrack-Listener -ets >NUL 2>&1
c:\windows\system32\logman stop Admin_PS_Provider -ets >NUL 2>&1
c:\windows\system32\logman stop RzPresentMon -ets >NUL 2>&1
c:\windows\system32\unlodctr ".NET CLR Data" NUL 2>&1
c:\windows\system32\unlodctr ".NET CLR Networking" NUL 2>&1
c:\windows\system32\unlodctr ".NET Data Provider for Oracle" NUL 2>&1
c:\windows\system32\unlodctr ".NET Data Provider for SqlServer" NUL 2>&1
c:\windows\system32\unlodctr ".NETFramework" NUL 2>&1
c:\windows\system32\unlodctr "BITS" NUL 2>&1
c:\windows\system32\unlodctr "esent" NUL 2>&1
c:\windows\system32\unlodctr "msdtc" NUL 2>&1
c:\windows\system32\unlodctr "MSDTC Bridge 3.0.0.0" NUL 2>&1
c:\windows\system32\unlodctr "rdyboost" NUL 2>&1
c:\windows\system32\unlodctr "remoteaccess" NUL 2>&1
c:\windows\system32\unlodctr "ServiceModelEndpoint 3.0.0.0" NUL 2>&1
c:\windows\system32\unlodctr "ServiceModelOperation 3.0.0.0" NUL 2>&1
c:\windows\system32\unlodctr "ServiceModelService 3.0.0.0" NUL 2>&1
c:\windows\system32\unlodctr "SMSvcHost 3.0.0.0" NUL 2>&1
c:\windows\system32\unlodctr "tapisrv" NUL 2>&1
c:\windows\system32\unlodctr "usbhub" NUL 2>&1
c:\windows\system32\unlodctr "Windows Workflow Foundation 3.0.0.0" NUL 2>&1
c:\windows\system32\unlodctr "WmiApRpl" NUL 2>&1

del /F /Q "%WINDIR%\system32\drivers\etc\hosts" >NUL 2>&1
ECHO 0.0.0.0 telemetry.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 vortex-win.data.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 telecommand.telemetry.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 telecommand.telemetry.microsoft.com.nsatc.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 oca.telemetry.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 oca.telemetry.microsoft.com.nsatc.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 sqm.telemetry.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 sqm.telemetry.microsoft.com.nsatc.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 watson.telemetry.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 watson.telemetry.microsoft.com.nsatc.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 redir.metaservices.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 choice.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 choice.microsoft.com.nsatc.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 df.telemetry.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 wes.df.telemetry.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 reports.wes.df.telemetry.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 services.wes.df.telemetry.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 sqm.df.telemetry.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 watson.ppe.telemetry.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 telemetry.appex.bing.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 telemetry.urs.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 telemetry.appex.bing.net:443>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 settings-sandbox.data.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 vortex-sandbox.data.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 watson.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 survey.watson.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 watson.live.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 statsfe2.ws.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 corpext.msitadfs.glbdns2.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 compatexchange.cloudapp.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cs1.wpc.v0cdn.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 a-0001.a-msedge.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 fe2.update.microsoft.com.akadns.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 statsfe2.update.microsoft.com.akadns.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 sls.update.microsoft.com.akadns.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 diagnostics.support.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 corp.sts.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 statsfe1.ws.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 pre.footprintpredict.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 i1.services.social.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 i1.services.social.microsoft.com.nsatc.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 feedback.windows.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 feedback.microsoft-hohm.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 feedback.search.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cdn.content.prod.cms.msn.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cdn.content.prod.cms.msn.com.edgekey.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 e10663.g.akamaiedge.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 dmd.metaservices.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 schemas.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 go.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 40.76.0.0/14>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 40.96.0.0/12>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 40.124.0.0/16>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 40.112.0.0/13>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 40.125.0.0/17>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 40.74.0.0/15>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 40.80.0.0/12>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 40.120.0.0/14>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 137.116.0.0/16>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 23.192.0.0/11>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 23.32.0.0/11>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 23.64.0.0/14>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 23.55.130.182>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 a.ads1.msads.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 a.ads1.msn.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 a.ads2.msads.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 a.ads2.msn.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 analytics.live.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 analytics.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 analytics.msn.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 bingads.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 browser.events.data.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cache.datamart.windows.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 events.data.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 manage.devcenter.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 mobile.events.data.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 mobile.pipe.aria.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 onecollector.cloudapp.aria.akadns.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 prod.nexusrules.live.com.akadns.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ris.api.iris.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 self.events.data.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 settings-win.data.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 spynet2.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 spynetalt.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 telecommand.alpha.telemetry.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 telecommand.df.telemetry.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 telemetry.appex.bing.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 telemetry.urs.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 telemetrysvc-by3p.smartscreen.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 us.vortex-win.data.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 v10-win.vortex.data.microsoft.com.akadns.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 v10.events.data.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 v10.vortex-win.data.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 v20.vortex-win.data.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 vortex-bn2.metron.live.com.nsatc.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 vortex-cy2.metron.live.com.nsatc.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 vortex.data.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 vortex.data.microsoft.com.akadns.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 web.vortex.data.microsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 telemetry.remoteapp.windowsazure.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 static.2mdn.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 b.ads1.msn.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 b.ads2.msads.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 b.rad.msn.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 tele.trafficmanager.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 1beb2a44.space>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 1q2w3.fun>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 1q2w3.me>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 300ca0d0.space>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 310ca263.space>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 320ca3f6.space>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 330ca589.space>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 340ca71c.space>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 360caa42.space>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 370cabd5.space>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 3c0cb3b4.space>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 3d0cb547.space>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 abc.pema.cl>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ad-miner.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adminer.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 analytics.blue>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 api.inwemo.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 azvjudwr.info>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 baiduccdn1.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 berserkpl.net.pl>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 biberukalap.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 bjorksta.men>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 blockchain.info>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 candid.zone>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cdn.adless.io>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cdn.cloudcoins.co>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 chainblock.science>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cnhv.co>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 coin-have.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 coin-hive.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 coinblind.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 coinerra.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 coinhive.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 coinhiveproxy.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 coinlab.biz>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 coinnebula.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 crypto-loot.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 crypto-webminer.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 crypto.csgocpu.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cryptoloot.pro>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cryweb.github.io>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 crywebber.github.io>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 dev.cryptobara.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 digger.cryptobara.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 flare-analytics.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 go.megabanners.cf>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 gridiogrid.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 gus.host>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 hive.tubetitties.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 hodlers.party>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 hodling.faith>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 host.d-ns.ga>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 intactoffers.club>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 jroqvbvw.info>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 jsccnn.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 jscdndel.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 jyhfuqoh.info>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 kdowqlpt.info>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 load.jsecoin.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 m.anyfiles.ovh>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 mine.nahnoji.cz>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 mine.torrent.pw>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 minemytraffic.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner.cryptobara.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner.nablabee.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner.pr0gramm.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 minero-proxy-01.now.sh>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 minero-proxy-02.now.sh>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 minero-proxy-03.now.sh>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 minero.pw>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 monerominer.rocks>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 noblock.pro>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 okeyletsgo.ml>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 papoto.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 playerassets.info>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ppoi.org>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 projectpoi.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 reservedoffers.club>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 rocks.io>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 smectapop12.pl>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 sparnove.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 static.sparechange.io>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 tokyodrift.ga>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 webassembly.stream>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 webmine.cz>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 webmine.pro>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 webminepool.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 webminepool.tk>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 wsp.marketgid.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.cryptonoter.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.freecontent.bid>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.mutuza.win>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.sparechange.io>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 xbasfbno.info>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cnhv.co>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 coin-hive.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 coinhive.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 authedmine.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 api.jsecoin.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 load.jsecoin.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 server.jsecoin.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner.pr0gramm.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 minemytraffic.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 crypto-loot.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cryptaloot.pro>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cryptoloot.pro>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 coinerra.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 coin-have.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 minero.pw>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 minero-proxy-01.now.sh>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 minero-proxy-02.now.sh>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 minero-proxy-03.now.sh>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 api.inwemo.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 rocks.io>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adminer.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ad-miner.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 jsccnn.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 jscdndel.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 coinhiveproxy.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 coinblind.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 coinnebula.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 monerominer.rocks>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cdn.cloudcoins.co>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 coinlab.biz>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 go.megabanners.cf>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 baiduccdn1.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 wsp.marketgid.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 papoto.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 flare-analytics.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.sparechange.io>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 static.sparechange.io>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner.nablabee.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 m.anyfiles.ovh>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.coinimp.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.coinimp.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.freecontent.bid>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.freecontent.date>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.freecontent.faith>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.freecontent.loan>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.freecontent.racing>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.freecontent.win>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.blockchained.party>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.hostingcloud.download>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.cryptonoter.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.mutuza.win>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 crypto-webminer.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cdn.adless.io>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 hegrinhar.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 verresof.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 hemnes.win>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 tidafors.xyz>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 moneone.ga>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 plexcoin.info>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.monkeyminer.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 go2.mercy.ga>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 coinpirate.cf>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 d.cpufan.club>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 krb.devphp.org.ua>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 nfwebminer.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cfcdist.gdn>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 node.cfcdist.gdn>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 webxmr.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 xmr.mining.best>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 webminepool.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 webminepool.tk>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 hive.tubetitties.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 playerassets.info>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 tokyodrift.ga>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 webassembly.stream>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.webassembly.stream>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 okeyletsgo.ml>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 candid.zone>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 webmine.pro>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 andlache.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 bablace.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 bewaslac.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 biberukalap.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 bowithow.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 butcalve.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 evengparme.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 gridiogrid.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 hatcalter.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 kedtise.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ledinund.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 nathetsof.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 renhertfo.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 rintindown.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 sparnove.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 witthethim.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 1q2w3.fun>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 1q2w3.me>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 bjorksta.men>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 crypto.csgocpu.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 noblock.pro>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner.cryptobara.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 digger.cryptobara.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 dev.cryptobara.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 reservedoffers.club>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 mine.torrent.pw>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 host.d-ns.ga>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 abc.pema.cl>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 js.nahnoji.cz>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 mine.nahnoji.cz>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 webmine.cz>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.webmine.cz>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 intactoffers.club>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 analytics.blue>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 smectapop12.pl>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 berserkpl.net.pl>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 hodlers.party>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 hodling.faith>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 chainblock.science>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 minescripts.info>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cdn.minescripts.info>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner.nablabee.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 wss.nablabee.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 clickwith.bid>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 dronml.ml>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 niematego.tk>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 tulip18.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 p.estream.to>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 didnkinrab.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ledhenone.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 losital.ru>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 mebablo.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 moonsade.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 nebabrop.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 pearno.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 rintinwa.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 willacrit.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www2.adfreetv.ch>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 minr.pw>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 new.minr.pw>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 test.minr.pw>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 staticsfs.host>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cdn-code.host>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 g-content.bid>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ad.g-content.bid>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cdn.static-cnt.bid>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cnt.statistic.date>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 jquery-uim.download>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cdn.jquery-uim.download>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cdn-jquery.host>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 p1.interestingz.pw>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 kippbeak.cf>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 pasoherb.gq>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 axoncoho.tk>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 depttake.ga>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 flophous.cf>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 pr0gram.org>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 authedmine.eu>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.monero-miner.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.datasecu.download>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.jquery-cdn.download>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.etzbnfuigipwvs.ru>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.terethat.ru>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 freshrefresher.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 api.pzoifaum.info>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ws.pzoifaum.info>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 api.bhzejltg.info>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ws.bhzejltg.info>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 d.cfcnet.top>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 vip.cfcnet.top>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 eu.cfcnet.top>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 as.cfcnet.top>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 us.cfcnet.top>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 eu.cfcdist.loan>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 as.cfcdist.loan>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 us.cfcdist.loan>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 gustaver.ddns.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 worker.salon.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 s2.appelamule.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 mepirtedic.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cdn.streambeam.io>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adzjzewsma.cf>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ffinwwfpqi.gq>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ininmacerad.pro>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 mhiobjnirs.gq>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 open-hive-server-1.pp.ua>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 pool.hws.ru>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 pool.etn.spacepools.org>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 api.aalbbh84.info>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.aymcsx.ru>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 aeros01.tk>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 aeros02.tk>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 aeros03.tk>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 aeros04.tk>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 aeros05.tk>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 aeros06.tk>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 aeros07.tk>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 aeros08.tk>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 aeros09.tk>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 aeros10.tk>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 aeros11.tk>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 aeros12.tk>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 npcdn1.now.sh>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 mxcdn2.now.sh>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 sxcdn6.now.sh>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 mxcdn1.now.sh>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 sxcdn02.now.sh>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 sxcdn4.now.sh>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 jqcdn2.herokuapp.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 sxcdn1.herokuapp.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 sxcdn5.herokuapp.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 wpcdn1.herokuapp.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 jqcdn01.herokuapp.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 jqcdn03.herokuapp.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 1q2w3.website>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 video.videos.vidto.me>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 play.play1.videos.vidto.me>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 playe.vidto.se>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 video.streaming.estream.to>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 eth-pocket.de>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 xvideosharing.site>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 bestcoinsignals.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 eucsoft.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 traviilo.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 wasm24.ru>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 xmr.cool>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 api.netflare.info>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cdnjs.cloudflane.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.cloudflane.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 clgserv.pro>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 hide.ovh>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 graftpool.ovh>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 encoding.ovh>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 altavista.ovh>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 scaleway.ovh>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 nexttime.ovh>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 never.ovh>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 2giga.download>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 webminerpool.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 minercry.pt>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adplusplus.fr>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ethtrader.de>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 gobba.myeffect.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 bauersagtnein.myeffect.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 besti.ga>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 jurty.ml>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 jurtym.cf>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 mfio.cf>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 mwor.gq>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 oei1.gq>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 wordc.ga>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 berateveng.ru>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ctlrnwbv.ru>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ermaseuc.ru>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 kdmkauchahynhrs.ru>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 uoldid.ru>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.jqrcdn.download>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.jqassets.download>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.jqcdn.download>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.jquerrycdn.download>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.jqwww.download>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 lightminer.co>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.lightminer.co>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 browsermine.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 api.browsermine.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 dl.browsermine.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 mlib.browsermine.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 minr.browsermine.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 static.browsermine.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ws.browsermine.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 bmst.pw>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 bmnr.pw>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 bmcm.pw>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 bmcm.ml>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 videoplayer2.xyz>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 play.video2.stream.vidzi.tv>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 001.0x1f4b0.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 002.0x1f4b0.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 003.0x1f4b0.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 004.0x1f4b0.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 005.0x1f4b0.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 006.0x1f4b0.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 007.0x1f4b0.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 008.0x1f4b0.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 authedwebmine.cz>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.authedwebmine.cz>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 skencituer.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 site.flashx.cc>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 play1.flashx.pw>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 play2.flashx.pw>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 play4.flashx.pw>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 play5.flashx.pw>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 js.vidoza.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 mm.zubovskaya-banya.ru>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 mysite.irkdsu.ru>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 play.estream.nu>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 play.estream.to>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 play.estream.xyz>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 play.play.estream.nu>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 play.play.estream.to>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 play.play.estream.xyz>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 play.tainiesonline.pw>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 play.vidzi.tv>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 play.pampopholf.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 s3.pampopholf.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 play.malictuiar.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 s3.malictuiar.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 play.play.tainiesonline.stream>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ocean2.authcaptcha.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 rock2.authcaptcha.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 stone2.authcaptcha.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 sass2.authcaptcha.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 sea2.authcaptcha.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 play.flowplayer.space>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 play.pc.belicimo.pw>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 play.power.tainiesonline.pw>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 play.s01.vidtodo.pro>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 wm.yololike.space>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 play.mix.kinostuff.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 play.on.animeteatr.ru>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 play.mine.gay-hotvideo.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 play.www.intellecthosting.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 mytestminer.xyz>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 play.vb.wearesaudis.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 flowplayer.space>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 s2.flowplayer.space>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 s3.flowplayer.space>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 thersprens.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 s2.thersprens.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 s3.thersprens.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 gramombird.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 play.gramombird.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ugmfvqsu.ru>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 bsyauqwerd.party>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ccvwtdtwyu.trade>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 baywttgdhe.download>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 pdheuryopd.loan>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 iaheyftbsn.review>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 djfhwosjck.bid>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 najsiejfnc.win>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 zndaowjdnf.stream>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 yqaywudifu.date>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 malictuiar.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 proofly.win>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 zminer.zaloapp.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 vkcdnservice.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 dexim.space>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 acbp0020171456.page.tl>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 vuryua.ru>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 minexmr.stream>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 gitgrub.pro>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 d8acddffe978b5dfcae6.date>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 eth-pocket.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 autologica.ga>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 whysoserius.club>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 aster18cdn.nl>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 nerohut.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 gnrdomimplementation.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 pon.ewtuyytdf45.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 hhb123.tk>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 dzizsih.ru>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 nddmcconmqsy.ru>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 silimbompom.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 unrummaged.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 fruitice.realnetwrk.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 synconnector.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 toftofcal.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 gasolina.ml>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 8jd2lfsq.me>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 afflow.18-plus.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 afminer.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 aservices.party>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 becanium.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 brominer.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cdn-analytics.pl>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cdn.static-cnt.bid>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cloudcdn.gdn>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 coin-service.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 coinpot.co>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 coinrail.io>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 etacontent.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 exdynsrv.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 formulawire.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 go.bestmobiworld.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 goldoffer.online>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 hallaert.online>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 hashing.win>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 igrid.org>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 laserveradedomaina.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 machieved.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 nametraff.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 offerreality.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ogrid.org>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 panelsave.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 party-vqgdyvoycc.now.sh>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 pertholin.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 premiumstats.xyz>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 serie-vostfr.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 salamaleyum.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 smartoffer.site>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 stonecalcom.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 thewhizmarketing.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 thewhizproducts.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 thewise.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 traffic.tc-clicks.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 vcfs6ip5h6.bid>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 web.dle-news.pw>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 webmining.co>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 wp-monero-miner.de>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 wtm.monitoringservice.co>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 xy.nullrefexcep.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 yrdrtzmsmt.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 wss.rand.com.ru>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.verifier.live>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.jshosting.bid>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.jshosting.date>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.jshosting.download>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.jshosting.faith>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.jshosting.loan>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.jshosting.party>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.jshosting.racing>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.jshosting.review>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.jshosting.science>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.jshosting.stream>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.jshosting.trade>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.jshosting.win>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.freecontent.download>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.freecontent.party>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.freecontent.review>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.freecontent.science>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.freecontent.stream>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.freecontent.trade>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.hostcontent.live>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.hostingcloud.accountant>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.hostingcloud.bid>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.hostingcloud.date>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.hostingcloud.download>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.hostingcloud.faith>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.hostingcloud.live>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.hostingcloud.loan>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.hostingcloud.party>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.hostingcloud.racing>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.hostingcloud.review>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.hostingcloud.science>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.hostingcloud.stream>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.hostingcloud.trade>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.hostingcloud.win>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 minerad.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 coin-cube.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 coin-services.info>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 service4refresh.info>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 money-maker-script.info>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 money-maker-default.info>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 de-ner-mi-nis4.info>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 de-nis-ner-mi-5.info>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 de-mi-nis-ner2.info>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 de-mi-nis-ner.info>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 mi-de-ner-nis3.info>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 s2.soodatmish.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 s2.thersprens.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 play.feesocrald.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cdn1.pebx.pl>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 play.nexioniect.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 play.besstahete.info>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 s2.myregeneaf.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 s3.myregeneaf.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 reauthenticator.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 rock.reauthenticator.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 serv1swork.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 str1kee.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 f1tbit.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 g1thub.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 swiftmining.win>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cashbeet.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 wmtech.website>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.notmining.org>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 coinminingonline.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 alflying.bid>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 alflying.date>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 alflying.win>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 anybest.host>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 anybest.pw>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 anybest.site>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 anybest.space>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 dubester.pw>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 dubester.site>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 dubester.space>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 flightsy.bid>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 flightsy.date>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 flightsy.win>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 flighty.win>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 flightzy.bid>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 flightzy.date>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 flightzy.win>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 gettate.date>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 gettate.faith>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 gettate.racing>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 mighbest.host>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 mighbest.pw>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 mighbest.site>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 zymerget.bid>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 zymerget.date>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 zymerget.faith>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 zymerget.party>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 zymerget.stream>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 zymerget.win>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 statdynamic.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 alpha.nimiqpool.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 api.miner.beeppool.org>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 beatingbytes.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 besocial.online>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 beta.nimiqpool.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 bulls.nimiqpool.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 de1.eu.nimiqpool.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ethmedialab.info>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 feilding.nimiqpool.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 foxton.nimiqpool.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ganymed.beeppool.org>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 himatangi.nimiqpool.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 levin.nimiqpool.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 mine.terorie.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner-1.team.nimiq.agency>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner-10.team.nimiq.agency>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner-11.team.nimiq.agency>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner-12.team.nimiq.agency>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner-13.team.nimiq.agency>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner-14.team.nimiq.agency>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner-15.team.nimiq.agency>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner-16.team.nimiq.agency>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner-17.team.nimiq.agency>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner-18.team.nimiq.agency>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner-19.team.nimiq.agency>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner-2.team.nimiq.agency>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner-3.team.nimiq.agency>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner-4.team.nimiq.agency>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner-5.team.nimiq.agency>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner-6.team.nimiq.agency>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner-7.team.nimiq.agency>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner-8.team.nimiq.agency>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner-9.team.nimiq.agency>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner-deu-1.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner-deu-2.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner-deu-3.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner-deu-4.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner-deu-5.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner-deu-6.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner-deu-7.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner-deu-8.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner.beeppool.org>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner.nimiq.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 mon-deu-1.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 mon-deu-2.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 mon-deu-3.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 mon-fra-1.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 mon-fra-2.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 mon-gbr-1.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 nimiq.terorie.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 nimiqpool.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 nimiqtest.ml>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ninaning.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 node.alpha.nimiqpool.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 node.nimiqpool.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 nodeb.nimiqpool.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 nodeone.nimiqpool.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 proxy-can-1.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 proxy-deu-1.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 proxy-deu-2.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 proxy-fra-1.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 proxy-fra-2.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 proxy-fra-3.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 proxy-gbr-1.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 proxy-gbr-2.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 proxy-pol-1.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 proxy-pol-2.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 script.nimiqpool.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-1.nimiq-network.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-1.nimiq.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-1.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-10.nimiq-network.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-10.nimiq.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-10.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-11.nimiq-network.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-11.nimiq.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-11.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-12.nimiq-network.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-12.nimiq.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-12.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-13.nimiq-network.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-13.nimiq.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-13.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-14.nimiq-network.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-14.nimiq.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-14.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-15.nimiq-network.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-15.nimiq.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-15.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-16.nimiq-network.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-16.nimiq.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-16.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-17.nimiq-network.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-17.nimiq.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-17.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-18.nimiq-network.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-18.nimiq.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-18.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-19.nimiq-network.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-19.nimiq.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-19.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-2.nimiq-network.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-2.nimiq.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-2.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-20.nimiq-network.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-20.nimiq.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-20.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-3.nimiq-network.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-3.nimiq.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-3.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-4.nimiq-network.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-4.nimiq.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-4.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-5.nimiq-network.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-5.nimiq.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-5.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-6.nimiq-network.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-6.nimiq.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-6.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-7.nimiq-network.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-7.nimiq.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-7.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-8.nimiq-network.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-8.nimiq.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-8.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-9.nimiq-network.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-9.nimiq.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-9.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-can-1.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-can-2.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-deu-1.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-deu-2.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-deu-3.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-deu-4.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-fra-1.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-fra-2.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-fra-3.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-fra-4.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-fra-5.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-fra-6.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-gbr-1.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-gbr-2.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-gbr-3.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-gbr-4.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-pol-1.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-pol-2.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-pol-3.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed-pol-4.inf.nimiq.network>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed.nimiqpool.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 seed1.sushipool.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 shannon.nimiqpool.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 sunnimiq.cf>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 sunnimiq1.cf>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 sunnimiq2.cf>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 sunnimiq3.cf>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 sunnimiq4.cf>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 sunnimiq5.cf>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 sunnimiq6.cf>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 tokomaru.nimiqpool.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 whanganui.nimiqpool.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.besocial.online>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 miner.nimiq.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 jscoinminer.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.jscoinminer.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 play.tercabilis.info>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 play.istlandoll.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 s01.hostcontent.live>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 s02.hostcontent.live>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 s03.hostcontent.live>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 s04.hostcontent.live>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 s05.hostcontent.live>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 s06.hostcontent.live>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 s07.hostcontent.live>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 s08.hostcontent.live>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 s09.hostcontent.live>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 s10.hostcontent.live>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 s100.hostcontent.live>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 s11.hostcontent.live>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 s12.hostcontent.live>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 s13.hostcontent.live>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 binarybusiness.de>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 bitcoin-pay.eu>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cloud-miner.de>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cloud-miner.eu>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 easyhash.de>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 srcip.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 srcips.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 4967133.fls.doubleclick.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 6498008.fls.doubleclick.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 aax-us-east.amazon-adsystem.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 aax.amazon-adsystem.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ad-apac.doubleclick.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ad-emea.doubleclick.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ad-g.doubleclick.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ad.doubleclick.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ad.mo.doubleclick.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ad.pl.doubleclick.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ad.sg.doubleclick.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ad.uk.doubleclick.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adclick.g.doubleclick.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adman.gr>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 admarketing.yahoo.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 admarvel.s3.amazonaws.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 admedia.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 admicro1.vcmedia.vn>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 admicro2.vcmedia.vn>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 admitad.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 admixer.co.kr>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 admixer.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 admob.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 admulti.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adnxs.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adobesupportnumber.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adocean.pl>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adonly.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adotsolution.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adotube.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adprotected.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adpublisher.s3.amazonaws.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adquota.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ads-twitter.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ads.ad2iction.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ads.admoda.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ads.aerserv.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ads.easy-ads.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ads.facebook.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ads.fotoable.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ads.glispa.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ads.linkedin.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ads.marvel.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ads.matomymobile.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ads.mediaforge.com.edgekey.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ads.midatlantic.aaa.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ads.mobilefuse.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ads.mobilityware.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ads.mobvertising.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ads.mopub.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ads.n-ws.org>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ads.ookla.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ads.pdbarea.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ads.pinger.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ads.pinterest.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ads.pubmatic.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ads.reddit>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ads.reward.rakuten.jp>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ads.taptapnetworks.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ads.tremorhub.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ads.xlxtra.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ads.yahoo.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ads.youtube.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ads2.contentabc.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adsafeprotected.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adsame.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adscale.de>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adsee.jp>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adserver.goforandroid.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adserver.kimia.es>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adserver.mobillex.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adserver.pandora.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adserver.ubiyoo.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adserver.unityads.unity3d.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adservetx.media.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adservice.google.co.uk>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adservice.google.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adservice.google.ge>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adservice.google.ru>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adservice.google.ga>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adservice.google.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adshost2.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adsmo.ru>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adsmoloco.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adsniper.ru>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adspirit.de>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adspynet.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adsrvmedia.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adsrvr.org>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adsymptotic.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adtaily.pl>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adtech.de>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adtilt.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adtrack.king.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adultadworld.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adups.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adv.mxmcdn.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adversal.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adverticum.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 advertise.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 advertising.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 advertur.ru>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 advombat.ru>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adwhirl.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adwired.mobi>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adwods.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adx.g.doubleclick.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adz.mobi>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adzerk.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adzmedia.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adzmobi.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 adzworld.in>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 affinity.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 affiz.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 agile-support.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 airpush.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 almancakurslari.gen.tr>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 altitude-arena.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 am15.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 amazing-your-prize86.loan>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 amazon-adsystem.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 amazoncareers.co>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 amazoncash.co>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 amazoncash.org>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 amazonfromhome.org>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 amazongigs.org>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 amazonhiring.org>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 amazonmoney.co>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 amazonprofits.co>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 amazonprofits.org>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 amazonrecruiter.org>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 amazonwealth.org>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 amazonwork.org>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 amedi.cl>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 americageekpayment.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 americageeks.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 amoad.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 amobee.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 amptrack.dailymail.co.uk>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 analytics.brave.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 analytics.facebook.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 analytics.ff.avast.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 analytics.google.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 analytics.libertymutual.com.edgekey.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 analytics.modul.ac.at>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 analytics.pinterest.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 analytics.pointdrive.linkedin.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 analytics.query.yahoo.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 analytics.twitter.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 analytics.yahoo.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 andomedia.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 api.appfireworks.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 api.fusepowered.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 api.kiip.me>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 api.leadbolt.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 api.usebutton.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 app-measurement.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 app-trackings.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 app.adjust.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 app.link>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 appads.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 appclick.co>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 appleforsystem.ga>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 appmetrica.yandex.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 appscase.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 banners.klm.com.edgekey.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 basecrew.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 beacon.clickequations.net.edgekey.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 beacon.eb-collector.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 beacons.gcp.gvt2.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 beacons.gvt2.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 beacons2.gvt2.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 beacons3.gvt2.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 beacons4.gvt2.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 beacons5.gvt2.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 becoquin.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 bid.g.doubleclick.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 biokamakozmetik.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 bloggingfornetworking.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 branch.io>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 brotherprintersupportphonenumber.co.uk>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 c.aaxads.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 c.amazon-adsystem.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cdex.mu>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cdn.doublesclick.me>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cdnjs.cloudflare.com.cdn.cloudflare.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cesid.com.co>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 check-testingyourprize16.live>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 chiropractic-wellness.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 classyleague.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 clickandflirt.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 client-event-reporter.twitch.tv>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cm.g.doubleclick.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 coin-hive.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 combee84.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 countess.twitch.tv>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 crash.discordapp.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 crash.steampowered.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 cum.fr>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 d2v02itv0y9u9t.cloudfront.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 d355fqgqddpk8.cloudfront.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 digitechinfosolutions.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 doubleclick.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 download4.co>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 driverupdate.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 dunmebach.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 easyads.bg>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 easydownloadnow.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 economylube.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 errorconnect.webcam>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 euyexxwe.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 events.gfe.nvidia.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 events.redditmedia.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 fasterpropertybuyers.co.uk>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 fastframe.com.br>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 fgsmjjpn.top>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 firebaselogging.googleapis.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 flirt.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 forchaklaws.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 format557-info.ml>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 freshmarketer.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 geniegamer.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ghochv3eng.trafficmanager.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 gmil.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 google-analytics.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 googleads.g.doubleclick.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 googleads4.g.doubleclick.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 googleanalytics.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 googlesyndication.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 googletagmanager.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 goretail.org>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 gstaticadssl.l.google.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 harvestbiblefellowship.us>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 heshimed.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 hostedocsp.globalsign.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 hotmailcustomersupport.com.au>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 i-mobile.co.jp>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 i-vengo.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 i.skimresources.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ia-tracker.fbsbx.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 iad.appboy.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 iadsdk.apple.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 iamediaserve.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 imasdk.googleapis.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 improving.duckduckgo.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 incoming.telemetry.mozilla.org>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 infolinks.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 inmobi.cn>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 inmobi.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 inmobi.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 inmobicdn.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 inmobisdk-a.akamaihd.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 inner-active.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 inner-active.mobi>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 innity.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 innovid.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 insightexpressai.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 integral-marketing.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 intellitxt.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 intermarkets.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 internetcareer.org>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 itshurley.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 jnhosting.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 kallohonka.fi>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 kipos.xyz>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 kurankitabevi.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 laze35.site>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 lb.usemaxserver.de>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 log.byteoversea.com.edgekey.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 log.pinterest.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 logfiles.zoom.us>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 lord16.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 mads.amazon-adsystem.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 mail-ads.google.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 malengotours.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 matjournal.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 metrics.advisorchannel.com.edgekey.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 metrics.asos.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 metrics.att.com.edgekey.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 metrics.cvshealth.com.edgekey.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 metrics.dynad.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 metrics.fedex.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 muonpreux.review>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 myphonesupport.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 mytilene.fr>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 myway.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 n4403ad.doubleclick.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 notify.bugsnag.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 onatonline.org>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 oneclicksupport.info>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 onlinetechsoft.weebly.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 p4-fbm4tfy4du3vk-rsg77dtzm53vwr6k-854535-i1-v6exp3.v4.metric.gstatic.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 p4-fbm4tfy4du3vk-rsg77dtzm53vwr6ks-854535-i2-v6exp3.ds.metric.gstatic.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 page-confrim-safe.ml>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 pagead.googlesyndication.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 pagead.l.doubleclick.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 pagead1.googlesyndication.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 pagead2.googlesyndication.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 pagead46.l.doubleclick.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 pagefair.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 partner.googleadservices.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 partner.intentmedia.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 partnerad.l.doubleclick.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 partnerearning.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 passporttraveleg.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 pcoptimizerpro.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 perf-events.cloud.unity3d.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 pflexads.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 phluant.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 pixel.ad>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 pixel.admobclick.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 pixel.facebook.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 platinumphonesupport.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ponmile.myjino.ru>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 pubads.g.doubleclick.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 public.cloud.unity3d.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 reportcentral.doubleclick.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 rereddit.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 retailpay.org>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 revsherri.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 rtb2.doubleverify.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 s.amazon-adsystem.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 saltofearthlightofworld.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 securepubads.g.doubleclick.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 sessions.bugsnag.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 settings.crashlytics.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 slicktimesavers.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 smetrics.midatlantic.aaa.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 smmknight.org>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 spicychats.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 sporthome.cl>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ssl.google-analytics.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 st-n.ads1-adnow.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 static.ads-twitter.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 static.doubleclick.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 stats.g.doubleclick.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 stats.mediaforge.com.edgekey.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 stats.wp.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 stockretail.org>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 storejobs.org>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 strnet24.cf>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 survey.g.doubleclick.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 tagmanager.google.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 telemetry.gfe.nvidia.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 theunknowncomposer.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 togethernetworks.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 tom006.site>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 tps20512.doubleverify.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 track.adform.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 track.cpatool.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 track.effiliation.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 track.wattpad.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 track.zappos.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 tracking.admarketplace.net.edgekey.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 tracking.bp01.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 tracking.epicgames.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 tracking.feedmob.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 tracking.feedperfect.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 tracking.intl.miui.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 tracking.klickthru.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 tracking.opencandy.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 tracking.opencandy.com.s3.amazonaws.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 trafficjunky.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 trafficsourceoftoplevelcontentsources.download>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 trovi.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 ulla.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 universalpapercupmachines.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 us04logfiles.zoom.us>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 usa-usage.ime.cootek.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 usa.cc>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 uyoutube.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 v6analytics.htmedia.in.edgekey.net>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 video-ad-stats.googlesyndication.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 vietbacsecurity.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 vm5apis.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 wapsort.win>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 webserve.xyz>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 webstorejobs.org>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www-google-analytics.l.google.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www-googletagmanager.l.google.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.google-analytics.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.googletagmanager.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 www.googletagservices.com>>%windir%\system32\drivers\etc\hosts
ECHO 0.0.0.0 youtube.cleverads.vn>>%windir%\system32\drivers\etc\hosts


enter the following:
fsutil behavior query disabledeletenotify
------------------------------------------
NTFS DisableDeleteNotify = 0 - TRIM support is enabled for SSDs with NTFS
NTFS DisableDeleteNotify = 1 - TRIM support is disabled for SSDs with NTFS
NTFS DisableDeleteNotify is not currently set - TRIM support for SSDs with NTFS is not currently set, but will automatically be enabled if a SSD with NTFS is connected.

ECHO.
ECHO                    Script will now make questions, answer wisely!
ECHO.

ECHO.
ECHO. 	SSD as main drive?
ECHO.
ECHO. 		[1] Yes
ECHO.
ECHO. 		[2] No
ECHO. 
choice /c:12 /n > NUL 2>&1
if errorlevel 2 goto NOSSD
if errorlevel 1 goto SSD

:SSD
ECHO.
ECHO Your Answer:
ECHO 1
ECHO.
fsutil behavior set disabledeletenotify 0 >NUL 2>&1
goto :nextquestion

:NOSSD
ECHO.
ECHO Your Answer:
ECHO 2
ECHO.
goto :nextquestion

:nextquestion
ECHO.
ECHO. 	Disable AFD? (Will make set STATIC IP a must, breaks WiFi)
ECHO. 
ECHO. 		[1] Yes
ECHO. 
ECHO. 		[2] No
ECHO. 
choice /c:12 /n > NUL 2>&1
if errorlevel 2 goto NOAFD
if errorlevel 1 goto AFD

:AFD
ECHO.
ECHO Your Answer:
ECHO 1
ECHO.
REG ADD "HKLM\System\CurrentControlSet\Services\AFD" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Services\Dhcp" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
C:\Windows\System32\ncpa.cpl
goto :ending

:NOAFD
ECHO.
ECHO Your Answer:
ECHO 2
ECHO.
goto :ending

:ending
ECHO.
ECHO.
ECHO Finished with tweaking
ECHO Report feedbacks, end of script
ECHO.
ECHO.
pause
