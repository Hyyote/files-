@echo off
title AMD REGS CONFIGURATION
echo Press A to apply tweaks
echo Press R to revert tweaks
set /p c=""
if /i %c% equ A goto :tweaks
if /i %c% equ R goto :revert

:tweaks
for /L %%i in (0,1,9) do (
    for /F "tokens=2* skip=2" %%a in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\000%%i" /v "ProviderName" 2^>nul') do (
	if /i "%%b"=="Advanced Micro Devices, Inc." (
		set G=000%%i
		)
	)
)

Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "ACGSupported" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "BankSwapDowngrade" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "CailDisableGdbSpmProgramming" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "CailDisableVbiosRegAccessDebug" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "CAILEnableACPIOptimization" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalAllowCPUPStateSwitch" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalAllowDirectMemoryAccessTrig" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalAllowDPrefSwitchingForGLSync" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalAllowNBPState" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalAllowSelfRefreshControl" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalAsicFIDLightSleep" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalDisable48MhzPwrDwn" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DALDisableAzClockGating" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalDisableClockGating" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalDisableDppPG" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalDisableDscPG" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalDisableFBCCompClkGate" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalDisableFEC" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalDisableHubpPG" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalDisableIdlePowerOptimizations" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalDisableMpcOtgPG" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalDisallowpstateChange" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalDPSkipPowerOff" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DaleAllowCCState" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalEnableDPMSTFeature" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalEnableFreesyncPowerOptimization" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalEnableHdcp22Debugging" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalEnableIdleRegChecks" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalEnableLTTPR" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalEnableOledEdpPowerUpOpt" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalEnableTiledDisplay" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DALExtraMCLatency" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DALExtraReorderingLatency" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalFeatureEnableUSB4PowerManagement" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalFineGrainClockGating" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalForceMaxDisplayClock" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalForcePSR" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalIgnoreDPRefClkSS" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalLimitModesOnSclk" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalLogEnable" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalLowVCEPerformance" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalMemLowPowerSupport" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalMPOSCLKDeepSleepIncrease" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalPowerGatingLb" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalPowerGatingPipe" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalPSRFeatureEnable" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalPSRPowerOpt" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalRegKey_DisableMemLowPower" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalReplayLowRefreshRateEnableOpt" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalSceEnable" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalSceOledEnable" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalSendDPMSNotification" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalStutterIgnoreFbcForNBp" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalWirelessDisplayIdleSupport" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableAcpPowerGating" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableAcpSupport" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableAllClockGating" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableAspmSWL1" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableBifLightSleep" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableBifMGCG" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableBlocknv11" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableClkReqSupport" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableCpPowerGating" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableDfMGCG" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableDMACopy" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableDrmdmaMGCG" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableDrmdmaPowerGating" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableDrmLightSleep" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableDrmMGCG" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableDynamicGfxMGPowerGating" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableEarlySamuInit" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableFBCForFullScreenApp" /t REG_SZ /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableFBCForXDMA" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableFBCSupport" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableForceUvdToSclk" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableGCEDC" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableGDSPowerGating" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableGfx3DCGCG" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableGfx3DCGLS" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableGfxCGPowerGating" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableGfxCGTS" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableGfxCGTS_LS" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableGfxClockGating" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableGfxCoarseGrainClockGating" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableGfxCoarseGrainLightSleep" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableGfxCpLightSleep" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableGfxMediumGrainClockGating" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableGfxMediumGrainLightSleep" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableGfxMGCGPerfMon" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableGfxPGCondClearStateWA" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableGFXPipelinePowerGating" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableGfxRlcLightSleep" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableGmcPowerGating" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableHdpLightSleep" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableHdpMGClockGating" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableKernelPowerInterface" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableLPTSupport" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableLTR" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableLTREnforcement" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableLTRNoSnoopRequirement" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableLTRSnoopRequirement" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableLTRStrap" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableMcLightSleep" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableMcMediumGrainClockGating" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableMcMGCG" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisablePllOffInL1" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisablePowerGating" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableQuickGfxMGPowerGating" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableRlcSmuPGHandshake" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableRomMGCGClockGating" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableSamuClockGating" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableSamuLightSleep" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableSAMUPowerGating" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableSdmaMGCG" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableSdmaMGLS" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableSpuMGCG" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableStaticGfxMGPowerGating" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableSysClockGating" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableUVDPowerGating" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableUVDPowerGatingDynamic" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableVceClockGating" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableVceLightSleep" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableVCEPowerGating" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableXdmaLightSleep" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableXdmaPowerGating" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableXdmaSclkGating" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DP_ForceSSEnable" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "EnableAspmL0s" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "EnableAspmL1" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "EnableAspmL1SS" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "EnableAtomworkDebugger" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "EnableCPLIBLog" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "EnableDfDramScrub" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "EnableGfxClockGatingThruSmu" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "EnableGPUVirtulizationFeature" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "EnableLBPWSupport" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "EnablePllOffInL1" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "EnablePPSMSupport" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "EnableSpreadSpectrum" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "EnableswGCCGPG" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "EnableswGCFakeCGCG" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "EnableswGCFakeCGPG" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "EnableswGcLbpw" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "EnableSysClockGatingThruSmu" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "EnableUlps" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "EnableUlps_NA" /t REG_SZ /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "EnableUlps_NB" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "EnableUmschSelfTest" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "EnableUvdClockGating" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "EnableVcePllSpreadSpectrum" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "EnableVceSwClockGating" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "EnableVCNMemoryShutdown" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "EnableVPECG" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "EnableVPEDpm" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "EnableVPEMemoryShutdown" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "GCOOPTION_DisableGPIOPowerSaveMode" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "GroupSizeDowngrade" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "IRQMgrDisableIHClockGating" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_BacoOnSingleGpu" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_CpDebugDump" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_DbgIntSupport" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_DeLagEnabled" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_DisableATIDBGPOST" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_DisableCgOnShutdownOnly" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_DisableDPD" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_DisableDxvaVPClockManagement" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_DisableFBCMixedMode" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_DisableFBCRegion" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_EnableAcpLogging" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_EnableAllocStackTrace" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_EnableBigPageAppLogging" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_EnableComputePreemption" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_EnableContextBasedPowerManagement" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_EnableDebugVmid" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_EnableEventLog" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_EnableGpuMessage" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_EnableGuestHibernation" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_EnableIoMmuGpuIsolation" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_EnableKiqDbg" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_EnableMesLog" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_EnableOPM2Interface" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_EnableParaVirtualization" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_EnableUvdRTPM" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_EnableVirtualDalSupport" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_ForceD3ColdAuxPowerSupport" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_ForceD3ColdSupport" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_ForceD3hotWhenD3coldSupported" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_ForceIpsForD3Cold" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_ForceTmzDisable" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_FRTEnabled" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_InjectWait3DIdle" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_LongIdleDetectOption" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_LoopCountForIdle" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_MaxUVDSessions" /t REG_DWORD /d "32" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_PXDPPEDynamicPowerStates" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_PXS3S4OptimizationSupport" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_RTPMEnabled" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_StandbyOptimization" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_WindowedModePowerManagement" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "MemoryBankDowngrade" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PipePowerGating" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PipeTilingDowngrade" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PO_DisableClockGating" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_ACDCGpioDisabled" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_ACPDPM" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_ActivityTarget" /t REG_DWORD /d "30" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_AllGraphicLevel_DownHyst" /t REG_DWORD /d "20" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_AllGraphicLevel_UpHyst" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_AutoWattManDebug" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_BACOSkipHardware" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_BACOSkipSMCInterrupt" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_BACOUseIOAccess" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_BAMACOEnabled" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_BreakOnAssert" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_BreakOnWarn" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_CGCGDisable" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_DisableAVFS" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_DisableCAC" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_DisableClockStretcher" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_DisableDBRamping" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_DisableDIDT" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_DisableDPM" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_DisableEDCLeakageController" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_DisableEngineTransition" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_DisableFFC" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_DisableLightSleep" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_DisableMCDownLoadFeature" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_DisableMemoryTransition" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_DisableMultiUVDStates" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_DisableOCLPowerOptimization" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_DisableODStateInDC" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_DisablePCIePerformanceRequest" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_DisablePowerContainment" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_DisablePowerControl" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_DisablePowerOptimization" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_DisablePPM" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_DisableShadowPstate" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_DisableSMUUVDHandshake" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_DisableSPLLShutdownSupport" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_DisableThermalManagement" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_DisableULPS" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_DisableULV" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_DisableUVDClientMCTuning" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_DisableUVDVCEShutDown" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_DisableVoltageIsland" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_DisableVoltageTransition" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_DisableXDMANaturalDPM" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_EnableACPIOptimization" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_EnableBACOSupportFeature" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_EnableChillOptimization" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_EnableDummyPstateTable" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_EnableDynamicLTRSupport" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_EnableHardwareThermalProtection" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_EnableLoadFalconSmcFirmware" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_EnableLongIdleBACOSupport" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_EnableMCLKOptimization" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_EnablePerDPM" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_EnablePkgPwrTracking" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_EnablePowerContainment" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_EnablePowerOptimization" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_EnablePowerSave" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_EnableRaceToIdle" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_EnableVPEPG" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_EngineSSEnabled" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_Force3DPerformanceMode" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_ForceHighDPMLevel" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_ForceHwAvfsEn" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_ForceMCLKHigh" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_GeminiLCSSupportFeature" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_GfxOffControl" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_GPUPowerDownEnabled" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_isIcafeEnable" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_LSCGDisable" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_MclkDpmDisabled" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_MCLKStutterModeThreshold" /t REG_DWORD /d "4096" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_MemorySSEnabled" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_MGCGCGTSSMDisable" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_MGCGDisable" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_MMClockGatingEnabled" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_ODNFeatureEnable" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_PcieDpmDisabled" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_SAMUDPM" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_SclkDeepSleepDisable" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_SclkDpmDisabled" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_SclkThrottleLowNotification" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_ShadowPstateMode" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_SkipQueryATPXPowerDown" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_SocclkDpmDisabled" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_ThermalAutoThrottlingEnable" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_ThermalOutGpioDisabled" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_UMDPStateDisable" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_UserBACOEnable" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_UVDDPM" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_VCEDPM" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_VRHotGpioDisabled" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "RowTilingDowngrade" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "SampleSplitDowngrade" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "SMU_DisableACG" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "SMU_DisableAthubPowerGating" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "SMU_DisableMmhubPowerGating" /t REG_DWORD /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "StutterMode" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "TVEnableOverscan" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "WmAgpMaxIdleClk" /t REG_DWORD /d "32" /f > nul 2>&1

Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\DAL2_DATA__2_0\DisplayPath_4\EDID_D109_78E9\Option" /v "ProtectionControl" /t REG_BINARY /d "0100000001000000" /f > nul 2>&1

Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "AnisoDegree" /t REG_BINARY /d "3400" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "AnisoDegree_DEF" /t REG_SZ /d "4" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "AnisotropyOptimise" /t REG_BINARY /d "3100" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "AnisoType" /t REG_BINARY /d "32000000" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "AnisoType_DEF" /t REG_SZ /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "AntiStuttering" /t REG_BINARY /d "3000" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "AreaAniso_DEF" /t REG_SZ /d "8" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "CatalystAI" /t REG_BINARY /d 30 00 00 00 /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "CatalystAI_DEF" /t REG_BINARY /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "EQAA" /t REG_BINARY /d "3000" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "FlipQueueSize" /t REG_SZ /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "ForceTripleBuffering" /t REG_BINARY /d "3000" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "ForceTripleBuffering_DEF" /t REG_SZ /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "ForceZBufferDepth" /t REG_BINARY /d "3100" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "ForceZBufferDepth_DEF" /t REG_SZ /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "ForceZBufferDepth_SET" /t REG_BINARY /d "3020313620323400" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "HighQualityAF" /t REG_BINARY /d "3300" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "LodAdj" /t REG_SZ /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "Main3D" /t REG_BINARY /d "3100" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "Main3D_DEF" /t REG_SZ /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "Main3D_SET" /t REG_BINARY /d "302031203220332034203500" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "MLF" /t REG_BINARY /d "3000" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "NoOSPowerOptions" /t REG_SZ /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "PowerState" /t REG_BINARY /d "3000" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "ShaderCache" /t REG_BINARY /d "3200" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "SurfaceFormatReplacements" /t REG_BINARY /d "3000" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "SurfaceFormatReplacements_DEF" /t REG_SZ /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "Tessellation" /t REG_BINARY /d "3100" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "Tessellation_DEF" /t REG_SZ /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "Tessellation_OPTION" /t REG_BINARY /d "3200" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "Tessellation_OPTION_DEF" /t REG_SZ /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "TextureLod" /t REG_BINARY /d "31000000" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "TextureLod_DEF" /t REG_SZ /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "TextureOpt" /t REG_BINARY /d "31000000" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "TextureOpt_DEF" /t REG_SZ /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "TFQ" /t REG_BINARY /d "3200" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "TFQ_DEF" /t REG_SZ /d "1" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "TrilinearOptimise" /t REG_BINARY /d "3100" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "TruformMode_DEF" /t REG_SZ /d "2" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "TruformMode_NA" /t REG_BINARY /d "3200" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "TurboSync" /t REG_BINARY /d "3000" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "ZFormats_NA" /t REG_BINARY /d "3100" /f > nul 2>&1

Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\Dwm" /v "OverlayTestMode" /t REG_DWORD /d "5" /f > nul 2>&1


Reg.exe add "HKCU\Software\AMD\CN" /v "AutoUpdateTriggered" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKCU\Software\AMD\CN" /v "AutoUpdate" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKCU\Software\AMD\CN" /v "AnimationEffect" /t REG_SZ /d "false" /f > nul 2>&1
Reg.exe add "HKCU\Software\AMD\CN" /v "PowerSaverAutoEnable_CUR" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKCU\Software\AMD\CN" /v "AllowWebContent" /t REG_SZ /d "false" /f > nul 2>&1
Reg.exe add "HKCU\Software\AMD\CN" /v "CN_Hide_Toast_Notification" /t REG_SZ /d "true" /f > nul 2>&1


Reg.exe add "HKLM\System\CurrentControlSet\Services\amdwddmg" /v "ChillEnabled" /t REG_DWORD /d "0" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Services\AMD Crash Defender Service" /v "Start" /t REG_DWORD /d "4" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Services\AMD External Events Utility" /v "Start" /t REG_DWORD /d "4" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Services\amdfendr" /v "Start" /t REG_DWORD /d "4" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Services\amdfendrmgr" /v "Start" /t REG_DWORD /d "4" /f > nul 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Services\amdlog" /v "Start" /t REG_DWORD /d "4" /f > nul 2>&1
sc config amdlog start=disabled
sc config "AMD External Events Utility" start=disabled
cls
echo Powersavings and services successfully disabled.
pause
exit

:revert
for /L %%i in (0,1,9) do (
    for /F "tokens=2* skip=2" %%a in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\000%%i" /v "ProviderName" 2^>nul') do (
	if /i "%%b"=="Advanced Micro Devices, Inc." (
		set G=000%%i
		)
	)
)
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "ACGSupported" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "BankSwapDowngrade" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "CailDisableGdbSpmProgramming" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "CailDisableVbiosRegAccessDebug" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "CAILEnableACPIOptimization" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalAllowCPUPStateSwitch" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalAllowDirectMemoryAccessTrig" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalAllowDPrefSwitchingForGLSync" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalAllowNBPState" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalAllowSelfRefreshControl" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalAsicFIDLightSleep" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalDisable48MhzPwrDwn" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DALDisableAzClockGating" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalDisableClockGating" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalDisableDppPG" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalDisableDscPG" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalDisableFBCCompClkGate" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalDisableFEC" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalDisableHubpPG" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalDisableIdlePowerOptimizations" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalDisableMpcOtgPG" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalDisallowpstateChange" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalDPSkipPowerOff" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DaleAllowCCState" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalEnableDPMSTFeature" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalEnableFreesyncPowerOptimization" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalEnableHdcp22Debugging" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalEnableIdleRegChecks" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalEnableLTTPR" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalEnableOledEdpPowerUpOpt" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalEnableTiledDisplay" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DALExtraMCLatency" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DALExtraReorderingLatency" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalFeatureEnableUSB4PowerManagement" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalFineGrainClockGating" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalForceMaxDisplayClock" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalForcePSR" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalIgnoreDPRefClkSS" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalLimitModesOnSclk" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalLogEnable" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalLowVCEPerformance" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalMemLowPowerSupport" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalMPOSCLKDeepSleepIncrease" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalPowerGatingLb" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalPowerGatingPipe" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalPSRFeatureEnable" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalPSRPowerOpt" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalRegKey_DisableMemLowPower" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalReplayLowRefreshRateEnableOpt" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalSceEnable" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalSceOledEnable" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalSendDPMSNotification" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalStutterIgnoreFbcForNBp" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DalWirelessDisplayIdleSupport" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableAcpPowerGating" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableAcpSupport" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableAllClockGating" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableAspmSWL1" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableBifLightSleep" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableBifMGCG" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableBlocknv11" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableClkReqSupport" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableCpPowerGating" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableDfMGCG" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableDMACopy" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableDrmdmaMGCG" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableDrmdmaPowerGating" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableDrmLightSleep" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableDrmMGCG" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableDynamicGfxMGPowerGating" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableEarlySamuInit" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableFBCForFullScreenApp" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableFBCForXDMA" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableFBCSupport" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableForceUvdToSclk" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableGCEDC" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableGDSPowerGating" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableGfx3DCGCG" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableGfx3DCGLS" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableGfxCGPowerGating" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableGfxCGTS" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableGfxCGTS_LS" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableGfxClockGating" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableGfxCoarseGrainClockGating" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableGfxCoarseGrainLightSleep" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableGfxCpLightSleep" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableGfxMediumGrainClockGating" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableGfxMediumGrainLightSleep" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableGfxMGCGPerfMon" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableGfxPGCondClearStateWA" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableGFXPipelinePowerGating" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableGfxRlcLightSleep" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableGmcPowerGating" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableHdpLightSleep" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableHdpMGClockGating" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableKernelPowerInterface" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableLPTSupport" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableLTR" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableLTREnforcement" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableLTRNoSnoopRequirement" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableLTRSnoopRequirement" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableLTRStrap" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableMcLightSleep" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableMcMediumGrainClockGating" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableMcMGCG" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisablePllOffInL1" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisablePowerGating" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableQuickGfxMGPowerGating" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableRlcSmuPGHandshake" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableRomMGCGClockGating" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableSamuClockGating" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableSamuLightSleep" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableSAMUPowerGating" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableSdmaMGCG" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableSdmaMGLS" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableSpuMGCG" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableStaticGfxMGPowerGating" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableSysClockGating" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableUVDPowerGating" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableUVDPowerGatingDynamic" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableVceClockGating" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableVceLightSleep" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableVCEPowerGating" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableXdmaLightSleep" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableXdmaPowerGating" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DisableXdmaSclkGating" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "DP_ForceSSEnable" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "EnableAspmL0s" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "EnableAspmL1" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "EnableAspmL1SS" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "EnableAtomworkDebugger" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "EnableCPLIBLog" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "EnableDfDramScrub" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "EnableGfxClockGatingThruSmu" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "EnableGPUVirtulizationFeature" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "EnableLBPWSupport" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "EnablePllOffInL1" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "EnablePPSMSupport" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "EnableSpreadSpectrum" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "EnableswGCCGPG" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "EnableswGCFakeCGCG" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "EnableswGCFakeCGPG" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "EnableswGcLbpw" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "EnableSysClockGatingThruSmu" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "EnableUlps" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "EnableUlps_NA" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "EnableUlps_NB" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "EnableUmschSelfTest" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "EnableUvdClockGating" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "EnableVcePllSpreadSpectrum" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "EnableVceSwClockGating" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "EnableVCNMemoryShutdown" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "EnableVPECG" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "EnableVPEDpm" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "EnableVPEMemoryShutdown" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "GCOOPTION_DisableGPIOPowerSaveMode" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "GroupSizeDowngrade" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "IRQMgrDisableIHClockGating" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_BacoOnSingleGpu" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_CpDebugDump" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_DbgIntSupport" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_DeLagEnabled" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_DisableATIDBGPOST" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_DisableCgOnShutdownOnly" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_DisableDPD" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_DisableDxvaVPClockManagement" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_DisableFBCMixedMode" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_DisableFBCRegion" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_EnableAcpLogging" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_EnableAllocStackTrace" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_EnableBigPageAppLogging" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_EnableComputePreemption" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_EnableContextBasedPowerManagement" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_EnableDebugVmid" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_EnableEventLog" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_EnableGpuMessage" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_EnableGuestHibernation" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_EnableIoMmuGpuIsolation" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_EnableKiqDbg" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_EnableMesLog" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_EnableOPM2Interface" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_EnableParaVirtualization" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_EnableUvdRTPM" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_EnableVirtualDalSupport" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_ForceD3ColdAuxPowerSupport" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_ForceD3ColdSupport" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_ForceD3hotWhenD3coldSupported" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_ForceIpsForD3Cold" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_ForceTmzDisable" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_FRTEnabled" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_InjectWait3DIdle" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_LongIdleDetectOption" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_LoopCountForIdle" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_MaxUVDSessions" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_PXDPPEDynamicPowerStates" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_PXS3S4OptimizationSupport" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_RTPMEnabled" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_StandbyOptimization" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "KMD_WindowedModePowerManagement" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "MemoryBankDowngrade" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PipePowerGating" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PipeTilingDowngrade" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PO_DisableClockGating" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_ACDCGpioDisabled" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_ACPDPM" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_ActivityTarget" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_AllGraphicLevel_DownHyst" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_AllGraphicLevel_UpHyst" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_AutoWattManDebug" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_BACOSkipHardware" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_BACOSkipSMCInterrupt" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_BACOUseIOAccess" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_BAMACOEnabled" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_BreakOnAssert" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_BreakOnWarn" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_CGCGDisable" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_DisableAVFS" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_DisableCAC" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_DisableClockStretcher" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_DisableDBRamping" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_DisableDIDT" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_DisableDPM" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_DisableEDCLeakageController" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_DisableEngineTransition" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_DisableFFC" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_DisableLightSleep" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_DisableMCDownLoadFeature" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_DisableMemoryTransition" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_DisableMultiUVDStates" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_DisableOCLPowerOptimization" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_DisableODStateInDC" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_DisablePCIePerformanceRequest" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_DisablePowerContainment" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_DisablePowerControl" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_DisablePowerOptimization" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_DisablePPM" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_DisableShadowPstate" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_DisableSMUUVDHandshake" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_DisableSPLLShutdownSupport" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_DisableThermalManagement" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_DisableULPS" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_DisableULV" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_DisableUVDClientMCTuning" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_DisableUVDVCEShutDown" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_DisableVoltageIsland" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_DisableVoltageTransition" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_DisableXDMANaturalDPM" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_EnableACPIOptimization" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_EnableBACOSupportFeature" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_EnableChillOptimization" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_EnableDummyPstateTable" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_EnableDynamicLTRSupport" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_EnableHardwareThermalProtection" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_EnableLoadFalconSmcFirmware" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_EnableLongIdleBACOSupport" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_EnableMCLKOptimization" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_EnablePerDPM" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_EnablePkgPwrTracking" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_EnablePowerContainment" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_EnablePowerOptimization" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_EnablePowerSave" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_EnableRaceToIdle" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_EnableVPEPG" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_EngineSSEnabled" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_Force3DPerformanceMode" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_ForceHighDPMLevel" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_ForceHwAvfsEn" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_ForceMCLKHigh" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_GeminiLCSSupportFeature" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_GfxOffControl" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_GPUPowerDownEnabled" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_isIcafeEnable" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_LSCGDisable" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_MclkDpmDisabled" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_MCLKStutterModeThreshold" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_MemorySSEnabled" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_MGCGCGTSSMDisable" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_MGCGDisable" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_MMClockGatingEnabled" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_ODNFeatureEnable" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_PcieDpmDisabled" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_SAMUDPM" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_SclkDeepSleepDisable" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_SclkDpmDisabled" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_SclkThrottleLowNotification" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_ShadowPstateMode" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_SkipQueryATPXPowerDown" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_SocclkDpmDisabled" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_ThermalAutoThrottlingEnable" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_ThermalOutGpioDisabled" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_UMDPStateDisable" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_UserBACOEnable" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_UVDDPM" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_VCEDPM" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "PP_VRHotGpioDisabled" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "RowTilingDowngrade" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "SampleSplitDowngrade" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "SMU_DisableACG" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "SMU_DisableAthubPowerGating" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "SMU_DisableMmhubPowerGating" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "StutterMode" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "TVEnableOverscan" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%" /v "WmAgpMaxIdleClk" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\DAL2_DATA__2_0\DisplayPath_4\EDID_D109_78E9\Option" /v "ProtectionControl" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "AnisoDegree" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "AnisoDegree_DEF" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "AnisotropyOptimise" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "AnisoType" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "AnisoType_DEF" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "AntiStuttering" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "AreaAniso_DEF" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "CatalystAI" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "CatalystAI_DEF" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "EQAA" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "FlipQueueSize" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "ForceTripleBuffering" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "ForceTripleBuffering_DEF" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "ForceZBufferDepth" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "ForceZBufferDepth_DEF" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "ForceZBufferDepth_SET" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "HighQualityAF" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "LodAdj" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "Main3D" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "Main3D_DEF" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "Main3D_SET" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "MLF" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "NoOSPowerOptions" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "PowerState" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "ShaderCache" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "SurfaceFormatReplacements" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "SurfaceFormatReplacements_DEF" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "Tessellation" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "Tessellation_DEF" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "Tessellation_OPTION" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "Tessellation_OPTION_DEF" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "TextureLod" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "TextureLod_DEF" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "TextureOpt" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "TextureOpt_DEF" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "TFQ" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "TFQ_DEF" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "TrilinearOptimise" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "TruformMode_DEF" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "TruformMode_NA" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "TurboSync" /f > nul 2>&1
Reg.exe delete "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\%G%\UMD" /v "ZFormats_NA" /f > nul 2>&1
Reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows\Dwm" /v "OverlayTestMode" /f > nul 2>&1
cls
echo Powersavings and services successfully reenabled.
pause
exit