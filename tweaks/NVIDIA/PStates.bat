@Echo off
For /L %%i in (0,1,9) Do (
    For /F "Tokens=2* Skip=2" %%a in ('Reg.exe Query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\000%%i" /v "ProviderName" 2^>Nul') Do (
	If /i "%%b"=="NVIDIA" (
		Set K=HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\000%%i
		)
	)
)
Reg.exe Add "%K%" /v "DisableDynamicPstate" /t REG_DWORD /d "1" /f
Reg.exe Add "%K%" /v "DisableAsyncPstates" /t REG_DWORD /d "1" /f