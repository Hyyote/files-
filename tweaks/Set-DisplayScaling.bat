@echo off
net session >nul 2>&1

powershell -ExecutionPolicy Bypass -Command "Get-ChildItem 'HKLM:\SYSTEM\ControlSet001\Control\GraphicsDrivers\Configuration' -Recurse -EA SilentlyContinue | Where-Object { (Get-ItemProperty $_.PSPath -Name 'Scaling' -EA SilentlyContinue) -ne $null } | ForEach-Object { Set-ItemProperty $_.PSPath -Name 'Scaling' -Value 2 -Type DWord; Write-Host ('  [+] ' + $_.Name) -ForegroundColor Green; $global:c++ }; if (-not $global:c) { Write-Host '  No Scaling keys found.' -ForegroundColor Yellow } else { Write-Host \"`n  Set Scaling=2 on $($global:c) display config(s).\" -ForegroundColor Cyan }"

pause
