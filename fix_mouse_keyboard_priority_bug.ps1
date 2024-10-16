<#
    Fix Mouse and Keyboard priorities in attempt to fix windows bug related to mouse feel when not properly ordered or virtual devices generated by the real for other functionality.

    Notes:
    - In my case, the mouse had 1 mouse and 1 keyboard instance, while the keyboard had 2 keyboard instances and 1 mouse. It can clearly vary.
    - This script should account for any device you choose to use/change automatically. Rather than having to update a script manually.
    - Execution goes as
        - Start as admin
        - Ask if you want to set the script to be run automatically every startup
            - Unless you prefer to do by hand every startup, since even if you uninstall/remove the virtual devices, they return after a reboot.
            - Beware that the same thing will happen if you scan for hardware changes.
        - Cleaning all unused devices
            - The ones you find in Device Manager when setting to show all hidden devices.
            - Categories: Mice, Keyboards and Universal Serial Bus Controllers
        - Remove devices, so that, mouse only stay mouse and keyboard only stay keyboard. This is the fix.

    References:
    https://forums.blurbusters.com/viewtopic.php?f=10&t=13690
    https://forums.blurbusters.com/viewtopic.php?f=10&t=9977
    https://www.overclock.net/threads/how-to-clean-install-a-new-mouse-2-windows-usb-bugs-affecting-most-people.1750736/
#>

param([switch]$IsStartupRun = $false)

if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
	Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit
}

# -------------------------------------------------------------------------------------------------------

Write-Host "Removing unused devices"
Get-PnpDevice -Class @('USB', 'Mouse', 'Keyboard') | Where Status -eq Unknown | ForEach { &pnputil /remove-device $_.InstanceId }

[Environment]::NewLine
Write-Host "Gathering fake / virtual mouse and keyboard devices"
$keyboardDevices = Get-PnpDevice -Class 'Keyboard' -Status 'OK'
[PsObject[]]$fakeDevices = @()
$pointingDeviceIds = Get-WmiObject Win32_PointingDevice | Select -ExpandProperty DeviceId

foreach ($pointDevice in $pointingDeviceIds) {
    if ($pointDevice.StartsWith('USB')) {
        $pointDeviceIdSplit = $pointDevice.Split('\')[1].Split('&')
        $partialDeviceId = $pointDeviceIdSplit[0] + '&' + $pointDeviceIdSplit[1]
        $fakeMouseDevices = $keyboardDevices | Where InstanceId -match $partialDeviceId
        foreach ($fakeMouseDevice in $fakeMouseDevices) {
            $device = Get-PnpDeviceProperty -InstanceId $fakeMouseDevice.InstanceId
            $parentDevicePropertyDeviceId = $device | Where KeyName -eq 'DEVPKEY_Device_Parent' | Select -ExpandProperty Data
            $parentDevice = Get-PnpDeviceProperty -InstanceId $parentDevicePropertyDeviceId
            $parentDeviceName = $parentDevice | Where KeyName -eq 'DEVPKEY_Device_BusReportedDeviceDesc' | Select -ExpandProperty Data
            $fakeDevices += [PsObject]@{
                DeviceId = $fakeMouseDevice.InstanceId
                From = 'Keyboard'
                Name = $fakeMouseDevice.FriendlyName
                ParentName = $parentDeviceName
            }
        }
    }
    if ($pointDevice.StartsWith('HID')) {
        $device = Get-PnpDeviceProperty -InstanceId $pointDevice
        $deviceName = $device | Where KeyName -eq 'DEVPKEY_Device_DeviceDesc' | Select -ExpandProperty Data
        $parentDevicePropertyDeviceId = $device | Where KeyName -eq 'DEVPKEY_Device_Parent' | Select -ExpandProperty Data
        $parentDevice = Get-PnpDeviceProperty -InstanceId $parentDevicePropertyDeviceId
        $parentDeviceName = $parentDevice | Where KeyName -eq 'DEVPKEY_Device_BusReportedDeviceDesc' | Select -ExpandProperty Data
        $fakeDevices += [PsObject]@{
            DeviceId = $pointDevice
            From = 'Mouse'
            Name = $deviceName
            ParentName = $parentDeviceName
        }
    }
}

[Environment]::NewLine
Write-Host "Removing virtual / fake devices"
[Environment]::NewLine

$fakeDevices | ForEach {
    Write-Host "DeviceId: $($_.DeviceId)"
    Write-Host "Name: $($_.Name)"
    Write-Host "From: $($_.From)"
    Write-Host "Parent Name: $($_.ParentName)"
    [Environment]::NewLine
    &pnputil /remove-device $_.DeviceId | Out-Null
}

# -------------------------------------------------------------------------------------------------------

$taskName = "FixMouseKeyboardPriorityBug"
$taskExists = Get-ScheduledTask | Where-Object {$_.TaskName -like $taskName }
if ($taskExists) {
	Write-Host "You already set this script up to be run automatically at every startup."
	[Environment]::NewLine
	return
}
$startup = Read-Host "Do you wish set this script to be automatically run at every windows start-up? [Y] or [N]"
[Environment]::NewLine
if ($startup -eq "Y") {
	Write-Host "Setting up this script to be run at every windows startup automatically. Be sure to keep this file where you executed it from, otherwise there will be nothing to run."
	[Environment]::NewLine
	if (!$taskExists) {
        $action = New-ScheduledTaskAction -Execute "powershell" -Argument "-WindowStyle hidden -ExecutionPolicy Bypass -File $PSScriptRoot\fix_mouse_keyboard_priority_bug.ps1 -IsStartupRun"
        $delay = New-TimeSpan -Seconds 10
        $trigger = New-ScheduledTaskTrigger -AtLogOn -RandomDelay $delay
        $UserName = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty UserName
        $principal = New-ScheduledTaskPrincipal -UserID $UserName -RunLevel Highest -LogonType Interactive
        $STSet = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 3) -WakeToRun -AllowStartIfOnBatteries
        Register-ScheduledTask -TaskName $($taskName) -Action $action -Trigger $trigger -Principal $principal -Settings $STSet
        [Environment]::NewLine

        # In case you have to remove the script from startup, but are not able to do from the UI, run:
        # Unregister-ScheduledTask -TaskName "FixMouseKeyboardPriorityBug"
    }
}

if ($IsStartupRun -eq $false) {
	cmd /c pause
}
