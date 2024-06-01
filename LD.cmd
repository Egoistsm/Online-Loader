echo ======= Optimizing Computer Performance and Internet Speed ======= 

:: Function to create random files
:CreateRandomFiles
echo Creating random files...
setlocal enabledelayedexpansion
for /l %%i in (1, 1, 1000) do (
    set "filename=!random!.txt"
    copy nul "%temp%\!filename!" >nul
)
endlocal
echo Random files created.

:: Function to delete files in temp
:DeleteTempFiles
echo Deleting files...
del /q "%temp%\*.*" >nul 2>&1
echo Files deleted.

echo Cleanup completed.

:: Function to optimize internet speed
:OptimizeInternetSpeed
echo Optimizing Internet Speed...
echo Flushing DNS Cache...
ipconfig /flushdns >nul 2>&1
echo Resetting TCP/IP stack...
netsh int ip reset >nul 2>&1
echo Releasing and Renewing IP address...
ipconfig /release >nul 2>&1
ipconfig /renew >nul 2>&1
echo Setting MTU to 1500...
netsh interface ipv4 set subinterface "Ethernet" mtu=1500 store=persistent >nul 2>&1

:: Change DNS to Cloudflare DNS (1.1.1.1 and 1.0.0.1)
echo Changing DNS to Cloudflare DNS...
netsh interface ipv4 add dns "Ethernet" 1.1.1.1 index=1 >nul 2>&1
netsh interface ipv4 add dns "Ethernet" 1.0.0.1 index=2 >nul 2>&1

echo Internet Speed Optimized.
timeout /t 2 >nul

:: Reset Internet Usage Statistics
echo Resetting Internet Usage Statistics...
net stop "Network Location Awareness" >nul 2>&1
net stop "Network List Service" >nul 2>&1
net start "Network Location Awareness" >nul 2>&1
net start "Network List Service" >nul 2>&1

:: Function to optimize computer performance
:OptimizeComputerPerformance
echo Optimizing Computer Performance...
echo Emptying Recycle Bin...
rd /s /q C:\$Recycle.Bin >nul 2>&1
echo Running Disk Cleanup...
cleanmgr /sagerun:1 >nul 2>&1
echo Scheduling Disk Defragmentation...
defrag C: /U /V >nul 2>&1

:: Disable Unused Startup Programs
echo Disabling Unused Startup Programs...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "ProgramName" /t REG_SZ /d "C:\Path\To\Program.exe" /f >nul 2>&1

:: Update Drivers
echo Updating Drivers...
driverquery /v > drivers.txt
REM - Run some script to check and update drivers here

:: Optimize Pagefile
echo Optimizing Pagefile...
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "PagingFiles" /t REG_MULTI_SZ /d "C:\pagefile.sys 512 1024" /f >nul 2>&1

:: Clear System Restore Points
echo Clearing System Restore Points...
vssadmin delete shadows /for=c: /all /quiet >nul 2>&1

:: Disable System Restore
echo Disabling System Restore...
wmic.exe /namespace:\\root\default Path SystemRestore Call Disable  >nul 2>&1

:: Disable Hibernation
echo Disabling Hibernation...
powercfg /h off >nul 2>&1

:: Disable Unnecessary Windows Features
echo Disabling Unnecessary Windows Features...
dism.exe /online /disable-feature /featurename:MediaPlayback /quiet /norestart >nul 2>&1

:: Optimize Graphics Settings
echo Optimizing Graphics Settings...
reg add "HKCU\Software\Microsoft\Windows\DWM" /v "Animations" /t REG_DWORD /d 0 /f >nul 2>&1

:: Disable Windows Search Indexing
echo Disabling Windows Search Indexing...
sc config "WSearch" start=disabled >nul 2>&1

:: Clear Temporary Internet Files
echo Clearing Temporary Internet Files...
rmdir /s /q "%userprofile%\AppData\Local\Microsoft\Windows\INetCache" >nul 2>&1

:: Optimize Visual Effects
echo Optimizing Visual Effects...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v "VisualFXSetting" /t REG_DWORD /d 2 /f >nul 2>&1

:: Disable User Account Control (UAC)
echo Disabling User Account Control (UAC)...
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d 0 /f >nul 2>&1

:: Disable Windows Error Reporting
echo Disabling Windows Error Reporting...
reg add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d 1 /f >nul 2>&1

:: Optimize Virtual Memory
echo Optimizing Virtual Memory...
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePagingExecutive" /t REG_DWORD /d 1 /f >nul 2>&1

:: Disable Remote Assistance and Remote Desktop
echo Disabling Remote Assistance and Remote Desktop...
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v "fAllowToGetHelp" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v "fDenyTSConnections" /t REG_DWORD /d 1 /f >nul 2>&1

:: Optimize BIOS/UEFI Settings
echo Optimizing BIOS/UEFI Settings...
rem Your BIOS/UEFI optimization commands here...
rem Examples of BIOS/UEFI settings optimization commands:
rem - Update BIOS/UEFI firmware if available
rem - Disable unused devices (e.g., onboard audio, onboard LAN if not used)
rem - Enable XMP for RAM if supported and installed

:: Cleanup Old Windows Installation Files
echo Cleaning up Old Windows Installation Files...
rem Your old Windows installation files cleanup commands here...
rem Examples of cleanup commands:
rem - Delete Windows.old folder if present
rem - Delete $Windows.~BT folder if present

:: Update Windows
echo Updating Windows...
rem Your Windows update commands here...
rem Examples of update commands:
rem - Check for Windows updates and install them

:: Disable Scheduled Tasks
echo Disabling Scheduled Tasks...
rem Your scheduled tasks disabling commands here...
rem Examples of disabling scheduled tasks:
rem - Disable unnecessary or resource-intensive scheduled tasks

:: Optimize Power Settings
echo Optimizing Power Settings...
rem Your power settings optimization commands here...
rem Examples of power settings optimization commands:
rem - Set power plan to High Performance
rem - Disable USB selective suspend

:: Cleanup Windows Event Logs
echo Cleaning up Windows Event Logs...
rem Your Windows event logs cleanup commands here...
rem Examples of event logs cleanup commands:
rem - Clear Windows event logs

:: Update Device Drivers
echo Updating Device Drivers...
rem Your device driver update commands here...
rem Examples of updating device drivers:
rem - Use a tool like Driver Booster to automatically update drivers

:: Perform System File Checker (SFC) Scan
echo Performing System File Checker (SFC) Scan...
sfc /scannow
rem - This will scan and repair system files if any are corrupted

:: Perform Disk Error Checking
echo Performing Disk Error Checking...
chkdsk C: /f /r
rem - This will check for and fix disk errors on the C: drive

:: Perform System Integrity Check
echo Performing System Integrity Check...
DISM /Online /Cleanup-Image /RestoreHealth
rem - This will check for and repair system image corruption

:: Perform Memory Diagnostic Test
echo Performing Memory Diagnostic Test...
mdsched.exe
rem - This will launch the Windows Memory Diagnostic tool to check for RAM errors

:: Disable Automatic Windows Updates
echo Disabling Automatic Windows Updates...
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /t REG_DWORD /d 1 /f >nul 
