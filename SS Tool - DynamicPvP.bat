::[Bat To Exe Converter]
::
::YAwzoRdxOk+EWAjk
::fBw5plQjdCyDJGyX8VAjFD1GTQqBM0GGIroL5uT07u6UnkkEWuMycYzLzKSeLudd40brFQ==
::YAwzuBVtJxjWCl3EqQJgSA==
::ZR4luwNxJguZRRnk
::Yhs/ulQjdF+5
::cxAkpRVqdFKZSjk=
::cBs/ulQjdFq5
::ZR41oxFsdFKZSDk=
::eBoioBt6dFKZSDk=
::cRo6pxp7LAbNWATEpCI=
::egkzugNsPRvcWATEpCI=
::dAsiuh18IRvcCxnZtBJQ
::cRYluBh/LU+EWAnk
::YxY4rhs+aU+IeA==
::cxY6rQJ7JhzQF1fEqQJhZksaH2Q=
::ZQ05rAF9IBncCkqN+0xwdVs0
::ZQ05rAF9IAHYFVzEqQIDG1tgQwuOfCb6IqwS6eXy7NqRki0=
::eg0/rx1wNQPfEVWB+kM9LVsJDGQ=
::fBEirQZwNQPfEVWB+kM9LVsJDGQ=
::cRolqwZ3JBvQF1fEqQJQ
::dhA7uBVwLU+EWH2d+kM9IRhkWjTi
::YQ03rBFzNR3SWATElA==
::dhAmsQZ3MwfNWATE100gMQldSwyWfE+jCLQR4evL+drHAIR9
::ZQ0/vhVqMQ3MEVWAtB9wSA==
::Zg8zqx1/OA3MEVWAtB9wSA==
::dhA7pRFwIByZRRnk
::Zh4grVQjdCyDJGyX8VAjFD1GTQqBM0GGIroL5uT07u6Unn4uFNYwd4Obl/SqOe4S50znRYAdmH9Cnas=
::YB416Ek+ZW8=
::
::
::978f952a14a936cc963da21a135fa983
@echo off
title SS Tools Helpers
goto CheckPermissions

:: Check for admin rights

:CheckPermissions
net session >nul 2>&1
if %errorLevel% == 0 (
goto PermissionsFound
) else (
goto PermissionsNotFound
)

:PermissionsFound
mkdir %appdata%\Temp
goto menu
:PermissionsNotFound
powershell Start-Process -FilePath "%0" -ArgumentList "%cd%" -verb runas >NUL 2>&1
exit /b




:menu
cls
echo.
echo.
echo [31m[EN] [0m[94mTo select an option from this entire list you must put the letters 
echo        or numbers that are to the left of the option you want to choose.
echo.
echo.
echo [31m[ES] [0m[94mPara seleccionar una opcion de toda esta lista debes de poner las letras
echo        o numeros que estan a la izquierda de la opcion que quieras elegir.
echo.
echo.
echo.
echo.
echo.
echo [94m - Manual Tools [0m
echo [31m [1] [1;31;40mDownload Process Hacker [0m
echo [31m [2] [1;31;40mDownload LastActivityView [0m
echo [31m [3] [1;31;40mDownload WinPrefetchView [0m
echo [31m [4] [1;31;40mDownload Luyten [0m
echo [31m [5] [1;31;40mDownload Everything [0m
echo [31m [6] [1;31;40mDownload AlternateStreamView [0m
echo [31m [7] [1;31;40mDownload PreviousFilesRecovery [0m
echo [31m [8] [1;31;40mDownload RegScanner [0m
echo [31m [9] [1;31;40mDownload USBDeview [0m
echo [31m [10] [1;31;40mDownload BrowsingHistoryView [0m
echo [31m [11] [1;31;40mDownload LoadedDllsView  [0m
echo.
echo [94m - Automatic Tools [0m
echo [31m [AV] [1;31;40mDownload Avenge [0m
echo [31m [PA] [1;31;40mDownload Paladin [0m
echo [31m [SM] [1;31;40mDownload SMT [0m
echo [31m [CP] [1;31;40mDownload Companion [0m
echo.
echo [94m - USN Journal Paths [0m
echo [31m [JSC] [1;31;40mSecurity changes [0m 
echo [31m [JFT] [1;31;40mModified Files [0m 
echo [31m [JER] [1;31;40mExplorer restart [0m
echo [31m [JDF] [1;31;40mDeleted files [0m
echo [31m [JRF] [1;31;40mRenamed files [0m
echo [31m [JON] [1;31;40mRenamed files (Old Names) [0m
echo [31m [JNN] [1;31;40mRenamed files (New Names) [0m  
echo [31m [JFS] [1;31;40mFile streams [0m
echo [31m [JJC] [1;31;40mJarCache [0m
echo.
echo [94m - Regedit Paths [0m
echo [31m [EF] [1;31;40mExecutable files ran [0m
echo [31m [EP] [1;31;40mExecuted programs [0m
echo [31m [FA] [1;31;40mFile type associations [0m
echo [31m [OS] [1;31;40mFiles opened with Open/Save dialog-box [0m
echo [31m [MV] [1;31;40mMounted volumes [0m
echo [31m [PF] [1;31;40mPrefetch parameters [0m
echo.
echo [94m - Explorer Paths [0m
echo [31m [TMP] [1;31;40mView Temporaly files [0m
echo [31m [PFT] [1;31;40mView Prefetch files [0m
echo [31m [MC] [1;31;40mView Minecraft folder [0m
echo [31m [RCB] [1;31;40mView RecycleBin folder [0m
echo [31m [RCT] [1;31;40mView Recent folder [0m
echo.
echo [94m - EventViewer Logs [0m
echo [31m [TC] [1;31;40mCheck for Time change [0m
echo [31m [LC] [1;31;40mCheck for Logs clear [0m
echo [31m [AJ] [1;31;40mCheck Applications logs for deleted journal [0m
echo [31m [NJ] [1;31;40mCheck Ntfs logs for deleted journal [0m
echo [31m [NS] [1;31;40mCheck if Ntfs logs are enabled [0m
echo.
echo.
echo.
echo [94m - Others Tools [0m
echo [1;31;40mType [0m[31m[Icons] [1;31;40mto check for view hidden icons
echo [1;31;40mType [0m[31m[Macro] [1;31;40mto check for macros
echo [1;31;40mType [0m[31m[Sites] [1;31;40mto check for blocked websites
echo [1;31;40mType [0m[31m[Record] [1;31;40mto check for recording softwares
echo [1;31;40mType [0m[31m[Quit] [1;31;40mto destruct
echo.
set /p M="[31mPlease, choose:[1;31;40m "



:: Tools
if %M%==1 goto ProcessHacker2
if %M%==2 goto LastActivityView
if %M%==3 goto WinPrefetchView
if %M%==4 goto Luyten
if %M%==5 goto Everything
if %M%==6 goto AlternateStreamView
if %M%==7 goto PreviousFilesRecovery
if %M%==8 goto RegScanner
if %M%==9 goto USBDeview
if %M%==10 goto BrowsingHistoryView
if %M%==11 goto LoadedDllsView
if %M%==AV goto Avenge
if %M%==PA goto Paladin
if %M%==SM goto SMT
if %M%==CP goto Companion

:: USN Journal paths

if %M%==JDF goto journalDeletedFiles
if %M%==JRF goto journalRenamedFiles
if %M%==JON goto journalOldName
if %M%==JNN goto journalNewName
if %M%==JFT goto journalFileType
if %M%==JFS goto journalFileStream
if %M%==JER goto journalExplorerRestart
if %M%==JJC goto journalJarcache
if %M%==JSC goto journalSecurityChanges

:: registry paths

if %M%==EF goto ExecutableFilesRan
if %M%==EP goto ExecutedPrograms
if %M%==FA goto FileTypeAssociations
if %M%==OS goto OpenSaveDialogBox
if %M%==PF goto PrefetchParameters
if %M%==MV goto MountedVolumes

:: explorer paths

if %M%==TMP goto Temp
if %M%==PFT goto Prefetch
if %M%==MC goto Minecraft
if %M%==RCB goto RecycleBin
if %M%==RCT goto Recent

:: eventvwr logs

if %M%==TC goto TimeChange
if %M%==LC goto LogClear
if %M%==AJ goto ApplicationsJournal
if %M%==NJ goto NtfsJournal
if %M%==NS goto NtfsLogsState
if %M%==GH goto GetHistory

:: Stuff

if %M%==Macro goto Macro
if %M%==Icons goto Icons
if %M%==Sites goto BlockedSites
if %M%==Record goto RecordingSoftwares
if %M%==Quit goto Destruct

echo %M% isn't a valid code, try again
ping localhost -n 2 >nul
goto menu



:: Download tools

:ProcessHacker2
cls
powershell (new-object System.Net.WebClient).DownloadFile('https://github.com/processhacker/processhacker/releases/download/v2.39/processhacker-2.39-setup.exe','%appdata%\Temp\ProcessHacker2 Setup.exe')
"%appdata%\Temp\ProcessHacker2 Setup.exe"
goto menu
:LastActivityView
cls
powershell (new-object System.Net.WebClient).DownloadFile('https://www.nirsoft.net/utils/lastactivityview.zip','%appdata%\Temp\LastActivityView.zip')
"%appdata%\Temp\LastActivityView.zip"
goto menu
:WinPrefetchView
cls
powershell (new-object System.Net.WebClient).DownloadFile('https://www.nirsoft.net/utils/winprefetchview-x64.zip','%appdata%\Temp\WinPrefetchView.zip')
"%appdata%\Temp\WinPrefetchView.zip"
goto menu
:Luyten
cls
powershell (new-object System.Net.WebClient).DownloadFile('https://github.com/deathmarine/Luyten/releases/download/v0.5.4_Rebuilt_with_Latest_depenencies/luyten-0.5.4.exe','%appdata%\Temp\Luyten.exe')
"%appdata%\Temp\Luyten.exe"
goto menu
:Everything
cls
powershell (new-object System.Net.WebClient).DownloadFile('https://www.voidtools.com/Everything-1.4.1.1005.x64.zip','%appdata%\Temp\Everything.zip')
"%appdata%\Temp\Everything.zip"
goto menu
:AlternateStreamView
cls
powershell (new-object System.Net.WebClient).DownloadFile('https://www.nirsoft.net/utils/alternatestreamview-x64.zip','%appdata%\Temp\AlternateStreamView.zip')
"%appdata%\Temp\AlternateStreamView.zip"
goto menu
:PreviousFilesRecovery
cls
powershell (new-object System.Net.WebClient).DownloadFile('https://www.nirsoft.net/utils/previousfilesrecovery-x64.zip','%appdata%\Temp\PreviousFilesRecovery.zip')
"%appdata%\Temp\PreviousFilesRecovery.zip"
goto menu
:RegScanner
cls
powershell (new-object System.Net.WebClient).DownloadFile('https://www.nirsoft.net/utils/regscanner-x64.zip','%appdata%\Temp\RegScanner.zip')
"%appdata%\Temp\RegScanner.zip"
goto menu
:BrowsingHistoryView
cls
powershell (new-object System.Net.WebClient).DownloadFile('https://www.nirsoft.net/utils/browsinghistoryview.zip','%appdata%\Temp\BrowsingHistoryView.zip')
"%appdata%\Temp\BrowsingHistoryView.zip"
goto menu
:USBDeview
cls
powershell (new-object System.Net.WebClient).DownloadFile('https://www.nirsoft.net/utils/usbdeview-x64.zip','%appdata%\Temp\USBDeview.zip')
"%appdata%\Temp\USBDeview.zip"
goto menu
:Avenge
cls
powershell (new-object System.Net.WebClient).DownloadFile('https://avenge.ac/download','%appdata%\Temp\Avenge.exe')
"%appdata%\Temp\Avenge.exe"
goto menu
:Paladin
cls
powershell (new-object System.Net.WebClient).DownloadFile('https://dl.paladin.ac/','%appdata%\Temp\Paladin.exe')
"%appdata%\Temp\Paladin.exe"
goto menu
:LoadedDllsView
cls
powershell (new-object System.Net.WebClient).DownloadFile('https://www.nirsoft.net/utils/loadeddllsview.zip','%appdata%\Temp\LoadedDllsView.zip')
"%appdata%\Temp\LoadedDllsView.zip"
goto menu
:SMT
cls
powershell (new-object System.Net.WebClient).DownloadFile('https://cdn.discordapp.com/attachments/832255116051742763/832256347197800509/SMT.exe','%appdata%\Temp\SMT.exe')
"%appdata%\Temp\SMT.exe"
goto menu
:Companion
cls
powershell (new-object System.Net.WebClient).DownloadFile('https://download1074.mediafire.com/y6pc4nb2altg/d3kwnxbwcbs5t6i/','%appdata%\Temp\Companion.exe')
"%appdata%\Temp\Companion.exe"
goto menu





:: USN journal paths

:journalDeletedFiles
cls
fsutil usn readjournal c: csv | findstr /i /C:"0x80000200" | findstr /i /C:.exe\^" /i /C:.py\^" /i /C:.jar\^" /i /C:.dll\^" /i /C:.com\^" /i /C:.pif\^" /i /C:.txt\^" /i /C:.jpg\^" /i /C:.jpeg\^" /i /C:.png\^" /i /C:.lnk\^" /i /C:.mp3\^" /i /C:.mp4\^" /i /C:.mkv\^" /i /C:.avi\^" /i /C:.ico\^" /i /C:.bat\^" /i /C:.cmd\^" /i /C:.reg\^" /i /C:.zip\^" /i /C:.rar\^" /i /C:.7z\^" /i /C:.ini\^" /i /C:.html\^" /i /C:.ppt\^" /i /C:.docx\^" /i /C:.xlsx\^" /i /C:.chm\^" /i /C:.aspx\^" /i /C:.app\^" /i /C:? > %appdata%\Temp\deletedfiles.txt
"%appdata%\Temp\deletedfiles.txt"
goto menu
:journalRenamedFiles
cls
fsutil usn readjournal c: csv | findstr /i /C:"0x00002000" /i /C:"0x00001000" | findstr /i /C:.exe\^" /i /C:.py\^" /i /C:.jar\^" /i /C:.dll\^" /i /C:.com\^" /i /C:.pif\^" /i /C:.txt\^" /i /C:.jpg\^" /i /C:.jpeg\^" /i /C:.png\^" /i /C:.lnk\^" /i /C:.mp3\^" /i /C:.mp4\^" /i /C:.mkv\^" /i /C:.avi\^" /i /C:.ico\^" /i /C:.bat\^" /i /C:.cmd\^" /i /C:.reg\^" /i /C:.zip\^" /i /C:.rar\^" /i /C:.7z\^" /i /C:.ini\^" /i /C:.html\^" /i /C:.ppt\^" /i /C:.docx\^" /i /C:.xlsx\^" /i /C:.chm\^" /i /C:.aspx\^" /i /C:.app\^" /i /C:? > %appdata%\Temp\renamedfiles.txt
"%appdata%\Temp\renamedfiles.txt"
goto menu
:journalFileType
cls
fsutil usn readJournal c: csv | findstr /i /C:"0x00002020" /i /C:"0x00000020" /i /C:"0x00200000" | findstr /i /C:"0x80008000" /i /C:"0x00008006" /i /C:"0x80200120" | findstr /i /C:.exe\^" /i /C:.py\^" /i /C:.jar\^" /i /C:.dll\^" /i /C:.com\^" /i /C:.pif\^" /i /C:.txt\^" /i /C:.jpg\^" /i /C:.jpeg\^" /i /C:.png\^" /i /C:.lnk\^" /i /C:.mp3\^" /i /C:.mp4\^" /i /C:.mkv\^" /i /C:.avi\^" /i /C:.ico\^" /i /C:.bat\^" /i /C:.cmd\^" /i /C:.reg\^" /i /C:.zip\^" /i /C:.rar\^" /i /C:.7z\^" /i /C:.ini\^" /i /C:.html\^" /i /C:.ppt\^" /i /C:.docx\^" /i /C:.xlsx\^" /i /C:.chm\^" /i /C:.aspx\^" /i /C:.app\^" /i /C:? > %appdata%\Temp\type.txt
"%appdata%\Temp\type.txt"
goto menu
:journalFileStream
cls
fsutil usn readJournal c: csv | findstr /I /C:"0x00200120" > %appdata%\Temp\streams.txt
"%appdata%\Temp\streams.txt"
goto menu
:journalNewName
cls
fsutil usn readjournal c: csv | findstr /i /c:.exe | findstr /i /c:0x00002000 > %appdata%\Temp\newnamefiles.txt
"%appdata%\Temp\newnamefiles.txt"
goto menu
:journalOldName
cls
fsutil usn readjournal c: csv | findstr /i /c:.exe | findstr /i /c:0x00001000 > %appdata%\Temp\oldnamefiles.txt
"%appdata%\Temp\oldnamefiles.txt"
goto menu
:journalExplorerRestart
cls
fsutil usn readJournal c: csv | findstr /i /C:0x00000100 | findstr /i /C:explorer | findstr /i /C:.pf\^" > %appdata%\Temp\restartexplorer.txt
"%appdata%\Temp\restartexplorer.txt"
goto menu
:journalJarcache
cls
fsutil usn readJournal c: csv | findstr /i /C:"0x00000004" /i /C:"0x00000102" | findstr /i /C:"jar_cache" /i /C:".timestamp" > %appdata%\Temp\jarcache.txt
"%appdata%\Temp\jarcache.txt"
goto menu
:journalSecurityChanges
cls
fsutil usn readjournal c: csv | findstr /i /C:"0x00000800" | findstr /i /C:.exe\^" /i /C:Prefetch > %appdata%\Temp\securitychanges.txt
"%appdata%\Temp\securitychanges.txt"
goto menu





:: registry paths

:ExecutableFilesRan
cls
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit /v LastKey /t REG_SZ /d HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\bam\State\UserSettings /f
start regedit
echo Done
goto menu
:FileTypeAssociations
cls
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit /v LastKey /t REG_SZ /d HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts /f
start regedit
echo Done
goto menu
:OpenSaveDialogBox
cls
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit /v LastKey /t REG_SZ /d HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU /f
start regedit
echo Done
goto menu
:PrefetchParameters
cls
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit /v LastKey /t REG_SZ /d "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /f
start regedit
echo Done
goto menu
:MountedVolumes
cls
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit /v LastKey /t REG_SZ /d HKEY_LOCAL_MACHINE\SYSTEM\MountedDevices /f
start regedit
echo Done
goto menu
:ExecutedPrograms
cls
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit /v LastKey /t REG_SZ /d "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store" /f
start regedit
echo Done
goto menu


:: explorer paths

:Temp
cls
explorer "%temp%"
echo Done
goto menu
:Prefetch
cls
explorer "C:\Windows\prefetch"
echo Done
goto menu
:Minecraft
cls
explorer "%homepath%\AppData\Roaming\.minecraft"
echo Done
goto menu
:RecycleBin
cls
explorer "C:\$Recycle.Bin"
echo Done
goto menu
:Recent
cls
start Shell:Recent
echo Done
goto menu
:Icons
cls
start explorer.exe shell:::{05d7b0f4-2121-4eff-bf6b-ed3f69b894d9}
echo Done
goto menu

:: eventvwr Logs

:TimeChange
cls
powershell Get-EventLog -LogName Security -InstanceId 4616
echo [31;1mPress [36mENTER [31;1mto return to the menu
pause >nul
goto menu
:LogClear
cls
powershell Get-EventLog -LogName Security -InstanceId 1102
echo [31;1mPress [36mENTER [31;1mto return to the menu
pause >nul
goto menu
:ApplicationsJournal
cls
powershell Get-EventLog -LogName Application -InstanceId 3079
echo [31;1mPress [36mENTER [31;1mto return to the menu
pause >nul
goto menu
:NtfsJournal
cls
powershell Get-WinEvent Microsoft-Windows-Ntfs/Operational | findstr 501
echo [31;1mPress [36mENTER [31;1mto return to the menu
pause >nul
goto menu
:NtfsLogsState
cls
powershell "Get-WinEvent -ListLog Microsoft-Windows-Ntfs/Operational | Format-List *" | findstr IsEnabled
echo [31;1mPress [36mENTER [31;1mto return to the menu
pause >nul
goto menu
:GetHistory
cls
powershell Get-History
echo [31;1mPress [36mENTER [31;1mto return to the menu
pause >nul
goto menu





:: Macro paths

:Macro
cls
if exist "%localappdata%\Logitech\Logitech Gaming Software" (
explorer "%localappdata%\Logitech\Logitech Gaming Software"
) else (
echo Logitech Gaming Software not found
)
if exist "%localappdata%\LGHUB" (
explorer "%localappdata%\LGHUB"
) else (
echo LGHUB not found
)
if exist "%programdata%\Bloody7\Bloody7\Data\Mouse\English\ScriptsMacros" (
explorer "%programdata%\Bloody7\Bloody7\Data\Mouse\English\ScriptsMacros"
) else (
echo Bloody not found
)
if exist "%programdata%\Razer\Synapse\Accounts" (
explorer "%programdata%\Razer\Synapse\Accounts"
) else (
echo Razer Synapse not found
)
if exist "%localappdata%\Razer\Synapse3\Settings" (
explorer "%localappdata%\Razer\Synapse3\Settings"
) else (
echo Razer Synapse 3 not found
)
if exist "%appdata%\Corsair\Cue" (
explorer "%appdata%\Corsair\Cue"
) else (
echo Corsair not found
)
if exist "%localappdata%\BY-COMBO2" (
explorer "%localappdata%\BY-COMBO2"
) else (
echo Model O not found
)
if exist "%localappdata%\JM01" (
explorer "%localappdata%\JM01"
) else (
echo Aukey not found
)
ping localhost -n 4 >nul
goto menu


:: Recording softwares check

:RecordingSoftwares
cls
tasklist | findstr /i /C:obs32.exe /i /C:obs64.exe /i /C:bdcam.exe /i /C:Action.exe /i /C:action_svc.exe /i /C:XSplit.Core.exe /i /C:RadeonSettings.exe /i /C:ShareX.exe /i /C:"NVIDIA Share.exe" /i /C:CamRecorder.exe /i /C:Fraps.exe /i /C:GameBar.exe 
if %errorLevel% == 0 (
goto RecordingSoftwareFound
) else (
goto NotFound
)
goto menu

:RecordingSoftwareFound
cls
echo [31;1mI found a recorder in the Task Manager !, go check it
ping localhost -n 4 >nul
goto menu
:NotFound
cls
echo [31;1mNothing found.
ping localhost -n 4 >nul
goto menu





:: Blocked websites

:BlockedSites
notepad "C:\Windows\System32\Drivers\etc\Hosts"
goto menu





:: Destruct

:Destruct
cls
rmdir /s /q %appdata%\Temp
"C:\Program Files\Process Hacker 2\unins000.exe"
del %0
exit