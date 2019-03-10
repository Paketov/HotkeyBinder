if "%1" == "" (
 call "%~dp0__sudo.bat" "%~f0" 1
 goto batExit
) 

del /F /Q %systemroot%\system32\HotKeyService.dll
reg delete HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /f /v HotkeyBinder




:batExit