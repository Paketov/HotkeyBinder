if "%1" == "" (
 call "%~dp0__sudo.bat" "%~f0" 1
 goto batExit
) 

set HotKeyConfFile=%~dp0HotkeyConfig.txt
rundll32 %systemroot%\system32\HotKeyService.dll SetSettings


:batExit


