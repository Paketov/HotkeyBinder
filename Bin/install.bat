if "%1" == "" (
 call "%~dp0__sudo.bat" "%~f0" 1
 goto batExit
)

IF EXIST "%PROGRAMFILES(X86)%" (set target_dll_name="%~dp0HotKeyService64.dll") ELSE (set target_dll_name="%~dp0HotKeyService32.dll")
copy /Y %target_dll_name% "%systemroot%\system32\HotKeyService.dll"
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /f /v HotkeyBinder /t REG_SZ /d "rundll32 %systemroot%\system32\HotKeyService.dll LdDll"




:batExit