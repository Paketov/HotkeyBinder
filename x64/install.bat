copy /Y %~dp0HotKeyService.dll %systemroot%\system32\HotKeyService.dll
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /f /v HotkeyBinder /t REG_SZ /d "rundll32 %systemroot%\system32\HotKeyService.dll LdDll"


