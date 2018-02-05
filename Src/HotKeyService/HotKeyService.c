/*
* HotkeyBinder
* Solodov A. N. (hotSAN)
* 2018
* Loads itself into the address space explorer.exe
* Recive hotkey window msg and generate press key
*/

#include <windows.h>
#include <stdarg.h>

#include <winbase.h>
#include <winreg.h>
#include <winsvc.h>
#include <stdint.h>
#include <dbt.h>
#include <ntstatus.h>
#include <Winternl.h>
#include <TlHelp32.h>


typedef struct HOT_KEYS {
	WORD		HotKeys[4];
	UWORD		Count;
} HOT_KEYS;

typedef struct HOT_KEY_INFO {
	HOT_KEYS    Shortcut;

	UWORD		CountEmulKeys; /* Count keys */
	HOT_KEYS	EmulKeys[10];

	ATOM		Atom;

	BOOL		Registred;
} HOT_KEY_INFO;


#define HOTKEYBINDER_REG_CONF L"Software\\HotkeyBinder"
#define HOTKEYBINDER_REG_CONF_ROOT_KEY HKEY_LOCAL_MACHINE

//static WCHAR ServiceName[] = L"HotKeyBinder";
//static SERVICE_STATUS_HANDLE ServiceStatusHandle;
//static SERVICE_STATUS ServiceStatus;

static HOT_KEY_INFO* HotKeys = NULL;
static uint32_t CountHotKeys = 0;
//static DWORD Error = ERROR_SUCCESS;
static DWORD ThreadId = 0;
static HMODULE hDll = NULL;
static HANDLE hThread = NULL;
//static BOOL IsHasTryGetObject = FALSE;

#define WM_TERMINATE_THREAD (WM_USER+2)
static DWORD WINAPI ServiceWorkerThread(LPVOID lpParam);
#define CpyConstString(DestStrBuf, ConstStr)  (memcpy(Dest, L ## ConstStr, sizeof( L ## ConstStr )), (sizeof( L ## ConstStr )/ sizeof(WCHAR) - 1))


static void* __memset(void* _Dst, int _Val, UINT _Size) {
	BYTE *buf = (BYTE *)_Dst, *m = buf + _Size;
	while(buf < m)
		*buf++ = (BYTE)_Val;
	return _Dst;
}

static int VirtualKeyCodeToString(LPWSTR Dest, size_t DestSize, UCHAR virtualKey) {
	UINT scanCode;
	switch(virtualKey) {
		case VK_APPS: return CpyConstString(Dest, "Apps");
		case VK_LWIN: return CpyConstString(Dest, "Left Win");
		case VK_RWIN: return CpyConstString(Dest, "Right Win");
		case VK_LMENU: return CpyConstString(Dest, "Left Alt");
		case VK_RMENU: return CpyConstString(Dest, "Right Alt");
		case VK_RCONTROL: return CpyConstString(Dest, "Right Ctrl");
		case VK_LCONTROL: return CpyConstString(Dest, "Left Ctrl");
		case VK_CLEAR: return CpyConstString(Dest, "Clear");

		case VK_BROWSER_BACK: return CpyConstString(Dest, "Browser Back");
		case VK_BROWSER_FORWARD: return CpyConstString(Dest, "Browser Forward");
		case VK_BROWSER_REFRESH: return CpyConstString(Dest, "Browser Refresh");
		case VK_BROWSER_STOP: return CpyConstString(Dest, "Browser Stop");
		case VK_BROWSER_SEARCH: return CpyConstString(Dest, "Browser Search");
		case VK_BROWSER_FAVORITES: return CpyConstString(Dest, "Browser Favorites");
		case VK_BROWSER_HOME: return CpyConstString(Dest, "Browser Home");

		case VK_VOLUME_UP: return CpyConstString(Dest, "Volume Up");
		case VK_VOLUME_DOWN: return CpyConstString(Dest, "Volume Down");
		case VK_VOLUME_MUTE: return CpyConstString(Dest, "Volume Mute");
		case VK_MEDIA_NEXT_TRACK: return CpyConstString(Dest, "Next Track");
		case VK_MEDIA_PREV_TRACK: return CpyConstString(Dest, "Previous Track");
		case VK_MEDIA_STOP: return CpyConstString(Dest, "Stop Media");
		case VK_MEDIA_PLAY_PAUSE: return CpyConstString(Dest, "Play/Pause Media");
		case VK_LAUNCH_MAIL: return CpyConstString(Dest, "Start Mail");
		case VK_LAUNCH_MEDIA_SELECT: return CpyConstString(Dest, "Select Media");
		case VK_LAUNCH_APP1: return CpyConstString(Dest, "Start Application 1");
		case VK_LAUNCH_APP2: return CpyConstString(Dest, "Start Application 2");
		case 0xC2: return 0;

		case VK_LEFT: case VK_UP: case VK_RIGHT: case VK_DOWN:
		case VK_PRIOR: case VK_NEXT:
		case VK_END: case VK_HOME:
		case VK_INSERT: case VK_DELETE:
		case VK_DIVIDE:
		case VK_NUMLOCK:
			scanCode = MapVirtualKeyW(virtualKey, MAPVK_VK_TO_VSC) | KF_EXTENDED;
			break;
		default:
			scanCode = MapVirtualKeyW(virtualKey, MAPVK_VK_TO_VSC);
	}
	return GetKeyNameTextW(scanCode << 16, Dest, DestSize);
}

static WORD ParseKey(LPWSTR KeyName, int KeyNameLength) {
	WCHAR Buf[128];
	int CountWrittenChar;
	int MaxCountWrittenChar = 0;
	WORD LastVk = 0;
	for(WORD i = 1; i <= 0xFE; i++) {
		if(
			((CountWrittenChar = VirtualKeyCodeToString(Buf, 127, i)) > 0) &&
			KeyNameLength == CountWrittenChar &&
			(CompareStringW(LOCALE_SYSTEM_DEFAULT, NORM_IGNORECASE, Buf, CountWrittenChar, KeyName, CountWrittenChar) == CSTR_EQUAL)
		) {
			return i;
		}
	}
	return 0;
}

static int GetStrKey(LPWSTR* StartPos) {
	LPWSTR c = *StartPos;
	for(; *c == L' ' || *c == L'\t'; c++);
	*StartPos = c;
	if(*c == L'+') {
		c++;
	} else {
		for(; !((*c == L'=' && c[1] == L'>') || *c == L'\0' || *c == L'\r' || *c == L'\n' || *c == L'+'); c++);
	}
	for(; (*StartPos <= (c - 1)) && (*(c - 1) == L' ' || *(c - 1) == L'\t'); c--);
	return c - *StartPos;
}

static int ParseHotKeys(WORD* TargetKeyArr, uint32_t MaxKeyCount, LPWSTR* StartPos) {
	uint32_t CurKeyCount = 0;
	LPWSTR c = *StartPos;
	WORD CurKey;
	int KeyLen;
	do {
		if(CurKeyCount >= MaxKeyCount) {
			//Error = ERROR_BUFFER_OVERFLOW;
			OutputDebugString(TEXT("HotKeyBinder: Hotkey limit overflow"));
			return -1;
		}
		if(*c == L'\0' || *c == L'\r' || *c == L'\n')
			return 0;
		if((KeyLen = GetStrKey(&c)) == 0) {
			//Error = ERROR_INVALID_DATA;
			OutputDebugString(TEXT("HotKeyBinder: Hotkey parse fail"));
			return -1;
		}
		if((CurKey = ParseKey(c, KeyLen)) == 0) {
			//Error = ERROR_INVALID_DATA;
			OutputDebugString(TEXT("HotKeyBinder: Hotkey parse fail"));
			return -1;
		}
		TargetKeyArr[CurKeyCount++] = CurKey;
		c += KeyLen;

		for(; *c == L' ' || *c == L'\t'; c++);
		if(*c == '+')
			c++;
		for(; *c == L' ' || *c == L'\t'; c++);
		if((*c == L'=') && (c[1] == L'>')) {
			c += 2;
			break;
		} else if(*c == L'\0' || *c == L'\r' || *c == L'\n') {
			break;
		}
	} while(TRUE);
	*StartPos = c;
	return CurKeyCount;
}

__declspec(dllexport) void WINAPI ServiceMain(/*DWORD argc, LPWSTR *argv*/) {
	HOT_KEY_INFO* HotKey;
	LPWSTR c;
	WORD CurKey;
	int CountKeys;
	DWORD ReadedSize;
	WCHAR* ConfigBuf;
	OutputDebugString(TEXT("HotKeyBinder: Start service"));
	//ServiceStatusHandle = RegisterServiceCtrlHandlerExW(ServiceName, ServiceControlHandlerEx, NULL);
	//if(!ServiceStatusHandle) {
	//	OutputDebugString(TEXT("HotKeyBinder: RegisterServiceCtrlHandlerExW() failed"));
	//	return;
	//}

	//UpdateServiceStatus(SERVICE_START_PENDING, 0, 0);

	ReadedSize = 0;
	if(
		RegGetValueW(
			HOTKEYBINDER_REG_CONF_ROOT_KEY,
			HOTKEYBINDER_REG_CONF,
			L"Config",
			RRF_RT_ANY,
			NULL,
			NULL,
			&ReadedSize
		) != ERROR_SUCCESS
	) {
		OutputDebugString(TEXT("HotKeyBinder: RegGetValueW(\"Config\") failed"));
		goto lblExit;
	}
	if((ConfigBuf = (WCHAR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ReadedSize)) == NULL) {
		//Error = GetLastError();
		OutputDebugString(TEXT("HotKeyBinder: HeapAlloc fail"));
		goto lblExit;
	}
	if(
		RegGetValueW(
			HOTKEYBINDER_REG_CONF_ROOT_KEY,
			HOTKEYBINDER_REG_CONF,
			L"Config",
			RRF_RT_ANY,
			NULL,
			ConfigBuf,
			&ReadedSize
		) != ERROR_SUCCESS
	) {
		OutputDebugString(TEXT("HotKeyBinder: RegGetValueW(\"Config\") failed"));
		goto lblExit;
	}
	c = ConfigBuf;
	CountHotKeys = 1;
	if((HotKeys = (HOT_KEY_INFO*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(HOT_KEY_INFO) * CountHotKeys)) == NULL) {
		//Error = GetLastError();
		OutputDebugString(TEXT("HotKeyBinder: HeapAlloc fail"));
		goto lblExit;
	}
	/* Parse keys */
	for(int i = 0; ; i++) {
		HotKey = &HotKeys[i];
		for(; *c == L'\r' || *c == L'\n'; c++);
		if((CountKeys = ParseHotKeys(HotKey->Shortcut.HotKeys, 4, &c)) < 0) {
			goto lblExit;
		} else if(CountKeys == 0) {
			//Error = ERROR_INVALID_DATA;
			OutputDebugString(TEXT("HotKeyBinder: Hotkey parse fail"));
			goto lblExit;
		}
		HotKey->Shortcut.Count = CountKeys;
		for(; ; ) {
			if(HotKey->CountEmulKeys >= 10) {
				//Error = ERROR_BUFFER_OVERFLOW;
				OutputDebugString(TEXT("HotKeyBinder: Emulate keys limit overflow"));
				goto lblExit;
			}
			if((CountKeys = ParseHotKeys(HotKey->EmulKeys[HotKey->CountEmulKeys].HotKeys, 4, &c)) < 0) {
				goto lblExit;
			} else if(CountKeys == 0 && HotKey->CountEmulKeys == 0) {
				//Error = ERROR_INVALID_DATA;
				OutputDebugString(TEXT("HotKeyBinder: Hotkey parse fail"));
				goto lblExit;
			} else if(CountKeys == 0) {
				break;
			}
			HotKey->EmulKeys[HotKey->CountEmulKeys++].Count = CountKeys;
		}
		CountHotKeys++;
		for(; *c == L'\r' || *c == L'\n' || *c == L' ' || *c == L'\t'; c++);
		if(*c == L'\0')
			break;
		if((HotKeys = (HOT_KEY_INFO*)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, HotKeys, sizeof(HOT_KEY_INFO) * CountHotKeys)) == NULL) {
			//Error = GetLastError();
			OutputDebugString(TEXT("HotKeyBinder: HeapAlloc fail"));
			goto lblExit;
		}
	}
	CountHotKeys--;
	hThread = CreateThread(NULL, 0, ServiceWorkerThread, NULL, 0, &ThreadId);
	if(hThread == NULL) {
		OutputDebugString(TEXT("HotkeyBinder: Cannot create thread"));
		goto lblExit;
	} else {
		OutputDebugString(TEXT("HotkeyBinder: Creating worker thread success"));
	}
	return;
lblExit:
	if(HotKeys != NULL)
		HeapFree(GetProcessHeap(), 0, HotKeys);
	if(ConfigBuf != NULL)
		HeapFree(GetProcessHeap(), 0, ConfigBuf);
	//UpdateServiceStatus(SERVICE_STOPPED, 0, 3);
	OutputDebugString(TEXT("HotKeyBinder: Exit from service"));
}


__declspec(dllexport) VOID WINAPI SetSettings() {
	WCHAR ConfPath[512];
	BY_HANDLE_FILE_INFORMATION info;
	HANDLE hFile;
	uint64_t FileSize;
	char* FileBuf;
	DWORD Readed = 0;
	WCHAR* WideFileBuf;
	int WideCharBufLen;
	HKEY Param = NULL;
	if(GetEnvironmentVariableW(L"HotKeyConfFile", ConfPath, 511) == 0) {
		OutputDebugString(TEXT("HotKeyBinder: GetEnvironmentVariableW() failed not have HotKeyConfFile enviroment var"));
		return;
	}
	hFile = CreateFileW(
		ConfPath, 
		GENERIC_READ, 
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 
		NULL,
		OPEN_EXISTING, 
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);
	if(hFile == INVALID_HANDLE_VALUE) {
		OutputDebugString(TEXT("HotKeyBinder: CreateFileW() failed open config file"));
		return;
	}
	GetFileInformationByHandle(hFile, &info);
	FileSize = ((uint64_t)info.nFileSizeHigh << 32) | info.nFileSizeLow;
	if(FileSize > 6000) {
		OutputDebugString(TEXT("HotKeyBinder: too big config file"));
		return;
	}
	if(FileSize == 0) {
		OutputDebugString(TEXT("HotKeyBinder: empty config file"));
		return;
	}
	FileBuf = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, FileSize + (sizeof(WCHAR) * 2));
	if(FileBuf == NULL) {
		OutputDebugString(TEXT("HotKeyBinder: HeapAlloc() failed"));
		return;
	}
	if(!ReadFile(hFile, FileBuf, FileSize, &Readed, NULL)) {
		OutputDebugString(TEXT("HotKeyBinder: ReadFile() failed"));
		return;
	}

	WideCharBufLen = MultiByteToWideChar(CP_UTF8, 0, FileBuf, -1, NULL, 0);
	WideCharBufLen++;
	WideCharBufLen *= sizeof(WCHAR);
	WideFileBuf = (WCHAR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, WideCharBufLen);
	if(WideFileBuf == NULL) {
		OutputDebugString(TEXT("HotKeyBinder: HeapAlloc() failed"));
		return;
	}
	MultiByteToWideChar(CP_UTF8, 0, FileBuf, -1, WideFileBuf, WideCharBufLen / sizeof(WCHAR));
	WideFileBuf[WideCharBufLen / sizeof(WCHAR) - 1] = L'\0';

	if(RegCreateKeyExW(HOTKEYBINDER_REG_CONF_ROOT_KEY, HOTKEYBINDER_REG_CONF, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &Param, NULL) != ERROR_SUCCESS) {
		OutputDebugString(TEXT("HotKeyBinder: RegOpenKeyExW() failed"));
		return;
	}
	if(RegSetValueExW(Param, L"Config", NULL, REG_BINARY, (BYTE*)WideFileBuf, WideCharBufLen) != ERROR_SUCCESS) {
		OutputDebugString(TEXT("HotKeyBinder: RegSetValueExW() failed"));
		return;
	}
	OutputDebugString(TEXT("HotKeyBinder: Success"));
}

static void EmulPressKeys(HOT_KEYS* HotKeys, BOOL EmulPress) {
	INPUT ip;
	ip.type = INPUT_KEYBOARD;
	ip.ki.wScan = 0; // hardware scan code for key
	ip.ki.time = 0;
	ip.ki.dwExtraInfo = 0;
	if(EmulPress) {
		for(int i = 0; i < HotKeys->Count; i++) {
			// Press the key
			ip.ki.wVk = HotKeys->HotKeys[i];
			ip.ki.dwFlags = 0; // 0 for key press
			SendInput(1, &ip, sizeof(INPUT));
		}
	}
	// Release the key
	for(int i = 0; i < HotKeys->Count; i++) {
		// Press the key
		ip.ki.wVk = HotKeys->HotKeys[i];
		ip.ki.dwFlags = KEYEVENTF_KEYUP;  // KEYEVENTF_KEYUP for key release
		SendInput(1, &ip, sizeof(INPUT));
	}
}

static DWORD WINAPI ServiceWorkerThread(LPVOID lpParam) {
	HOT_KEY_INFO* HotKey = NULL;
	UINT fsModifiers;
	UINT Vk;
	MSG msg = {0};
	//Error = ERROR_SUCCESS;

	for(int i = 0; i < CountHotKeys; i++) {
		HotKey = &HotKeys[i];
		fsModifiers = 0;
		Vk = 0;
		for(int i = 0; i < HotKey->Shortcut.Count; i++) {
			switch(HotKey->Shortcut.HotKeys[i]) {
				case VK_CONTROL: fsModifiers |= MOD_CONTROL; break;
				case VK_SHIFT: fsModifiers |= MOD_SHIFT; break;
				case VK_MENU: fsModifiers |= MOD_ALT; break;
				case VK_LWIN:
				case VK_RWIN: fsModifiers |= MOD_WIN; break;
				default:
					if(Vk != 0) {
						//Error = ERROR_BADKEY;
						OutputDebugString(TEXT("HotKeyBinder: So much keys"));
						goto lblExit;
					} else {
						Vk = HotKey->Shortcut.HotKeys[i];
						break;
					}
			}
		}
		if(Vk == 0) {
			//Error = ERROR_BADKEY;
			goto lblExit;
		}
		HotKey->Atom = GlobalAddAtom(MAKEINTATOM(1024 + i));
		if(!RegisterHotKey(NULL, HotKey->Atom, fsModifiers, Vk)) {
			OutputDebugString(TEXT("HotKeyBinder: RegisterHotKey() fail"));
			//Error = GetLastError();
			goto lblExit;
		}
		HotKey->Registred = TRUE;
	}

	//UpdateServiceStatus(SERVICE_RUNNING, SERVICE_STOPPED, 0);
	while(GetMessageW(&msg, NULL, 0, 0) != 0) {
		if(msg.message == WM_HOTKEY) {
			//int Key = HIWORD(msg.lParam);
			//int Modifier = LOWORD(msg.lParam);
			if(msg.wParam != IDHOT_SNAPDESKTOP && msg.wParam != IDHOT_SNAPWINDOW) {
				for(int i = 0; i < CountHotKeys; i++) {
					HotKey = &HotKeys[i];
					if(HotKey->Atom == msg.wParam) { /* found id hot key */
													 /* Emullate press keys */
						for(int i = 0; i < HotKey->CountEmulKeys; i++)
							EmulPressKeys(&HotKey->EmulKeys[i], TRUE);
					}
				}
			}
		} else if(msg.message == WM_TERMINATE_THREAD) { /* If need out of loop */
			break;
		}
	}
lblExit:
	if(HotKeys != NULL) {
		for(int i = 0; i < CountHotKeys; i++) {
			HotKey = &HotKeys[i];
			if(HotKey->Registred && HotKey->Atom != 0) {
				UnregisterHotKey(NULL, HotKey->Atom);
			}
			if(HotKey->Atom != 0) {
				GlobalDeleteAtom(HotKey->Atom);
			}
			HotKey->Registred = FALSE;
			HotKey->Atom = 0;
		}
	}

	return ERROR_SUCCESS;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
	WCHAR szFileName[MAX_PATH + 1];
	WCHAR PathToDll[512];
	DWORD CurPid;
	DWORD PathToDllLength;
	switch(fdwReason) {
		case DLL_PROCESS_ATTACH:
			OutputDebugString(TEXT("HotKeyBinder: Loaded"));
			hDll = hinstDLL;
			CurPid = GetProcessIdByProcessImageName(L"explorer.exe");
			if(CurPid == GetCurrentProcessId()) {
				OutputDebugString(TEXT("HotKeyBinder: Loaded in explorer.exe"));
				PathToDllLength = GetModuleFileNameW(hDll, PathToDll, sizeof(PathToDll));
				if(PathToDllLength == 0) {
					OutputDebugString(TEXT("HotKeyBinder: GetModuleFileNameW() failed"));
					return;
				}
				LoadLibraryW(PathToDll); /* increment count pointers on dll */
				ServiceMain();
			}
			DisableThreadLibraryCalls(hinstDLL);
			break;
		case DLL_PROCESS_DETACH:
			if(hThread != NULL) {
				PostThreadMessage(ThreadId, WM_TERMINATE_THREAD, 0, 0); /* Notify thread for Terminate */
				WaitForSingleObject(hThread, INFINITE);
				hThread = NULL;
			}
			OutputDebugString(TEXT("HotKeyBinder: Unloaded"));
			break;
	}
	return TRUE;
}

__declspec(dllexport) int NextHook(int code, WPARAM wParam, LPARAM lParam) {
	return CallNextHookEx(NULL, code, wParam, lParam);
}

static DWORD GetProcessIdByProcessImageName(WCHAR* wzProcessImageName) {
	HANDLE ProcessSnapshotHandle = NULL;
	PROCESSENTRY32 ProcessEntry32;
	DWORD TargetProcessId = 0;
	
	__memset(&ProcessEntry32, 0, sizeof(ProcessEntry32));
	ProcessEntry32.dwSize = sizeof(PROCESSENTRY32);
	ProcessSnapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if(ProcessSnapshotHandle == INVALID_HANDLE_VALUE) {
		return 0;
	}
	Process32FirstW(ProcessSnapshotHandle, &ProcessEntry32);
	do {
		if(lstrcmpiW(ProcessEntry32.szExeFile, wzProcessImageName) == 0)
		{
			TargetProcessId = ProcessEntry32.th32ProcessID;
			break;
		}
	} while(Process32NextW(ProcessSnapshotHandle, &ProcessEntry32));
	CloseHandle(ProcessSnapshotHandle);
	ProcessSnapshotHandle = NULL;
	return TargetProcessId;
}


__declspec(dllexport) void LdDll() {
	HANDLE ThreadSnapshotHandle = NULL;
	THREADENTRY32 ThreadEntry32;
	HHOOK hHook = NULL;
	BOOL unhookSuc;
	DWORD tId;
	DWORD ProcId;

	__memset(&ThreadEntry32, 0, sizeof(ThreadEntry32));
	ProcId = GetProcessIdByProcessImageName(L"explorer.exe");
	if(ProcId == 0) {
		OutputDebugString(TEXT("HotKeyBinder: find explorer.exe fail"));
		return;
	}
	ThreadEntry32.dwSize = sizeof(THREADENTRY32);
	ThreadSnapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if(ThreadSnapshotHandle == INVALID_HANDLE_VALUE) {
		OutputDebugString(TEXT("HotKeyBinder: find CreateToolhelp32Snapshot() fail"));
		return;
	}
	Thread32First(ThreadSnapshotHandle, &ThreadEntry32);
	do {
		if(ThreadEntry32.th32OwnerProcessID == ProcId) {
			hHook = SetWindowsHookExW(WH_GETMESSAGE, (HOOKPROC)NextHook, hDll, ThreadEntry32.th32ThreadID); // Or WH_KEYBOARD if you prefer to trigger the hook manually
			if(hHook != NULL) {
				tId = ThreadEntry32.th32ThreadID;
				break;
			}
		}
	} while(Thread32Next(ThreadSnapshotHandle, &ThreadEntry32));

	CloseHandle(ThreadSnapshotHandle);
	ThreadSnapshotHandle = NULL;
	if(hHook != NULL) {
		if(!PostThreadMessageW(tId, WM_NULL, NULL, NULL)) {
			OutputDebugString(TEXT("HotKeyBinder: PostThreadMessageW() fail"));
			return;
		}
		Sleep(200);
		if(!UnhookWindowsHookEx(hHook)) {
			OutputDebugString(TEXT("HotKeyBinder: UnhookWindowsHookEx() fail"));
			return;
		}
		OutputDebugString(TEXT("HotKeyBinder: Hook success"));
	} else {
		OutputDebugString(TEXT("HotKeyBinder: SetWindowsHookExW() fail"));
	}
}
