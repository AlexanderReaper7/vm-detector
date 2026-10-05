#include "pch.h"
#include "instrumentation.h"

/*
Frida's injected agent listens on TCP 27042 by default (27043 for the extra
control channel). A successful loopback connect to that port is a strong signal
that a frida-server or gadget is live in the environment. The socket is opened
non-blocking-ish with a short timeout so a closed port fails fast.
*/
BOOL frida_default_port()
{
	const u_short szPorts[] = { 27042, 27043 };

	WSADATA wsa;
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
		return FALSE;

	BOOL found = FALSE;
	for (int i = 0; i < _countof(szPorts) && !found; i++) {
		SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (s == INVALID_SOCKET)
			continue;

		/* Short send/recv timeouts so a RST/closed port returns quickly. */
		DWORD timeout = 300;
		setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
		setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));

		sockaddr_in addr;
		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_port = htons(szPorts[i]);
		InetPton(AF_INET, _T("127.0.0.1"), &addr.sin_addr);

		if (connect(s, (sockaddr*)&addr, sizeof(addr)) == 0)
			found = TRUE;

		closesocket(s);
	}

	WSACleanup();
	return found;
}


/*
frida-gum spins up worker threads with fixed names ("gum-js-loop", "gmain",
"gdbus", "pool-frida"). Enumerate this process's threads and read each thread
description via GetThreadDescription (Win10 1607+, resolved dynamically). A
match means a gum runtime is loaded in-process.
*/
BOOL frida_thread_names()
{
	typedef HRESULT(WINAPI* pGetThreadDescription)(HANDLE, PWSTR*);
	HMODULE hKernel = GetModuleHandle(_T("kernel32.dll"));
	if (hKernel == NULL)
		return FALSE;

	auto GetThreadDescription =
		(pGetThreadDescription)GetProcAddress(hKernel, "GetThreadDescription");
	if (GetThreadDescription == NULL)
		return FALSE; /* pre-1607; cannot query thread names this way */

	const WCHAR* szBad[] = {
		L"gum-js-loop", L"gmain", L"gdbus", L"pool-frida", L"frida",
	};

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hSnap == INVALID_HANDLE_VALUE)
		return FALSE;

	DWORD ownPid = GetCurrentProcessId();
	THREADENTRY32 te;
	te.dwSize = sizeof(te);
	BOOL found = FALSE;

	if (Thread32First(hSnap, &te)) {
		do {
			if (te.th32OwnerProcessID != ownPid)
				continue;

			HANDLE hThread =
				OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, te.th32ThreadID);
			if (hThread == NULL)
				continue;

			PWSTR desc = NULL;
			if (SUCCEEDED(GetThreadDescription(hThread, &desc)) && desc != NULL) {
				for (int j = 0; j < _countof(szBad); j++) {
					if (wcsstr(desc, szBad[j]) != NULL) {
						found = TRUE;
						break;
					}
				}
				LocalFree(desc);
			}
			CloseHandle(hThread);
		} while (!found && Thread32Next(hSnap, &te));
	}

	CloseHandle(hSnap);
	return found;
}


/*
Walk the loaded modules of this process and match frida's agent module name.
On Windows the injected agent maps as frida-agent.dll / frida-gadget.dll (and
older builds as frida-agent-*.dll). A module whose base name contains "frida"
is the agent itself.
*/
BOOL frida_loaded_modules()
{
	HMODULE hMods[1024];
	DWORD cbNeeded = 0;
	HANDLE hProc = GetCurrentProcess();

	if (!EnumProcessModules(hProc, hMods, sizeof(hMods), &cbNeeded))
		return FALSE;

	DWORD count = cbNeeded / sizeof(HMODULE);
	for (DWORD i = 0; i < count; i++) {
		TCHAR szName[MAX_PATH];
		if (GetModuleBaseName(hProc, hMods[i], szName, _countof(szName))) {
			for (TCHAR* p = szName; *p; ++p)
				*p = (TCHAR)_totlower(*p);
			if (_tcsstr(szName, _T("frida")) != NULL)
				return TRUE;
		}
	}

	return FALSE;
}


/*
Detect Intel Pin and DynamoRIO by their on-host artifacts: the driver/runtime
modules they map into the target (pinvm.dll, pintool, dynamorio.dll, drsyms,
drlib), the launcher processes (pin.exe, drrun.exe, drinject.exe), and the
DynamoRIO environment variables. Any one is enough.
*/
BOOL dbi_tool_artifacts()
{
	/* Mapped modules in this process. */
	const TCHAR* szBadModules[] = {
		_T("pinvm"), _T("pintool"), _T("pin3dwarf"),
		_T("dynamorio"), _T("drsyms"), _T("drlib"), _T("dr_"),
	};

	HMODULE hMods[1024];
	DWORD cbNeeded = 0;
	HANDLE hProc = GetCurrentProcess();
	if (EnumProcessModules(hProc, hMods, sizeof(hMods), &cbNeeded)) {
		DWORD count = cbNeeded / sizeof(HMODULE);
		for (DWORD i = 0; i < count; i++) {
			TCHAR szName[MAX_PATH];
			if (GetModuleBaseName(hProc, hMods[i], szName, _countof(szName))) {
				for (TCHAR* p = szName; *p; ++p)
					*p = (TCHAR)_totlower(*p);
				for (int j = 0; j < _countof(szBadModules); j++) {
					if (_tcsstr(szName, szBadModules[j]) != NULL)
						return TRUE;
				}
			}
		}
	}

	/* Launcher processes anywhere on the system. */
	const TCHAR* szBadProcs[] = {
		_T("pin.exe"), _T("drrun.exe"), _T("drinject.exe"), _T("drconfig.exe"),
	};
	for (int j = 0; j < _countof(szBadProcs); j++) {
		if (GetProcessIdFromName(szBadProcs[j]))
			return TRUE;
	}

	/* DynamoRIO environment. */
	const TCHAR* szBadEnv[] = {
		_T("DYNAMORIO_OPTIONS"), _T("DYNAMORIO_HOME"), _T("DYNAMORIO_LOGDIR"),
	};
	for (int j = 0; j < _countof(szBadEnv); j++) {
		if (GetEnvironmentVariable(szBadEnv[j], NULL, 0) != 0)
			return TRUE;
	}

	return FALSE;
}


/*
Count ntdll syscall stubs whose prologue no longer looks like a clean x64 stub.
An untouched x64 Nt* stub begins with 4C 8B D1 B8 (mov r10,rcx; mov eax,ssn).
A DBI engine (Pin, DynamoRIO, frida-gum) relocates execution into a code cache
and rewrites these prologues, so several will start with a jump (E9/FF25) or an
int3. One rewritten stub can be an ordinary EDR hook; a handful at once is the
signature of a whole-process instrumentation engine. x64 only: the x86 stub
layout differs across Windows versions, so this returns FALSE on x86.
*/
BOOL dbi_ntdll_prologue_tampering()
{
#ifdef _WIN64
	const char* szStubs[] = {
		"NtClose", "NtCreateFile", "NtOpenFile", "NtReadFile", "NtWriteFile",
		"NtCreateThreadEx", "NtQuerySystemInformation", "NtQueryInformationProcess",
		"NtProtectVirtualMemory", "NtAllocateVirtualMemory", "NtFreeVirtualMemory",
		"NtMapViewOfSection", "NtOpenProcess", "NtResumeThread", "NtSetInformationThread",
		"NtQueryVirtualMemory", "NtDeviceIoControlFile", "NtWaitForSingleObject",
		"NtDelayExecution", "NtCreateSection",
	};

	HMODULE hNtdll = GetModuleHandle(_T("ntdll.dll"));	if (hNtdll == NULL)
		return FALSE;

	int tampered = 0;
	for (int i = 0; i < _countof(szStubs); i++) {
		BYTE* fn = (BYTE*)GetProcAddress(hNtdll, szStubs[i]);
		if (fn == NULL)
			continue;

		/* Clean stub: 4C 8B D1 B8 (mov r10,rcx; mov eax,imm32). */
		BOOL clean = (fn[0] == 0x4C && fn[1] == 0x8B && fn[2] == 0xD1 && fn[3] == 0xB8);
		if (!clean)
			tampered++;
	}

	/* One hooked stub is a plausible EDR userland hook; several at once is a
	   whole-process instrumentation engine rewriting the syscall layer. */
	return tampered >= 3 ? TRUE : FALSE;
#else
	return FALSE;
#endif
}
