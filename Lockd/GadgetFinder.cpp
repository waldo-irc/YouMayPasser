#pragma once
#include "GadgetFinder.hpp"

// 0 gets the spoofer 1 gets the cryptor
void* gadgetfinder64(int version, int iteration) {
	HMODULE hMods[1024];
	HANDLE hProcess;
	DWORD cbNeeded;
	MODULEINFO lpmodinfo;

	// Get a handle to the process.
	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
		PROCESS_VM_READ,
		FALSE, GetCurrentProcessId());

	// Get a list of all the modules in this process.
	if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
	{
		for (int i = iteration; i < (cbNeeded / sizeof(HMODULE)); i++)
		{
			char szModName[MAX_PATH];

			LPBYTE moduleMath = (LPBYTE)hMods[i];
			MEMORY_BASIC_INFORMATION memInfo = { 0 };
			while (VirtualQuery((PVOID)moduleMath, &memInfo, sizeof(memInfo)) != 0) {
				if (memInfo.Protect == PAGE_EXECUTE_READ || memInfo.Protect == PAGE_EXECUTE_READWRITE) {
					for (int x = 0; x < memInfo.RegionSize; x++) {
						//\x59\x5a\x41\x58\x41\x59\xc3
						//7 Bytes
						//This is ideal but is it possible?
						if (memcmp(moduleMath + x, "\xFF", 1) == 0 && version == 0) {
							if (memcmp((moduleMath + x + 1), "\x23", 1) == 0) {
								//printf("Found jmp rbx at %p!\n", moduleMath + x);
								void* gadget = (LPVOID)(moduleMath + x);
								return gadget;
							}
						}
						if (memcmp(moduleMath + x, "\x5a\x59\x41\x58\x41\x59\x41\x5A\x41\x5B\xC3", 11) == 0 && version == 1) {
							void* gadget = (LPVOID)(moduleMath + x);
							return gadget;
						}
					}
				}
				moduleMath += memInfo.RegionSize;
			}
			return 0;
		}
	}
	CloseHandle(hProcess);
}