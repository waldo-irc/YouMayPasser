#pragma once
#include "Refresh.hpp"

// This will refresh the .text section of a requested DLL
// This will also detect if a DLL has page guard on it (VEH HOOK) and act accordingly as well
int universalRefresher(const char* szModuleName) {
	HANDLE hProcess;
	DWORD processID = GetCurrentProcessId();

	// Get a handle to the process.
	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
		PROCESS_VM_READ,
		FALSE, processID);
	if (NULL == hProcess)
		return 1;

	// Get a list of all the modules in this process.
	PSIZE_T returnLength = 0;
	//HMODULE moduleToRefresh = GetModuleHandleA(szModuleName);
	HMODULE moduleToRefresh = LoadLibraryA(szModuleName);

	char szModName[MAX_PATH];
	if (K32GetModuleFileNameExA(hProcess, moduleToRefresh, szModName,
		sizeof(szModName) / sizeof(char)))
	{
		// Get file Bytes
		FILE* pFile;
		long lSize;
		BYTE* buffer;
		size_t result;
		pFile = fopen(szModName, "rb");
		// obtain file size:
		fseek(pFile, 0, SEEK_END);
		lSize = ftell(pFile);
		rewind(pFile);
		// allocate memory to contain the whole file:
		buffer = (BYTE*)malloc(sizeof(BYTE) * lSize);
		// copy the file into the buffer:
		result = fread(buffer, 1, lSize, pFile);
		fclose(pFile);

		// Get memory Bytes
		BYTE* buff;
		buff = (BYTE*)malloc(sizeof(BYTE) * lSize);
		ReadProcessMemory(hProcess, moduleToRefresh, buff, lSize, NULL);

		PIMAGE_NT_HEADERS64 NtHeader = ImageNtHeader(buff);
		if (NtHeader != NULL) {
			// Print the module name and handle value.
			//printf(TEXT("Refreshing %s\n"), szModName);
			PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(NtHeader);
			WORD NumSections = NtHeader->FileHeader.NumberOfSections;
			for (WORD i = 0; i < NumSections; i++)
			{
				std::string secName(reinterpret_cast<char const*>(Section->Name), 5);
				// Check if the memory is executable
				if (secName.find(".text") != std::string::npos) {
					break;
				}
				Section++; // If not executable check next section
			}

			// The first is the offset from the file on disk
			// The second is the offset to .txt from memory
			LPBYTE txtSectionFile = buffer + Section->PointerToRawData;
			LPBYTE txtSectionMem = buff + Section->VirtualAddress;
			LPBYTE txtSectionLoadedModule = (LPBYTE)moduleToRefresh + Section->VirtualAddress;
			char* moduleChar = (char*)txtSectionLoadedModule;
			//DWORD oldProtect;
			ULONG oldProtect;
			VirtualProtect((PVOID*)&txtSectionLoadedModule, (SIZE_T)Section->SizeOfRawData, PAGE_EXECUTE_READWRITE, &oldProtect);
			for (int i = 0; i < Section->SizeOfRawData; i++) {
				if ((char*)txtSectionMem[i] != (char*)txtSectionFile[i]) {
					moduleChar[i] = txtSectionFile[i];
				}
			}
			VirtualProtect((PVOID*)&txtSectionLoadedModule, (SIZE_T)Section->SizeOfRawData, oldProtect, &oldProtect);

			memset(buffer, 0x00, lSize);
			memset(buff, 0x00, lSize);
			free(buffer);
			free(buff);
		}
	}
	// Release the handle to the process.
	CloseHandle(hProcess);
	return 0;
}