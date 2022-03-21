#pragma once
#include <Windows.h>
#include <Psapi.h>
#include <Tlhelp32.h>
#pragma comment( lib, "Psapi" )

#ifndef _CCONTEXTHOOK_H_
#define _CCONTEXTHOOK_H_
// VEH Handler
extern PVOID pHandler;
// ThreadIDs (These are used to identify what threads to hook)
extern DWORD hookID;
extern DWORD masterThreadID;
// Functions
HANDLE HookedGetProcessHeap();
LPVOID HookedVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
void WINAPI HookedExitProcess(DWORD dwExitCode);
void WINAPI HookedSleep(DWORD dwMiliseconds);
void Initialize2Context(BOOL Suspend);
void Initialize3Context(BOOL Suspend);
void Initialize4Context(BOOL Suspend);
LONG WINAPI ExceptionHandler(EXCEPTION_POINTERS* e);

typedef struct {
	DWORD64 Hook1;
	DWORD64 Hook2;
	DWORD64 Hook3;
	DWORD64 Hook4;
} Context_t;

typedef void(__cdecl* Handler_t)(Context_t* C, EXCEPTION_POINTERS* E);

class CContextHook
{
public:

	bool	  InitiateContext(Handler_t ContextHandler, Context_t* C, BOOL Suspend, BOOL Master);
	bool	  ClearContext(void);
	Context_t* GetContextInfo(void);
	Handler_t   GetHandlerInfo(void);
	HANDLE   GetMasterThread(void);

private:

	bool   IsReady(DWORD64* H);
	HANDLE   GetMainThread(void);

private:

	Context_t   m_Context;
	Handler_t   m_Handler;
	PVOID	  m_pHandler;
};

extern CContextHook GContextHook;
extern CContextHook GContextHookM;

#endif
