#pragma once
#include "CContextHook.hpp"

CContextHook GContextHook;
CContextHook GContextHookM;
// VEH Handler
PVOID pHandler;
// ThreadIDs (These are used to identify what threads to hook)
DWORD hookID;
DWORD masterThreadID = NULL;

LONG WINAPI ExceptionHandler(EXCEPTION_POINTERS* e)
{
	if (e->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
	{
		return EXCEPTION_CONTINUE_SEARCH;
	}

	Context_t* Context = NULL;
	if (GetCurrentThreadId() == hookID) {
		Context = GContextHook.GetContextInfo();
	}
	else {
		Context = GContextHookM.GetContextInfo();
	}

	if (Context)
	{
		if (e->ExceptionRecord->ExceptionAddress == (PVOID)Context->Hook1 ||
			e->ExceptionRecord->ExceptionAddress == (PVOID)Context->Hook2 ||
			e->ExceptionRecord->ExceptionAddress == (PVOID)Context->Hook3 ||
			e->ExceptionRecord->ExceptionAddress == (PVOID)Context->Hook4)
		{
			Handler_t Handler = NULL;
			if (GetCurrentThreadId() == hookID) {
				Handler = GContextHook.GetHandlerInfo();
			}
			else {
				Handler = GContextHookM.GetHandlerInfo();
			}

			if (Handler)
			{
				Handler(Context, e);
			}

			return EXCEPTION_CONTINUE_EXECUTION;
		}
	}

	return EXCEPTION_CONTINUE_SEARCH;
}

bool CContextHook::InitiateContext(Handler_t ContextHandler, Context_t* C, BOOL Suspend, BOOL Master)
{

	if (C == NULL || ContextHandler == NULL)
		return false;

	m_Handler = ContextHandler;

	memcpy(&m_Context, C, sizeof(Context_t));

	if (IsReady(&C->Hook1) == false)
		return false;
	HANDLE hMainThread;
	if (Master == TRUE) {
		hMainThread = GetMasterThread();
	}
	else {
		hMainThread = GetMainThread();
	}

	if (hMainThread == INVALID_HANDLE_VALUE)
		return false;
	srand(GetTickCount());
	if (pHandler == NULL) {
		pHandler = AddVectoredExceptionHandler(rand() % 0xFFFFFF, ExceptionHandler);
	}
	if (pHandler == NULL)
		return false;
	CONTEXT c;

	c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	if (Suspend == TRUE) {
		SuspendThread(hMainThread);
	}
	GetThreadContext(hMainThread, &c);
	c.Dr0 = C->Hook1;

	int SevenFlags = (1 << 0);

	if (IsReady(&C->Hook2))
	{
		SevenFlags |= (1 << 2);

		c.Dr1 = C->Hook2;
	}
	if (IsReady(&C->Hook3))
	{
		SevenFlags |= (1 << 4);

		c.Dr2 = C->Hook3;
	}
	if (IsReady(&C->Hook4))
	{
		SevenFlags |= (1 << 6);

		c.Dr3 = C->Hook4;
	}

	c.Dr6 = 0x00000000;

	c.Dr7 = SevenFlags;


	SetThreadContext(hMainThread, &c);

	if (Suspend == TRUE) {
		ResumeThread(hMainThread);
	}

	return true;
}

Context_t* CContextHook::GetContextInfo(void)
{
	return &m_Context;
}

Handler_t CContextHook::GetHandlerInfo(void)
{
	return m_Handler;
}

bool CContextHook::ClearContext(void)
{
	HANDLE hMainThread;
	if (GetCurrentThreadId() == hookID) {
		hMainThread = GetMainThread();
	}
	else {
		hMainThread = GetMasterThread();
	}

	if (hMainThread == INVALID_HANDLE_VALUE)
		return false;

	CONTEXT c;

	c.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	//SuspendThread(hMainThread);

	GetThreadContext(hMainThread, &c);

	c.Dr0 = 0;
	c.Dr1 = 0;
	c.Dr2 = 0;
	c.Dr3 = 0;
	c.Dr6 = 0;
	c.Dr7 = 0;

	SetThreadContext(hMainThread, &c);

	//ResumeThread(hMainThread);

	return true;
}

bool CContextHook::IsReady(DWORD64* H)
{
	if (!H)
		return false;

	return (*H != NULL);
}

void ContextHandler(Context_t* C, EXCEPTION_POINTERS* E)
{
	if (!C || !E)
		return;

	if (E->ContextRecord->Rip == (DWORD64)Sleep)
	{

		E->ContextRecord->Rip = (DWORD64)HookedSleep;
	}
	else if (E->ContextRecord->Rip == (DWORD64)GetProcessHeap)
	{

		E->ContextRecord->Rip = (DWORD64)HookedGetProcessHeap;
	}
	else if (E->ContextRecord->Rip == (DWORD64)VirtualAlloc)
	{

		E->ContextRecord->Rip = (DWORD64)HookedVirtualAlloc;
	}
	else if (E->ContextRecord->Rip == (DWORD64)ExitProcess)
	{

		E->ContextRecord->Rip = (DWORD64)HookedExitProcess;
	}
}

void Initialize2Context(BOOL Suspend)
{
	Context_t C;
	C.Hook1 = (DWORD64)ExitProcess;
	if (!GContextHookM.InitiateContext(ContextHandler, &C, Suspend, TRUE))
	{
		exit(0);
	}
}


void Initialize3Context(BOOL Suspend)
{
	Context_t C;
	C.Hook1 = (DWORD64)Sleep;
	C.Hook2 = (DWORD64)GetProcessHeap;
	C.Hook3 = (DWORD64)VirtualAlloc;
	if (!GContextHook.InitiateContext(ContextHandler, &C, Suspend, FALSE))
	{
		exit(0);
	}
}

void Initialize4Context(BOOL Suspend)
{
	Context_t C;
	C.Hook1 = (DWORD64)Sleep;
	C.Hook2 = (DWORD64)GetProcessHeap;
	C.Hook3 = (DWORD64)ExitProcess;
	if (!GContextHook.InitiateContext(ContextHandler, &C, Suspend, FALSE))
	{
		exit(0);
	}
}

HANDLE CContextHook::GetMainThread(void)
{
	DWORD ProcessThreadId = hookID;
	return OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, TRUE, ProcessThreadId);
}

HANDLE CContextHook::GetMasterThread(void)
{
	if (masterThreadID == NULL) {
		masterThreadID = GetCurrentThreadId();
	}
	return OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, TRUE, masterThreadID);
}