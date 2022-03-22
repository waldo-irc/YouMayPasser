#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <string>
#include <psapi.h>
#include <dbghelp.h>
#pragma comment(lib, "dbghelp.lib")

// This will refresh the .text section of a requested DLL
// This will also detect if a DLL has page guard on it (VEH HOOK) and act accordingly as well
int universalRefresher(const char* szModuleName);