#pragma once
#include <windows.h>
#include <psapi.h>

// 0 gets the spoofer 1 gets the cryptor
void* gadgetfinder64(int version, int iteration);