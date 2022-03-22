#pragma once
#include <windows.h>
#include <psapi.h>

// 0 gets the spoofer 1 gets the cryptor
void* gadgetfinder64(int version, int iteration, void* bytes = 0x00, size_t sizeOfBytes = 0);