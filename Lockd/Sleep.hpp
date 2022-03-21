#pragma once
#include <windows.h>
#include <chrono>

// Custom more accurate sleep to bypass BeaconHunter
// https://blat-blatnik.github.io/computerBear/making-accurate-sleep-function/
// https://github.com/3lp4tr0n/BeaconHunter
void timerSleep(double seconds);