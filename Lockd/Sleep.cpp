#pragma once
#include "Sleep.hpp"

void timerSleep(double seconds) {
	using namespace std::chrono;

	static HANDLE timer = CreateWaitableTimer(NULL, FALSE, NULL);
	static double estimate = 5e-3;
	static double mean = 5e-3;
	static double m2 = 0;
	static int64_t count = 1;

	while (seconds - estimate > 1e-7) {
		double toWait = seconds - estimate;
		LARGE_INTEGER due;
		due.QuadPart = -int64_t(toWait * 1e7);
		auto start = high_resolution_clock::now();
		SetWaitableTimerEx(timer, &due, 0, NULL, NULL, NULL, 0);
		WaitForSingleObject(timer, INFINITE);
		auto end = high_resolution_clock::now();

		double observed = (end - start).count() / 1e9;
		seconds -= observed;

		++count;
		double error = observed - toWait;
		double delta = error - mean;
		mean += delta / count;
		m2 += delta * (error - mean);
		double stddev = sqrt(m2 / (count - 1));
		estimate = mean + stddev;
	}

	// spin lock
	auto start = high_resolution_clock::now();
	while ((high_resolution_clock::now() - start).count() / 1e9 < seconds);
}