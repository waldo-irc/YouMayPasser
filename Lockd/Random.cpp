#pragma once
#include "Random.hpp"

std::string gen_random(const int len) {

	std::string tmp_s;

	srand((unsigned)time(NULL) * _getpid());

	tmp_s.reserve(len);

	for (int i = 0; i < len; ++i)
		tmp_s += rand() % 256;

	return tmp_s;

}