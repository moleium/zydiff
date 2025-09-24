#pragma once

#include <print>

#ifdef DEBUG
#include <cstdio>

#define LOG(...) std::print(__VA_ARGS__)
#else
#define LOG(...) 
#endif

