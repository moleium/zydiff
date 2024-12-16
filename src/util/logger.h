#pragma once

#ifdef DEBUG
#include <cstdio>

#define LOG(...) printf(__VA_ARGS__)
#else
#define LOG(...) 
#endif

