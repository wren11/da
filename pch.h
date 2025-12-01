#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <conio.h>
#include <iostream>
#include <vector>
#include <string>
#include <memory>
#include <algorithm>
#include <cstring>
#include <fstream>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <iomanip>
#pragma comment(lib, "psapi.lib")