#pragma once
#pragma warning(disable: 4996)
#include <ntddk.h>
#include <intrin.h>
#include <ntimage.h>

using uint8_t = unsigned char;
using uint16_t = unsigned short;
using uint32_t = unsigned int;
using uint64_t = unsigned long long;

extern "C" int _fltused = 0; // Compiler issues

#define ENABLE_DEBUG_LOG
#ifdef ENABLE_DEBUG_LOG
#define dbg_log(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[DEBUG-LOG] " fmt, ##__VA_ARGS__)
#define dbg_log_no_prefix(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, fmt, ##__VA_ARGS__)

#else
#define dbg_log(fmt, ...) 0
#endif // ENABLE_DEBUG_LOG