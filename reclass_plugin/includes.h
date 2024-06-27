#pragma warning (disable: 4091 6328 6031)
#pragma once
#include <Windows.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <stdio.h>
#include <assert.h>

// Logging macros
#define log(fmt, ...) printf("[reclass-plugin] " fmt "\n", ##__VA_ARGS__)
#define log_new_line(fmt) printf(fmt "\n")

// #define DEBUG_MODE
inline void alloc_console(void) {
#ifdef DEBUG_MODE
	AllocConsole();
	SetConsoleTitle(L"DEBUG-INFO");
	freopen("CONOUT$", "w", stdout);
	freopen("CONOUT$", "w", stderr);
	freopen("CONIN$", "r", stdin);
#endif // DEBUG_MODE
}