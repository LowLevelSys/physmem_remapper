#pragma warning (disable: 4091 6328 6031)
#pragma once
#include <Windows.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <stdio.h>
#include <assert.h>
#include <mutex>

// Logging macros
#define log(fmt, ...) printf("[vext] " fmt "\n", ##__VA_ARGS__)
#define log_new_line(fmt) printf(fmt "\n")