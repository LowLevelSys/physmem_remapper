#pragma once
#pragma warning(disable: 4996)

#include "crt.hpp"

#include <ntddk.h>
#include <intrin.h>

using uint8_t = unsigned char;
using uint16_t = unsigned short;
using uint32_t = unsigned int;
using uint64_t = unsigned long long;

// Assembly function declarations
extern "C" uint64_t __read_rax(void);
extern "C" void asm_recover_regs(void);
extern "C" uint32_t asm_get_curr_processor_number(void);

// Asssembly variables declarations
extern "C" uint64_t global_proc_cr3;