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

extern "C" uint16_t get_tr_index(void);
extern "C" uint64_t get_current_gdt_base(void);
extern "C" uint64_t get_tss_descriptor(void);

extern "C" uint32_t asm_get_curr_processor_number(void);
extern "C" void set_tss_descriptor_available(void);