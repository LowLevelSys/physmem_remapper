#pragma once
#include "../physmem/physmem.hpp"
#include "../physmem/remapping.hpp"
#include "../gdt/gdt.hpp"

#include "idt_structs.hpp"

#include <ntimage.h>

#define PARTIALLY_USE_SYSTEM_IDT
#define ENABLE_IDT_LOGGING
// #define EXTENSIVE_IDT_LOGGING

#ifdef ENABLE_IDT_LOGGING
#define dbg_log_idt(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[IDT] " fmt, ##__VA_ARGS__)
#else
#define dbg_log_idt(fmt, ...) (void)0
#endif

inline idt_ptr_t my_idt_ptr;
inline idt_ptr_t* idt_storing_region;

// Pointer to tables of 256 idt entries
inline idt_entry_t my_idt_table[256];

inline bool is_idt_inited = false;

bool init_idt(void);

extern "C" void asm_non_maskable_interrupt_handler(void);
extern "C" void asm_ecode_interrupt_handler(void);
extern "C" void asm_no_ecode_interrupt_handler(void);