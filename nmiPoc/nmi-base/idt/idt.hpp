#pragma once
#include "idt_structs.hpp"

// Global variables
inline uint64_t g_driver_base = 0;
inline uint64_t g_driver_size = 0;

// Idt related declarations
extern "C" idt_ptr_t* curr_kernel_idt_ptr = 0;
inline idt_ptr_t my_idt_ptr;
inline idt_entry_t my_idt_table[256];

// These globals have to be declared before these two includes cause of our compiler
#include "assembly_declarations.hpp"
#include "nmi.hpp"
#include "idt_util.hpp"

// Main Initialization function for seh
inline bool init_seh(uint64_t driver_base, uint64_t driver_size) {
	if (!driver_base || !driver_size)
		return false;

	idt_ptr_t idt;
	__sidt(&idt);

	if (!idt.base)
		return false;

	// Clear my idt table and copy the system one
	memset(my_idt_table, 0, sizeof(my_idt_table[0]) * 256);
	memcpy(my_idt_table, (void*)idt.base, idt.limit);

	if (!init_nmi_handler()) {
		dbg_log("Failed to init nmi handler");
		return false;
	}

	my_idt_ptr = get_idt_ptr();

	PHYSICAL_ADDRESS max_addr = { 0 };
	max_addr.QuadPart = MAXULONG64;

	curr_kernel_idt_ptr = (idt_ptr_t*)MmAllocateContiguousMemory(sizeof(idt_ptr_t), max_addr);
	if (!curr_kernel_idt_ptr) {
		dbg_log("Failed to alloc idt ptr mem");
		return false;
	}
	memset(curr_kernel_idt_ptr, 0, sizeof(idt_ptr_t));

	// Safe globals used for seh
	g_driver_base = driver_base;
	g_driver_size = driver_size;

	dbg_log("Successfully initialized idt");

	return true;
}