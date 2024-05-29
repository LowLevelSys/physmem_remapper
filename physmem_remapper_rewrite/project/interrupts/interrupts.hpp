#pragma once
#include "../project_includes.hpp"
#include "interrupt_structs.hpp"
#include <ntimage.h>

extern "C" uint16_t __readcs(void);
extern "C" void _cli(void);
extern "C" void _sti(void);

extern "C" void asm_nmi_handler(void);

namespace interrupts {
	// Initialization functions
	project_status init_interrupts();

	// Exposed API's
	bool is_initialized(void);
	segment_descriptor_register_64 get_constructed_idt_ptr(void);
	void* get_windows_nmi_handler(void);
};