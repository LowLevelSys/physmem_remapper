#include "../idt/safe_crt.hpp"

#include "idt.hpp"

extern "C" int _fltused = 0; // Compiler issues

extern "C" void handle_non_maskable_interrupt(trap_frame_t* trap_frame) {
	UNREFERENCED_PARAMETER(trap_frame);

	// To do: Implement a system to hide from eac's NMI's
}

extern "C" void handle_ecode_interrupt(trap_frame_ecode_t* regs) {
	IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)my_driver_base;
	IMAGE_NT_HEADERS64* nt_headers = (IMAGE_NT_HEADERS64*)(my_driver_base + dos_header->e_lfanew);
	IMAGE_DATA_DIRECTORY* exception = &nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	RUNTIME_FUNCTION* rt_functions = (RUNTIME_FUNCTION*)(my_driver_base + exception->VirtualAddress);
	uint64_t rva = regs->rip - my_driver_base;


	// Try to resolve the exception directly with rip
	for (ULONG idx = 0; idx < exception->Size / sizeof(RUNTIME_FUNCTION); ++idx)
	{
		RUNTIME_FUNCTION* function = &rt_functions[idx];

		if (!(rva >= function->BeginAddress && rva < function->EndAddress))
			continue;

		UNWIND_INFO* unwind_info = (UNWIND_INFO*)(my_driver_base + function->UnwindData);

		if (!(unwind_info->Flags & UNW_FLAG_EHANDLER))
			continue;

		SCOPE_TABLE* scope_table = (SCOPE_TABLE*)((uint64_t)(&unwind_info->UnwindCode[(unwind_info->CountOfCodes + 1) & ~1]) + sizeof(uint32_t));

		for (uint32_t entry = 0; entry < scope_table->Count; ++entry) {
			SCOPE_RECORD* scope_record = &scope_table->ScopeRecords[entry];
			if (rva >= scope_record->BeginAddress && rva < scope_record->EndAddress) {
				regs->rip = my_driver_base + scope_record->JumpTarget;
				return;
			}
		}
	}

	// If we reached here this means that the exception couldn't get
	// resolved with rip, so we have to stack trace to find the __except
	// block

	uint64_t* stack_ptr = (uint64_t*)regs->rbp;
	while(stack_ptr) {
		// Return address is always stored above the base pointer
		uint64_t caller_rip = *(stack_ptr + 1); 
		uint64_t caller_rva = caller_rip - my_driver_base;

		// Check whether the caller can even be from our driver
		// to speed up the stack walking process
		if(caller_rva > my_driver_size) {
			// Move on to previous frame using current frame's base pointer
			stack_ptr = (uint64_t*)*stack_ptr;
			continue;
		}

		for (ULONG idx = 0; idx < exception->Size / sizeof(RUNTIME_FUNCTION); ++idx) {
			RUNTIME_FUNCTION* function = &rt_functions[idx];

			if (!(caller_rva >= function->BeginAddress && caller_rva < function->EndAddress))
				continue;

			UNWIND_INFO* unwind_info = (UNWIND_INFO*)(my_driver_base + function->UnwindData);

			if (!(unwind_info->Flags & UNW_FLAG_EHANDLER))
				continue;

			SCOPE_TABLE* scope_table = (SCOPE_TABLE*)((uint64_t)(&unwind_info->UnwindCode[(unwind_info->CountOfCodes + 1) & ~1]) + sizeof(uint32_t));

			for (uint32_t entry = 0; entry < scope_table->Count; ++entry) {
				SCOPE_RECORD* scope_record = &scope_table->ScopeRecords[entry];
				if (caller_rva >= scope_record->BeginAddress && caller_rva < scope_record->EndAddress) {
					regs->rip = my_driver_base + scope_record->JumpTarget;
					return;
				}
			}
		}
	}
}

idt_ptr_t get_idt_ptr() {
	idt_ptr_t idtr;

	idtr.limit = sizeof(my_idt_table) - 1;
	idtr.base = reinterpret_cast<uint64_t>(&my_idt_table);

	return idtr;
}

idt_entry_t create_interrupt_gate(void* handler_address) {
	idt_entry_t entry = { 0 };

	uint64_t offset = reinterpret_cast<uint64_t>(handler_address);

	entry.offset_low = (offset >> 0) & 0xFFFF;
	entry.offset_middle = (offset >> 16) & 0xFFFF;
	entry.offset_high = (offset >> 32) & 0xFFFFFFFF;

	entry.segment_selector = __read_cs().flags;
	entry.gate_type = SEGMENT_DESCRIPTOR_TYPE_INTERRUPT_GATE;
	entry.present = true;

	return entry;
}

bool test_idt(void) {
	_cli();

	idt_ptr_t idt;
	__sidt(&idt);
	__lidt(&my_idt_ptr);

	bool gpf_tested = false, pf_read_tested = false, pf_write_tested = false;
	bool de_tested = false, ud_tested = false;

	// #GP test
	__try {
		paging_structs::cr4 curr = { 0 };

		curr.flags = __readcr4();
		curr.reserved2 = 1;

		__writecr4(curr.flags);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		gpf_tested = true;
	}

	// #PF test (Read)
	__try {
		volatile int* p = reinterpret_cast<volatile int*>(0x1);
		int dummy = *p;
		UNREFERENCED_PARAMETER(dummy);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		pf_read_tested = true;
	}

	// #PF test (Write)
	__try {
		volatile int* p = reinterpret_cast<volatile int*>(0x1);
		*p = 0x1337;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		pf_write_tested = true;
	}

	// #DE test (Divide Error)
	__try {
		volatile int zero = 0;
		volatile int result = 1 / zero;
		UNREFERENCED_PARAMETER(result);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		de_tested = true;
	}

	// #UD test (Invalid Opcode)
	__try {
		__ud2();
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		ud_tested = true;
	}

	__lidt(&idt);
	_sti();

#ifdef EXTENSIVE_IDT_LOGGING
	dbg_log_idt("Idt test results: \n");
	dbg_log_idt("#GP %d", gpf_tested);
	dbg_log_idt("#PF read %d", pf_read_tested);
	dbg_log_idt("#PF write %d", pf_write_tested);
	dbg_log_idt("#DE %d", de_tested);
	dbg_log_idt("#UD %d", ud_tested);
#endif

	return gpf_tested && pf_read_tested && pf_write_tested && de_tested && ud_tested;
}


bool init_idt(void) {
	idt_ptr_t idt;
	__sidt(&idt);

	safe_crt::memset(my_idt_table, 0, sizeof(my_idt_table[0]) * 256);

#ifdef PARTIALLY_USE_SYSTEM_IDT
	// Copy over the "normal" kernel idt
	safe_crt::memcpy(my_idt_table, (void*)idt.base, idt.limit);
#endif // PARTIALLY_USE_SYSTEM_IDT

	// Replace the nmi handler
	my_idt_table[DIVIDE_ERROR] = create_interrupt_gate(asm_no_ecode_interrupt_handler);
	my_idt_table[NMI_HANDLER] = create_interrupt_gate(asm_non_maskable_interrupt_handler);
	my_idt_table[INVALID_OPCODE] = create_interrupt_gate(asm_no_ecode_interrupt_handler);
	my_idt_table[PAGE_FAULT] = create_interrupt_gate(asm_ecode_interrupt_handler);
	my_idt_table[GENERAL_PROTECTION] = create_interrupt_gate(asm_ecode_interrupt_handler);

	// Idt compatible
	my_idt_ptr = get_idt_ptr();

#ifdef EXTENSIVE_IDT_LOGGING
#ifndef PARTIALLY_USE_SYSTEM_IDT


	dbg_log_idt("Idt initialized \n");

	for (uint64_t i = 0; i < 256; i++) {
		if (my_idt_table[i].present) {
			uint64_t handler_address = (static_cast<uint64_t>(my_idt_table[i].offset_high) << 32) |
				(static_cast<uint64_t>(my_idt_table[i].offset_middle) << 16) |
				(my_idt_table[i].offset_low);
			dbg_log_idt("Idt Entry %llu at %p", i, (void*)handler_address);
		}
	}

	dbg_log("\n");
#endif // !PARTIALLY_USE_SYSTEM_IDT
#endif // EXTENSIVE_IDT_LOGGING
	uint64_t processor_count = KeQueryActiveProcessorCount(0);
	PHYSICAL_ADDRESS max_addr = { 0 };
	max_addr.QuadPart = MAXULONG64;

	idt_storing_region = (idt_ptr_t*)MmAllocateContiguousMemory(sizeof(idt_ptr_t) * processor_count, max_addr);
	if (!idt_storing_region) {
		dbg_log_idt("Failed to allocate idt state");
		return false;
	}

	safe_crt::memset(idt_storing_region, 0, sizeof(idt_ptr_t) * processor_count);

	if (!test_idt()) {
		dbg_log_idt("Failed to test my idt");
		return false;
	}

	is_idt_inited = true;

	return true;
}