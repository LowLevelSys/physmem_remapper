#pragma once
#include "interrupts.hpp"

#include "../communication/shellcode.hpp"
#include "../spinlock.hpp"

namespace interrupts {
	/*
		Definitions
	*/
	uint64_t SEGMENT_DESCRIPTOR_TYPE_INTERRUPT_GATE = 0xE;

	/*
		Global variables
	*/
    bool initialized = false;
	segment_descriptor_interrupt_gate_64* constructed_idt_table = 0;
    segment_descriptor_register_64 constructed_idt_ptr = { 0 };


	/*
		Utility
	*/
	segment_descriptor_interrupt_gate_64 create_interrupt_gate(void* assembly_handler) {
		segment_descriptor_interrupt_gate_64 gate;

		gate.interrupt_stack_table = 0;
		gate.segment_selector = __readcs();
		gate.must_be_zero_0 = 0;
		gate.type = SEGMENT_DESCRIPTOR_TYPE_INTERRUPT_GATE;
		gate.must_be_zero_1 = 0;
		gate.descriptor_privilege_level = 0;
		gate.present = 1;
		gate.reserved = 0;

		uint64_t offset = (uint64_t)assembly_handler;
		gate.offset_low = (offset >> 0) & 0xFFFF;
		gate.offset_middle = (offset >> 16) & 0xFFFF;
		gate.offset_high = (offset >> 32) & 0xFFFFFFFF;

		return gate;
	}

	segment_descriptor_register_64 get_constructed_idt_ptr(void) {
		return constructed_idt_ptr;
	}

	/*
		Initialization functions
	*/

	project_status init_interrupts() {
		PHYSICAL_ADDRESS max_addr = { 0 };
		max_addr.QuadPart = MAXULONG64;

		constructed_idt_table = (segment_descriptor_interrupt_gate_64*)MmAllocateContiguousMemory(sizeof(segment_descriptor_interrupt_gate_64) * 256, max_addr);
		if (!constructed_idt_table)
			return status_memory_allocation_failed;

		crt::memset(constructed_idt_table, 0, sizeof(segment_descriptor_interrupt_gate_64) * 256);

		constructed_idt_table[exception_vector::nmi] = create_interrupt_gate(asm_nmi_handler);

        constructed_idt_ptr.base_address = (uint64_t)&constructed_idt_table;
        constructed_idt_ptr.limit = sizeof(constructed_idt_table) - 1;

        initialized = true;

		return status_success;
	}

    /*
        Exposed API's
    */
    bool is_initialized(void) {
        return initialized;
    }
	
	/*
		APC
	*/

	project_status remove_apc() {

		KThread* Thread = reinterpret_cast<KThread*>(KeGetCurrentThread());

		if (!Thread)
			return status_not_present;

		originalFlags = Thread->MiscFlags;

		Thread->MiscFlags &= ~(1UL << MISC_FLAG_ALERTABLE); // Null Alertable
		Thread->MiscFlags &= ~(1UL << MISC_FLAG_APC); // Null APC

		//project_log_info("REMOVED APC! (Thread->MiscFlags : %i)\n", Thread->MiscFlags);

		return status_success;
	}

	project_status restore_apc() {

		KThread* Thread = reinterpret_cast<KThread*>(KeGetCurrentThread());

		if (!Thread)
			return status_not_present;

		Thread->MiscFlags = originalFlags;

		//project_log_info("RESTORED APC! (Thread->MiscFlags : %i)\n", Thread->MiscFlags);

		return status_success;
	}
};