#pragma once
#include "interrupts.hpp"

#include "../communication/shellcode.hpp"
#include "../physmem/physmem.hpp"

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
	uint64_t g_windows_nmi_handler;


	/*
		Utility
	*/
	segment_descriptor_interrupt_gate_64 create_interrupt_gate(void* assembly_handler, segment_descriptor_interrupt_gate_64 windows_gate) {
		segment_descriptor_interrupt_gate_64 gate;

		gate.interrupt_stack_table = windows_gate.interrupt_stack_table;
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
		Core
	*/
	extern "C" void nmi_handler(trap_frame_t* trap_frame) {
		uint64_t star_msr = __readmsr(IA32_STAR);
		KPCR* kcpr = __getpcr(); // Only valid if you call this while gs == kernel_gs
		uint64_t curr_user_panic_rip = shellcode::get_current_nmi_panic_function();
		rflags curr_user_rflags = { 0 };

		// Enable the interrupt flag again
		curr_user_rflags.flags = trap_frame->rflags;
		curr_user_rflags.interrupt_enable_flag = 1;
		curr_user_rflags.virtual_8086_mode_flag = 0;
		curr_user_rflags.reserved1 = 0; 
		curr_user_rflags.reserved2 = 0;
		curr_user_rflags.reserved3 = 0;
		curr_user_rflags.reserved4 = 0;
		curr_user_rflags.read_as_1 = 1;
		curr_user_rflags.nested_task_flag = 0;
		curr_user_rflags.io_privilege_level = 3;
		curr_user_rflags.resume_flag = 0;
		curr_user_rflags.alignment_check_flag = 0;

		// RPL is forced to 3
		uint16_t sysret_cs = (uint16_t)(((star_msr >> 48) + 16) | 3);  // (STAR[63:48] + 16) | 3
		uint16_t sysret_ss = (uint16_t)(((star_msr >> 48) + 8) | 3);   // (STAR[63:48] + 8) | 3

		trap_frame->rsp = kcpr->UserRsp;
		trap_frame->rip = curr_user_panic_rip;
		trap_frame->rflags = curr_user_rflags.flags;
		trap_frame->cs_selector = sysret_cs;
		trap_frame->ss_selector = sysret_ss;

		// Swap back to the um gs
		__swapgs();

		// Finally remove all mappings that the current driver called used up
		// in order to avoid the pte table filling up
		physmem::free_mem_copying_pte_table();
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

		segment_descriptor_register_64 idt = { 0 };
		__sidt(&idt);

		segment_descriptor_interrupt_gate_64* windows_idt = (segment_descriptor_interrupt_gate_64*)idt.base_address;
		if (!windows_idt)
			return status_failure;

		g_windows_nmi_handler = (static_cast<uint64_t>(windows_idt[exception_vector::nmi].offset_high) << 32) |
			(static_cast<uint64_t>(windows_idt[exception_vector::nmi].offset_middle) << 16) |
			(windows_idt[exception_vector::nmi].offset_low);;

		constructed_idt_table[exception_vector::nmi] = create_interrupt_gate(asm_nmi_handler, windows_idt[exception_vector::nmi]);

        constructed_idt_ptr.base_address = (uint64_t)constructed_idt_table;
        constructed_idt_ptr.limit = (sizeof(segment_descriptor_interrupt_gate_64) * 256) - 1;

        initialized = true;

		return status_success;
	}

    /*
        Exposed API's
    */
    bool is_initialized(void) {
        return initialized;
    }

	void* get_windows_nmi_handler(void) {
		return (void*)g_windows_nmi_handler;
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

		return status_success;
	}

	project_status restore_apc() {

		KThread* Thread = reinterpret_cast<KThread*>(KeGetCurrentThread());

		if (!Thread)
			return status_not_present;

		Thread->MiscFlags = originalFlags;

		return status_success;
	}
};