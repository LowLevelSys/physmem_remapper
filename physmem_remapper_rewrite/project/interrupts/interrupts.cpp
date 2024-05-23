#pragma once
#include "interrupts.hpp"

extern "C" uint16_t __readcs(void);

extern "C" void asm_ecode_interrupt_handler(void);
extern "C" void asm_no_ecode_interrupt_handler(void);
extern "C" void asm_nmi_handler(void);


namespace interrupts {
	/*
		Definitions
	*/
	uint64_t SEGMENT_DESCRIPTOR_TYPE_INTERRUPT_GATE = 0xE;

	/*
		Global variables
	*/
    bool initialized = false;
	uint64_t g_driver_base = 0;
	uint64_t g_driver_size = 0;
	segment_descriptor_interrupt_gate_64 constructed_idt_table[256] = { 0 };
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

    segment_descriptor_register_64 load_constructed_idt(void) {
        segment_descriptor_register_64 orig_idt = { 0 };

        __sidt(&orig_idt);
        __lidt(&constructed_idt_ptr);

        return orig_idt;
    }

    void load_original_idt(segment_descriptor_register_64 orig_idt) {
        __lidt(&orig_idt);
    }

    void recursive_de(uint32_t depth) {
        if (depth == 0) {
            volatile int zero = 0;
            volatile int result = 1 / zero;
            UNREFERENCED_PARAMETER(result);
        }
        else {
            recursive_de(depth - 1);
        }
    }

	/*
		Core functions
	*/

	namespace seh {
        IMAGE_DOS_HEADER* dos_header = 0;
        IMAGE_NT_HEADERS64* nt_headers = 0;
        IMAGE_DATA_DIRECTORY* exception_directory = 0;
        _IMAGE_RUNTIME_FUNCTION_ENTRY* runtime_functions = 0;
        uint32_t runtime_function_count = 0;

        project_status get_runtime_function(uint64_t rva, _IMAGE_RUNTIME_FUNCTION_ENTRY*& entry, UNWIND_INFO*& unwind_info, SCOPE_TABLE*& scope_table) {
            if (!dos_header) {
                dos_header = (IMAGE_DOS_HEADER*)g_driver_base;
                nt_headers = (IMAGE_NT_HEADERS64*)(g_driver_base + dos_header->e_lfanew);

                exception_directory = &nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
                runtime_functions = (_IMAGE_RUNTIME_FUNCTION_ENTRY*)(g_driver_base + exception_directory->VirtualAddress);
                runtime_function_count = exception_directory->Size / sizeof(_IMAGE_RUNTIME_FUNCTION_ENTRY);
            }

            if (rva > g_driver_size)
                return status_rva_outside_driver;

            for (uint32_t i = 0; i < runtime_function_count; ++i) {
                _IMAGE_RUNTIME_FUNCTION_ENTRY* runtime_function = &runtime_functions[i];

                if (rva < runtime_function->BeginAddress || rva >= runtime_function->EndAddress)
                    continue;
                
                entry = runtime_function;
                unwind_info = (UNWIND_INFO*)(g_driver_base + entry->UnwindData);
                scope_table = (SCOPE_TABLE*)((uint64_t)(&unwind_info->UnwindCode[(unwind_info->CountOfCodes + 1) & ~1]) + sizeof(uint32_t));

            get_chained_entry:
                // If the entry is chained, the real data is right after the unwind info
                if (unwind_info->Flags & UNW_FLAG_CHAININFO) {
                    entry = (_IMAGE_RUNTIME_FUNCTION_ENTRY*)&unwind_info->UnwindCode[(unwind_info->CountOfCodes + 1) & ~1];
                    unwind_info = (UNWIND_INFO*)(g_driver_base + entry->UnwindData);
                    scope_table = (SCOPE_TABLE*)((uint64_t)(&unwind_info->UnwindCode[(unwind_info->CountOfCodes + 1) & ~1]) + sizeof(uint32_t));
                    goto get_chained_entry;
                }

                return status_success;
            }

            return status_no_runtime_function_found;
        }

        // Tries to dispatch an exception that happened in our driver.
        // If this returns status_failure it means that the exception
        // occured outside of our driver, idk how though
		project_status dispatch_driver_exception(trap_frame_ecode_t* context) {
			if (!context)
				return status_invalid_parameter;
         
            project_status status = status_success;
            trap_frame_ecode_t unwind_ctx = *context;
       
            while (true) {
                _IMAGE_RUNTIME_FUNCTION_ENTRY* entry = 0;
                UNWIND_INFO* unwind_info = 0;
                SCOPE_TABLE* scope_table = 0;
                uint64_t rva = unwind_ctx.rip - g_driver_base;

                // First get the runtime function including info about it, and if it's
                // a leaf function continue the search and manually unwind
                status = get_runtime_function(rva, entry, unwind_info, scope_table);
                if (status != status_success) {
                    unwind_ctx.rip = *(uint64_t*)unwind_ctx.rsp;
                    unwind_ctx.rsp += 8;
                    continue;
                }
                
                // The info has to have an exception handler or a termination handler
                if (!(unwind_info->Flags & UNW_FLAG_EHANDLER) &&
                    !(unwind_info->Flags & UNW_FLAG_UHANDLER)) {
                    unwind_ctx.rip = *(uint64_t*)unwind_ctx.rsp;
                    unwind_ctx.rsp += 8;
                    continue;
                }

                // Then walk the the scope table and find the right scope record
                // and continue excution from the info stored in there
                for (uint32_t entry_idx = 0; entry_idx < scope_table->Count; ++entry_idx) {
                    SCOPE_RECORD* scope_record = &scope_table->ScopeRecords[entry_idx];
                    if (rva >= scope_record->BeginAddress && rva < scope_record->EndAddress) {

                        // Restore rip
                        unwind_ctx.rip = g_driver_base + scope_record->JumpTarget;
                        unwind_ctx.rax = 0x1337; // Should in theory contain the exception code xD

                        // And finally set the context to the unwinded one
                        *context = unwind_ctx;

                        return status_success;
                    }
                }

                // If we reached here this means that we failed to find a scope record
                // capable of returning execution in our function, so just move on to
                // the next frame
                unwind_ctx.rip = *(uint64_t*)unwind_ctx.rsp;
                unwind_ctx.rsp += 8;
            }

            return status_failure;
		}
    };

	extern "C" void handle_ecode_interrupt(trap_frame_ecode_t* trap_frame) {
		project_status status = status_success;

		// Dispatch the exception
		status = seh::dispatch_driver_exception(trap_frame);
		if (status != status_success) {
            
		}
	} 

	/*
		Initialization functions
	*/

	project_status init_interrupts(uint64_t driver_base, uint64_t driver_size) {
		g_driver_base = driver_base;
		g_driver_size = driver_size;

		segment_descriptor_register_64 idt = { 0 };
		__sidt(&idt);

		memcpy(constructed_idt_table, (void*)idt.base_address, idt.limit);

        constructed_idt_table[divide_error] = create_interrupt_gate(asm_no_ecode_interrupt_handler);
        constructed_idt_table[invalid_opcode] = create_interrupt_gate(asm_no_ecode_interrupt_handler);

        constructed_idt_table[page_fault] = create_interrupt_gate(asm_ecode_interrupt_handler);
        constructed_idt_table[general_protection] = create_interrupt_gate(asm_ecode_interrupt_handler);

		// constructed_idt_table[nmi] = create_interrupt_gate(asm_nmi_handler);

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
        Exposed tests
    */
    project_status stress_test_seh(void) {
        if (!initialized)
            return status_not_initialized;

        project_status status = status_success;
        segment_descriptor_register_64 orig_idt = load_constructed_idt();

        // #GP
        __try {
            cr4 curr = { 0 };
            curr.flags = __readcr4();
            curr.reserved2 = 1;
            __writecr4(curr.flags);
        }
        __except (1) { }

        // #PF (read)
        __try {
            volatile int* p = reinterpret_cast<volatile int*>(0x1);
            int dummy = *p;
            UNREFERENCED_PARAMETER(dummy);

            status = status_pf_read_failed;
            goto cleanup;
        }
        __except (1) { }

        // #PF (write)
        __try {
            volatile int* p = reinterpret_cast<volatile int*>(0x1);
            *p = 0x1337;

            status = status_pf_write_failed;
            goto cleanup;
        }
        __except (1) { }

        // #DE
        __try {
            volatile int zero = 0;
            volatile int result = 1 / zero;
            UNREFERENCED_PARAMETER(result);

            status = status_de_failed;
            goto cleanup;
        }
        __except (1) { }

        // #UD
        __try {
            __ud2();

            status = status_ud_failed;
            goto cleanup;
        }
        __except (1) { }
 
        // #DE but in a recursive format to test
        // stack unwinding
        __try {
            recursive_de(4);

            status = status_nested_failed;
            goto cleanup;
        }
        __except (1) {}

    cleanup:
        load_original_idt(orig_idt);

        if (status == status_success) {
            project_log_info("Seh stress test finished successfully");
        }

        return status;
    }
};