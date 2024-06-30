#pragma once
#include "../project_includes.hpp"
#include "../project/interrupts/interrupt_structs.hpp"
#include "../project/stack/stack_manager.hpp"
#include "../project/interrupts/interrupts.hpp"

#include <ntddk.h>

struct info_page_t {
	segment_descriptor_register_64 constructed_idt;
	segment_descriptor_register_64 user_idt_storage;

	uint64_t constructed_rsp;

	uint64_t user_rsp_storage;
	uint64_t user_cr3_storage;

	uint64_t nmi_panic_function_storage;
};

namespace shellcode {
	inline void* g_enter_constructed_space_executed = 0;
	inline void* g_enter_constructed_space_shown = 0;
	inline void* g_exit_constructed_space = 0;
	inline void* g_nmi_shellcode = 0;

	inline info_page_t* g_info_page = 0;
	inline bool initialized = false;

	inline void construct_executed_enter_shellcode(void* enter_constructed_space, info_page_t* info_page_base,
									      void* orig_data_ptr_value, void* handler_address, 
										  uint64_t constructed_cr3) {
		static const uint8_t start_place_holder_shellcode[] = {
			0xFA,                                                       // cli
			0x0F, 0xAE, 0xF0,                                           // mfence
			0x81, 0xFA, 0x69, 0x69, 0x00, 0x00,                         // cmp edx, 0x6969
			0x74, 0x0D,                                                 // je jump_to_handler
			0xFB,                                                       // sti
			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, imm64 (address of orig_data_ptr_value)
			0xFF, 0xE0,                                                 // jmp rax

			// jump_to_handler:
			0x53,                                                       // push rbx
			0x51,                                                       // push rcx
			0x52,                                                       // push rdx
			0x48, 0x31, 0xC0,                                           // xor rax, rax
			0xB8, 0x0B, 0x00, 0x00, 0x00,                               // mov eax, 0x0B (Leaf)
			0x31, 0xC9,                                                 // xor ecx, ecx
			0x0F, 0xA2,                                                 // cpuid
			0x8B, 0xC2,                                                 // mov eax, edx
			0x5A,                                                       // pop rdx
			0x59,                                                       // pop rcx
			0x5B,                                                       // pop rbx
			0x48, 0x6B, 0xC0, 0x00,                                     // imul rax, rax, sizeof(info_page_t)
			0x53,                                                       // push rbx
			0x48, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rbx, imm64 (info_page_base)
			0x48, 0x01, 0xD8,                                           // add rax, rbx
			0x5B,                                                       // pop rbx
			0x48, 0x8B, 0xD0,                                           // mov rdx, rax
		};

		static const uint8_t cr3_shellcode[] = {
			// Store the user Cr3
			0x52,                                                       // push rdx
			0x48, 0x83, 0xC0, 0x00,                                     // add rax, offsetof(info_page_t, user_cr3_storage)
			0x48, 0x0F, 0x20, 0xDA,                                     // mov rdx, cr3
			0x48, 0x89, 0x10,                                           // mov [rax], rdx
			0x5A,                                                       // pop rdx

			// Change to constructed Cr3
			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, imm64 (constructed cr3 value)
			0x48, 0x0F, 0x22, 0xD8,                                     // mov cr3, rax
			0x0F, 0xAE, 0xF0											// mfence
		};

		static const uint8_t nmi_panic_shellcode[] = {
			0x48, 0x8B, 0xC2,                                           // mov rax, rdx

			// Store the NMI panic function
			0x48, 0x83, 0xC0, 0x00,                                     // add rax, offsetof(info_page_t, nmi_panic_function_storage)
			0x4C, 0x89, 0x00,                                           // mov [rax], r8
		};

		static const uint8_t rsp_shellcode[] = {
			0x48, 0x8B, 0xC2,                                           // mov rax, rdx

			// Store the user RSP
			0x48, 0x83, 0xC0, 0x00,                                     // add rax, offsetof(info_page_t, user_rsp_storage)
			0x48, 0x89, 0x20,                                           // mov [rax], rsp
			0x48, 0x8B, 0xC2,                                           // mov rax, rdx

			// Load the constructed RSP
			0x48, 0x83, 0xC0, 0x00,                                     // add rax, offsetof(info_page_t, constructed_rsp)
			0x48, 0x8B, 0x00,                                           // mov rsp, [rax]
		};

		static const uint8_t idt_shellcode[] = {
			0x48, 0x8B, 0xC2,                                           // mov rax, rdx

			// Save the user IDT
			0x48, 0x83, 0xC0, 0x00,                                     // add rax, offsetof(info_page_t, user_idt_storage)
			0x0F, 0x01, 0x08,                                           // sidt [rax]
			0x48, 0x8B, 0xC2,                                           // mov rax, rdx

			// Load the constructed IDT
			0x48, 0x83, 0xC0, 0x00,                                     // add rax, offsetof(info_page_t, constructed_idt)
			0x0F, 0x01, 0x18,                                           // lidt [rax]
		};

		static const uint8_t jump_to_handler_shellcode[] = {
			// Jump to my handler
			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, imm64 (address of my asm handler)
			0xFF, 0xE0                                                  // jmp rax
		};

		*(void**)((uint8_t*)start_place_holder_shellcode + 15) = orig_data_ptr_value;
		*(uint8_t*)((uint8_t*)start_place_holder_shellcode + 48) = sizeof(info_page_t);
		*(void**)((uint8_t*)start_place_holder_shellcode + 52) = info_page_base;

		*(uint8_t*)((uint8_t*)cr3_shellcode + 4) = offsetof(info_page_t, user_cr3_storage);
		*(uint64_t*)((uint8_t*)cr3_shellcode + 15) = constructed_cr3;

		*(uint8_t*)((uint8_t*)nmi_panic_shellcode + 6) = offsetof(info_page_t, nmi_panic_function_storage);

		*(uint8_t*)((uint8_t*)rsp_shellcode + 6) = offsetof(info_page_t, user_rsp_storage);
		*(uint8_t*)((uint8_t*)rsp_shellcode + 16) = offsetof(info_page_t, constructed_rsp);

		*(uint8_t*)((uint8_t*)idt_shellcode + 6) = offsetof(info_page_t, user_idt_storage);
		*(uint8_t*)((uint8_t*)idt_shellcode + 16) = offsetof(info_page_t, constructed_idt);

		*(void**)((uint8_t*)jump_to_handler_shellcode + 2) = handler_address;

		uint8_t* current_position = (uint8_t*)enter_constructed_space;
		crt::memcpy(current_position, start_place_holder_shellcode, sizeof(start_place_holder_shellcode));
		current_position += sizeof(start_place_holder_shellcode);

		crt::memcpy(current_position, cr3_shellcode, sizeof(cr3_shellcode));
		current_position += sizeof(cr3_shellcode);

		crt::memcpy(current_position, nmi_panic_shellcode, sizeof(nmi_panic_shellcode));
		current_position += sizeof(nmi_panic_shellcode);

		crt::memcpy(current_position, rsp_shellcode, sizeof(rsp_shellcode));
		current_position += sizeof(rsp_shellcode);

		crt::memcpy(current_position, idt_shellcode, sizeof(idt_shellcode));
		current_position += sizeof(idt_shellcode);

		crt::memcpy(current_position, jump_to_handler_shellcode, sizeof(jump_to_handler_shellcode));
	}

	inline void construct_shown_enter_shellcode(void* enter_constructed_space, info_page_t* info_page_base,
												   void* orig_data_ptr_value, uint64_t constructed_cr3) {
		static const uint8_t start_place_holder_shellcode[] = {
			0xFA,                                                       // cli
			0x0F, 0xAE, 0xF0,                                           // mfence
			0x81, 0xFA, 0x69, 0x69, 0x00, 0x00,                         // cmp edx, 0x6969
			0x74, 0x0D,                                                 // je jump_to_handler
			0xFB,                                                       // sti
			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, imm64 (address of orig_data_ptr_value)
			0xFF, 0xE0,                                                 // jmp rax

			// jump_to_handler:
			0x53,                                                       // push rbx
			0x51,                                                       // push rcx
			0x52,                                                       // push rdx
			0x48, 0x31, 0xC0,                                           // xor rax, rax
			0xB8, 0x0B, 0x00, 0x00, 0x00,                               // mov eax, 0x0B (Leaf)
			0x31, 0xC9,                                                 // xor ecx, ecx
			0x0F, 0xA2,                                                 // cpuid
			0x8B, 0xC2,                                                 // mov eax, edx
			0x5A,                                                       // pop rdx
			0x59,                                                       // pop rcx
			0x5B,                                                       // pop rbx
			0x48, 0x6B, 0xC0, 0x00,                                     // imul rax, rax, sizeof(info_page_t)
			0x53,                                                       // push rbx
			0x48, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rbx, imm64 (info_page_base)
			0x48, 0x01, 0xD8,                                           // add rax, rbx
			0x5B,                                                       // pop rbx
			0x48, 0x8B, 0xD0,                                           // mov rdx, rax
		};

		static const uint8_t cr3_shellcode[] = {
			// Store the user Cr3
			0x52,                                                       // push rdx
			0x48, 0x83, 0xC0, 0x00,                                     // add rax, offsetof(info_page_t, user_cr3_storage)
			0x48, 0x0F, 0x20, 0xDA,                                     // mov rdx, cr3
			0x48, 0x89, 0x10,                                           // mov [rax], rdx
			0x5A,                                                       // pop rdx

			// Change to constructed Cr3
			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, imm64 (constructed cr3 value)
			0x48, 0x0F, 0x22, 0xD8,                                     // mov cr3, rax
			0x0F, 0xAE, 0xF0											// mfence
		};

		// Won't be executed
		static const uint8_t return_shellcode[] = {
			0x90,														// lock nop (only here to act as a buffer for the lock)
			0xC3														// ret
		};

		*(void**)((uint8_t*)start_place_holder_shellcode + 15) = orig_data_ptr_value;
		*(uint8_t*)((uint8_t*)start_place_holder_shellcode + 48) = sizeof(info_page_t);
		*(void**)((uint8_t*)start_place_holder_shellcode + 52) = info_page_base;

		*(uint8_t*)((uint8_t*)cr3_shellcode + 4) = offsetof(info_page_t, user_cr3_storage);
		*(uint64_t*)((uint8_t*)cr3_shellcode + 15) = constructed_cr3;

		uint8_t* current_position = (uint8_t*)enter_constructed_space;
		crt::memcpy(current_position, start_place_holder_shellcode, sizeof(start_place_holder_shellcode));
		current_position += sizeof(start_place_holder_shellcode);

		crt::memcpy(current_position, cr3_shellcode, sizeof(cr3_shellcode));
		current_position += sizeof(cr3_shellcode);

		crt::memcpy(current_position, return_shellcode, sizeof(return_shellcode));
		current_position += sizeof(return_shellcode);
	}

	inline void construct_exit_shellcode(void* exit_constructed_space, info_page_t* info_page_base) {
		static const uint8_t calculate_base_shellcode[] = {
			0x53,                                                       // push rbx
			0x51,                                                       // push rcx
			0x52,                                                       // push rdx
			0x48, 0x31, 0xC0,                                           // xor rax, rax (only eax, eax would be necessary but I want to clear rax fully for the imul)
			0xB8, 0x0B, 0x00, 0x00, 0x00,                               // mov eax, 0x0B (Leaf)
			0x31, 0xC9,                                                 // xor ecx, ecx
			0x0F, 0xA2,                                                 // cpuid
			0x8B, 0xC2,                                                 // mov eax, edx (Store Apic id in eax)
			0x5A,                                                       // pop rdx
			0x59,                                                       // pop rcx
			0x5B,                                                       // pop rbx
			0x48, 0x6B, 0xC0, 0x00,                                     // imul rax, rax, sizeof(info_page_t) (calculate the offset)
			0x53,                                                       // push rbx
			0x48, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rbx, imm64 (info_page_base)
			0x48, 0x01, 0xD8,                                           // add rax, rbx
			0x5B,                                                       // pop rbx
			0x48, 0x8B, 0xD0,                                           // mov rdx, rax (save &info_page_base[apic_id] into rdx)
		};

		static const uint8_t restore_rsp_shellcode[] = {
			// Restore Rsp
			0x48, 0x83, 0xC0, 0x00,										// add rax, offsetof(info_page_t, user_rsp_storage)
			0x48, 0x8B, 0x20,											// mov rsp, [rax]

			0x48, 0x8B, 0xC2,											// mov rax, rdx (Restore &info_page_base[apic_id] from rdx)
		};

		static const uint8_t restore_idt_shellcode[] = {
			0x48, 0x83, 0xC0, 0x00,                                     // add rax, offsetof(info_page_t, user_idt_storage)
			0x0F, 0x01, 0x18,                                           // lidt [rax]
			0x48, 0x8B, 0xC2,                                           // mov rax, rdx (Restore &info_page_base[apic_id] from rdx)
		};

		static const uint8_t restore_cr3_shellcode[] = {
			0x48, 0x83, 0xC0, 0x00,                                     // add rax, offsetof(info_page_t, user_cr3_storage)
			0x48, 0x8B, 0x00,                                           // mov rax, [rax]
			0x0F, 0x22, 0xD8,                                           // mov cr3, rax
			0x0F, 0xAE, 0xF0											// mfence
		};

		static const uint8_t return_shellcode[] = {
			0x90,														// lock nop (only here to act as a buffer for the lock)
			0xC3														// ret
		};

		*(uint8_t*)((uint8_t*)calculate_base_shellcode + 23) = sizeof(info_page_t);

		*(void**)((uint8_t*)calculate_base_shellcode + 27) = info_page_base;

		*(uint8_t*)((uint8_t*)restore_rsp_shellcode + 3) = offsetof(info_page_t, user_rsp_storage);

		*(uint8_t*)((uint8_t*)restore_idt_shellcode + 3) = offsetof(info_page_t, user_idt_storage);

		*(uint8_t*)((uint8_t*)restore_cr3_shellcode + 3) = offsetof(info_page_t, user_cr3_storage);

		uint8_t* current_position = (uint8_t*)exit_constructed_space;
		crt::memcpy(current_position, calculate_base_shellcode, sizeof(calculate_base_shellcode));
		current_position += sizeof(calculate_base_shellcode);

		crt::memcpy(current_position, restore_rsp_shellcode, sizeof(restore_rsp_shellcode));
		current_position += sizeof(restore_rsp_shellcode);

		crt::memcpy(current_position, restore_idt_shellcode, sizeof(restore_idt_shellcode));
		current_position += sizeof(restore_idt_shellcode);

		crt::memcpy(current_position, restore_cr3_shellcode, sizeof(restore_cr3_shellcode));
		current_position += sizeof(restore_cr3_shellcode);

		crt::memcpy(current_position, return_shellcode, sizeof(return_shellcode));
		current_position += sizeof(return_shellcode);
	}

	inline void construct_nmi_shellcode(void* nmi_shellcode, info_page_t* info_page_base, void* windows_nmi_handler) {
		static const uint8_t calculate_base_shellcode[] = {
			0x53,                                                       // push rbx
			0x51,                                                       // push rcx
			0x52,                                                       // push rdx
			0x48, 0x31, 0xC0,                                           // xor rax, rax (only eax, eax would be necessary but I want to clear rax fully for the imul)
			0xB8, 0x0B, 0x00, 0x00, 0x00,                               // mov eax, 0x0B (Leaf)
			0x31, 0xC9,                                                 // xor ecx, ecx
			0x0F, 0xA2,                                                 // cpuid
			0x8B, 0xC2,                                                 // mov eax, edx (Store Apic id in eax)
			0x5A,                                                       // pop rdx
			0x59,                                                       // pop rcx
			0x5B,                                                       // pop rbx
			0x48, 0x6B, 0xC0, 0x00,                                     // imul rax, rax, sizeof(info_page_t) (calculate the offset)
			0x53,                                                       // push rbx
			0x48, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rbx, imm64 (info_page_base)
			0x48, 0x01, 0xD8,                                           // add rax, rbx
			0x5B,                                                       // pop rbx
			0x48, 0x8B, 0xD0,                                           // mov rdx, rax (save &info_page_base[apic_id] into rdx)
		};

		static const uint8_t restore_idt_shellcode[] = {
			0x48, 0x83, 0xC0, 0x00,                                     // add rax, offsetof(info_page_t, user_idt_storage)
			0x0F, 0x01, 0x18,                                           // lidt [rax]
			0x48, 0x8B, 0xC2,                                           // mov rax, rdx (Restore &info_page_base[apic_id] from rdx)
		};

		static const uint8_t restore_cr3_shellcode[] = {
			0x48, 0x83, 0xC0, 0x00,                                     // add rax, offsetof(info_page_t, user_cr3_storage)
			0x48, 0x8B, 0x00,                                           // mov rax, [rax]
			0x0F, 0x22, 0xD8,                                           // mov cr3, rax
			0x0F, 0xAE, 0xF0											// mfence
		};

		static const uint8_t jump_windows_handler[] = {
			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, imm64 (address of handler_address)
			0xFF, 0xE0,                                                 // jmp rax
		};

		*(uint8_t*)((uint8_t*)calculate_base_shellcode + 23) = sizeof(info_page_t);

		*(void**)((uint8_t*)calculate_base_shellcode + 27) = info_page_base;

		*(uint8_t*)((uint8_t*)restore_idt_shellcode + 3) = offsetof(info_page_t, user_idt_storage);

		*(uint8_t*)((uint8_t*)restore_cr3_shellcode + 3) = offsetof(info_page_t, user_cr3_storage);

		*(void**)((uint8_t*)jump_windows_handler + 2) = windows_nmi_handler;

		uint8_t* current_position = (uint8_t*)nmi_shellcode;
		crt::memcpy(current_position, calculate_base_shellcode, sizeof(calculate_base_shellcode));
		current_position += sizeof(calculate_base_shellcode);

		crt::memcpy(current_position, restore_idt_shellcode, sizeof(restore_idt_shellcode));
		current_position += sizeof(restore_idt_shellcode);

		crt::memcpy(current_position, restore_cr3_shellcode, sizeof(restore_cr3_shellcode));
		current_position += sizeof(restore_cr3_shellcode);

		crt::memcpy(current_position, jump_windows_handler, sizeof(jump_windows_handler));
		current_position += sizeof(jump_windows_handler);
	}

	inline project_status construct_shellcodes(void*& enter_constructed_space_executed, void*& enter_constructed_space_shown, void*& exit_constructed_space, void*& nmi_shellcode,
											   segment_descriptor_register_64 my_idt_ptr,
											   void* orig_data_ptr_value, void* handler_address, 
											   uint64_t constructed_cr3) {
		PHYSICAL_ADDRESS max_addr = { 0 };
		project_status status = status_success;
		info_page_t* info_page = 0;

		max_addr.QuadPart = MAXULONG64;

		enter_constructed_space_executed = MmAllocateContiguousMemory(PAGE_SIZE, max_addr);
		enter_constructed_space_shown = MmAllocateContiguousMemory(PAGE_SIZE, max_addr);
		exit_constructed_space = MmAllocateContiguousMemory(PAGE_SIZE, max_addr);
		nmi_shellcode = MmAllocateContiguousMemory(PAGE_SIZE, max_addr);
		info_page = (info_page_t*)MmAllocateContiguousMemory(MAX_PROCESSOR_COUNT * sizeof(info_page_t), max_addr);

		if (!enter_constructed_space_executed || !enter_constructed_space_shown || !exit_constructed_space || !info_page) {
			status = status_memory_allocation_failed;
			goto cleanup;
		}

		crt::memset(enter_constructed_space_executed, 0, PAGE_SIZE);
		crt::memset(enter_constructed_space_shown, 0, PAGE_SIZE);
		crt::memset(exit_constructed_space, 0, PAGE_SIZE);
		crt::memset(nmi_shellcode, 0, PAGE_SIZE);
		crt::memset(info_page, 0, PAGE_SIZE);


		/*
			Setup every info page for each core
		*/
		for (uint32_t i = 0; i < KeQueryActiveProcessorCount(0); i++) {

			status = stack_manager::get_stack_base((void*&)info_page[i].constructed_rsp, i);
			if (status != status_success)
				return status;

			info_page[i].constructed_idt = my_idt_ptr;
		}

		construct_executed_enter_shellcode(enter_constructed_space_executed, info_page,
								  orig_data_ptr_value, 
								  handler_address, constructed_cr3);

		construct_shown_enter_shellcode(enter_constructed_space_shown, info_page, 
										orig_data_ptr_value, constructed_cr3);

		construct_exit_shellcode(exit_constructed_space, info_page);

		construct_nmi_shellcode(nmi_shellcode, info_page, interrupts::get_windows_nmi_handler());

		g_enter_constructed_space_executed = enter_constructed_space_executed;
		g_enter_constructed_space_shown = enter_constructed_space_shown;
		g_exit_constructed_space = exit_constructed_space;
		g_nmi_shellcode = nmi_shellcode;

		g_info_page = info_page;
		initialized = true;

	cleanup:
		return status;
	}

	inline void log_shellcode_addresses(void) {

		project_log_info("Executed entering shellcode at %p", g_enter_constructed_space_executed);
		project_log_info("Shown entering shellcode at %p", g_enter_constructed_space_shown);
		project_log_info("Exiting shellcode at %p", g_exit_constructed_space);
		project_log_info("Nmi shellcode at %p", g_nmi_shellcode);
	}

	inline uint64_t get_current_user_cr3(void) {
		if (!initialized)
			return 0;

		return g_info_page[get_proc_number()].user_cr3_storage;
	}

	inline uint64_t get_current_nmi_panic_function(void) {
		if (!initialized)
			return 0;

		return g_info_page[get_proc_number()].nmi_panic_function_storage;
	}

	inline uint64_t get_current_user_rsp(void) {
		if (!initialized)
			return 0;

		return g_info_page[get_proc_number()].user_rsp_storage;
	}
};