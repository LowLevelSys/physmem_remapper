#pragma once
#include "../project_includes.hpp"
#include "../project/interrupts/interrupt_structs.hpp"
#include <ntddk.h>

struct info_page_t {
	segment_descriptor_register_64 constructed_idt;
	segment_descriptor_register_64 user_idt_storage;

	uint64_t nmi_panic_function_storage;
	uint64_t user_rsp_storage;
	uint64_t user_cr3_storage;
	uint8_t is_call_in_progress_flag;
};

namespace shellcode {
	inline void* g_enter_constructed_space = 0;
	inline void* g_exit_constructed_space = 0;
	inline void* g_nmi_shellcode = 0;

	inline info_page_t* g_info_page = 0;
	inline bool initialized = false;

	inline void construct_enter_shellcode(void* enter_constructed_space, info_page_t* info_page,
									      void* orig_data_ptr_value, void* handler_address, 
										  void* my_stack, uint64_t my_cr3) {
		static const uint8_t enter_shellcode[] = {
			// Disable interrupts
			0xFA,														// cli
			0x0F, 0xAE, 0xF0,                                           // mfence

			// Check call in progress flag
			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, imm64 (address of info_page->is_call_in_progress_flag)
			0x8A, 0x00,                                                 // mov al, [rax]
			0x84, 0xC0,                                                 // test al, al
			0x0F, 0x85, 0x8D, 0x00, 0x00, 0x00,				            // jne call_in_progress

			// Store the user cr3
			0x52,														// push rdx
			0x48, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rdx, imm64 (address of info_page->user_cr3_storage)
			0x48, 0x0F, 0x20, 0xD8,										// mov rax, cr3
			0x48, 0x89, 0x02,										    // mov [rdx], rax
			0x5A,														// pop rdx

			// Change to constructed cr3
			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, imm64 (constructed cr3 value)
			0x48, 0x0F, 0x22, 0xD8,										// mov cr3, rax

			// Flush the TLB via write to cr4 (clear PGE bit)
			0x0F, 0x20, 0xE0,                                           // mov rax, cr4
			0x48, 0x25, 0x7F, 0xFF, 0xFF, 0xFF,                         // and rax, 0xFFFFFFFFFFFFFF7F (clear PGE bit)
			0x0F, 0x22, 0xE0,                                           // mov cr4, rax
			0x48, 0x0D, 0x80, 0x00, 0x00, 0x00,                         // or rax, 0x80 (set PGE bit back)
			0x0F, 0x22, 0xE0,                                           // mov cr4, rax

			// Set the call in progress flag
			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, imm64 (address of info_page->is_call_in_progress_flag)
			0xC6, 0x00, 0x01,                                           // mov byte ptr [rax], 1 (set flag)

			// Store the user panic function
			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, imm64 (address of info_page->nmi_panic_function_storage)
			0x4C, 0x89, 0x00,											// mov [rax], r8 (save the function ptr)	

			// Store the user idt
			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, imm64 (address of info_page->user_idt_storage)
			0x0F, 0x01, 0x08,											// sidt [rax]

			// Load the constructed idt
			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, imm64 (address of info_page->constructed_idt)
			0x0F, 0x01, 0x18,											// lidt [rax]

			// Store the user rsp
			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, imm64 (address of info_page->user_rsp_storage)
			0x48, 0x89, 0x20,											// mov [rax], rsp

			// Load the constructed rsp
			0x48, 0xBC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rsp, imm64 (constructed rsp value)

			// Jump to my handler
			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, imm64 (address of my asm handler)
			0xFF, 0xE0,                                                 // jmp rax

			// call_in_progress:
			// Enable interrupts again
			0x0F, 0xAE, 0xF0,                                           // mfence
			0xFB,														// sti

			// jump_to_orig_data_ptr_value:
			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, imm64 (address of orig_data_ptr_value)
			0xFF, 0xE0,                                                 // jmp rax
		};

		crt::memcpy(enter_constructed_space, enter_shellcode, sizeof(enter_shellcode));


		*(void**)((uint8_t*)enter_constructed_space + 6) = &info_page->is_call_in_progress_flag;

		*(void**)((uint8_t*)enter_constructed_space + 27) = &info_page->user_cr3_storage;

		*(uint64_t*)((uint8_t*)enter_constructed_space + 45) = my_cr3;

		*(void**)((uint8_t*)enter_constructed_space + 80) = &info_page->is_call_in_progress_flag;

		*(void**)((uint8_t*)enter_constructed_space + 93) = &info_page->nmi_panic_function_storage;

		*(void**)((uint8_t*)enter_constructed_space + 106) = &info_page->user_idt_storage;

		*(void**)((uint8_t*)enter_constructed_space + 119) = &info_page->constructed_idt;

		*(void**)((uint8_t*)enter_constructed_space + 132) = &info_page->user_rsp_storage;

		*(void**)((uint8_t*)enter_constructed_space + 145) = my_stack;

		*(void**)((uint8_t*)enter_constructed_space + 155) = handler_address;

		// Calling the orig func in case a call is in progress
		*(void**)((uint8_t*)enter_constructed_space + 171) = orig_data_ptr_value;

	}

	inline void construct_exit_shellcode(void* exit_constructed_space, info_page_t* info_page, void* orig_data_ptr_value) {
		static const uint8_t exiting_shellcode[] = {
			0x48, 0x3D, 0xAD, 0xDE, 0x00, 0x00,							// cmp rax, 0xDEAD
			0x74, 0x51,							                        // je call_orig_data_ptr

			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, imm64 (address of info_page->user_rsp_storage)
			0x48, 0x8B, 0x20,											// mov rsp, [rax]

			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, imm64 (address of info_page->user_idt_storage)
			0x0F, 0x01, 0x18,											// lidt [rax]

			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, imm64 (address of info_page->user_cr3_storage)
			0x48, 0x8B, 0x00,											// mov rax [rax]
			0x0F, 0x22, 0xD8,											// mov cr3, rax

			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, imm64 (address of info_page->is_call_in_progress_flag)
			0xC6, 0x00, 0x00,                                           // mov byte ptr [rax], 0 (unset flag)

			// Flush the TLB via write to cr4 (clear PGE bit)
			0x0F, 0x20, 0xE0,                                           // mov rax, cr4
			0x48, 0x25, 0x7F, 0xFF, 0xFF, 0xFF,                         // and rax, 0xFFFFFFFFFFFFFF7F (clear PGE bit)
			0x0F, 0x22, 0xE0,                                           // mov cr4, rax
			0x48, 0x0D, 0x80, 0x00, 0x00, 0x00,                         // or rax, 0x80 (set PGE bit back)
			0x0F, 0x22, 0xE0,                                           // mov cr4, rax

			0x0F, 0xAE, 0xF0,                                           // mfence
			0xFB,														// sti

			0xC3,														// ret

			// call_orig_data_ptr
			// Call orig data ptr if return value rax was DEAD
						0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, imm64 (address of info_page->user_rsp_storage)
			0x48, 0x8B, 0x20,											// mov rsp, [rax]

			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, imm64 (address of info_page->user_idt_storage)
			0x0F, 0x01, 0x18,											// lidt [rax]

			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, imm64 (address of info_page->user_cr3_storage)
			0x48, 0x8B, 0x00,											// mov rax [rax]
			0x0F, 0x22, 0xD8,											// mov cr3, rax

			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, imm64 (address of info_page->is_call_in_progress_flag)
			0xC6, 0x00, 0x00,                                           // mov byte ptr [rax], 0 (unset flag)

			// Flush the TLB via write to cr4 (clear PGE bit)
			0x0F, 0x20, 0xE0,                                           // mov rax, cr4
			0x48, 0x25, 0x7F, 0xFF, 0xFF, 0xFF,                         // and rax, 0xFFFFFFFFFFFFFF7F (clear PGE bit)
			0x0F, 0x22, 0xE0,                                           // mov cr4, rax
			0x48, 0x0D, 0x80, 0x00, 0x00, 0x00,                         // or rax, 0x80 (set PGE bit back)
			0x0F, 0x22, 0xE0,                                           // mov cr4, rax

			0x0F, 0xAE, 0xF0,                                           // mfence
			0xFB,														// sti

			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, imm64 (address of orig_data_ptr_value)
			0xFF, 0xE0,                                                 // jmp rax
		};

		crt::memcpy(exit_constructed_space, exiting_shellcode, sizeof(exiting_shellcode));

		// Ret normally
		*(void**)((uint8_t*)exit_constructed_space + 10) = &info_page->user_rsp_storage;

		*(void**)((uint8_t*)exit_constructed_space + 23) = &info_page->user_idt_storage;

		*(void**)((uint8_t*)exit_constructed_space + 36) = &info_page->user_cr3_storage;

		*(void**)((uint8_t*)exit_constructed_space + 52) = &info_page->is_call_in_progress_flag;

		
		// Call the orig data ptr
		*(void**)((uint8_t*)exit_constructed_space + 91) = &info_page->user_rsp_storage;
		
		*(void**)((uint8_t*)exit_constructed_space + 104) = &info_page->user_idt_storage;

		*(void**)((uint8_t*)exit_constructed_space + 117) = &info_page->user_cr3_storage;

		*(void**)((uint8_t*)exit_constructed_space + 133) = &info_page->is_call_in_progress_flag;
		
		*(void**)((uint8_t*)exit_constructed_space + 171) = orig_data_ptr_value;
	}

	inline void construct_nmi_shellcode(void* exit_nmi_space, info_page_t* info_page, void* windows_nmi_handler) {
		static const uint8_t nmi_shellcode[] = {
			// Restore cr3
			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, imm64 (address of cr3_storage)
			0x48, 0x8B, 0x00,											// mov rax [rax]
			0x0F, 0x22, 0xD8,											// mov cr3, rax

			// Flush the TLB via write to cr4 (clear PGE bit)
			0x0F, 0x20, 0xE0,                                           // mov rax, cr4
			0x48, 0x25, 0x7F, 0xFF, 0xFF, 0xFF,                         // and rax, 0xFFFFFFFFFFFFFF7F (clear PGE bit)
			0x0F, 0x22, 0xE0,                                           // mov cr4, rax
			0x48, 0x0D, 0x80, 0x00, 0x00, 0x00,                         // or rax, 0x80 (set PGE bit back)
			0x0F, 0x22, 0xE0,                                           // mov cr4, rax

			// Restore idt
			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, imm64 (address of idt_storage)
			0x0F, 0x01, 0x18,											// lidt [rax]

			// Unset call_in_progress_fag
			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, imm64 (address of is_call_in_progress)
			0xC6, 0x00, 0x00,                                           // mov byte ptr [rax], 0 (unset flag)

			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, imm64 (address of handler_address)
			0xFF, 0xE0,                                                 // jmp rax
		};

		crt::memcpy(exit_nmi_space, nmi_shellcode, sizeof(nmi_shellcode));

		// Cr3 storage
		*(void**)((uint8_t*)exit_nmi_space + 2) = &info_page->user_cr3_storage;

		// Idt storage
		*(void**)((uint8_t*)exit_nmi_space + 39) = &info_page->user_idt_storage;

		// Call in progress flags
		*(void**)((uint8_t*)exit_nmi_space + 52) = &info_page->is_call_in_progress_flag;

		// Windows nmi handler address
		*(void**)((uint8_t*)exit_nmi_space + 65) = windows_nmi_handler;
	}

	inline project_status construct_shellcodes(void*& enter_constructed_space, void*& exit_constructed_space, void*& nmi_shellcode,
											   void* windows_nmi_handler, segment_descriptor_register_64 my_idt_ptr,
											   void* orig_data_ptr_value, void* handler_address, 
											   void* my_stack_base, uint64_t my_cr3) {
		PHYSICAL_ADDRESS max_addr = { 0 };
		project_status status = status_success;
		info_page_t* info_page = 0;

		max_addr.QuadPart = MAXULONG64;

		enter_constructed_space = MmAllocateContiguousMemory(PAGE_SIZE, max_addr);
		exit_constructed_space = MmAllocateContiguousMemory(PAGE_SIZE, max_addr);
		nmi_shellcode = MmAllocateContiguousMemory(PAGE_SIZE, max_addr);
		info_page = (info_page_t*)MmAllocateContiguousMemory(PAGE_SIZE, max_addr);

		if (!enter_constructed_space || !exit_constructed_space || !nmi_shellcode || !info_page) {
			status = status_memory_allocation_failed;
			goto cleanup;
		}

		memset(enter_constructed_space, 0, PAGE_SIZE);
		memset(exit_constructed_space, 0, PAGE_SIZE);
		memset(nmi_shellcode, 0, PAGE_SIZE);
		memset(info_page, 0, PAGE_SIZE);

		info_page->constructed_idt = my_idt_ptr;

		construct_enter_shellcode(enter_constructed_space, info_page,
								  orig_data_ptr_value, 
								  handler_address,
								  my_stack_base, my_cr3);

		construct_exit_shellcode(exit_constructed_space, info_page, orig_data_ptr_value);

		construct_nmi_shellcode(nmi_shellcode, info_page, windows_nmi_handler);

		g_enter_constructed_space = enter_constructed_space;
		g_exit_constructed_space = exit_constructed_space;
		g_nmi_shellcode = nmi_shellcode;

		g_info_page = info_page;
		initialized = true;

	cleanup:
		return status;
	}

	inline void log_shellcode_addresses(void) {
		project_log_info("Entering shellcode at %p", g_enter_constructed_space);
		project_log_info("Exiting shellcode at %p", g_exit_constructed_space);
		project_log_info("Nmi shellcode at %p", g_nmi_shellcode);
	}

	inline uint64_t get_current_user_cr3(void) {
		if (!initialized)
			return 0;

		return g_info_page->user_cr3_storage;
	}

	inline uint64_t get_current_nmi_panic_function(void) {
		if (!initialized)
			return 0;

		return g_info_page->nmi_panic_function_storage;
	}

	inline uint64_t get_current_user_rsp(void) {
		if (!initialized)
			return 0;

		return g_info_page->user_rsp_storage;
	}

	inline bool get_current_is_call_in_progress(void) {
		if (!initialized)
			return 0;

		return g_info_page->is_call_in_progress_flag;
	}
};