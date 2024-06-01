#pragma once
#include "../project_includes.hpp"
#include "../project/interrupts/interrupt_structs.hpp"

namespace shellcode {
	inline void* g_enter_constructed_space = 0;
	inline void* g_exit_constructed_space = 0;
	inline void* g_nmi_shellcode = 0;

	inline void* g_info_page = 0;

	inline uint64_t* cr3_storing_region;

	inline bool initialized = false;

	inline void construct_enter_shellcode(void* enter_constructed_space, void* info_page, segment_descriptor_register_64 my_idt_ptr,
									      void* orig_data_ptr_value, void* handler_address, 
										  void* my_stack, uint64_t my_cr3) {
		UNREFERENCED_PARAMETER(enter_constructed_space);
		UNREFERENCED_PARAMETER(info_page);
		UNREFERENCED_PARAMETER(my_idt_ptr);
		UNREFERENCED_PARAMETER(orig_data_ptr_value);
		UNREFERENCED_PARAMETER(handler_address);
		UNREFERENCED_PARAMETER(my_stack);
		UNREFERENCED_PARAMETER(my_cr3);

		static const uint8_t enter_shellcode[] = {
			// First check if is_call_in_progress is set
			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, imm64 (address of is_call_in_progress)
			0x8A, 0x00,                                                 // mov al, [rax]
			0x84, 0xC0,                                                 // test al, al
			0x0F, 0x85, 0x82, 0x00, 0x00, 0x00,                         // jne call_in_progress
	
			// If no call in progress, check rdx
			0x81, 0xFA, 0x69, 0x69, 0x00, 0x00,                         // cmp edx, 0x6969
			0x0F, 0x85, 0x89, 0x00, 0x00, 0x00,                         // jne jump_to_orig_data_ptr_value

			// If the call is our call, set is_call_in_progress and call our handler
			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, imm64 (address of is_call_in_progress)
			0xC6, 0x00, 0x01,                                           // mov byte ptr [rax], 1 (set flag)

			0xFA,														// cli

			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, imm64 (address of panic_function_storage)
			0x4C, 0x89, 0x00,											// mov [rax], r8 (save the function ptr)	

			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, imm64 (address of rsp_storage)
			0x48, 0x89, 0x20,											// mov [rax], rsp
			0x48, 0xBC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rsp, imm64 (address of my_stack)

			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, imm64 (address of cr3_storage)
			0x48, 0x0F, 0x20, 0xDA,										// mov rdx, cr3
			0x48, 0x89, 0x10,											// mov [rax], rdx

			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, imm64 (my_cr3 value)
			0x0F, 0x22, 0xD8,											// mov cr3, rax

			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, imm64 (address of idt_storage)
			0x0F, 0x01, 0x08,											// sidt [rax]

			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, imm64 (address of my_idt_ptr)
			0x0F, 0x01, 0x18,											// lidt [rax]

			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, imm64 (address of handler_address)
			0xFF, 0xE0,                                                 // jmp rax

			// call_in_progress:
			0x81, 0xFA, 0x69, 0x69, 0x00, 0x00,                         // cmp edx, 0x6969
			0x75, 0x0B,                                                 // jne jump_to_orig_data_ptr_value
			0x48, 0xB8, 0x96, 0x96, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, 0x9696
			0xC3,                                                       // ret

			// jump_to_orig_data_ptr_value:
			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, imm64 (address of orig_data_ptr_value)
			0xFF, 0xE0                                                  // jmp rax
		};

		crt::memcpy(enter_constructed_space, enter_shellcode, sizeof(enter_shellcode));

		// Call in progress flags
		uint64_t is_call_in_progress_addr = (uint64_t)info_page;
		crt::memcpy((uint8_t*)enter_constructed_space + 2, &is_call_in_progress_addr, sizeof(is_call_in_progress_addr));
		crt::memcpy((uint8_t*)enter_constructed_space + 34, &is_call_in_progress_addr, sizeof(is_call_in_progress_addr));
		
		// Nmi-Restoring function
		uint64_t* panic_function_storage_addr = (uint64_t*)((uint64_t)info_page + 4 * sizeof(uint64_t));
		crt::memcpy((uint8_t*)enter_constructed_space + 48, &panic_function_storage_addr, sizeof(panic_function_storage_addr));

		// Rsp storage
		uint64_t rsp_storage_addr = (uint64_t)info_page + sizeof(uint64_t);
		crt::memcpy((uint8_t*)enter_constructed_space + 61, &rsp_storage_addr, sizeof(rsp_storage_addr));

		// My rsp
		uint64_t my_stack_addr = (uint64_t)my_stack;
		crt::memcpy((uint8_t*)enter_constructed_space + 74, &my_stack_addr, sizeof(my_stack_addr));

		// Cr3 storage
		uint64_t cr3_storage_address = (uint64_t)info_page + 2 * sizeof(uint64_t);
		crt::memcpy((uint8_t*)enter_constructed_space + 84, &cr3_storage_address, sizeof(cr3_storage_address));

		// My Cr3 value
		crt::memcpy((uint8_t*)enter_constructed_space + 101, &my_cr3, sizeof(my_cr3));

		// Idt storage
		uint64_t idt_storage_addr = (uint64_t)info_page + 3 * sizeof(uint64_t);
		crt::memcpy((uint8_t*)enter_constructed_space + 114, &idt_storage_addr, sizeof(idt_storage_addr));

		// My Idt storage
		crt::memcpy((uint8_t*)enter_constructed_space + 500, &my_idt_ptr, sizeof(my_idt_ptr));
		uint64_t my_idt_storage_addr = (uint64_t)enter_constructed_space + 500;
		crt::memcpy((uint8_t*)enter_constructed_space + 127, &my_idt_storage_addr, sizeof(idt_storage_addr));

		// My handler address
		uint64_t handler_address_val = (uint64_t)handler_address;
		crt::memcpy((uint8_t*)enter_constructed_space + 140, &handler_address_val, sizeof(handler_address_val));

		// Orig NtUserGetCmd
		uint64_t orig_data_ptr_value_addr = (uint64_t)orig_data_ptr_value;
		crt::memcpy((uint8_t*)enter_constructed_space + 171, &orig_data_ptr_value_addr, sizeof(orig_data_ptr_value_addr));
	}

	inline void construct_exit_shellcode(void* exit_constructed_space, void* info_page) {
		static const uint8_t exiting_shellcode[] = {
			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, imm64 (address of is_call_in_progress)
			0xC6, 0x00, 0x00,                                           // mov byte ptr [rax], 0 (unset flag)

			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, imm64 (address of rsp_storage)
			0x48, 0x8B, 0x20,											// mov rsp, [rax]

			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, imm64 (address of cr3_storage)
			0x48, 0x8B, 0x00,											// mov rax [rax]
			0x0F, 0x22, 0xD8,											// mov cr3, rax

			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, imm64 (address of idt_storage)
			0x0F, 0x01, 0x18,											// lidt [rax]

			0xFB,														// sti

			0xC3														// ret
		};

		crt::memcpy(exit_constructed_space, exiting_shellcode, sizeof(exiting_shellcode));

		uint64_t is_call_in_progress_addr = (uint64_t)info_page;
		crt::memcpy((uint8_t*)exit_constructed_space + 2, &is_call_in_progress_addr, sizeof(is_call_in_progress_addr));

		uint64_t rsp_storage_addr = (uint64_t)info_page + sizeof(uint64_t);
		crt::memcpy((uint8_t*)exit_constructed_space + 15, &rsp_storage_addr, sizeof(rsp_storage_addr));

		uint64_t cr3_storage_addr = (uint64_t)info_page + 2 * sizeof(uint64_t);
		crt::memcpy((uint8_t*)exit_constructed_space + 28, &cr3_storage_addr, sizeof(cr3_storage_addr));

		uint64_t idt_storage_addr = (uint64_t)info_page + 3 * sizeof(uint64_t);
		crt::memcpy((uint8_t*)exit_constructed_space + 44, &idt_storage_addr, sizeof(idt_storage_addr));
	}

	inline void construct_nmi_shellcode(void* exit_nmi_space, void* info_page, void* windows_nmi_handler) {
		static const uint8_t nmi_shellcode[] = {
			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, imm64 (address of is_call_in_progress)
			0xC6, 0x00, 0x00,                                           // mov byte ptr [rax], 0 (unset flag)

			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, imm64 (address of cr3_storage)
			0x48, 0x8B, 0x00,											// mov rax [rax]
			0x0F, 0x22, 0xD8,											// mov cr3, rax

			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, imm64 (address of idt_storage)
			0x0F, 0x01, 0x18,											// lidt [rax]

			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, imm64 (address of handler_address)
			0xFF, 0xE0,                                                 // jmp rax
		};

		crt::memcpy(exit_nmi_space, nmi_shellcode, sizeof(nmi_shellcode));

		// Call in progress flags
		uint64_t is_call_in_progress_addr = (uint64_t)info_page;
		crt::memcpy((uint8_t*)exit_nmi_space + 2, &is_call_in_progress_addr, sizeof(is_call_in_progress_addr));

		// Cr3 storage
		uint64_t cr3_storage_addr = (uint64_t)info_page + 2 * sizeof(uint64_t);
		crt::memcpy((uint8_t*)exit_nmi_space + 15, &cr3_storage_addr, sizeof(cr3_storage_addr));

		// Idt storage
		uint64_t idt_storage_addr = (uint64_t)info_page + 3 * sizeof(uint64_t);
		crt::memcpy((uint8_t*)exit_nmi_space + 31, &idt_storage_addr, sizeof(idt_storage_addr));

		// Windows nmi handler address
		crt::memcpy((uint8_t*)exit_nmi_space + 44, &windows_nmi_handler, sizeof(windows_nmi_handler));
	}

	inline project_status construct_shellcodes(void*& enter_constructed_space, void*& exit_constructed_space, void*& nmi_shellcode,
											   void* windows_nmi_handler, segment_descriptor_register_64 my_idt_ptr,
											   void* orig_data_ptr_value, void* handler_address, 
											   void* my_stack_base, uint64_t my_cr3) {
		PHYSICAL_ADDRESS max_addr = { 0 };
		project_status status = status_success;
		void* info_page = 0;

		max_addr.QuadPart = MAXULONG64;

		enter_constructed_space = MmAllocateContiguousMemory(PAGE_SIZE, max_addr);
		exit_constructed_space = MmAllocateContiguousMemory(PAGE_SIZE, max_addr);
		nmi_shellcode = MmAllocateContiguousMemory(PAGE_SIZE, max_addr);
		info_page = MmAllocateContiguousMemory(PAGE_SIZE, max_addr);

		if (!enter_constructed_space || !exit_constructed_space || !nmi_shellcode || !info_page) {
			status = status_memory_allocation_failed;
			goto cleanup;
		}

		crt::memset(enter_constructed_space, 0, PAGE_SIZE);
		crt::memset(exit_constructed_space, 0, PAGE_SIZE);
		crt::memset(nmi_shellcode, 0, PAGE_SIZE);
		crt::memset(info_page, 0, PAGE_SIZE);
		
		construct_enter_shellcode(enter_constructed_space, info_page, 
								  my_idt_ptr, orig_data_ptr_value, 
								  handler_address,
								  my_stack_base, my_cr3);

		construct_exit_shellcode(exit_constructed_space, info_page);

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

		uint64_t* cr3_storage_addr = (uint64_t*)((uint64_t)g_info_page + 2 * sizeof(uint64_t));

		return *cr3_storage_addr;
	}

	inline uint64_t get_current_nmi_panic_function(void) {
		if (!initialized)
			return 0;

		uint64_t* panic_function_storage_addr = (uint64_t*)((uint64_t)g_info_page + 4 * sizeof(uint64_t));

		return *panic_function_storage_addr;
	}

	inline uint64_t get_current_user_rsp(void) {
		if (!initialized)
			return 0;

		uint64_t* rsp_storage_addr = (uint64_t*)((uint64_t)g_info_page + sizeof(uint64_t));

		return *rsp_storage_addr;
	}

	inline bool get_current_is_call_in_progress(void) {
		if (!initialized)
			return 0;

		bool* is_call_in_progress_addr = (bool*)g_info_page;

		return *is_call_in_progress_addr;
	}
};