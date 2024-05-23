#pragma once
#include "../project_includes.hpp"

namespace shellcode {
	void* g_enter_constructed_space = 0;
	void* g_exit_constructed_space = 0;

	inline void construct_enter_shellcode(void* enter_constructed_space, bool* is_call_in_progress, void* orig_data_ptr_value, void* handler_address) {
		static const uint8_t enter_shellcode[] = {
			// First check if is_call_in_progress is set
			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, imm64 (address of is_call_in_progress)
			0x8A, 0x00,                                                 // mov al, [rax]
			0x84, 0xC0,                                                 // test al, al
			0x75, 0x21,                                                 // jne call_in_progress

			// If no call in progress, check rdx
			0x81, 0xFA, 0x69, 0x69, 0x00, 0x00,                         // cmp edx, 0x6969
			0x75, 0x2C,                                                 // jne jump_to_orig_data_ptr_value

			// If the call is our call, set is_call_in_progress and call our handler
			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, imm64 (address of is_call_in_progress)
			0xC6, 0x00, 0x01,                                           // mov byte ptr [rax], 1 (set flag)
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

		memcpy(enter_constructed_space, enter_shellcode, sizeof(enter_shellcode));

		uint64_t is_call_in_progress_addr = (uint64_t)is_call_in_progress;
		memcpy((uint8_t*)enter_constructed_space + 2, &is_call_in_progress_addr, sizeof(is_call_in_progress_addr));

		memcpy((uint8_t*)enter_constructed_space + 26, &is_call_in_progress_addr, sizeof(is_call_in_progress_addr));

		uint64_t handler_address_val = (uint64_t)handler_address;
		memcpy((uint8_t*)enter_constructed_space + 39, &handler_address_val, sizeof(handler_address_val));

		uint64_t orig_data_ptr_value_addr = (uint64_t)orig_data_ptr_value;
		memcpy((uint8_t*)enter_constructed_space + 70, &orig_data_ptr_value_addr, sizeof(orig_data_ptr_value_addr));
	}

	inline void construct_exit_shellcode(void* exit_constructed_space, bool* is_call_in_progress, void* orig_data_ptr_value) {
		static const uint8_t exiting_shellcode[] = {
			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, imm64 (address of is_call_in_progress)
			0xC6, 0x00, 0x00,                                           // mov byte ptr [rax], 0 (unset flag)

			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, imm64 (address of orig_data_ptr_value)
			0xFF, 0xE0,                                                 // jmp rax
		};

		memcpy(exit_constructed_space, exiting_shellcode, sizeof(exiting_shellcode));

		uint64_t is_call_in_progress_addr = (uint64_t)is_call_in_progress;
		memcpy((uint8_t*)exit_constructed_space + 2, &is_call_in_progress_addr, sizeof(is_call_in_progress_addr));

		uint64_t orig_data_ptr_value_addr = (uint64_t)orig_data_ptr_value;
		memcpy((uint8_t*)exit_constructed_space + 15, &orig_data_ptr_value_addr, sizeof(orig_data_ptr_value_addr));
	}

	inline project_status construct_shellcodes(void*& enter_constructed_space, void*& exit_constructed_space, void* orig_data_ptr_value, void* handler_address) {
		PHYSICAL_ADDRESS max_addr = { 0 };
		project_status status = status_success;
		bool* is_call_in_progress = 0;

		max_addr.QuadPart = MAXULONG64;

		enter_constructed_space = MmAllocateContiguousMemory(PAGE_SIZE, max_addr);
		exit_constructed_space = MmAllocateContiguousMemory(PAGE_SIZE, max_addr);
		is_call_in_progress = (bool*)MmAllocateContiguousMemory(PAGE_SIZE, max_addr);

		if (!enter_constructed_space || !exit_constructed_space) {
			status = status_memory_allocation_failed;
			goto cleanup;
		}

		memset(enter_constructed_space, 0, PAGE_SIZE);
		memset(exit_constructed_space, 0, PAGE_SIZE);
		memset(is_call_in_progress, 0, PAGE_SIZE);

		construct_enter_shellcode(enter_constructed_space, is_call_in_progress, orig_data_ptr_value, handler_address);
		construct_exit_shellcode(exit_constructed_space, is_call_in_progress, orig_data_ptr_value);

	cleanup:
		return status;
	}

	inline void log_shellcode_addresses(void) {
		project_log_info("Entering shellcode at %p", g_enter_constructed_space);
		project_log_info("Exiting shellcode at %p", g_exit_constructed_space);
	}
};