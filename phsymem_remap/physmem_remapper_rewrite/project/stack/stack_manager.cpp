#include "stack_manager.hpp"

namespace stack_manager {
	/*
		Global variables
	*/
	void* stack_pointers[MAX_PROCESSOR_COUNT] = { 0 }; // Points to the top of the stack
	uint32_t processor_count = 0;
	bool initialized = false;

	/*
		Initialization functions
	*/
	project_status init_stack_manager(void) {
		PHYSICAL_ADDRESS max_addr = { 0 };
		project_status status = status_success;

		max_addr.QuadPart = MAXULONG64;

		processor_count = KeQueryActiveProcessorCount(0);

		for (uint32_t i = 0; i < processor_count; i++) {
			stack_pointers[i] = MmAllocateContiguousMemory(KERNEL_STACK_SIZE, max_addr);
			if (!stack_pointers[i]) {
				status = status_memory_allocation_failed;
				goto cleanup;
			}

			crt::memset(stack_pointers[i], 0, KERNEL_STACK_SIZE);

			stack_pointers[i] = static_cast<char*>(stack_pointers[i]) + KERNEL_STACK_SIZE;
		}

		initialized = true;

	cleanup:
		return status;
	}

	/*
		Exposed API's
	*/

	bool is_initialized(void) {
		return initialized;
	}

	project_status get_stack_base(void*& stack_base, uint32_t proc_number) {
		if (!initialized)
			return status_not_initialized;

		if (proc_number > processor_count)
			return status_invalid_parameter;

		stack_base = stack_pointers[proc_number];

		return status_success;
	}
};