#include "stack_manager.hpp"

namespace stack_manager {
	/*
		Global variables
	*/
	void* my_stack_base = 0; // Points to the top of the stack
	bool initialized = false;

	/*
		Initialization functions
	*/
	project_status init_stack_manager(void) {
		PHYSICAL_ADDRESS max_addr = { 0 };
		project_status status = status_success;

		max_addr.QuadPart = MAXULONG64;

		my_stack_base = MmAllocateContiguousMemory(KERNEL_STACK_SIZE, max_addr);
		if (!my_stack_base) {
			status = status_memory_allocation_failed;
			goto cleanup;
		}

		memset(my_stack_base, 0, KERNEL_STACK_SIZE);

		my_stack_base = static_cast<char*>(my_stack_base) + KERNEL_STACK_SIZE;

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

	project_status get_stack_base(void*& stack_base) {
		if (!initialized)
			return status_not_initialized;

		stack_base = my_stack_base;

		return status_success;
	}
};