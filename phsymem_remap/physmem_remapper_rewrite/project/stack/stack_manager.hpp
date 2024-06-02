#pragma once
#include "../project_includes.hpp"

#define MAX_PROCESSOR_COUNT 128

namespace stack_manager {
	// Initialization functions
	project_status init_stack_manager(void);

	// Exposed API's
	project_status get_stack_base(void*& stack_base, uint32_t proc_number);
	bool is_initialized(void);
};