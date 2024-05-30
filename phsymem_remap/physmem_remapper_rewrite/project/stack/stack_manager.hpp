#pragma once
#include "../project_includes.hpp"

namespace stack_manager {
	// Initialization functions
	project_status init_stack_manager(void);

	// Exposed API's
	project_status get_stack_base(void*& stack_base);
	bool is_initialized(void);
};