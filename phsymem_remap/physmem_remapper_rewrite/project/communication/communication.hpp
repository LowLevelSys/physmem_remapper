#pragma once
#include "../project_includes.hpp"

namespace communication {
	// Initialization functions
	project_status init_communication(void* driver_base, uint64_t driver_size);
};