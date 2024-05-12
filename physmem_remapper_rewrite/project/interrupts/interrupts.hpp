#pragma once
#include "../project_includes.hpp"


namespace interrupts {
	// Initialization functions
	project_status init_interrupts(uint64_t driver_base, uint64_t driver_size);
}