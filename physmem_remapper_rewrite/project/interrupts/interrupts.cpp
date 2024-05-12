#pragma once
#include "interrupts.hpp"

namespace interrupts {
	// Initialization functions
	project_status init_interrupts(uint64_t driver_base, uint64_t driver_size) {
		UNREFERENCED_PARAMETER(driver_base);
		UNREFERENCED_PARAMETER(driver_size);

		return status_success;
	}
}