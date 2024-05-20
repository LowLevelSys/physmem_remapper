#pragma once
#include "../project_includes.hpp"
#include "interrupt_structs.hpp"
#include <ntimage.h>

namespace interrupts {
	// Initialization functions
	project_status init_interrupts(uint64_t driver_base, uint64_t driver_size);

	// Exposed tests
	project_status stress_test_seh(void);
}