#pragma once

#include "../project_api.hpp"
#include "../project_utility.hpp"
#include "../communication/shared_structs.hpp"

namespace logging {
	// Initialization
	project_status init_root_logger();

	// Exposed API'S
	void root_printf(const char* fmt, ...);
	void output_root_logs(log_entry_t* user_message_buffer, uint64_t user_cr3, uint32_t message_count);
};