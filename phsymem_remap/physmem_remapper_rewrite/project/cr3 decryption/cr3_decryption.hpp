#pragma once
#include "../project_api.hpp"
#include "../project_utility.hpp"
#include "../communication/shared_structs.hpp"

#pragma warning(push)
#pragma warning(disable:4201)
struct _MMPFN {
	uintptr_t flags;
	uintptr_t pte_address;
	uintptr_t Unused_1;
	uintptr_t Unused_2;
	uintptr_t Unused_3;
	uintptr_t Unused_4;
};
static_assert(sizeof(_MMPFN) == 0x30);

constexpr size_t operator ""_MiB(size_t num) { return num << 20; }

enum iteration_status {
	status_stop_iteration,
	status_continue_iteration
};

namespace cr3_decryption {
	// Initialization
	project_status init_eac_cr3_decryption(void);

	namespace eproc {
		// Exposed API'S
		uint64_t get_cr3(uint64_t target_pid);
		uint64_t get_pid(const char* target_process_name);
	};

	namespace peb {
		// Exposed API'S
		project_status get_data_table_entry_info(uint64_t target_pid, module_info_t* info_array, uint64_t proc_cr3);
		uint64_t get_data_table_entry_count(uint64_t target_pid);

		uint64_t get_module_base(uint64_t target_pid, char* module_name);
		uint64_t get_module_size(uint64_t target_pid, char* module_name);
	};
}