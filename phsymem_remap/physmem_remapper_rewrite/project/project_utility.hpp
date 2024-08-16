#include "project_includes.hpp"

/*
	Exposed utility
*/
namespace utility {
	project_status get_driver_module_base(const wchar_t* driver_name, void*& driver_base);
	project_status get_eprocess(const char* process_name, PEPROCESS& pe_proc);
	project_status is_data_ptr_in_valid_region(uint64_t data_ptr);
	uint64_t get_cr3(uint64_t target_pid);

	uintptr_t find_pattern_in_range(uintptr_t region_base, size_t region_size, const char* pattern, size_t pattern_size, char wildcard);
	uintptr_t search_pattern_in_section(void* module_handle, const char* section_name, const char* pattern, uint64_t pattern_size, char wildcard);
};