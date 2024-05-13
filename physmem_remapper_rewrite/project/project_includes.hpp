#pragma once
#include <ntddk.h>
#include <intrin.h>

/*
	typedefs
*/

using uint8_t =  unsigned char;
using uint16_t = unsigned short;
using uint32_t = unsigned int;
using uint64_t = unsigned long long;

/*
	Structs
*/


/*
	Enums
*/

// A return type to use instead of bool
// to get more information from the return
enum project_status {
	status_success,
	status_failure,
	status_memory_allocation_failed,
	status_address_translation_failed,
	status_invalid_page_table_index,
	status_no_available_page_tables,
	status_invalid_parameter,
	status_not_initialized,
};

/*
	Macros
*/

#define extract_file_name(file) (strrchr(file, '\\') ? strrchr(file, '\\') + 1 : file)

#define project_log_error(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] " "[%s:%d] " fmt, extract_file_name(__FILE__), __LINE__, ##__VA_ARGS__)
#define project_log_warning(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[~] " "[%s:%d] " fmt, extract_file_name(__FILE__), __LINE__, ##__VA_ARGS__)
#define project_log_success(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[+] " "[%s:%d] " fmt, extract_file_name(__FILE__), __LINE__, ##__VA_ARGS__)
#define project_log_info(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[*] " "[%s:%d] " fmt, extract_file_name(__FILE__), __LINE__, ##__VA_ARGS__)

/*
	Win API wrappers
*/

inline uint64_t win_get_physical_address(void* virtual_address) {
	return MmGetPhysicalAddress(virtual_address).QuadPart;
}

inline uint64_t win_get_virtual_address(uint64_t physical_address) {
	PHYSICAL_ADDRESS phys_addr = { 0 };
	phys_addr.QuadPart = physical_address;

	return (uint64_t)(MmGetVirtualForPhysical(phys_addr));
}