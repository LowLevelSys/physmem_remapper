#pragma once
#include <ntddk.h>
#include <intrin.h>

#include "windows_structs.hpp"

// We like nice declarations
typedef signed char        int8_t;
typedef short              int16_t;
typedef int                int32_t;
typedef long long          int64_t;
typedef unsigned char      uint8_t;
typedef unsigned short     uint16_t;
typedef unsigned int       uint32_t;
typedef unsigned long long uint64_t;


/*
	Enums
*/

// A return type to use instead of bool
// to get more information from the return
enum project_status {
	/*
		GENERAL
	*/
	status_success,
	status_failure,
	status_invalid_parameter,
	status_memory_allocation_failed,
	status_win_address_translation_failed,
	status_not_supported,

	/*
		WINDOWS
	*/
	status_cr3_not_found,

	/*
		PHYSMEM
	*/
	status_invalid_paging_idx,
	status_paging_entry_not_present,
	status_remapping_entry_found,
	status_no_valid_remapping_entry,
	status_no_available_page_tables,
	status_remapping_list_full,
	status_wrong_context,
	status_invalid_my_page_table,
	status_address_already_remapped,
	status_non_aligned,
	status_paging_wrong_granularity,
	status_page_already_unmapped,
	status_potential_mem_unmapping_overflow,

	/*
		Communication
	*/
	status_data_ptr_invalid,
	status_no_gadget_found,
};

/*
	Macros
*/

#define extract_file_name(file) (strrchr(file, '\\') ? strrchr(file, '\\') + 1 : file)

#define project_log_error(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] " "[%s:%d] " fmt "\n", extract_file_name(__FILE__), __LINE__, ##__VA_ARGS__)
#define project_log_warning(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[~] " "[%s:%d] " fmt "\n", extract_file_name(__FILE__), __LINE__, ##__VA_ARGS__)
#define project_log_success(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[+] " "[%s:%d] " fmt "\n", extract_file_name(__FILE__), __LINE__, ##__VA_ARGS__)
#define project_log_info(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[*] " "[%s:%d] " fmt "\n", extract_file_name(__FILE__), __LINE__, ##__VA_ARGS__)

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

inline void sleep(LONG milliseconds) {
	LARGE_INTEGER interval;

	// Convert milliseconds to 100-nanosecond intervals
	interval.QuadPart = -((LONGLONG)milliseconds * 10000);

	KeDelayExecutionThread(KernelMode, false, &interval);
}

/*
	Assembly function declaration
*/

extern "C" uint32_t get_proc_number(void);
extern "C" void asm_handler(void);

/*
	Declaration of imports
*/
extern "C" NTKERNELAPI VOID KeStackAttachProcess(PRKPROCESS PROCESS, PKAPC_STATE ApcState);
extern "C" NTKERNELAPI VOID KeUnstackDetachProcess(PKAPC_STATE ApcState);
extern "C" PLIST_ENTRY PsLoadedModuleList;

/*
	Driver globals
*/
inline void* g_driver_base;
inline uint64_t g_driver_size;