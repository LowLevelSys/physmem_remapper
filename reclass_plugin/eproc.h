#pragma once
#include <winternl.h>
#include "includes.h"
#include "reclass_structs.h"
#include "info_storage_structs.h"
#include "driver/driver_um_lib.hpp"
#include "windows_offsets.h"

inline void extract_proc_name(EnumerateProcessData* proc_data) {
	// Find the length of the Path
	size_t path_len = std::char_traits<RC_UnicodeChar>::length(proc_data->Path);

	// Find the last occurrence of the path separator
	RC_UnicodeChar* last_sep = nullptr;
	for (size_t i = 0; i < path_len; ++i) {
		if (proc_data->Path[i] == u'\\') {
			last_sep = &proc_data->Path[i];
		}
	}

	// If no separator was found, the path is just the filename
	RC_UnicodeChar* name_start = last_sep ? last_sep + 1 : proc_data->Path;

	// Copy the process name into the Name buffer
	std::char_traits<RC_UnicodeChar>::copy(proc_data->Name, name_start, std::char_traits<RC_UnicodeChar>::length(name_start) + 1);
}

inline void print_utf16_string(const RC_UnicodeChar* name) {
	std::u16string utf16_str(name);

	std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> convert;
	std::string utf8_str = convert.to_bytes(utf16_str);

	log("%s", utf8_str.c_str());
}


namespace driver_data {
	inline std::vector<per_process_struct> process_vector;
	inline physmem_remapper_um_t* physmem_instance = 0;
	inline uint64_t owner_pid;
	inline uint64_t owner_cr3;

	inline uint64_t kernel_pid;
	inline uint64_t kernel_cr3;
	
	inline bool inited;

	inline void init_driver(void) {
		if (inited)
			return;

		inited = true;

		// Allocates a console if you are in debug
		alloc_console();

		physmem_instance = physmem_remapper_um_t::init_physmem_remapper_lib();
		if (!physmem_instance) {
			log("Can't init process if the physmem instance is not allocated");
			return;
		}

		if (!physmem_instance->is_lib_inited()) {
			log("Can't init process if the physmem instance is not initialized");
			return;
		}

		// First setup the owner process
		owner_pid = GetCurrentProcessId();
		if (!owner_pid) {
			log("Failed to get pid of owner process");
			return;
		}
		owner_cr3 = physmem_instance->get_cr3(owner_pid);
		if (!owner_cr3) {
			log("Failed to get cr3 of owner process");
			return;
		}

		// Then setup the kernel process
		kernel_pid = 4;
		kernel_cr3 = physmem_instance->get_cr3(kernel_pid);
		if (!kernel_cr3) {
			log("Failed to get cr3 of owner process");
			return;
		}
	}

	inline void* get_next_eprocess(void* curr_eproc) {
		if (!inited)
			return 0;

		LIST_ENTRY curr_list;
		if (!physmem_instance->copy_virtual_memory(kernel_cr3, owner_cr3, (void*)((uint64_t)curr_eproc + FLINK_OFFSET), &curr_list, sizeof(curr_list))) {
			log("Failed to move on to next eproc");
			return 0;
		}

		void* next_eproc;
		next_eproc = curr_list.Flink;
		next_eproc = (void*)((uintptr_t)next_eproc - FLINK_OFFSET);

		return next_eproc;
	}

	inline bool is_running_process(void* curr_eproc) {
		if (!inited)
			return false;

		uint32_t active_threads;
		if (!driver_data::physmem_instance->copy_virtual_memory(driver_data::kernel_cr3, driver_data::owner_cr3, (void*)((uintptr_t)curr_eproc + ACTIVE_THREADS), &active_threads, sizeof(active_threads))) {
			log("Failed to copy active thread count");
			return false;
		}

		if (active_threads) {
			return true;
		}
		else {
			return false;
		}
	}

	inline bool is_x64_proc(void* curr_eproc) {
		if (!inited)
			return false;

		void* wow64_proc;
		if (!physmem_instance->copy_virtual_memory(kernel_cr3, owner_cr3, (void*)((uintptr_t)curr_eproc + WOW_64_PROCESS), &wow64_proc, sizeof(wow64_proc))) {
			log("Failed to check process architecture");
			return false;
		}

		if (wow64_proc) {
			return false;
		}
		else {
			return true;
		}
	}

	inline bool get_proc_data(void* curr_eproc, EnumerateProcessData* proc_data) {
		if (!inited || !curr_eproc || !proc_data) {
			log("Invalid input data");
			return false;
		}

		// Copy process pid
		uint64_t pid;
		if (!physmem_instance->copy_virtual_memory(kernel_cr3, owner_cr3, (void*)((uintptr_t)curr_eproc + PID_OFFSET), &pid, sizeof(pid))) {
			log("Failed to get pid");
			return false;
		}

		// Ignore pid = 0 and system proc
		if (pid == 0 || pid == 4)
			return false;
		
		proc_data->Id = pid;

		// Copy the path
		uint64_t user_cr3;
		if (!physmem_instance->copy_virtual_memory(kernel_cr3, owner_cr3, (void*)((uintptr_t)curr_eproc + DIRECTORY_TABLE_BASE_OFFSET), &user_cr3, sizeof(user_cr3))) {
			log("Failed to copy user cr3");
			return false;
		}

		void* peb_address;
		if (!physmem_instance->copy_virtual_memory(kernel_cr3, owner_cr3, (void*)((uintptr_t)curr_eproc + PEB_OFFSET), &peb_address, sizeof(peb_address))) {
			log("Failed to copy peb address");
			return false;
		}
		if (!peb_address) {
			log("Read invalid peb address");
			return false;
		}

		// Some processes like Registry don't have that for some reason...
		void* puser_proc_params;
		if (!physmem_instance->copy_virtual_memory(user_cr3, owner_cr3, (void*)((uintptr_t)peb_address + PROCESS_PARAMETERS_PEB_OFFSET), &puser_proc_params, sizeof(puser_proc_params)) || !puser_proc_params) {
			return false;
		}
		if (!puser_proc_params) {
			log("Read invalid puser_proc_params");
			return false;
		}

		RTL_USER_PROCESS_PARAMETERS user_proc_params;
		if (!physmem_instance->copy_virtual_memory(user_cr3, owner_cr3, puser_proc_params, &user_proc_params, sizeof(user_proc_params))) {
			log("Failed to copy Userprocessparams");
			return false;
		}
		if (!physmem_instance->copy_virtual_memory(user_cr3, owner_cr3, user_proc_params.ImagePathName.Buffer, &proc_data->Path, user_proc_params.ImagePathName.Length)) {
			log("Failed to copy Image Path");
			return false;
		}

		// Null-terminate the path
		proc_data->Path[user_proc_params.ImagePathName.Length / sizeof(WCHAR)] = L'\0';

		// Then from the path extract the name of the file
		extract_proc_name(proc_data);

		// Add process to vector
		per_process_struct process_entry;
		process_entry.target_pid = proc_data->Id;
		process_entry.target_cr3 = user_cr3;

		print_utf16_string(proc_data->Name);
		log("Cr3 %p\n", process_entry.target_cr3);

		process_vector.push_back(process_entry);

		return true;
	}
}
