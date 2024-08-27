#pragma once
#pragma warning (disable: 4003)
#include "../driver/driver_um_lib.hpp"

namespace process {
	inline bool inited = false;

	// Owner specific data
	inline uint64_t owner_pid = 0;
	inline uint64_t owner_cr3 = 0;

	// Target specific data
	inline std::string target_process_name;
	inline uint64_t target_pid = 0;
	inline uint64_t target_cr3 = 0;

	inline uint64_t target_module_count = 0;

	inline module_info_t* target_modules = 0;

	inline bool init_process(std::string process_name) {

		target_process_name = process_name;

		if (!physmem::init_physmem_remapper_lib()) {
			return false;
		}

		if (!physmem::is_lib_inited()) {
			log("Can't init process if the physmem instance is not initialized");
			return false;
		}

		owner_pid = GetCurrentProcessId();
		if (!owner_pid) {
			log("Failed to get pid of owner process");
			return false;
		}

		owner_cr3 = physmem::get_cr3(owner_pid);
		if (!owner_cr3) {
			log("Failed to get cr3 of owner process");
			physmem::flush_logs();
			return false;
		}

		target_pid = physmem::get_pid_by_name(process_name.c_str());
		if (!target_pid) {
			log("Failed to get pid of target process: %s", process_name.c_str());
			physmem::flush_logs();
			return false;
		}

		// Then get the cr3
		target_cr3 = physmem::get_cr3(target_pid);
		if (!target_cr3) {
			log("Failed to get cr3 of target process: %s", process_name.c_str());
			physmem::flush_logs();
			return false;
		}

		target_module_count = physmem::get_ldr_data_table_entry_count(target_pid);
		if (!target_module_count) {
			log("Failed get target module count");
			physmem::flush_logs();
			return false;
		}

		target_modules = (module_info_t*)malloc(sizeof(module_info_t) * target_module_count);
		if (!target_modules) {
			log("Failed to alloc memory for modules");
			return false;
		}

		// Ensure that the memory is present (mark pte as present)
		memset(target_modules, 0, sizeof(module_info_t) * target_module_count);

		if (!physmem::get_data_table_entry_info(target_pid, target_modules)) {
			log("Failed getting data table entry info");
			physmem::flush_logs();
			return false;
		}

		inited = true;

		return true;
	}

	inline bool attach_to_proc(std::string process_name) {
		return init_process(process_name);
	}

	template <typename t>
	inline t read(void* src, uint64_t size = sizeof(t)) {
		t buffer{};

		if (!physmem::copy_virtual_memory(target_cr3, owner_cr3, src, &buffer, sizeof(t))) {
			log("Failed to copy memory from src: [%p] to dest: [%p]", (void*)src, &buffer);
			return { 0 };
		}

		return buffer;
	}

	inline bool write(void* dest, void* src, uint64_t size) {
		return physmem::copy_virtual_memory(owner_cr3, target_cr3, src, dest, size);
	}

	inline module_info_t get_module(std::string module_name) {
		for (uint64_t i = 0; i < target_module_count - 1; i++) {

			if (strstr(module_name.c_str(),target_modules[i].name)) {
				return target_modules[i];
			}
		}

		return { 0 };
	}

	inline uint64_t get_module_base(std::string module_name) {
		module_info_t module = get_module(module_name);
		return module.base;
	}

	inline uint64_t get_module_size(std::string module_name) {
		module_info_t module = get_module(module_name);
		return module.size;
	}

	inline void log_modules(void) {
		for (uint64_t i = 0; i < target_module_count - 1; i++) {
			log("%s", target_modules[i].name);
		}
	}

	namespace testing {
		inline void speed_test(void) {
			if (!inited) {
				log("Init with a process first");
				return;
			}

			log("Speedtest:");
			std::chrono::steady_clock::time_point start_time, end_time;
			double elapsed_seconds;
			start_time = std::chrono::steady_clock::now();

			char buffer[0x1000];

			uint64_t mod_base = get_module_base(target_process_name);

			for (uint64_t iteration = 0; iteration < 1000; iteration++) {
				physmem::copy_virtual_memory(target_cr3, owner_cr3, (void*)mod_base, &buffer, 0x1000);
			}

			end_time = std::chrono::steady_clock::now();
			elapsed_seconds = std::chrono::duration_cast<std::chrono::duration<double>>(end_time - start_time).count();
			double reads_per_second = 1000.0 / elapsed_seconds;

			log("PAGE_SIZE Read");
			log("Took %e seconds to read PAGE_SIZE bytes 1000 times -> %e reads per second", elapsed_seconds, reads_per_second);

			start_time = std::chrono::steady_clock::now();
			for (uint64_t iteration = 0; iteration < 1000; iteration++) {
				physmem::copy_virtual_memory(target_cr3, owner_cr3, (void*)mod_base, &buffer, 4);
			}

			end_time = std::chrono::steady_clock::now();
			elapsed_seconds = std::chrono::duration_cast<std::chrono::duration<double>>(end_time - start_time).count();
			reads_per_second = 1000.0 / elapsed_seconds;

			log("4 Byte Read");
			log("Took %e seconds to read 4 bytes 1000 times -> %e reads per second\n", elapsed_seconds, reads_per_second);
		}
	};
};