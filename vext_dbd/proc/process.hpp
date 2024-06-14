#pragma once
#pragma warning (disable: 4003)
#include "../driver/driver_um_lib.hpp"

typedef class process_t {
private:
	// 1 Static instance to ensure you don't accidentily use an unitialized or different class with another process loaded or sth.
	static process_t* process_instance;

	physmem_remapper_um_t* physmem_instance = 0;
	bool inited = false;

	// Owner specific data
	uint64_t owner_pid = 0;
	uint64_t owner_cr3 = 0;

	// Target specific data
	uint64_t target_pid = 0;
	uint64_t target_cr3 = 0;

	uint64_t target_module_count = 0;

	module_info_t* target_modules = 0;

	bool init_process(std::string process_name) {

		physmem_instance = physmem_remapper_um_t::init_physmem_remapper_lib();

		if (!physmem_instance) {
			log("Can't init process if the physmem instance is not allocated");
			return false;
		}

		if (!physmem_instance->is_lib_inited()) {
			log("Can't init process if the physmem instance is not initialized");
			return false;
		}

		owner_pid = GetCurrentProcessId();
		if (!owner_pid) {
			log("Failed to get pid of owner process");
			return false;
		}

		owner_cr3 = physmem_instance->get_cr3(owner_pid);
		if (!owner_cr3) {
			log("Failed to get cr3 of owner process");
			log("Driver most likely not loaded");
			return false;
		}

		target_pid = physmem_instance->get_pid_by_name(process_name.c_str());
		if (!target_pid) {
			log("Failed to get pid of target process: %s", process_name.c_str());
			return false;
		}

		// Then get the cr3
		target_cr3 = physmem_instance->get_cr3(target_pid);
		if (!target_cr3) {
			log("Failed to get cr3 of target process: %s", process_name.c_str());
			return false;
		}

		target_module_count = physmem_instance->get_ldr_data_table_entry_count(target_pid);
		if (!target_module_count) {
			log("Failed get target module count");
			return false;
		}

		target_modules = (module_info_t*)malloc(sizeof(module_info_t) * target_module_count);
		if (!target_modules) {
			log("Failed to alloc memory for modules");
			return false;
		}

		// Ensure that the memory is present (mark pte as present)
		memset(target_modules, 0, sizeof(module_info_t) * target_module_count);

		if (!physmem_instance->get_data_table_entry_info(target_pid, target_modules)) {
			log("Failed getting data table entry info");
			return false;
		}

		return true;
	}


public:

	~process_t() {
		delete physmem_instance;
		physmem_instance = 0;
	}

	static process_t* get_inst(std::string process_name) {
		if (!process_instance) {
			process_instance = new process_t();
			if (!process_instance) {
				log("Failed to allocate process instance");
				return 0;
			}

			if (!process_instance->init_process(process_name)) {
				log("Failed to init for process %s", process_name.c_str());
				return 0;
			}
		}

		return process_instance;
	}

	bool read_array(void* dest, void* src, uint64_t size) {
		return physmem_instance->copy_virtual_memory(target_cr3, owner_cr3, src, dest, size);
	}

	bool write_array(void* dest, void* src, uint64_t size) {
		return physmem_instance->copy_virtual_memory(owner_cr3, target_cr3, src, dest, size);
	}

	template <typename T>
	T read(void* src, uint64_t size = sizeof(T)) {
		T buffer{};

		if (!physmem_instance->copy_virtual_memory(target_cr3, owner_cr3, src, &buffer, size)) {
			return T{};
		}

		return buffer;
	}


	bool write(void* dest, void* src, uint64_t size) {
		return physmem_instance->copy_virtual_memory(owner_cr3, target_cr3, src, dest, size);
	}

	module_info_t get_module(std::string module_name) {
		for (uint64_t i = 0; i < target_module_count - 1; i++) {

			if (strstr(module_name.c_str(),target_modules[i].name)) {
				return target_modules[i];
			}
		}

		return { 0 };
	}

	uint64_t get_module_base(std::string module_name) {
		module_info_t module = get_module(module_name);
		return module.base;
	}

	uint64_t get_module_size(std::string module_name) {
		module_info_t module = get_module(module_name);
		return module.size;
	}

	bool remove_apc() {
		bool result = physmem_instance->remove_apc();
		return result;
	}

	bool restore_apc() {
		bool result = physmem_instance->restore_apc();
		return result;
	}
};

inline process_t* process_t::process_instance = 0;

inline process_t* g_proc;