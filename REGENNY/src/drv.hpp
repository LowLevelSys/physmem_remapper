#pragma once
#pragma warning (disable: 4003)
#include "driver_um_lib.hpp"
#include <vector>
#include <exception>

class process_t {
private:
    // 1 Static instance to ensure you don't accidentily use an unitialized or different class with another process
    // loaded or sth.
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

    std::vector<module_info_t> target_modules;
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

        log("Owner pid: [%p]", (void*)owner_pid);

        owner_cr3 = physmem_instance->get_cr3(owner_pid);
        if (!owner_cr3) {
            log("Failed to get cr3 of owner process");
            return false;
        }

        log("Owner cr3: [%p]", (void*)owner_cr3);

        target_pid = physmem_instance->get_pid_by_name(process_name.c_str());
        if (!target_pid) {
            log("Failed to get pid of target process: %s", process_name.c_str());
            return false;
        }

        log("%s pid: [%p]", process_name.c_str(), (void*)target_pid);

        // Then get the cr3
        target_cr3 = physmem_instance->get_cr3(target_pid);
        if (!target_cr3) {
            log("Failed to get cr3 of target process: %s", process_name.c_str());
            return false;
        }

        log("%s cr3: [%p]", process_name.c_str(), (void*)target_cr3);

        target_module_count = physmem_instance->get_ldr_data_table_entry_count(target_pid);
        if (!target_module_count) {
            log("Failed get target module count");
            return false;
        }

        // The below should fill the vector, and ensure the memory is filled with zeros, etc...
        try {
            target_modules.resize(target_module_count);
        } catch (const std::bad_alloc& e) {
            log("Failed to resize the target_modules vector: %s", e.what());
            return false;
        }

        log("%s module count: [%llu]", process_name.c_str(), target_module_count);
        log_new_line();
        log_new_line();

        if (!physmem_instance->get_data_table_entry_info(target_pid, target_modules.data())) {
            log("Failed getting data table entry info");
            return false;
        }

        log("Logging modules: ");
        log_new_line();

        // last one is not valid
        for (uint64_t i = 0; i < target_module_count - 1; i++)
            log("%s loaded at: [%p] with size [%p]", target_modules[i].name, (void*)target_modules[i].base, (void*)target_modules[i].size);

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

    bool read_array(void* dest, void* src, size_t size) {
        if (uint64_t(src) < 0xFFFFFF || uint64_t(src) > 0x7FFFFFFFFFFF || uint64_t(dest) < 0xFFFFFF || uint64_t(dest) > 0x7FFFFFFFFFFF)
            return false;

        if (!physmem_instance->copy_virtual_memory(target_cr3, owner_cr3, src, dest, size))
            return false;

        return true;
    }

    template <typename t> t read(void* src, size_t size = sizeof(t)) {
        if ((uint64_t(src) < 0xFFFFFF || uint64_t(src) > 0x7FFFFFFFFFFF))
            return false;

        t buffer{};
        if (!physmem_instance->copy_virtual_memory(target_cr3, owner_cr3, src, &buffer, size))
            return {0};

        return buffer;
    }

    bool write(void* dest, void* src, size_t size) {
        return physmem_instance->copy_virtual_memory(owner_cr3, target_cr3, src, dest, size);
    }

    std::vector<module_info_t> get_modules() const {
        return target_modules;
    }

    module_info_t get_module(std::string module_name) {
        for (uint64_t i = 0; i < target_module_count - 1; i++)
            if (strstr(module_name.c_str(), target_modules[i].name))
                return target_modules[i];
        return module_info_t();
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

    uint32_t get_target_pid() const { return target_pid; }
};

process_t* process_t::process_instance = 0;

inline process_t* g_proc;