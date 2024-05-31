#include "driver_um_lib.hpp"
#include <winnt.h>
#include <winternl.h>

physmem_remapper_um_t* physmem_remapper_um_t::instance = 0;

bool physmem_remapper_um_t::copy_virtual_memory(uint64_t source_cr3, uint64_t destination_cr3, void* source, void* destination, uint64_t size) {
    if (!inited || !NtUserGetCPD)
        return false;

    auto nmi_panic_function = [&](uint64_t source_cr3, uint64_t destination_cr3, void* source, void* destination, uint64_t size) -> bool {
        return copy_virtual_memory(source_cr3, destination_cr3, source, destination, size);
        };

    copy_virtual_memory_t copy_mem_cmd = { 0 };
    copy_mem_cmd.source_cr3 = source_cr3;
    copy_mem_cmd.destination_cr3 = destination_cr3;
    copy_mem_cmd.source = source;
    copy_mem_cmd.destination = destination;
    copy_mem_cmd.size = size;

    command_t cmd = { 0 };
    cmd.call_type = cmd_copy_virtual_memory;
    cmd.sub_command_ptr = &copy_mem_cmd;

    __int64 ret = NtUserGetCPD((uint64_t)&cmd, caller_signature, (uint64_t)&nmi_panic_function);
    if (ret == call_in_progress_signature) {
        log("Call currently in progress");
        return false;
    }

    return cmd.status;
}

uint64_t physmem_remapper_um_t::get_cr3(uint64_t pid) {
    if (!inited || !NtUserGetCPD)
        return 0;

    auto nmi_panic_function = [&](uint64_t pid) -> uint64_t {
        return get_cr3(pid);
        };

    get_cr3_t get_cr3_cmd = { 0 };
    get_cr3_cmd.pid = pid;

    command_t cmd = { 0 };
    cmd.call_type = cmd_get_cr3;
    cmd.sub_command_ptr = &get_cr3_cmd;

    __int64 ret = NtUserGetCPD((uint64_t)&cmd, caller_signature, (uint64_t)&nmi_panic_function);
    if (ret == call_in_progress_signature) {
        log("Call currently in progress");
        return false;
    }

    return get_cr3_cmd.cr3;
}

uint64_t physmem_remapper_um_t::get_module_base(const char* module_name, uint64_t pid) {
    if (!inited || !NtUserGetCPD)
        return 0;

    auto nmi_panic_function = [&](const char* module_name, uint64_t pid) -> uint64_t {
        return get_module_base(module_name, pid);
        };

    get_module_base_t get_module_base_cmd = { 0 };
    strncpy(get_module_base_cmd.module_name, module_name, MAX_PATH - 1);
    get_module_base_cmd.pid = pid;

    command_t cmd = { 0 };
    cmd.call_type = cmd_get_module_base;
    cmd.sub_command_ptr = &get_module_base_cmd;

    __int64 ret = NtUserGetCPD((uint64_t)&cmd, caller_signature, (uint64_t)&nmi_panic_function);
    if (ret == call_in_progress_signature) {
        log("Call currently in progress");
        return false;
    }

    return get_module_base_cmd.module_base;
}

uint64_t physmem_remapper_um_t::get_module_size(const char* module_name, uint64_t pid) {
    if (!inited || !NtUserGetCPD)
        return 0;

    auto nmi_panic_function = [&](const char* module_name, uint64_t pid) -> uint64_t {
        return get_module_size(module_name, pid);
        };

    get_module_size_t get_module_size_cmd = { 0 };
    strncpy(get_module_size_cmd.module_name, module_name, MAX_PATH - 1);
    get_module_size_cmd.pid = pid;

    command_t cmd = { 0 };
    cmd.call_type = cmd_get_module_size;
    cmd.sub_command_ptr = &get_module_size_cmd;

    __int64 ret = NtUserGetCPD((uint64_t)&cmd, caller_signature, (uint64_t)&nmi_panic_function);
    if (ret == call_in_progress_signature) {
        log("Call currently in progress");
        return false;
    }

    return get_module_size_cmd.module_size;
}

uint64_t physmem_remapper_um_t::get_pid_by_name(const char* name) {
    if (!inited || !NtUserGetCPD)
        return 0;

    auto nmi_panic_function = [&](const char* name) -> uint64_t {
        return get_pid_by_name(name);
        };

    get_pid_by_name_t get_pid_by_name_cmd = { 0 };
    strncpy(get_pid_by_name_cmd.name, name, MAX_PATH - 1);

    command_t cmd = { 0 };
    cmd.call_type = cmd_get_pid_by_name;
    cmd.sub_command_ptr = &get_pid_by_name_cmd;

    __int64 ret = NtUserGetCPD((uint64_t)&cmd, caller_signature, (uint64_t)&nmi_panic_function);
    if (ret == call_in_progress_signature) {
        log("Call currently in progress");
        return false;
    }

    return get_pid_by_name_cmd.pid;
}

uint64_t physmem_remapper_um_t::get_ldr_data_table_entry_count(uint64_t pid) {
    if (!inited || !NtUserGetCPD)
        return {};

    auto nmi_panic_function = [&](const char* name) -> uint64_t {
        return get_pid_by_name(name);
        };

    get_ldr_data_table_entry_count_t get_ldr_data_table_entry = { 0 };
    get_ldr_data_table_entry.pid = pid;

    command_t cmd = { 0 };
    cmd.call_type = cmd_get_ldr_data_table_entry_count;
    cmd.sub_command_ptr = &get_ldr_data_table_entry;

    __int64 ret = NtUserGetCPD((uint64_t)&cmd, caller_signature, (uint64_t)&nmi_panic_function);
    if (ret == call_in_progress_signature) {
        log("Call currently in progress");
        return false;
    }

    return get_ldr_data_table_entry.count;
}

bool physmem_remapper_um_t::get_data_table_entry_info(uint64_t pid, module_info_t* info_array) {
    if (!inited || !NtUserGetCPD)
        return {};

    auto nmi_panic_function = [&](const char* name) -> uint64_t {
        return get_data_table_entry_info(pid, info_array);
        };

    cmd_get_data_table_entry_info_t get_module_at_index = { 0 };
    get_module_at_index.pid = pid;
    get_module_at_index.info_array = info_array;

    command_t cmd = { 0 };
    cmd.call_type = cmd_get_data_table_entry_info;
    cmd.sub_command_ptr = &get_module_at_index;

    __int64 ret = NtUserGetCPD((uint64_t)&cmd, caller_signature, (uint64_t)&nmi_panic_function);
    if (ret == call_in_progress_signature) {
        log("Call currently in progress");
        return false;
    }

    return cmd.status;
}