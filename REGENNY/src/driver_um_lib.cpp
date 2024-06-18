#include "driver_um_lib.hpp"
#include <winnt.h>
#include <winternl.h>
physmem_remapper_um_t* physmem_remapper_um_t::instance = 0;
extern "C" NtUserGetCPD_type NtUserGetCPD = 0;

// Function to attempt to acquire a spin lock
inline bool spinlock_try_lock(volatile long* lock) {
    return (!(*lock) && !_interlockedbittestandset(lock, 0));
}

// Function to lock a spin lock
inline void spinlock_lock(volatile long* lock) {
    static unsigned max_wait = 65536;
    unsigned wait = 1;

    while (!spinlock_try_lock(lock)) {
        for (unsigned i = 0; i < wait; ++i) {
            _mm_pause();
        }

        if (wait * 2 > max_wait) {
            wait = max_wait;
        }
        else {
            wait = wait * 2;
        }
    }
}

// Function to unlock a spin lock
inline void spinlock_unlock(volatile long* lock) {
    *lock = 0;
}

inline volatile long handler_lock = 0;

// Restores from a nmi
extern "C" void nmi_restoring(trap_frame_t* trap_frame) {
    uint64_t* stack_ptr = (uint64_t*)trap_frame->rsp;

    while (true) {
        if (*stack_ptr != stack_id) {
            stack_ptr++; // Move up the stack
            continue;
        }

        trap_frame->rax = nmi_occured;
        
        // Restore rsp
        trap_frame->rsp = (uint64_t)stack_ptr + 0x8; // Point top of rsp to a ret address

        // Return to the send request
        return;
    }
}

__int64 physmem_remapper_um_t::send_request(void* cmd) {
    spinlock_lock(&handler_lock);

    __int64 ret = asm_call_driver((uint64_t)cmd, caller_signature, (uint64_t)asm_nmi_restoring);
    if (ret == nmi_occured) {
        spinlock_unlock(&handler_lock);

        // The nmi handler code pops stack id for us, so just recurively call the request
        return send_request(cmd);
    }
    spinlock_unlock(&handler_lock);

    return ret;
}

bool physmem_remapper_um_t::copy_virtual_memory(uint64_t source_cr3, uint64_t destination_cr3, void* source, void* destination, uint64_t size) {
    if (!inited || !NtUserGetCPD)
        return false;

    copy_virtual_memory_t copy_mem_cmd = { 0 };
    copy_mem_cmd.source_cr3 = source_cr3;
    copy_mem_cmd.destination_cr3 = destination_cr3;
    copy_mem_cmd.source = source;
    copy_mem_cmd.destination = destination;
    copy_mem_cmd.size = size;

    command_t cmd = { 0 };
    cmd.call_type = cmd_copy_virtual_memory;
    cmd.sub_command_ptr = &copy_mem_cmd;

    send_request(&cmd);
   
    return cmd.status;
}

uint64_t physmem_remapper_um_t::get_cr3(uint64_t pid) {
    if (!inited || !NtUserGetCPD)
        return 0;

    get_cr3_t get_cr3_cmd = { 0 };
    get_cr3_cmd.pid = pid;

    command_t cmd = { 0 };
    cmd.call_type = cmd_get_cr3;
    cmd.sub_command_ptr = &get_cr3_cmd;

    send_request(&cmd);

    return get_cr3_cmd.cr3;
}

uint64_t physmem_remapper_um_t::get_module_base(const char* module_name, uint64_t pid) {
    if (!inited || !NtUserGetCPD)
        return 0;

    get_module_base_t get_module_base_cmd = { 0 };
    strncpy(get_module_base_cmd.module_name, module_name, MAX_PATH - 1);
    get_module_base_cmd.pid = pid;

    command_t cmd = { 0 };
    cmd.call_type = cmd_get_module_base;
    cmd.sub_command_ptr = &get_module_base_cmd;

    send_request(&cmd);

    return get_module_base_cmd.module_base;
}

uint64_t physmem_remapper_um_t::get_module_size(const char* module_name, uint64_t pid) {
    if (!inited || !NtUserGetCPD)
        return 0;

    get_module_size_t get_module_size_cmd = { 0 };
    strncpy(get_module_size_cmd.module_name, module_name, MAX_PATH - 1);
    get_module_size_cmd.pid = pid;

    command_t cmd = { 0 };
    cmd.call_type = cmd_get_module_size;
    cmd.sub_command_ptr = &get_module_size_cmd;

    send_request(&cmd);

    return get_module_size_cmd.module_size;
}

uint64_t physmem_remapper_um_t::get_pid_by_name(const char* name) {
    if (!inited || !NtUserGetCPD)
        return 0;

    get_pid_by_name_t get_pid_by_name_cmd = { 0 };
    strncpy(get_pid_by_name_cmd.name, name, MAX_PATH - 1);

    command_t cmd = { 0 };
    cmd.call_type = cmd_get_pid_by_name;
    cmd.sub_command_ptr = &get_pid_by_name_cmd;

    send_request(&cmd);

    return get_pid_by_name_cmd.pid;
}

uint64_t physmem_remapper_um_t::get_ldr_data_table_entry_count(uint64_t pid) {
    if (!inited || !NtUserGetCPD)
        return {};

    get_ldr_data_table_entry_count_t get_ldr_data_table_entry = { 0 };
    get_ldr_data_table_entry.pid = pid;

    command_t cmd = { 0 };
    cmd.call_type = cmd_get_ldr_data_table_entry_count;
    cmd.sub_command_ptr = &get_ldr_data_table_entry;

    send_request(&cmd);

    return get_ldr_data_table_entry.count;
}

bool physmem_remapper_um_t::get_data_table_entry_info(uint64_t pid, module_info_t* info_array) {
    if (!inited || !NtUserGetCPD)
        return {};

    cmd_get_data_table_entry_info_t get_module_at_index = { 0 };
    get_module_at_index.pid = pid;
    get_module_at_index.info_array = info_array;

    command_t cmd = { 0 };
    cmd.call_type = cmd_get_data_table_entry_info;
    cmd.sub_command_ptr = &get_module_at_index;

    send_request(&cmd);

    return cmd.status;
}

bool physmem_remapper_um_t::remove_apc() {
    if (!inited || !NtUserGetCPD)
        return 0;

    command_t cmd = { 0 };
    cmd.call_type = cmd_remove_apc;

    send_request(&cmd);

    return cmd.status;
}

bool physmem_remapper_um_t::restore_apc() {
    if (!inited || !NtUserGetCPD)
        return 0;

    command_t cmd = { 0 };
    cmd.call_type = cmd_restore_apc;

    send_request(&cmd);

    return cmd.status;
}
