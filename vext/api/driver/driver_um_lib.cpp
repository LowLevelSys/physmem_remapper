#include "driver_um_lib.hpp"
#include <winnt.h>
#include <winternl.h>

extern "C" NtUserGetCPD_type NtUserGetCPD = 0;

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

namespace physmem {

    __int64 send_request(void* cmd) {

        __int64 ret = asm_call_driver((uint64_t)cmd, caller_signature, (uint64_t)asm_nmi_restoring);
        if (ret == nmi_occured) {
            // The nmi handler code pops stack id for us, so just recurively call the request
            return send_request(cmd);
        }

        return ret;
    }

    bool copy_virtual_memory(uint64_t src_cr3, uint64_t dst_cr3, void* src, void* dst, uint64_t size) {
        if (!inited || !NtUserGetCPD)
            return false;

        copy_virtual_memory_t copy_mem_cmd = { 0 };
        copy_mem_cmd.src_cr3 = src_cr3;
        copy_mem_cmd.dst_cr3 = dst_cr3;
        copy_mem_cmd.src = src;
        copy_mem_cmd.dst = dst;
        copy_mem_cmd.size = size;

        command_t cmd = { 0 };
        cmd.call_type = cmd_copy_virtual_memory;
        cmd.sub_command_ptr = &copy_mem_cmd;

        send_request(&cmd);

        return cmd.status;
    }

    uint64_t get_cr3(uint64_t pid) {
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

    uint64_t get_module_base(const char* module_name, uint64_t pid) {
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

    uint64_t get_module_size(const char* module_name, uint64_t pid) {
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

    uint64_t get_pid_by_name(const char* name) {
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

    uint64_t get_ldr_data_table_entry_count(uint64_t pid) {
        if (!inited || !NtUserGetCPD)
            return 0;

        get_ldr_data_table_entry_count_t get_ldr_data_table_entry = { 0 };
        get_ldr_data_table_entry.pid = pid;

        command_t cmd = { 0 };
        cmd.call_type = cmd_get_ldr_data_table_entry_count;
        cmd.sub_command_ptr = &get_ldr_data_table_entry;

        send_request(&cmd);

        return get_ldr_data_table_entry.count;
    }

    bool get_data_table_entry_info(uint64_t pid, module_info_t* info_array) {
        if (!inited || !NtUserGetCPD)
            return false;

        cmd_get_data_table_entry_info_t get_module_at_index = { 0 };
        get_module_at_index.pid = pid;
        get_module_at_index.info_array = info_array;

        command_t cmd = { 0 };
        cmd.call_type = cmd_get_data_table_entry_info;
        cmd.sub_command_ptr = &get_module_at_index;

        send_request(&cmd);

        return cmd.status;
    }

    bool hide_driver(void) {
        if (!inited || !NtUserGetCPD)
            return false;

        command_t cmd = { 0 };
        cmd.call_type = cmd_remove_from_system_page_tables;

        send_request(&cmd);

        return cmd.status;
    }

    bool unload_driver(void) {
        if (!inited || !NtUserGetCPD)
            return false;

        command_t cmd = { 0 };
        cmd.call_type = cmd_unload_driver;

        send_request(&cmd);

        return cmd.status;
    }

    bool ping_driver(void) {
        if (!inited || !NtUserGetCPD)
            return false;

        command_t cmd = { 0 };
        cmd.call_type = cmd_ping_driver;

        send_request(&cmd);

        return cmd.status;
    }
};