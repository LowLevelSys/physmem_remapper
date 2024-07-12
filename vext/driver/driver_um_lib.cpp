#include "driver_um_lib.hpp"
#include <winnt.h>
#include <winternl.h>

physmem_remapper_um_t* physmem_remapper_um_t::instance = 0;
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

__int64 physmem_remapper_um_t::send_request(void* cmd) {

    __int64 ret = asm_call_driver((uint64_t)cmd, caller_signature, (uint64_t)asm_nmi_restoring);
    if (ret == nmi_occured) {
        // The nmi handler code pops stack id for us, so just recurively call the request
        return send_request(cmd);
    }

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

void* physmem_remapper_um_t::get_eprocess(uint64_t pid) {
    if (!inited || !NtUserGetCPD)
        return 0;

    cmd_get_eprocess_t sub_cmd;
    sub_cmd.pid = pid;

    command_t cmd = { 0 };
    cmd.call_type = cmd_get_eproc;
    cmd.sub_command_ptr = &sub_cmd;

    send_request(&cmd);

    return sub_cmd.eproc;
}

void write_to_read_only(uint64_t address, uint8_t* bytes, uint64_t len) {
    DWORD old_prot = 0;
    VirtualProtect((LPVOID)address, len, PAGE_EXECUTE_READWRITE, &old_prot);
    memcpy((void*)address, (void*)bytes, len);
    VirtualProtect((LPVOID)address, len, old_prot, 0);
}

void trigger_cow_locally(uint8_t* address) {
    uint8_t buff = *address;

    // Trigger coW
    write_to_read_only((uint64_t)address, (uint8_t*)"\xC3", 1);
    write_to_read_only((uint64_t)address, &buff, 1);
}

bool physmem_remapper_um_t::trigger_cow(void* target_address, uint64_t target_cr3, uint64_t source_cr3) {
    /*
        First trigger cow in your own process
    */
    trigger_cow_locally((uint8_t*)target_address);

    cmd_trigger_cow_t sub_cmd;
    sub_cmd.target_address = target_address;
    sub_cmd.target_cr3 = target_cr3;
    sub_cmd.source_cr3 = source_cr3;

    command_t cmd = { 0 };
    cmd.call_type = cmd_trigger_cow;
    cmd.sub_command_ptr = &sub_cmd;

    send_request(&cmd);

    return cmd.status;
}

void physmem_remapper_um_t::revert_cow_triggering(void* target_address, uint64_t target_cr3) {
    cmd_revert_cow_triggering_t sub_cmd;
    sub_cmd.target_address = target_address;
    sub_cmd.target_cr3 = target_cr3;

    command_t cmd = { 0 };
    cmd.call_type = cmd_revert_cow_triggering;
    cmd.sub_command_ptr = &sub_cmd;

    send_request(&cmd);
}

bool physmem_remapper_um_t::find_and_copy_cow_page(void* target_address, uint64_t target_cr3, uint64_t source_cr3) {
    cmd_find_and_copy_cow_page_t sub_cmd;
    sub_cmd.target_address = target_address;
    sub_cmd.target_cr3 = target_cr3;
    sub_cmd.source_cr3 = source_cr3;

    command_t cmd = { 0 };
    cmd.call_type = cmd_find_and_copy_cow_page;
    cmd.sub_command_ptr = &sub_cmd;

    send_request(&cmd);

    return cmd.status;
}