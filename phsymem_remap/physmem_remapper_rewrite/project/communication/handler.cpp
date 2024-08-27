#include "communication.hpp"
#include "shared_structs.hpp"

#include "../project_api.hpp"
#include "../project_utility.hpp"
#include "../cr3 decryption/cr3_decryption.hpp"

bool is_removed = false;

/*
    Our main handler that handles communication with um
    a) It assumes that the call to it is valid; Validity is checked for in shell code via rdx
    hwnd: ptr to cmd
    flags: non valid (is used as a validation key in the shellcode)
    dw_data: non valid
*/
extern "C" __int64 __fastcall handler(uint64_t hwnd, uint32_t flags, ULONG_PTR dw_data) {
    UNREFERENCED_PARAMETER(flags);
    UNREFERENCED_PARAMETER(dw_data);

    if (!hwnd)
        return status_invalid_parameter;

    project_status status = status_success;
    command_t cmd;

    uint64_t user_cr3 = shellcode::get_current_user_cr3();
    status = physmem::runtime::copy_memory_to_constructed_cr3(&cmd, (void*)hwnd, sizeof(command_t), user_cr3);
    if (status != status_success)
        return 0;
   
    switch (cmd.call_type) {
    case cmd_copy_virtual_memory: {
        copy_virtual_memory_t sub_cmd;

        status = physmem::runtime::copy_memory_to_constructed_cr3(&sub_cmd, cmd.sub_command_ptr, sizeof(sub_cmd), user_cr3);
        if (status != status_success)
            break;

        status = physmem::runtime::copy_virtual_memory(sub_cmd.dst, sub_cmd.src, sub_cmd.size, sub_cmd.dst_cr3, sub_cmd.src_cr3);
        if (status != status_success)
            break;

        // Do not copy back to improve performance; There is no return value for this
    } break;

    case cmd_get_pid_by_name: {
        get_pid_by_name_t sub_cmd;
        status = physmem::runtime::copy_memory_to_constructed_cr3(&sub_cmd, cmd.sub_command_ptr, sizeof(sub_cmd), user_cr3);
        if (status != status_success)
            break;

        sub_cmd.pid = cr3_decryption::eproc::get_pid(sub_cmd.name);
        if (!sub_cmd.pid)
            status = status_failure;

        if (status != status_success)
            break;

        status = physmem::runtime::copy_memory_from_constructed_cr3(cmd.sub_command_ptr, &sub_cmd, sizeof(sub_cmd), user_cr3);
        if (status != status_success)
            break;
    } break;

    case cmd_get_cr3: {

        get_cr3_t sub_cmd;
        status = physmem::runtime::copy_memory_to_constructed_cr3(&sub_cmd, cmd.sub_command_ptr, sizeof(sub_cmd), user_cr3);
        if (status != status_success)
            break;

        sub_cmd.cr3 = cr3_decryption::eproc::get_cr3(sub_cmd.pid);
        if (!sub_cmd.cr3)
            status = status_failure;

        if (status != status_success)
            break;

        status = physmem::runtime::copy_memory_from_constructed_cr3(cmd.sub_command_ptr, &sub_cmd, sizeof(sub_cmd), user_cr3);
        if (status != status_success)
            break;

    } break;

    case cmd_get_module_base: {
        get_module_base_t sub_cmd;
        status = physmem::runtime::copy_memory_to_constructed_cr3(&sub_cmd, cmd.sub_command_ptr, sizeof(sub_cmd), user_cr3);
        if (status != status_success)
            break;

        sub_cmd.module_base = cr3_decryption::peb::get_module_base(sub_cmd.pid, sub_cmd.module_name);
        if (!sub_cmd.module_base)
            status = status_failure;

        if (status != status_success)
            break;

        status = physmem::runtime::copy_memory_from_constructed_cr3(cmd.sub_command_ptr, &sub_cmd, sizeof(sub_cmd), user_cr3);
        if (status != status_success)
            break;
    } break;

    case cmd_get_module_size: {
        get_module_size_t sub_cmd;
        status = physmem::runtime::copy_memory_to_constructed_cr3(&sub_cmd, cmd.sub_command_ptr, sizeof(sub_cmd), user_cr3);
        if (status != status_success)
            break;

        sub_cmd.module_size = cr3_decryption::peb::get_module_size(sub_cmd.pid, sub_cmd.module_name);
        if (!sub_cmd.module_size)
            status = status_failure;

        if (status != status_success)
            break;

        status = physmem::runtime::copy_memory_from_constructed_cr3(cmd.sub_command_ptr, &sub_cmd, sizeof(sub_cmd), user_cr3);
        if (status != status_success)
            break;
    } break;

    case cmd_get_ldr_data_table_entry_count: {
        get_ldr_data_table_entry_count_t sub_cmd;
        status = physmem::runtime::copy_memory_to_constructed_cr3(&sub_cmd, cmd.sub_command_ptr, sizeof(sub_cmd), user_cr3);
        if (status != status_success)
            break;

        sub_cmd.count = cr3_decryption::peb::get_data_table_entry_count(sub_cmd.pid);
        if (!sub_cmd.count)
            status = status_failure;

        if (status != status_success)
            break;

        status = physmem::runtime::copy_memory_from_constructed_cr3(cmd.sub_command_ptr, &sub_cmd, sizeof(sub_cmd), user_cr3);
        if (status != status_success)
            break;
    } break;

    case cmd_get_data_table_entry_info: {
        cmd_get_data_table_entry_info_t sub_cmd;
        status = physmem::runtime::copy_memory_to_constructed_cr3(&sub_cmd, cmd.sub_command_ptr, sizeof(sub_cmd), user_cr3);
        if (status != status_success)
            break;

        status = cr3_decryption::peb::get_data_table_entry_info(sub_cmd.pid, sub_cmd.info_array, user_cr3);
        if (status != status_success)
            break;

        // Do not copy back to improve performance; There is no return value for this
    } break;

    case cmd_output_logs: {
        cmd_output_logs_t sub_cmd;
        status = physmem::runtime::copy_memory_to_constructed_cr3(&sub_cmd, cmd.sub_command_ptr, sizeof(sub_cmd), user_cr3);
        if (status != status_success)
            break;

        logging::output_root_logs(sub_cmd.log_array, user_cr3, sub_cmd.count);

        status = physmem::runtime::copy_memory_from_constructed_cr3(cmd.sub_command_ptr, &sub_cmd, sizeof(sub_cmd), user_cr3);
        if (status != status_success)
            break;

    } break;

    // This is a substitute for MmRemovePhysicalMemory (=
    case cmd_remove_from_system_page_tables: {

        // Do not try to double remove it, it won't work...
        if (is_removed)
            break;

        status = physmem::paging_manipulation::win_unmap_memory_range(g_driver_base, physmem::util::get_system_cr3().flags, g_driver_size);
        if (status != status_success)
            break;

        is_removed = true;

    } break;

    case cmd_unload_driver: {

        status = communication::unhook_data_ptr();
        if (status != status_success)
            break;

    } break;

    case cmd_ping_driver: {

        // Hello usermode

    } break;

    default: {

        logging::root_printf("UNKNOWN CMD %d", cmd.call_type);

    } break;
    }

    // Set the success flag in the main cmd
    if (status == status_success) {
        cmd.status = true;
    }
    else {
        cmd.status = false;
    }

    // Copy back th main cmd
    physmem::runtime::copy_memory_from_constructed_cr3((void*)hwnd, &cmd, sizeof(command_t), user_cr3);
    return 0;
}