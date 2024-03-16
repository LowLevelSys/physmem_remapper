#include "comm.hpp"
#include "shared.hpp"
#include "comm_util.hpp"

/*
    Our main handler that handles communication with um
    It assumes to be called under the process cr3
    hwnd: ptr to cmd
    flags: crypting key
    dw_data: crypting key 2
*/
extern "C" __int64 __fastcall handler(uint64_t hwnd, uint32_t flags, ULONG_PTR dw_data) {

    paging_structs::cr3 proc_cr3 = { 0 };
    proc_cr3.flags = __readcr3();

    // If the calculated hash doesn't match the given one
    // it is a random call, so just return the orig function
    if (!check_keys(flags, dw_data)) {
        return orig_NtUserGetCPD(hwnd, flags, dw_data);
    }

    physmem* inst = physmem::get_physmem_instance();
    command* cmd = (command*)hwnd;

    cmd->result = false;

    // Example handling of specific command types
    switch (cmd->command_number) {
        case cmd_allocate_memory: {
            allocate_memory_struct* sub_cmd = (allocate_memory_struct*)cmd->sub_command_ptr;

            sub_cmd->memory_base = ExAllocatePool(NonPagedPool, sub_cmd->size);

            if (!sub_cmd->memory_base) {
                dbg_log("Failed allocating pool of size %p", sub_cmd->size);
                break;
            }

            cmd->result = true;

            dbg_log("Allocated memory at %p", sub_cmd->memory_base);

        } break;

        case cmd_free_memory: {
            free_memory_struct* sub_cmd = (free_memory_struct*)cmd->sub_command_ptr;

            if (!sub_cmd->memory_base) {
                dbg_log("Invalid argument for freeing mem");
                break;
            }
             
            cmd->result = true;

            ExFreePool(sub_cmd->memory_base);

            dbg_log("Freed memory at %p", sub_cmd->memory_base);

        } break;

        case cmd_copy_virtual_memory: {
            copy_virtual_memory_struct* sub_cmd = (copy_virtual_memory_struct*)cmd->sub_command_ptr;
            paging_structs::cr3 source_cr3;
            paging_structs::cr3 destination_cr3;
            
            source_cr3.flags = sub_cmd->source_cr3;
            destination_cr3.flags = sub_cmd->destination_cr3;

            if (sub_cmd->size != inst->copy_virtual_memory(source_cr3, sub_cmd->source, destination_cr3, sub_cmd->destination, sub_cmd->size)) {
                dbg_log("Failed to copy virtual memory");
                break;
            }

            cmd->result = true;

        } break;

        case cmd_get_cr3: {
            get_cr3_struct* sub_cmd = (get_cr3_struct*)cmd->sub_command_ptr;

            sub_cmd->cr3 = get_cr3(sub_cmd->pid);

            if (!sub_cmd->cr3) {
                dbg_log("Failed to get cr3 from pid %p", sub_cmd->pid);
                break;
            }

            cmd->result = true;

        } break;

        case cmd_get_module_base: {
            get_module_base_struct* sub_cmd = (get_module_base_struct*)cmd->sub_command_ptr;
            
            sub_cmd->module_base = get_module_base(sub_cmd->pid, sub_cmd->module_name);

            if (!sub_cmd->module_base) {
                dbg_log("Failed to get module base from module %s in pid %p", sub_cmd->module_name, sub_cmd->pid);
                break;
            }

            cmd->result = true;

        } break;

        case cmd_get_module_size: {
            get_module_size_struct* sub_cmd = (get_module_size_struct*)cmd->sub_command_ptr;
            sub_cmd->module_size = get_module_base(sub_cmd->pid, sub_cmd->module_name);

            if (!sub_cmd->module_size) {
                dbg_log("Failed to get module size from module %s in pid %p", sub_cmd->module_name, sub_cmd->pid);
                break;
            }

            cmd->result = true;

        } break;

        case cmd_get_pid_by_name: {
            get_pid_by_name_struct* sub_cmd = (get_pid_by_name_struct*)cmd->sub_command_ptr;
            
            sub_cmd->pid = get_pid(sub_cmd->name);

            if (!sub_cmd->pid) {
                dbg_log("Failed getting pid from process %s", sub_cmd->name);
                break;
            }

            cmd->result = true;

            dbg_log("Got pid %p from process %s", sub_cmd->pid, sub_cmd->name);

        } break;

        case cmd_get_physical_address: {
            get_physical_address_struct* sub_cmd = (get_physical_address_struct*)cmd->sub_command_ptr;

            sub_cmd->physical_address = get_physical_address((void*)sub_cmd->virtual_address);

            if (!sub_cmd->physical_address) {
                dbg_log("Failed getting pa from va %p", sub_cmd->virtual_address);
                break;
            }
           
            cmd->result = true;

            dbg_log("Translated va %p to pa %p", sub_cmd->virtual_address, sub_cmd->physical_address);

        } break;

        case cmd_get_virtual_address: {
            get_virtual_address_struct* sub_cmd = (get_virtual_address_struct*)cmd->sub_command_ptr;

            sub_cmd->virtual_address = get_virtual_address(sub_cmd->physical_address);

            if (!sub_cmd->physical_address) {
                dbg_log("Failed getting va from pa %p", sub_cmd->physical_address);
                break;
            }

            cmd->result = true;

            dbg_log("Translated pa %p to va %p", sub_cmd->physical_address, sub_cmd->virtual_address);
        } break;

        case cmd_comm_test: {
            // Handle comm_test command
            test_call = true;
            dbg_log("Test called");
        } break;

        default: {
            dbg_log("Unimplemented cmd %p ", cmd->command_number);
        } break;
    }

    return 0;
}