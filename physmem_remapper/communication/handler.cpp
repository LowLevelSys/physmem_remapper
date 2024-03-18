#include "comm.hpp"
#include "shared.hpp"
#include "comm_util.hpp"
#include "../physmem/physmem.hpp"

/*
   We use templates here to avoid a very very large code base (look at my hv
   if you want to know what NOT to do)
*/

template<typename T>
bool copy_to_host(const paging_structs::cr3& proc_cr3, uint64_t src, T& dest) {
    physmem* inst = physmem::get_physmem_instance();
    return sizeof(T) == inst->copy_memory_to_inside(proc_cr3, src, reinterpret_cast<uint64_t>(&dest), sizeof(T));
}

template<typename T>
bool copy_from_host(uint64_t dest, const T& src, const paging_structs::cr3& proc_cr3) {
    physmem* inst = physmem::get_physmem_instance();
    return sizeof(T) == inst->copy_memory_from_inside(reinterpret_cast<const uint64_t>(&src), dest, proc_cr3, sizeof(T));
}

/*
    Our main handler that handles communication with um
    It assumes to be called under the process cr3
    hwnd: ptr to cmd
    flags: crypting key
    dw_data: crypting key 2
*/
extern "C" __int64 __fastcall handler(uint64_t hwnd, uint32_t flags, ULONG_PTR dw_data) {
    // In case another call happens during the execution of our handler, make a backup now
    uint64_t safed_proc_cr3 = global_proc_cr3;

    // If the calculated hash doesn't match the given one
    // it is a random call, so just return the orig function
    if (!check_keys(flags, dw_data)) {
        __writecr3(safed_proc_cr3);
        return orig_NtUserGetCPD(hwnd, flags, dw_data);
    }

    physmem* inst = physmem::get_physmem_instance();
    command* cmd_ptr = (command*)hwnd;
    command cmd;

    paging_structs::cr3 proc_cr3 = { 0 };
    proc_cr3.flags = safed_proc_cr3;

    if (sizeof(cmd) != inst->copy_memory_to_inside(proc_cr3, (uint64_t)cmd_ptr, (uint64_t)&cmd, sizeof(cmd))) {
        dbg_log_handler("Failed to copy main cmd");
        __writecr3(safed_proc_cr3);
        return 0;
    }

    cmd.result = false;

    // Example handling of specific command types
    switch (cmd.command_number) {
    case cmd_allocate_memory: {
        allocate_memory_struct sub_cmd;
        if (!copy_to_host(proc_cr3, (uint64_t)cmd.sub_command_ptr, sub_cmd)) {
            dbg_log_handler("Failed to copy allocate_memory_struct");
            break;
        }

        // Allocate memory
        sub_cmd.memory_base = ExAllocatePool(NonPagedPool, sub_cmd.size);
        cmd.result = (sub_cmd.memory_base != 0);
        
        if (cmd.result) 
            dbg_log_handler("Allocated memory at %p", sub_cmd.memory_base);
        else 
            dbg_log_handler("Failed allocating pool of size %p", sub_cmd.size);
        

        if (!copy_from_host((uint64_t)cmd.sub_command_ptr, sub_cmd, proc_cr3)) 
            dbg_log_handler("Failed to copy back allocate_memory_struct");
        

    } break;

    case cmd_free_memory: {
        free_memory_struct sub_cmd;
        if (!copy_to_host(proc_cr3, (uint64_t)cmd.sub_command_ptr, sub_cmd)) {
            dbg_log_handler("Failed to copy free_memory_struct");
            break;
        }

        // Free memory if the base is valid
        cmd.result = (sub_cmd.memory_base != 0);
        if (cmd.result) {
            ExFreePool(sub_cmd.memory_base);
            dbg_log_handler("Freed memory at %p", sub_cmd.memory_base);
        }
        else 
            dbg_log_handler("Invalid argument for freeing memory");
        

    } break;

    case cmd_copy_virtual_memory: {
        copy_virtual_memory_struct sub_cmd;
        if (!copy_to_host(proc_cr3, (uint64_t)cmd.sub_command_ptr, sub_cmd)) {
            dbg_log_handler("Failed to copy copy_virtual_memory_struct");
            break;
        }

        paging_structs::cr3 source_cr3 = { .flags = sub_cmd.source_cr3 };
        paging_structs::cr3 destination_cr3 = { .flags = sub_cmd.destination_cr3 };

        // Copy virtual memory from a to b
        cmd.result = (sub_cmd.size == inst->copy_virtual_memory(source_cr3, sub_cmd.source, destination_cr3, sub_cmd.destination, sub_cmd.size));
        if (!cmd.result) 
            dbg_log_handler("Failed to copy virtual memory");
        

    } break;

    case cmd_get_cr3: {
        get_cr3_struct sub_cmd;
        if (!copy_to_host(proc_cr3, (uint64_t)cmd.sub_command_ptr, sub_cmd)) {
            dbg_log_handler("Failed to copy get_cr3_struct");
            break;
        }

        // Get Cr3 value
        sub_cmd.cr3 = get_cr3(sub_cmd.pid);
        cmd.result = (sub_cmd.cr3 != 0);

        if (!cmd.result) 
            dbg_log_handler("Failed to get cr3 from pid %p", sub_cmd.pid);

        if (!copy_from_host((uint64_t)cmd.sub_command_ptr, sub_cmd, proc_cr3))
            dbg_log_handler("Failed to copy back get_cr3_struct");
        
    } break;

    case cmd_get_module_base: {
        get_module_base_struct sub_cmd;
        if (!copy_to_host(proc_cr3, (uint64_t)cmd.sub_command_ptr, sub_cmd)) {
            dbg_log_handler("Failed to copy get_module_base_struct");
            break;
        }

        // Get module base
        sub_cmd.module_base = get_module_base(sub_cmd.pid, sub_cmd.module_name);
        cmd.result = (sub_cmd.module_base != 0);
        if (!cmd.result) 
            dbg_log_handler("Failed to get module base for %s in pid %p", sub_cmd.module_name, sub_cmd.pid);
        

        if (!copy_from_host((uint64_t)cmd.sub_command_ptr, sub_cmd, proc_cr3))
            dbg_log_handler("Failed to copy back get_module_base_struct");
        
    } break;

    case cmd_get_module_size: {
        get_module_size_struct sub_cmd;
        if (!copy_to_host(proc_cr3, (uint64_t)cmd.sub_command_ptr, sub_cmd)) {
            dbg_log_handler("Failed to copy get_module_size_struct");
            break;
        }

        // Get the module size
        sub_cmd.module_size = get_module_size(sub_cmd.pid, sub_cmd.module_name);
        cmd.result = (sub_cmd.module_size != 0);

        if (!cmd.result) {
            dbg_log_handler("Failed to get module size from module %s in pid %p", sub_cmd.module_name, sub_cmd.pid);
            break;
        }

        if (!copy_from_host((uint64_t)cmd.sub_command_ptr, sub_cmd, proc_cr3)) 
            dbg_log_handler("Failed to copy back get_module_size_struct");
        
    } break;


    case cmd_get_pid_by_name: {
        get_pid_by_name_struct sub_cmd;
        if (!copy_to_host(proc_cr3, (uint64_t)cmd.sub_command_ptr, sub_cmd)) {
            dbg_log_handler("Failed to copy get_module_size_struct");
            break;
        }

        // Get the pid
        sub_cmd.pid = get_pid(sub_cmd.name);

        if (!sub_cmd.pid) {
            dbg_log_handler("Failed getting pid from process %s", sub_cmd.name);
            break;
        }

        cmd.result = true;

        // Copying back might be necessary to return the PID
        if (!copy_from_host((uint64_t)cmd.sub_command_ptr, sub_cmd, proc_cr3))
            dbg_log_handler("Failed to copy back get_pid_by_name_struct");
        
    } break;

    case cmd_get_physical_address: {
        get_physical_address_struct sub_cmd;
        if (!copy_to_host(proc_cr3, (uint64_t)cmd.sub_command_ptr, sub_cmd)) {
            dbg_log_handler("Failed to copy get_physical_address_struct");
            break;
        }

        // Get the physical address
        sub_cmd.physical_address = get_physical_address((void*)sub_cmd.virtual_address);

        if (!sub_cmd.physical_address) {
            dbg_log_handler("Failed getting PA from VA %p", sub_cmd.virtual_address);
            break;
        }

        cmd.result = true;

        if (!copy_from_host((uint64_t)cmd.sub_command_ptr, sub_cmd, proc_cr3))
            dbg_log_handler("Failed to copy back get_physical_address_struct");
        
    } break;

    case cmd_get_virtual_address: {
        get_virtual_address_struct sub_cmd;
        if (!copy_to_host(proc_cr3, (uint64_t)cmd.sub_command_ptr, sub_cmd)) {
            dbg_log_handler("Failed to copy get_virtual_address_struct");
            break;
        }

        sub_cmd.virtual_address = get_virtual_address(sub_cmd.physical_address);

        if (!sub_cmd.virtual_address) {
            dbg_log_handler("Failed getting VA from PA %p", sub_cmd.physical_address);
            break;
        }

        cmd.result = true;

        if (!copy_from_host((uint64_t)cmd.sub_command_ptr, sub_cmd, proc_cr3))
            dbg_log_handler("Failed to copy back get_virtual_address_struct");
        
    } break;

    case cmd_ensure_mapping: {

        if (is_mapping_ensured) {
            dbg_log_handler("Mapping is already ensured");
            break;
        }

        if (!ensure_address_space_mapping(driver_base, driver_size, inst->get_kernel_cr3())) {
            dbg_log_handler("Failed to ensure address space mapping from %p to %p", driver_base, driver_base + driver_size);
            break;
        }
        
        dbg_log_handler("Ensured address space mapping from %p to %p", driver_base, driver_base + driver_size);

        cmd.result = true;
        is_mapping_ensured = true;

    } break;

    case cmd_get_driver_info: {
        get_driver_info_struct sub_cmd;

        // Return info to the caller
        sub_cmd.base = driver_base;
        sub_cmd.size = driver_size;

        cmd.result = true;

        dbg_log_handler("Got driver info");

        if (!copy_from_host((uint64_t)cmd.sub_command_ptr, sub_cmd, proc_cr3))
            dbg_log_handler("Failed to copy back get_driver_info_struct");

    } break;

    case cmd_remove_system_mapping: {
        remove_system_mapping_struct sub_cmd;
        if (!copy_to_host(proc_cr3, (uint64_t)cmd.sub_command_ptr, sub_cmd)) {
            dbg_log_handler("Failed to copy get_virtual_address_struct");
            break;
        }
        
        PHYSICAL_ADDRESS physical_base = { 0 };
        LARGE_INTEGER size = { 0 };

        physical_base.QuadPart =  sub_cmd.physical_base;
        size.QuadPart =  sub_cmd.size;

        // Remove the pool from physical memory
        if (!NT_SUCCESS(MmRemovePhysicalMemory(&physical_base, &size))) {
            dbg_log("Failed to remove physical memory range %p to %p from system mappings", physical_base.QuadPart, physical_base.QuadPart + size.QuadPart);
            break;
        }

        test_call = true;
        dbg_log("Removed  physical memory range %p to %p from system mappings", physical_base.QuadPart, physical_base.QuadPart + size.QuadPart);

        if (!copy_from_host((uint64_t)cmd.sub_command_ptr, sub_cmd, proc_cr3))
            dbg_log_handler("Failed to copy back remove_system_mapping_struct");

    } break;

    case cmd_comm_test: {

        test_call = true;
        
        cmd.result = true;

        dbg_log_handler("Test called");
    } break;

    default: {
        dbg_log_handler("Unimplemented cmd %p ", cmd.command_number);
    } break;
    }

    if (sizeof(cmd) != inst->copy_memory_from_inside((uint64_t)&cmd, (uint64_t)cmd_ptr, proc_cr3, sizeof(cmd))) 
        dbg_log_handler("Failed to copy back main cmd");
    
    __writecr3(safed_proc_cr3);

    return 0;
}