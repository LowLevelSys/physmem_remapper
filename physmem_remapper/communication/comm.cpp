#include "comm.hpp"
#include "shared.hpp"

extern "C" uint64_t global_proc_cr3 = 0;

// Generates shellcode which jumps to our handler
void generate_executed_jump_gadget(uint8_t* gadget, void* mem, uint64_t jmp_address) {
    // mov rax, cr3 (store current cr3 into rax)
    gadget[0] = 0x0f; gadget[1] = 0x20; gadget[2] = 0xd8;

    // push rax (save current cr3 on stack)
    gadget[3] = 0x50;

    // mov rax, imm64 (move my cr3 value into rax)
    gadget[4] = 0x48; gadget[5] = 0xb8;
    uint64_t cr3_value = physmem::get_physmem_instance()->get_my_cr3().flags;
    *reinterpret_cast<uint64_t*>(&gadget[6]) = cr3_value;

    // mov cr3, rax (update cr3)
    gadget[14] = 0x0f; gadget[15] = 0x22; gadget[16] = 0xd8;

    // mov rax, imm64 (move pool address into rax)
    gadget[17] = 0x48; gadget[18] = 0xb8;
    uint64_t pool_addr = reinterpret_cast<uint64_t>(mem);
    *reinterpret_cast<uint64_t*>(&gadget[19]) = pool_addr;

    // invlpg [rax] (invalidate page)
    gadget[27] = 0x0f; gadget[28] = 0x01; gadget[29] = 0x38;

    // mfence (memory fence)
    gadget[30] = 0x0f; gadget[31] = 0xae; gadget[32] = 0xf0;

    // mov rax, imm64 (move jump address into rax)
    gadget[33] = 0x48; gadget[34] = 0xb8;
    *reinterpret_cast<uint64_t*>(&gadget[35]) = jmp_address;

    // jmp rax (jump to address)
    gadget[43] = 0xff; gadget[44] = 0xe0;
}

// Generates shellcode which will effectively just write to cr3
void generate_shown_jump_gadget(uint8_t* gadget, void* mem) {
    // mov rax, cr3 (store current cr3 into rax)
    gadget[0] = 0x0f; gadget[1] = 0x20; gadget[2] = 0xd8;

    // push rax (save current cr3 on stack)
    gadget[3] = 0x50;

    // mov rax, imm64 (move my cr3 value into rax)
    gadget[4] = 0x48; gadget[5] = 0xb8;
    uint64_t cr3_value = physmem::get_physmem_instance()->get_my_cr3().flags;
    *reinterpret_cast<uint64_t*>(&gadget[6]) = cr3_value;

    // mov cr3, rax (update cr3)
    gadget[14] = 0x0f; gadget[15] = 0x22; gadget[16] = 0xd8;

    // mov rax, imm64 (move pool address into rax)
    gadget[17] = 0x48; gadget[18] = 0xb8;
    uint64_t pool_addr = reinterpret_cast<uint64_t>(mem);
    *reinterpret_cast<uint64_t*>(&gadget[19]) = pool_addr;

    // invlpg [rax] (invalidate page)
    gadget[27] = 0x0f; gadget[28] = 0x01; gadget[29] = 0x38;

    // mfence (memory fence)
    gadget[30] = 0x0f; gadget[31] = 0xae; gadget[32] = 0xf0;

    // ret (return)
    gadget[33] = 0xc3;
}

bool execute_tests(void) {
    orig_NtUserGetCPD_type handler = (orig_NtUserGetCPD_type)global_new_data_ptr;
    uint32_t flags;
    uint64_t dw_data;

    // Generate the validation keys
    generate_keys(flags, dw_data);

    command cmd;

    cmd.command_number = cmd_comm_test;

    // First call it for a test run (;
    handler((uint64_t)&cmd, flags, dw_data);

    if (!test_call) {
        dbg_log("Failed to do a test call");
        return false;
    }

#ifdef ENABLE_EXTENSIVE_COMMUNICATION_TESTS
    allocate_memory_struct alloc_mem = { 0 };
    alloc_mem.size = PAGE_SIZE;
    cmd.sub_command_ptr = &alloc_mem;
    cmd.command_number = cmd_allocate_memory;

    handler((uint64_t)&cmd, flags, dw_data);

    // Check the allocation
    if (!alloc_mem.memory_base) {
        dbg_log("Failed to allocate memory");
        return false;
    }

    free_memory_struct free_mem = { 0 };
    free_mem.memory_base = alloc_mem.memory_base;
    cmd.sub_command_ptr = &free_mem;
    cmd.command_number = cmd_free_memory;

    handler((uint64_t)&cmd, flags, dw_data);

    // Nothing we could really check here

    uint64_t a = 0x123;
    uint64_t b = 0;
    copy_virtual_memory_struct copy_mem;

    copy_mem.source = (uint64_t)&a;
    copy_mem.destination = (uint64_t)&b;
    copy_mem.size = sizeof(uint64_t);
    copy_mem.source_cr3 = __readcr3();
    copy_mem.destination_cr3 = __readcr3();

    cmd.sub_command_ptr = &copy_mem;
    cmd.command_number = cmd_copy_virtual_memory;

    handler((uint64_t)&cmd, flags, dw_data);

    if (a != b) {
        dbg_log("Failed to copy virtual memory");
        return false;
    }


    get_cr3_struct get_cr3;
    get_cr3.pid = 4;

    cmd.sub_command_ptr = &get_cr3;
    cmd.command_number = cmd_get_cr3;

    handler((uint64_t)&cmd, flags, dw_data);

    if (get_cr3.cr3 != __readcr3()) {
        dbg_log("Failed to get cr3");
        return false;
    }

    get_pid_by_name_struct get_pid;
    crt::memcpy(get_pid.name, "System", sizeof("System"));

    cmd.sub_command_ptr = &get_pid;
    cmd.command_number = cmd_get_pid_by_name;

    handler((uint64_t)&cmd, flags, dw_data);

    if (get_pid.pid != 4) {
        dbg_log("Failed to get pid");
        return false;
    }

    uint64_t dummy;
    get_physical_address_struct get_phys_addr;

    get_phys_addr.virtual_address = (uint64_t)&dummy;

    cmd.sub_command_ptr = &get_phys_addr;
    cmd.command_number = cmd_get_physical_address;

    handler((uint64_t)&cmd, flags, dw_data);

    get_virtual_address_struct get_virt_addr;

    get_virt_addr.physical_address = get_phys_addr.physical_address;

    cmd.sub_command_ptr = &get_virt_addr;
    cmd.command_number = cmd_get_virtual_address;

    handler((uint64_t)&cmd, flags, dw_data);

    if (get_virt_addr.virtual_address != (uint64_t)&dummy) {
        dbg_log("Failed translating addresses");
        return false;
    }

    // Force our driver to be mapped in our cr3, even when it isn't present in the system page tables
    cmd.command_number = cmd_ensure_mapping;

    handler((uint64_t)&cmd, flags, dw_data);

    if (!is_mapping_ensured) {
        dbg_log("Failed ensuring mapping");
        return false;
    }

    /*
        To do: implement test for cmd_get_module_base and cmd_get_module_size
    */
#endif // ENABLE_EXTENSIVE_COMMUNICATION_TESTS

    return true;
}

bool init_communication(void) {
	physmem* instance = physmem::get_physmem_instance();

	if (!instance->is_inited()) {
		dbg_log("Physmem instance not inited; Returning...");
		return false;
	}

    auto hwin32k = get_driver_module_base(L"win32k.sys");
    if (!hwin32k) {
        dbg_log("Failed to get win32k.sys base address");
        return false;
    }

#ifdef ENABLE_COMMUNICATION_LOGGING
    dbg_log("Win32k.sys at %p", hwin32k);
    dbg_log("\n");
#endif // ENABLE_COMMUNICATION_LOGGING

    auto winlogon_eproc = get_eprocess("winlogon.exe");
    if(!winlogon_eproc) {
        dbg_log("Failed to get winlogon.exe eproc");
        return false;
    }

    // We need to attach to winlogon.exe to read from win32k.sys...
    KAPC_STATE apc;
    KeStackAttachProcess((PRKPROCESS)winlogon_eproc, &apc);

    // NtUserGetCPD
    // 48 83 EC 28 48 8B 05 99 02
    uint64_t pattern = search_pattern_in_section(hwin32k, ".text", "\x48\x83\xEC\x28\x48\x8B\x05\x99\x02", 9, 0x0);

    int* displacement_ptr = (int*)(pattern + 7);
    uint64_t target_address = pattern + 7 + 4 + *displacement_ptr;
    uint64_t orig_data_ptr = *(uint64_t*)target_address;

#ifdef ENABLE_COMMUNICATION_LOGGING
    dbg_log("Pattern at %p", pattern);
    dbg_log("Target .data ptr stored at %p", target_address);
    dbg_log("Target .data ptr value %p", orig_data_ptr);
    dbg_log("\n");
#endif // ENABLE_COMMUNICATION_LOGGING

    // Don't forget to detach
    KeUnstackDetachProcess(&apc);

    void* executed_pool = ExAllocatePool(NonPagedPool, PAGE_SIZE);
    void* shown_pool = ExAllocatePool(NonPagedPool, PAGE_SIZE);

    if (!executed_pool || !shown_pool)
        return false;

    crt::memset(executed_pool, 0, PAGE_SIZE);
    crt::memset(shown_pool, 0, PAGE_SIZE);

    uint8_t shown_gadget[34] = { 0 };
    uint8_t executed_gadget[45] = { 0 };

    // We need to set the va for executed 
    generate_executed_jump_gadget(executed_gadget, shown_pool, (uint64_t)asm_recover_regs);
    generate_shown_jump_gadget(shown_gadget, shown_pool);
    
    crt::memcpy(executed_pool, &executed_gadget, sizeof(executed_gadget));
    crt::memcpy(shown_pool, &shown_gadget, sizeof(shown_gadget));

    // Map the c3 bytes instead of the cc bytes (Source is what will be displayed and Target is where the memory will appear)
    if (!remap_outside_virtual_address((uint64_t)executed_pool, (uint64_t)shown_pool, instance->get_kernel_cr3())) {
        dbg_log("Failed to remap outside virtual address %p in my cr3 to %p", shown_pool, executed_pool);
        return false;
    }

#ifdef ENABLE_COMMUNICATION_LOGGING
    dbg_log("Executed pool at %p", executed_pool);
    dbg_log("Shown pool at %p", shown_pool);
    dbg_log("\n");
#endif

#ifdef ENABLE_COMMUNICATION_PAGING_LOGGING
    log_paging_hierarchy((uint64_t)shown_pool, global_kernel_cr3);
    dbg_log("\n");
    log_paging_hierarchy((uint64_t)shown_pool, instance->get_my_cr3());
    dbg_log("\n");
#endif // ENABLE_COMMUNICATION_PAGING_LOGGING


    // Store all the info in global variables
    global_orig_data_ptr = orig_data_ptr;
    global_new_data_ptr = (uint64_t)shown_pool; // points to our gadget
    global_data_ptr_address = (uint64_t*)target_address;
    orig_NtUserGetCPD = (orig_NtUserGetCPD_type)global_orig_data_ptr;
    
    // Try to execute all commands before exchanging the .data ptr
    if (!execute_tests()) {
        dbg_log("Failed tests... Not proceeding");
        return false;
    }

    // Attach to winlogon.exe
    KeStackAttachProcess((PRKPROCESS)winlogon_eproc, &apc);

    // Point it to our gadget
    *global_data_ptr_address = global_new_data_ptr;

    // Don't forget to detach
    KeUnstackDetachProcess(&apc);

    return true;
}