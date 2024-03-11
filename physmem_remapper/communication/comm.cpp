#include "comm.hpp"

void generate_executed_jump_gadget(uint8_t* gadget, void* mem, uint64_t jmp_address) {
    // push rax
    gadget[0] = 0x50;

    // mov rax, imm64
    gadget[1] = 0x48; gadget[2] = 0xb8;
    uint64_t cr3_value = physmem::get_physmem_instance()->get_my_cr3().flags;
    *reinterpret_cast<uint64_t*>(&gadget[3]) = cr3_value;

    // mov cr3, rax
    gadget[11] = 0x0f; gadget[12] = 0x22; gadget[13] = 0xd8;

    // mov rax, imm64
    gadget[14] = 0x48; gadget[15] = 0xb8;
    uint64_t pool_addr = reinterpret_cast<uint64_t>(mem);
    *reinterpret_cast<uint64_t*>(&gadget[16]) = pool_addr;

    // invlpg [rax]
    gadget[24] = 0x0f; gadget[25] = 0x01; gadget[26] = 0x38;

    // mfence
    gadget[27] = 0x0f; gadget[28] = 0xae; gadget[29] = 0xf0;

    // mov rax, imm64
    gadget[30] = 0x48; gadget[31] = 0xb8;
    *reinterpret_cast<uint64_t*>(&gadget[32]) = jmp_address;

    // jmp rax (jump using rax)
    gadget[40] = 0xff; gadget[41] = 0xe0;
}

void generate_shown_jump_gadget(uint8_t* gadget, void* mem) {
    // push rax
    gadget[0] = 0x50;

    // mov rax, imm64
    gadget[1] = 0x48; gadget[2] = 0xb8;
    uint64_t cr3_value = physmem::get_physmem_instance()->get_my_cr3().flags;
    *reinterpret_cast<uint64_t*>(&gadget[3]) = cr3_value;

    // mov cr3, rax
    gadget[11] = 0x0f; gadget[12] = 0x22; gadget[13] = 0xd8;

    // mov rax, imm64
    gadget[14] = 0x48; gadget[15] = 0xb8;
    uint64_t pool_addr = reinterpret_cast<uint64_t>(mem);
    *reinterpret_cast<uint64_t*>(&gadget[16]) = pool_addr;

    // invlpg [rax]
    gadget[24] = 0x0f; gadget[25] = 0x01; gadget[26] = 0x38;

    // mfence
    gadget[27] = 0x0f; gadget[28] = 0xae; gadget[29] = 0xf0;

    // ret (which won't be executed)
    gadget[30] = 0xc3;
}

bool init_communication(void) {
	physmem* instance = physmem::get_physmem_instance();

	if (!instance->is_inited()) {
		dbg_log("Physmem instance not inited; Returning...");
		return false;
	}

    global_kernel_cr3.flags = __readcr3();

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

    uint8_t shown_gadget[31] = { 0 };
    uint8_t executed_gadget[42] = { 0 };

    // We need to set the va for executed 
    generate_executed_jump_gadget(executed_gadget, shown_pool, (uint64_t)handler);
    generate_shown_jump_gadget(shown_gadget, shown_pool);
    
    crt::memcpy(executed_pool, &executed_gadget, sizeof(executed_gadget));
    crt::memcpy(shown_pool, &shown_gadget, sizeof(shown_gadget));

    // Map the c3 bytes instead of the cc bytes (Source is what will be displayed and Target is where the memory will appear)
    if (!remap_outside_virtual_address((uint64_t)executed_pool, (uint64_t)shown_pool, global_kernel_cr3)) {
        dbg_log("Failed to remap outside virtual address %p in my cr3 to %p", shown_pool, executed_pool);
        return false;
    }

#ifdef ENABLE_COMMUNICATION_LOGGING
    dbg_log("Executed pool at %p", executed_pool);
    dbg_log("Shown pool at %p", shown_pool);
    dbg_log("\n");
#endif

#ifdef ENABLE_COMMUNICATION_LOGGING
    log_paging_hierarchy((uint64_t)shown_pool, global_kernel_cr3);
    dbg_log("\n");
    log_paging_hierarchy((uint64_t)shown_pool, instance->get_my_cr3());
    dbg_log("\n");

#endif // ENABLE_COMMUNICATION_LOGGING


    // Store all the info in global variables
    global_orig_data_ptr = orig_data_ptr;
    global_new_data_ptr = (uint64_t)shown_pool; // points to our gadget
    global_data_ptr_address = (uint64_t*)target_address;
    orig_NtUserGetCPD = (orig_NtUserGetCPD_type)global_orig_data_ptr;

    /*
    KeStackAttachProcess((PRKPROCESS)winlogon_eproc, &apc);

    // point it to our gadget
    *global_data_ptr_address = global_new_data_ptr;

    // Don't forget to detach
    KeUnstackDetachProcess(&apc);
    */

    func_sig func = (func_sig)shown_pool;

    return true;
}