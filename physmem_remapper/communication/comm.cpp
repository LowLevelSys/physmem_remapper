#include "comm.hpp"
#include "shared.hpp"
#include "../idt/idt.hpp"
#include "shellcode_bakery.hpp"

extern "C" uint64_t global_returning_shellcode = 0;
extern "C" uint64_t* return_address_storage = 0;


bool execute_tests(void) {
    orig_NtUserGetCPD_type handler = (orig_NtUserGetCPD_type)global_new_data_ptr;
    uint32_t flags;
    uint64_t dw_data;

    // Generate the validation keys
    generate_keys(flags, dw_data);

    command cmd;

    // First call it for a test run (;
    cmd.command_number = cmd_comm_test;
    handler((uint64_t)&cmd, flags, dw_data);

    if (!test_call) {
        dbg_log_communication("Failed to do a test call");
        return false;
    }

    return true;
}

bool init_communication(void) {
	physmem* instance = physmem::get_physmem_instance();

	if (!instance->is_inited()) {
		dbg_log_communication("Physmem instance not inited; Returning...");
		return false;
	}

    auto hwin32k = get_driver_module_base(L"win32k.sys");
    if (!hwin32k) {
        dbg_log_communication("Failed to get win32k.sys base address");
        return false;
    }

#ifdef ENABLE_COMMUNICATION_LOGGING
    dbg_log_communication("Win32k.sys at %p \n", hwin32k);
#endif // ENABLE_COMMUNICATION_LOGGING

    auto winlogon_eproc = get_eprocess("winlogon.exe");
    if(!winlogon_eproc) {
        dbg_log_communication("Failed to get winlogon.exe eproc");
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
    dbg_log_communication("Pattern at %p", pattern);
    dbg_log_communication("Target .data ptr stored at %p", target_address);
    dbg_log_communication("Target .data ptr value %p \n", orig_data_ptr);
    dbg_log("\n");
#endif // ENABLE_COMMUNICATION_LOGGING

    // Don't forget to detach
    KeUnstackDetachProcess(&apc);

    PHYSICAL_ADDRESS max_addr = { 0 };
    max_addr.QuadPart = MAXULONG64;
    uint64_t processor_count = KeQueryActiveProcessorCount(0);

    void* executed_pool = ExAllocatePool(NonPagedPool, PAGE_SIZE);
    void* shown_pool = ExAllocatePool(NonPagedPool, PAGE_SIZE);
    global_returning_shellcode = (uint64_t)ExAllocatePool(NonPagedPool, PAGE_SIZE);
    return_address_storage = (uint64_t*)MmAllocateContiguousMemory(processor_count * sizeof(uint64_t), max_addr);

    if (!executed_pool || !shown_pool || !global_returning_shellcode)
        return false;

    crt::memset(executed_pool, 0, PAGE_SIZE);
    crt::memset(shown_pool, 0, PAGE_SIZE);
    crt::memset((void*)global_returning_shellcode, 0, PAGE_SIZE);

    generate_executed_jump_gadget((uint8_t*)executed_pool, cr3_storing_region,
        shown_pool, (uint64_t)asm_handler,
        &my_idt_ptr, idt_storing_region,
        gdt_ptrs, gdt_storing_region,
        tr_ptrs, tr_storing_region);

    generate_shown_jump_gadget((uint8_t*)shown_pool, shown_pool, cr3_storing_region);

    generate_return_gadget((uint8_t*)global_returning_shellcode, orig_data_ptr, cr3_storing_region, idt_storing_region, gdt_storing_region, tr_storing_region);

    // Map the c3 bytes instead of the cc bytes (Source is what will be displayed and Target is where the memory will appear)
    if (!remap_outside_virtual_address((uint64_t)executed_pool, (uint64_t)shown_pool, instance->get_kernel_cr3())) {
        dbg_log_communication("Failed to remap outside virtual address %p in my cr3 to %p", shown_pool, executed_pool);
        return false;
    }

    // Ensure the whole driver image mapped in our addresss space
    if (!ensure_address_space_mapping(driver_base, driver_size, instance->get_kernel_cr3())) {
        dbg_log_communication("Failed to ensure virtual address mapping");
        return false;
    }

    // Ensure the returning gadget is even mapped in our addresss space
    if (!ensure_address_space_mapping(global_returning_shellcode, PAGE_SIZE, instance->get_kernel_cr3())) {
        dbg_log_communication("Failed to ensure virtual address mapping");
        return false;
    }

    // Just to make sure when returning back to the normal cr3, that the cr3 storing region is mapped
    if (!ensure_address_space_mapping((uint64_t)cr3_storing_region, processor_count * sizeof(uint64_t), instance->get_kernel_cr3())) {
        dbg_log_communication("Failed to ensure virtual address mapping");
        return false;
    }

#ifdef ENABLE_COMMUNICATION_LOGGING
    dbg_log_communication("Executed pool at %p", executed_pool);
    dbg_log_communication("Shown pool at %p \n", shown_pool);
    dbg_log_communication("Returning shellcode at %p \n", global_returning_shellcode);
    dbg_log_communication("Handler at %p \n", handler);
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
        dbg_log_communication("Failed tests... Not proceeding");
        return false;
    }
    
    /*
    // Attach to winlogon.exe
    KeStackAttachProcess((PRKPROCESS)winlogon_eproc, &apc);

    // Point it to our gadget
    *global_data_ptr_address = global_new_data_ptr;

    // Don't forget to detach
    KeUnstackDetachProcess(&apc);
    */

    return true;
}