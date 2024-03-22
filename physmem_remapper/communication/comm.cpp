#include "comm.hpp"
#include "shared.hpp"
#include "../idt/idt.hpp"

extern "C" uint64_t global_proc_cr3 = 0;
extern "C" uint64_t global_proc_idt = 0;

// Generates shellcode which jumps to our handler
void generate_executed_jump_gadget(uint8_t* gadget, void* mem, uint64_t jmp_address, 
                                   idt_ptr_t* my_idt, idt_ptr_t* my_idt_storing_region, 
                                   gdt_ptr_t* my_gdt_ptrs, gdt_ptr_t* my_gdt_storing_region) {
    uint32_t index = 0;

    // Store the current cr3
    // mov rax, cr3
    gadget[index++] = 0x0f; gadget[index++] = 0x20; gadget[index++] = 0xd8;
    // push rax
    gadget[index++] = 0x50;

    // Write my cr3 to cr3
    // mov rax, imm64 (move my cr3 value into rax)
    gadget[index++] = 0x48; gadget[index++] = 0xb8;
    uint64_t cr3_value = physmem::get_physmem_instance()->get_my_cr3().flags;
    *reinterpret_cast<uint64_t*>(&gadget[index]) = cr3_value;
    index += 8;
    // mov cr3, rax
    gadget[index++] = 0x0f; gadget[index++] = 0x22; gadget[index++] = 0xd8;

    // Force this page to be reloaded
    // mov rax, imm64
    gadget[index++] = 0x48; gadget[index++] = 0xb8;
    uint64_t pool_addr = reinterpret_cast<uint64_t>(mem);
    *reinterpret_cast<uint64_t*>(&gadget[index]) = pool_addr;
    index += 8;
    // invlpg [rax]
    gadget[index++] = 0x0f; gadget[index++] = 0x01; gadget[index++] = 0x38;

    // mfence
    gadget[index++] = 0x0f; gadget[index++] = 0xae; gadget[index++] = 0xf0;

    // This is basically mov eax, curr_processor_number (Ty KeGetCurrentProcessorNumberEx)
    // mov rax, gs:[20h]
    gadget[index++] = 0x65; gadget[index++] = 0x48; gadget[index++] = 0x8B; gadget[index++] = 0x04;
    gadget[index++] = 0x25; gadget[index++] = 0x20; gadget[index++] = 0x00; gadget[index++] = 0x00; gadget[index++] = 0x00;

    // mov eax, [rax+24h]
    gadget[index++] = 0x8B; gadget[index++] = 0x80; gadget[index++] = 0x24; gadget[index++] = 0x00; gadget[index++] = 0x00; gadget[index++] = 0x00;

    // Clear the top 32 bits of rax to ensure proper address calculation
    // mov eax, eax
    gadget[index++] = 0x89; gadget[index++] = 0xc0;

    // Calculate the byte offset of base (using processor_index * 10)
    // imul eax, eax, 10
    gadget[index++] = 0x48; gadget[index++] = 0x6b;
    gadget[index++] = 0xc0; gadget[index++] = 0x0a;

    // push rdx
    gadget[index++] = 0x52;

    // push rax
    gadget[index++] = 0x50;

    // mov rdx, imm64
    gadget[index++] = 0x48; gadget[index++] = 0xba;
    *reinterpret_cast<uint64_t*>(&gadget[index]) = (uint64_t)my_gdt_storing_region;
    index += 8;

    // lea rax, [rdx + rax]
    gadget[index++] = 0x48; gadget[index++] = 0x8d;
    gadget[index++] = 0x04; gadget[index++] = 0x02;

    // sgdt [rax]
    gadget[index++] = 0x0f; gadget[index++] = 0x01; gadget[index++] = 0x00;

    // pop rax
    gadget[index++] = 0x58;

    // mov rdx, imm64
    gadget[index++] = 0x48; gadget[index++] = 0xba;
    *reinterpret_cast<uint64_t*>(&gadget[index]) = (uint64_t)my_gdt_ptrs;
    index += 8;

    // lea rax, [rdx + rax]
    gadget[index++] = 0x48; gadget[index++] = 0x8d;
    gadget[index++] = 0x04; gadget[index++] = 0x02;

    // lgdt [rax]
    gadget[index++] = 0x0f; gadget[index++] = 0x01; gadget[index++] = 0x10;

    // pop rdx
    gadget[index++] = 0x5a;

    // Store the current idt in idt_storing_region
    // mov rax, imm64
    gadget[index++] = 0x48; gadget[index++] = 0xb8;
    *reinterpret_cast<uint64_t*>(&gadget[index]) = (uint64_t)my_idt_storing_region;
    index += 8;
    // sidt [rax]
    gadget[index++] = 0x0F; gadget[index++] = 0x01; gadget[index++] = 0x08;

    // Load our idt handler from my_idt
    // mov rax, imm64
    gadget[index++] = 0x48; gadget[index++] = 0xB8;
    *reinterpret_cast<uint64_t*>(&gadget[index]) = (uint64_t)my_idt;
    index += 8;
    // lidt [rax]
    gadget[index++] = 0x0F; gadget[index++] = 0x01; gadget[index++] = 0x18;

    // Jump to our handler
    // mov rax, imm64
    gadget[index++] = 0x48; gadget[index++] = 0xb8;
    *reinterpret_cast<uint64_t*>(&gadget[index]) = jmp_address;
    index += 8;
    // jmp rax
    gadget[index++] = 0xff; gadget[index++] = 0xe0;
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

    // First call it for a test run (;
    cmd.command_number = cmd_comm_test;
    handler((uint64_t)&cmd, flags, dw_data);

    if (!test_call) {
        dbg_log_communication("Failed to do a test call");
        return false;
    }

    // Then ensure our driver being mapped in our cr3
    cmd.command_number = cmd_ensure_mapping;
    handler((uint64_t)&cmd, flags, dw_data);

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

    void* executed_pool = ExAllocatePool(NonPagedPool, PAGE_SIZE);
    void* shown_pool = ExAllocatePool(NonPagedPool, PAGE_SIZE);

    if (!executed_pool || !shown_pool)
        return false;

    crt::memset(executed_pool, 0, PAGE_SIZE);
    crt::memset(shown_pool, 0, PAGE_SIZE);

    // We need to set the va for executed 
    generate_executed_jump_gadget((uint8_t*)executed_pool, shown_pool, (uint64_t)asm_recover_regs, &my_idt_ptr, &idt_storing_region, gdt_ptrs, gdt_storing_region);
    generate_shown_jump_gadget((uint8_t*)shown_pool, shown_pool);
    
    // Map the c3 bytes instead of the cc bytes (Source is what will be displayed and Target is where the memory will appear)
    if (!remap_outside_virtual_address((uint64_t)executed_pool, (uint64_t)shown_pool, instance->get_kernel_cr3())) {
        dbg_log_communication("Failed to remap outside virtual address %p in my cr3 to %p", shown_pool, executed_pool);
        return false;
    }

#ifdef ENABLE_COMMUNICATION_LOGGING
    dbg_log_communication("Executed pool at %p", executed_pool);
    dbg_log_communication("Shown pool at %p \n", shown_pool);
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