#include "remapping.hpp"
#include "singleton.hpp"

/*
 This assembly sequence needs a bit of explaining:
 Since kernel pages, which our gadget will reside in, are global pages,
 we can't just write to cr3 and flush the tlb for it, but we have to force it out of
 tlb by executing a invlpg with the address we want to change as an argument
*/
void generate_gadget(uint8_t* gadget, void* mem, uint64_t rax_val) {
    // mov rax, imm64
    gadget[0] = 0x48;
    gadget[1] = 0xb8; 

    // imm64 value for CR3
    uint64_t cr3_value = physmem::get_physmem_instance()->get_my_cr3().flags;
    *reinterpret_cast<uint64_t*>(&gadget[2]) = cr3_value; // Place CR3 value at offset 2

    // mov cr3, rax
    gadget[10] = 0x0f;
    gadget[11] = 0x22;
    gadget[12] = 0xd8;

    // mov rax, imm64
    gadget[13] = 0x48;
    gadget[14] = 0xb8;

    // imm64 value for pool_addr
    uint64_t pool_addr = reinterpret_cast<uint64_t>(mem);
    *reinterpret_cast<uint64_t*>(&gadget[15]) = pool_addr;

    // invlpg [rax]
    gadget[23] = 0x0f;
    gadget[24] = 0x01;
    gadget[25] = 0x38;

    // mfence
    gadget[26] = 0x0f;
    gadget[27] = 0xae;
    gadget[28] = 0xf0;

    // mov rax, imm64
    gadget[29] = 0x48;
    gadget[30] = 0xb8;

    // imm64 value
    *reinterpret_cast<uint64_t*>(&gadget[31]) = rax_val;

    // ret
    gadget[39] = 0xc3;
}

// Tries to replace the contents of a virtual address in our cr3,
// by manually constructing the paging entries for it and once you switch
// cr3 you should then see the replaced contents 
bool physmem_experiment(void) {

#ifdef ENABLE_EXPERIMENT_TESTS
    paging_structs::cr3 kernel_cr3 = { 0 };
    kernel_cr3.flags = __readcr3();

    void* mem = ExAllocatePool(NonPagedPool, PAGE_SIZE);
    void* diff_mem = ExAllocatePool(NonPagedPool, PAGE_SIZE);

    if (!mem || !diff_mem)
        return false;

    uint8_t sohwn_gadget[40] = { 0 };
    uint8_t executed_gadget[40] = { 0 };

    generate_gadget(sohwn_gadget, mem, 0x1);
    generate_gadget(executed_gadget, mem, 0x1337);

    crt::memcpy(mem, &sohwn_gadget, sizeof(sohwn_gadget));
    crt::memcpy(diff_mem, &executed_gadget, sizeof(executed_gadget));

    // Map the c3 bytes instead of the cc bytes (Source is what will be displayed and Target is where the memory will appear)
    if (!remap_outside_virtual_address((uint64_t)diff_mem, (uint64_t)mem, kernel_cr3)) {
        dbg_log("Failed to remap outside virtual address %p in my cr3 to %p", mem, diff_mem);
        return false;
    }

#ifdef EXPERIMENT_LOGGING
    log_paging_hierarchy((uint64_t)mem, kernel_cr3);
    log_paging_hierarchy((uint64_t)mem, physmem::get_physmem_instance()->get_my_cr3());
#endif // EXPERIMENT_LOGGING

    // Try to execute the cr3 gadgets
    func_sig funca = (func_sig)mem;
    funca();

    uint64_t rax = __read_rax();

    // return to the normal, kernel, cr3
    __writecr3(kernel_cr3.flags);

    // Check whether the gadget worked
    if (rax != 0x1337) {
        dbg_log("Failed to execute gadget under my cr3");
        return false;
    }

#ifdef EXPERIMENT_LOGGING
    dbg_log("Mem at %p", mem);
    dbg_log("Diff mem at %p", diff_mem);
    dbg_log("\n");
#endif // EXPERIMENT_LOGGING

    // Don't free the pools as 
    // otherwise it fucks up comm.cpp

#endif

    return true;
}