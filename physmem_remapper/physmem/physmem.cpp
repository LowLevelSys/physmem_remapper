#include "physmem.hpp"

// We love compilers
physmem* physmem::physmem_instance = 0;

uint32_t find_free_pml4e_index(paging_structs::pml4e_64* pml4e_table) {
    for (uint32_t i = 0; i < 512; i++) {
        if (!pml4e_table[i].present) {
            return i;
        }
    }
    return 0xdead;
}

uint32_t find_free_pdpte_1gb_index(paging_structs::pdpte_1gb_64* pdpte_1gb_table) {
    for (uint32_t i = 0; i < 512; i++) {
        if (!pdpte_1gb_table[i].present) {
            return i;
        }
    }

    return 0xdead;
}

uint32_t find_free_pde_2mb_index(paging_structs::pde_2mb_64* pde_2mb_table) {
    for (uint32_t i = 0; i < 512; i++) {
        if (!pde_2mb_table[i].present) {
            return i;
        }
    }

    return 0xdead;
}

uint32_t find_free_pte_index(paging_structs::pte_64* pte_table) {
    for (uint32_t i = 0; i < 512; i++) {
        if (!pte_table[i].present) {
            return i;
        }
    }

    return 0xdead;
}

void free_pml4e_entries_except(paging_structs::pml4e_64* pml4e_table, uint64_t curr_index) {
    for (uint32_t i = 0; i < 512; i++) {
        if (i != curr_index) {
            pml4e_table[i].present = false;
        }
    }
}

void free_pdpte_1gb_entries_except(paging_structs::pdpte_1gb_64* pdpte_1gb_table, uint64_t curr_index) {
    for (uint32_t i = 0; i < 512; i++) {
        if (i != curr_index) {
            pdpte_1gb_table[i].present = false;
        }
    }
}

void free_pde_2mb_entries_except(paging_structs::pde_2mb_64* pde_2mb_table, uint64_t curr_index) {
    for (uint32_t i = 0; i < 512; i++) {
        if (i != curr_index) {
            pde_2mb_table[i].present = false;
        }
    }
}

void free_pte_entries_except(paging_structs::pte_64* pte_table, uint64_t curr_index) {
    for (uint32_t i = 0; i < 512; i++) {
        if (i != curr_index) {
            pte_table[i].present = false;
        }
    }
}

// Maps a given virtual address into our cr3
uint64_t physmem::map_outside_virtual_addr(uint64_t outside_va, paging_structs::cr3 outside_cr3, uint64_t* offset_to_next_page) {
    uint64_t curr;
    curr = __readcr3();

    __writecr3(my_cr3.flags);

    uint64_t dummy;
    virtual_address vaddr = { outside_va };
    paging_structs::pml4e_64* pml4e_table = (paging_structs::pml4e_64*)(map_outside_physical_addr(outside_cr3.address_of_page_directory << 12, &dummy));
    paging_structs::pml4e_64 pml4e = pml4e_table[vaddr.pml4_idx];

    if (!pml4e.present) {
        dbg_log("Pml4 entry not present");
        __writecr3(curr);
        return 0;
    }

    paging_structs::pdpte_64* pdpt_table = (paging_structs::pdpte_64*)(map_outside_physical_addr(pml4e.page_frame_number << 12, &dummy));
    paging_structs::pdpte_64 pdpte = pdpt_table[vaddr.pdpt_idx];

    if (!pdpte.present) {
        dbg_log("Pdpte entry not present");
        __writecr3(curr);
        return 0;
    }

    if (pdpte.large_page) {
        paging_structs::pdpte_1gb_64 pdpte_1gb;
        pdpte_1gb.flags = pdpte.flags;

        uint64_t offset = (vaddr.pd_idx << 21) + (vaddr.pt_idx << 12) + vaddr.offset;

        if (offset_to_next_page)
            *offset_to_next_page = 0x40000000 - offset;

        virtual_address generated_virtual_address = { 0 };
        generated_virtual_address.offset = vaddr.offset;
        generated_virtual_address.pml4_idx = free_pml4_index;
        generated_virtual_address.pdpt_idx = find_free_pdpte_1gb_index(page_tables->pdpt_1gb_table[MEMORY_COPYING_SLOT]);
        // Pd and pt index don't matter as they won't ever be used

        if (generated_virtual_address.pdpt_idx == 0xdead) {
            free_pdpte_1gb_entries_except(page_tables->pdpt_1gb_table[MEMORY_COPYING_SLOT], curr_pdpt_1gb_index);
            generated_virtual_address.pdpt_idx = find_free_pdpte_1gb_index(page_tables->pdpt_1gb_table[MEMORY_COPYING_SLOT]);
        }

        if (generated_virtual_address.pdpt_idx == 0xdead) {
            __writecr3(curr);
            dbg_log("No free pdpt slots!");
            return 0;
        }

        // Copy over the flags and force the write flag
        page_tables->pdpt_1gb_table[MEMORY_COPYING_SLOT][generated_virtual_address.pdpt_idx].flags = pdpte_1gb.flags;
        page_tables->pdpt_1gb_table[MEMORY_COPYING_SLOT][generated_virtual_address.pdpt_idx].write = true;

        curr_pdpt_1gb_index = generated_virtual_address.pdpt_idx;

        __invlpg((void*)generated_virtual_address.address);
        __writecr3(curr);

        return generated_virtual_address.address;
    }

    paging_structs::pde_64* pd_table = (paging_structs::pde_64*)(map_outside_physical_addr(pdpte.page_frame_number << 12, &dummy));
    paging_structs::pde_64 pde = pd_table[vaddr.pd_idx];

    if (!pde.present) {
        dbg_log("Pde entry not present");
        __writecr3(curr);
        return 0;
    }

    if (pde.large_page) {
        paging_structs::pde_2mb_64 pde_2mb;
        pde_2mb.flags = pde.flags;

        uint64_t offset = (vaddr.pt_idx << 12) + vaddr.offset;

        if (offset_to_next_page)
            *offset_to_next_page = 0x200000 - offset;

        virtual_address generated_virtual_address = { 0 };
        generated_virtual_address.offset = vaddr.offset;
        generated_virtual_address.pml4_idx = free_pml4_index;
        generated_virtual_address.pdpt_idx = NORMAL_PAGE_ENTRY;
        generated_virtual_address.pd_idx = find_free_pde_2mb_index(page_tables->pde_2mb_table[MEMORY_COPYING_SLOT]);
        // Pd and pt index don't matter as they won't ever be used

        if (generated_virtual_address.pd_idx == 0xdead) {
            free_pde_2mb_entries_except(page_tables->pde_2mb_table[MEMORY_COPYING_SLOT], curr_pde_2mb_index);
            generated_virtual_address.pd_idx = find_free_pde_2mb_index(page_tables->pde_2mb_table[MEMORY_COPYING_SLOT]);
        }

        if (generated_virtual_address.pd_idx == 0xdead) {
            __writecr3(curr);
            dbg_log("No free pde slots!");
            return 0;
        }

        // Copy over the flags and force the write flag
        page_tables->pde_2mb_table[MEMORY_COPYING_SLOT][generated_virtual_address.pd_idx].flags = pde_2mb.flags;
        page_tables->pde_2mb_table[MEMORY_COPYING_SLOT][generated_virtual_address.pd_idx].write = true;

        curr_pde_2mb_index = generated_virtual_address.pd_idx;

        __invlpg((void*)generated_virtual_address.address);
        __writecr3(curr);

        return generated_virtual_address.address;
    }

    paging_structs::pte_64* pt_table = (paging_structs::pte_64*)(map_outside_physical_addr(pde.page_frame_number << 12, &dummy));
    paging_structs::pte_64 pte = pt_table[vaddr.pt_idx];

    if (!pte.present) {
        dbg_log("Pte entry not present");
        __writecr3(curr);
        return 0;
    }

    if (offset_to_next_page)
        *offset_to_next_page = 0x1000 - vaddr.offset;

    virtual_address generated_virtual_address = { 0 };

    generated_virtual_address.offset = vaddr.offset;
    generated_virtual_address.pml4_idx = free_pml4_index;
    generated_virtual_address.pdpt_idx = NORMAL_PAGE_ENTRY;
    generated_virtual_address.pd_idx = NORMAL_PAGE_ENTRY;
    generated_virtual_address.pt_idx = find_free_pte_index(&page_tables->pte_table[MEMORY_COPYING_SLOT][0]);

    if (generated_virtual_address.pt_idx == 0xdead) {
        free_pte_entries_except(&page_tables->pte_table[MEMORY_COPYING_SLOT][0], curr_pte_index);
        generated_virtual_address.pt_idx = find_free_pte_index(&page_tables->pte_table[MEMORY_COPYING_SLOT][0]);
    }

    if (generated_virtual_address.pt_idx == 0xdead) {
        dbg_log("No free pte slots!");
        __writecr3(curr);
        return 0;
    }

    // Copy over the flags and force the write flag
    page_tables->pte_table[MEMORY_COPYING_SLOT][generated_virtual_address.pt_idx].flags = pte.flags;
    page_tables->pte_table[MEMORY_COPYING_SLOT][generated_virtual_address.pt_idx].write = true;

    // Save the current index
    curr_pte_index = generated_virtual_address.pt_idx;

    __invlpg((void*)generated_virtual_address.address);
    __writecr3(curr);

    return generated_virtual_address.address;
}

// Maps a given physical address into our cr3 and returns a va for it
uint64_t physmem::map_outside_physical_addr(uint64_t outside_pa, uint64_t* offset_to_next_page) {

    virtual_address generated_virtual_address = { 0 };
    uint64_t page_boundary = (uint64_t)PAGE_ALIGN((void*)outside_pa);

    generated_virtual_address.offset = outside_pa - page_boundary;
    generated_virtual_address.pml4_idx = free_pml4_index;
    generated_virtual_address.pdpt_idx = NORMAL_PAGE_ENTRY;
    generated_virtual_address.pd_idx = NORMAL_PAGE_ENTRY;
    generated_virtual_address.pt_idx = find_free_pte_index(page_tables->pte_table[MEMORY_COPYING_SLOT]);

    if (generated_virtual_address.pt_idx == 0xdead) {
        free_pte_entries_except(page_tables->pte_table[MEMORY_COPYING_SLOT], curr_pte_index);
        generated_virtual_address.pt_idx = find_free_pte_index(page_tables->pte_table[MEMORY_COPYING_SLOT]);
    }

    if (generated_virtual_address.pt_idx == 0xdead)
        return 0;

    paging_structs::pte_64& pte = page_tables->pte_table[MEMORY_COPYING_SLOT][generated_virtual_address.pt_idx];

    pte.present = true;
    pte.write = true;
    pte.page_frame_number = page_boundary >> 12;

    curr_pte_index = generated_virtual_address.pt_idx;

    // Calculate the offset to the next page boundary
    if (offset_to_next_page)
        *offset_to_next_page = PAGE_SIZE - generated_virtual_address.offset;

    paging_structs::cr3 current_cr3 = { 0 };
    current_cr3.flags = __readcr3();

    __writecr3(my_cr3.flags);
    _mm_lfence();

    __invlpg((void*)generated_virtual_address.address);

    _mm_lfence();
    __writecr3(current_cr3.flags);

    return generated_virtual_address.address;
}

uint64_t physmem::copy_memory_to_inside(paging_structs::cr3 source_cr3, uint64_t source, uint64_t destination, uint64_t size) {
    uint64_t bytes_read = 0;

    // This barrier is placed to force the caller to be in host mode to copy mem into host
    // as he might otherwise try to access that mem even in non host mode
    if (__readcr3() != my_cr3.flags) {
        dbg_log("Only call this function in host mode");
        return 0;
    }

    while (bytes_read < size) {
        uint64_t src_remaining = 0;

        // Map both the source and destination and source into our cr3
        uint64_t curr_src = map_outside_virtual_addr(source + bytes_read, source_cr3, &src_remaining);
        uint64_t curr_dst = destination + bytes_read;

        if (!curr_src) {
            dbg_log("Failed to map src: %p and dst %p", curr_src, curr_dst);
            return bytes_read;
        }

        // Get the max size that is copyable at once
        uint64_t curr_size = min(size - bytes_read, src_remaining);

        __invlpg((void*)curr_src);
        _mm_lfence();

        crt::memcpy((void*)curr_dst, (void*)curr_src, curr_size);

        bytes_read += curr_size;
    }

    return bytes_read;
}

uint64_t physmem::copy_memory_from_inside(uint64_t source, uint64_t destination, paging_structs::cr3 destination_cr3, uint64_t size) {
    uint64_t bytes_read = 0;
    uint64_t curr;
    curr = __readcr3();

    __writecr3(my_cr3.flags);

    while (bytes_read < size) {
        uint64_t dst_remaining = 0;

        // Map both the source and destination and source into our cr3
        uint64_t curr_src = source + bytes_read;
        uint64_t curr_dst = map_outside_virtual_addr(destination + bytes_read, destination_cr3, &dst_remaining);

        if (!curr_dst) {
            dbg_log("Failed to map src: %p and dst %p", curr_src, curr_dst);
            __writecr3(curr);
            return bytes_read;
        }

        // Get the max size that is copyable at once
        uint64_t curr_size = min(size - bytes_read, dst_remaining);

        __invlpg((void*)curr_dst);
        _mm_lfence();

        crt::memcpy((void*)curr_dst, (void*)curr_src, curr_size);

        bytes_read += curr_size;
    }

    __writecr3(curr);
    return bytes_read;
}

uint64_t physmem::get_outside_physical_addr(uint64_t outside_va, paging_structs::cr3 outside_cr3) {
    virtual_address vaddr = { outside_va };
    uint64_t dummy;

    uint64_t curr_cr3 = __readcr3();

    __writecr3(my_cr3.flags);

    paging_structs::pml4e_64* pml4_table = (paging_structs::pml4e_64*)map_outside_physical_addr(outside_cr3.address_of_page_directory << 12, &dummy);

    if (!pml4_table) {
        dbg_log("PML4 table not found");
        __writecr3(curr_cr3);
        return 0;
    }

    paging_structs::pml4e_64 pml4_entry = pml4_table[vaddr.pml4_idx];

    paging_structs::pdpte_64* pdpt_table = (paging_structs::pdpte_64*)map_outside_physical_addr(pml4_entry.page_frame_number << 12, &dummy);
    if (!pdpt_table) {
        dbg_log("PDPT table not found");
        __writecr3(curr_cr3);
        return 0;
    }

    paging_structs::pdpte_64 pdpt_entry = pdpt_table[vaddr.pdpt_idx];

    if (pdpt_entry.large_page) {
        paging_structs::pdpte_1gb_64 pdpte_1gb;
        pdpte_1gb.flags = pdpt_entry.flags;

        uint64_t offset = (vaddr.pd_idx << 21) + (vaddr.pt_idx << 12) + vaddr.offset;

        uint64_t address = (pdpte_1gb.page_frame_number << 30) + offset;

        __writecr3(curr_cr3);

        return address;
    }

    paging_structs::pde_64* pde_table = (paging_structs::pde_64*)map_outside_physical_addr(pdpt_entry.page_frame_number << 12, &dummy);
    if (!pde_table) {
        dbg_log("PDE table not found");
        __writecr3(curr_cr3);
        return 0;
    }

    paging_structs::pde_64 pde_entry = pde_table[vaddr.pd_idx];

    if (pde_entry.large_page) {
        paging_structs::pde_2mb_64 pde_2mb_entry;
        pde_2mb_entry.flags = pde_entry.flags;

        uint64_t offset = (vaddr.pt_idx << 12) + vaddr.offset;

        uint64_t address = (pde_2mb_entry.page_frame_number << 21) + offset;

        __writecr3(curr_cr3);

        return address;
    }

    paging_structs::pte_64* pte_table = (paging_structs::pte_64*)map_outside_physical_addr(pde_entry.page_frame_number << 12, &dummy);
    if (!pte_table) {
        dbg_log("PTE table not found");
        __writecr3(curr_cr3);
        return 0;
    }

    paging_structs::pte_64 pte_entry = pte_table[vaddr.pt_idx];

    uint64_t address = (pte_entry.page_frame_number << 12) + vaddr.offset;

    __writecr3(curr_cr3);

    return address;
}

paging_structs::pte_64 physmem::get_pte_entry(uint64_t outside_va, paging_structs::cr3 outside_cr3) {
    virtual_address vaddr = { outside_va };
    uint64_t dummy;

    uint64_t curr_cr3 = __readcr3();

    __writecr3(my_cr3.flags);

    paging_structs::pml4e_64* pml4_table = (paging_structs::pml4e_64*)map_outside_physical_addr(outside_cr3.address_of_page_directory << 12, &dummy);

    if (!pml4_table) {
        dbg_log("PML4 table not found");
        __writecr3(curr_cr3);
        return { 0 };
    }

    paging_structs::pml4e_64 pml4_entry = pml4_table[vaddr.pml4_idx];

    paging_structs::pdpte_64* pdpt_table = (paging_structs::pdpte_64*)map_outside_physical_addr(pml4_entry.page_frame_number << 12, &dummy);
    if (!pdpt_table) {
        dbg_log("PDPT table not found");
        __writecr3(curr_cr3);
        return { 0 };
    }

    paging_structs::pdpte_64 pdpt_entry = pdpt_table[vaddr.pdpt_idx];

    if (pdpt_entry.large_page) {
        dbg_log("Large Page");
        __writecr3(curr_cr3);
        return { 0 };
    }

    paging_structs::pde_64* pde_table = (paging_structs::pde_64*)map_outside_physical_addr(pdpt_entry.page_frame_number << 12, &dummy);
    if (!pde_table) {
        dbg_log("PDe table not found");
        __writecr3(curr_cr3);
        return { 0 };
    }

    paging_structs::pde_64 pde_entry = pde_table[vaddr.pd_idx];

    if (pde_entry.large_page) {
        dbg_log("Large Page");
        __writecr3(curr_cr3);
        return { 0 };
    }

    paging_structs::pte_64* pte_table = (paging_structs::pte_64*)map_outside_physical_addr(pde_entry.page_frame_number << 12, &dummy);
    if (!pte_table) {
        dbg_log("PTE table not found");
        __writecr3(curr_cr3);
        return { 0 };
    }

    paging_structs::pte_64 pte_entry = pte_table[vaddr.pt_idx];
    __writecr3(curr_cr3);

    return pte_entry;
}


bool physmem::set_pte_entry(uint64_t outside_va, paging_structs::cr3 outside_cr3, paging_structs::pte_64 new_ptr) {
    virtual_address vaddr = { outside_va };
    uint64_t dummy;

    uint64_t curr_cr3 = __readcr3();

    __writecr3(my_cr3.flags);

    paging_structs::pml4e_64* pml4_table = (paging_structs::pml4e_64*)map_outside_physical_addr(outside_cr3.address_of_page_directory << 12, &dummy);

    if (!pml4_table) {
        dbg_log("PML4 table not found");
        __writecr3(curr_cr3);
        return false;
    }

    paging_structs::pml4e_64 pml4_entry = pml4_table[vaddr.pml4_idx];

    paging_structs::pdpte_64* pdpt_table = (paging_structs::pdpte_64*)map_outside_physical_addr(pml4_entry.page_frame_number << 12, &dummy);
    if (!pdpt_table) {
        dbg_log("PDPT table not found");
        __writecr3(curr_cr3);
        return false;
    }

    paging_structs::pdpte_64 pdpt_entry = pdpt_table[vaddr.pdpt_idx];

    if (pdpt_entry.large_page) {
        dbg_log("Large Page");
        __writecr3(curr_cr3);
        return false;
    }

    paging_structs::pde_64* pde_table = (paging_structs::pde_64*)map_outside_physical_addr(pdpt_entry.page_frame_number << 12, &dummy);
    if (!pde_table) {
        dbg_log("PDe table not found");
        __writecr3(curr_cr3);
        return false;
    }

    paging_structs::pde_64 pde_entry = pde_table[vaddr.pd_idx];

    if (pde_entry.large_page) {
        dbg_log("Large Page");
        __writecr3(curr_cr3);
        return false;
    }

    paging_structs::pte_64* pte_table = (paging_structs::pte_64*)map_outside_physical_addr(pde_entry.page_frame_number << 12, &dummy);
    if (!pte_table) {
        dbg_log("PTE table not found");
        __writecr3(curr_cr3);
        return false;
    }

    paging_structs::pte_64* pte_entry = &pte_table[vaddr.pt_idx];

    crt::memcpy(pte_entry, &new_ptr, sizeof(paging_structs::pte_64));

    __writecr3(curr_cr3);

    return true;
}

bool physmem::set_address_range_not_global(uint64_t base, uint64_t size, paging_structs::cr3 outside_cr3) {
    uint64_t alligned_base = (uint64_t)PAGE_ALIGN(base);

    paging_structs::pte_64 sanity = { 0 };

    for (uint64_t curr_va = alligned_base; curr_va < base + size; curr_va += PAGE_SIZE) {
        // First get the pte entry and unset the global flag
        paging_structs::pte_64 pte = get_pte_entry(curr_va, get_kernel_cr3());
        pte.global = false;

        if (crt::memcmp(&sanity, &pte, sizeof(paging_structs::pte_64)) == 0) {
            dbg_log("Failed sanity 0 check while trying to set va: %p in cr3: %p to non global", curr_va, outside_cr3);
            return false;
        }

        // Then store it again
        if (!set_pte_entry(curr_va, get_kernel_cr3(), pte)) {
            dbg_log("Failed return check while trying to set va: %p in cr3: %p to non global", curr_va, outside_cr3);
            return false;
        }
    }

    // After calling this function, you have to manually flush them out of the tlb for all cores

    return true;
}


// Copies memory from one va to another based on cr3 without accessing eithers va
uint64_t physmem::copy_virtual_memory(paging_structs::cr3 source_cr3, uint64_t source, paging_structs::cr3 destination_cr3, uint64_t destination, uint64_t size) {
    uint64_t bytes_read = 0;

    paging_structs::cr3 current_cr3 = { 0 };
    current_cr3.flags = __readcr3();

    __writecr3(my_cr3.flags);
    _mm_lfence();

    while (bytes_read < size) {
        uint64_t src_remaining = 0;
        uint64_t dst_remaining = 0;

        // Map both the source and destination and source into our cr3
        uint64_t curr_src = map_outside_virtual_addr(source + bytes_read, source_cr3, &src_remaining);
        uint64_t curr_dst = map_outside_virtual_addr(destination + bytes_read, destination_cr3, &dst_remaining);

        if (!curr_src || !curr_dst) {
            _mm_lfence();
            __writecr3(current_cr3.flags);
            dbg_log("Failed to map src: %p and dst %p", curr_src, curr_dst);
            return bytes_read;
        }

        // Get the max size that is copyable at once
        uint64_t curr_size = min(size - bytes_read, src_remaining);
        curr_size = min(curr_size, dst_remaining);

        __invlpg((void*)curr_src);
        __invlpg((void*)curr_dst);
        _mm_lfence();

        crt::memcpy((void*)curr_dst, (void*)curr_src, curr_size);

        __invlpg((void*)curr_src);
        __invlpg((void*)curr_dst);

        bytes_read += curr_size;
    }

    // Make sure everything is executed before switching back to the kernel cr3
    _mm_lfence();
    __writecr3(current_cr3.flags);

    return bytes_read;
}

bool log_paging_hierarchy(uint64_t va, paging_structs::cr3 target_cr3);

// Copies memory from one pa to another pa
uint64_t physmem::copy_physical_memory(uint64_t source_physaddr, uint64_t destination_physaddr, uint64_t size) {
    uint64_t bytes_read = 0;

    if (!source_physaddr || !destination_physaddr)
        return bytes_read;

    paging_structs::cr3 current_cr3 = { 0 };
    current_cr3.flags = __readcr3();

    _mm_lfence();
    __writecr3(my_cr3.flags);
    _mm_lfence();

    while (bytes_read < size) {
        uint64_t src_remaining = 0;
        uint64_t dst_remaining = 0;

        // Map both the source and destination and source into our cr3
        uint64_t curr_src = map_outside_physical_addr(source_physaddr + bytes_read, &src_remaining);
        uint64_t curr_dst = map_outside_physical_addr(destination_physaddr + bytes_read, &dst_remaining);

        if (!curr_src || !curr_dst) {
            _mm_lfence();
            __writecr3(current_cr3.flags);
            return bytes_read;
        }

        // Get the max size that is copyable at once
        uint64_t curr_size = min(size - bytes_read, src_remaining);
        curr_size = min(curr_size, dst_remaining);

        __invlpg((void*)curr_src);
        __invlpg((void*)curr_dst);
        _mm_lfence();

        crt::memcpy((void*)curr_dst, (void*)curr_src, curr_size);

        bytes_read += curr_size;
    }

    // Make sure everything is executed before switching back to the kernel cr3
    _mm_lfence();
    __writecr3(current_cr3.flags);

    return bytes_read;
}

bool log_paging_hierarchy(uint64_t va, paging_structs::cr3 target_cr3);

// Tests whether copying memory is working
bool physmem::test_page_tables(void) {

#ifdef ENABLE_PHYSMEM_TESTS
    paging_structs::cr3 kernel_cr3 = { 0 };
    kernel_cr3.flags = __readcr3();

    // Test setup (allocating mem)
    uint64_t mem_a = (uint64_t)ExAllocatePool(NonPagedPool, PAGE_SIZE);
    uint64_t mem_b = (uint64_t)ExAllocatePool(NonPagedPool, PAGE_SIZE);
    if (!mem_a || !mem_b)
        return false;

    // Set 1 pool of mem to some value
    crt::memset((void*)mem_a, 0xaa, PAGE_SIZE);

    // Copy it over via virtual memory copying
    if (PAGE_SIZE != copy_virtual_memory(kernel_cr3, mem_a, kernel_cr3, mem_b, PAGE_SIZE)) {
        dbg_log("Failed to copy virtual memory");
        ExFreePool((void*)mem_a);
        ExFreePool((void*)mem_b);
        return false;
    }

    // Check whether the content of the pages are the same
    bool has_same_content = crt::memcmp((void*)mem_a, (void*)mem_b, PAGE_SIZE) == 0;
    if (!has_same_content) {
        dbg_log("Failed comparison 1");
        ExFreePool((void*)mem_a);
        ExFreePool((void*)mem_b);
        return false;
    }

    // Set 1 pool of mem to some value
    crt::memset((void*)mem_a, 0xbb, PAGE_SIZE);

    // Copy it over via physical memory copying
    if (PAGE_SIZE != copy_physical_memory(get_physical_address((void*)mem_a), get_physical_address((void*)mem_b), PAGE_SIZE)) {
        dbg_log("Failed to copy physical memory");
        ExFreePool((void*)mem_a);
        ExFreePool((void*)mem_b);
        return false;
    }

    // Check whether the content of the pages are the same
    has_same_content = crt::memcmp((void*)mem_a, (void*)mem_b, PAGE_SIZE) == 0;
    if (!has_same_content) {
        dbg_log("Failed comparison 2");
        ExFreePool((void*)mem_a);
        ExFreePool((void*)mem_b);
        return false;
    }

    ExFreePool((void*)mem_a);
    ExFreePool((void*)mem_b);
#endif // ENABLE_PHYSMEM_TESTS

    return true;
}

// Sets up our paging hierachy for memory copying
bool physmem::setup_paging_hierachy(void) {

    // Find a free pml4 slot index
    uint32_t free_index = find_free_pml4e_index(page_tables->pml4_table);
    if (free_index == 0xdead) {
        dbg_log("No free Pml4 index left; Weird");
        return false;
    }

    free_pml4_index = free_index;

    // Use the just determined free pml4 paging slot
    paging_structs::pml4e_64& free_pml4_slot = page_tables->pml4_table[free_index];

    free_pml4_slot.present = true;
    free_pml4_slot.write = true;
    free_pml4_slot.page_frame_number = get_physical_address(&page_tables->pdpt_table[MEMORY_COPYING_SLOT][0]) >> 12;

    // Use the first entry for the 1gb large page
    paging_structs::pdpte_1gb_64& pdpte_1gb_slot = page_tables->pdpt_1gb_table[MEMORY_COPYING_SLOT][LARGE_PAGE_ENTRY];

    pdpte_1gb_slot.present = true;
    pdpte_1gb_slot.write = true;
    pdpte_1gb_slot.large_page = true;
    pdpte_1gb_slot.page_frame_number = 0; // Has to be set when trying to copy memory from a 1gb large page

    // Use the second entry for the normal page
    paging_structs::pdpte_64& pdpte_64_slot = page_tables->pdpt_table[MEMORY_COPYING_SLOT][NORMAL_PAGE_ENTRY];

    pdpte_64_slot.present = true;
    pdpte_64_slot.write = true;
    // Point it to our pde table
    pdpte_64_slot.page_frame_number = get_physical_address(&page_tables->pde_table[MEMORY_COPYING_SLOT][0]) >> 12;

    // Use the first entry for the 2mb large page
    paging_structs::pde_2mb_64& pde_2mb_slot = page_tables->pde_2mb_table[MEMORY_COPYING_SLOT][LARGE_PAGE_ENTRY];

    pde_2mb_slot.present = true;
    pde_2mb_slot.write = true;
    pde_2mb_slot.large_page = true;
    pde_2mb_slot.page_frame_number = 0; // Has to be set when trying to copy memory from a 2mb large page

    // Use the second entry for the normal page
    paging_structs::pde_64& pde_slot = page_tables->pde_table[MEMORY_COPYING_SLOT][NORMAL_PAGE_ENTRY];

    pde_slot.present = true;
    pde_slot.write = true;
    pde_slot.page_frame_number = get_physical_address(&page_tables->pte_table[MEMORY_COPYING_SLOT][0]) >> 12;

    // On this one you could use both normal and large page slot; it doesn't matter
    paging_structs::pte_64& pte_slot = page_tables->pte_table[MEMORY_COPYING_SLOT][NORMAL_PAGE_ENTRY];

    pte_slot.present = true;
    pte_slot.write = true;
    pte_slot.page_frame_number = 0; // Has to be set when trying to copy memory from a normal page

    // Set the first slots all to occupied
    page_tables->is_pdpt_table_occupied[MEMORY_COPYING_SLOT] = true;
    page_tables->is_pde_table_occupied[MEMORY_COPYING_SLOT] = true;
    page_tables->is_pte_table_occupied[MEMORY_COPYING_SLOT] = true;

    return true;
}

// Returns the current physmem instance
physmem* physmem::get_physmem_instance(void) {

    PHYSICAL_ADDRESS max_addr = { 0 };
    max_addr.QuadPart = MAXULONG64;

    if (physmem_instance)
        return physmem_instance;

    physmem_instance = (physmem*)MmAllocateContiguousMemory(sizeof(physmem), max_addr);
    if (!physmem_instance)
        return 0;

    // Backup the inst before clearing the mem
    auto inst = physmem_instance;

    // Clear the mem
    crt::memset(physmem_instance, 0, sizeof(physmem));

    // Restore the inst after clearing the mem
    physmem_instance = inst;

    physmem_instance->page_tables = (page_table_t*)MmAllocateContiguousMemory(sizeof(page_table_t), max_addr);
    if (!physmem_instance->page_tables)
        return 0;

    crt::memset(physmem_instance->page_tables, 0, sizeof(page_table_t));

    physmem_instance->page_tables->pml4_table = (paging_structs::pml4e_64*)MmAllocateContiguousMemory(PAGE_SIZE, max_addr);
    if (!physmem_instance->page_tables->pml4_table) {
        dbg_log("Failed to alloc mem");
        return 0;
    }

    crt::memset(physmem_instance->page_tables->pml4_table, 0, PAGE_SIZE);

    for (uint64_t i = 0; i < TABLE_COUNT; i++) {
        physmem_instance->page_tables->pdpt_table[i] = (paging_structs::pdpte_64*)MmAllocateContiguousMemory(PAGE_SIZE, max_addr);
        physmem_instance->page_tables->pde_table[i] = (paging_structs::pde_64*)MmAllocateContiguousMemory(PAGE_SIZE, max_addr);
        physmem_instance->page_tables->pte_table[i] = (paging_structs::pte_64*)MmAllocateContiguousMemory(PAGE_SIZE, max_addr);

        if (!physmem_instance->page_tables->pdpt_table[i] ||
            !physmem_instance->page_tables->pde_table[i] ||
            !physmem_instance->page_tables->pte_table[i]) {
            dbg_log("Failed to alloc mem");
            return 0;
        }

        crt::memset(physmem_instance->page_tables->pdpt_table[i], 0, PAGE_SIZE);
        crt::memset(physmem_instance->page_tables->pde_table[i], 0, PAGE_SIZE);
        crt::memset(physmem_instance->page_tables->pte_table[i], 0, PAGE_SIZE);
    }

    paging_structs::pml4e_64* kernel_pml4_page_table = 0;
    paging_structs::cr3 kernel_cr3 = { 0 };
    kernel_cr3.flags = __readcr3();

    kernel_pml4_page_table = (paging_structs::pml4e_64*)get_virtual_address(kernel_cr3.address_of_page_directory << 12);

    //Copy the top most layer of pml4 because that's the kernel and we need that
    crt::memcpy(physmem_instance->page_tables->pml4_table, kernel_pml4_page_table, sizeof(paging_structs::pml4e_64) * 512);

    physmem_instance->my_cr3.flags = kernel_cr3.flags;
    physmem_instance->my_cr3.address_of_page_directory = get_physical_address(physmem_instance->page_tables->pml4_table) >> 12;

    if (!physmem_instance->setup_paging_hierachy()) {
        dbg_log("Setting up the paging hierachy failed");
        return 0;
    }

#ifdef ENABLE_PHYSMEM_LOGGING
    dbg_log("Successfully set up paging hierachy");
#endif // ENABLE_PHYSMEM_LOGGING

    // Test page tables
    if (!physmem_instance->test_page_tables()) {
        dbg_log("Testing memory copying failed");
        return 0;
    }

#ifdef ENABLE_PHYSMEM_LOGGING
    dbg_log("Tests regarding memory copying succeeded");
#endif // ENABLE_PHYSMEM_LOGGING

    physmem_instance->inited = true;

    return physmem_instance;
}