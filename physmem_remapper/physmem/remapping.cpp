#include "remapping.hpp"

uint32_t get_free_pdpt_table_index(page_table_t* inst) {

    for (uint32_t i = 0; i < TABLE_COUNT; i++) {
        if (!inst->is_pdpt_table_occupied[i]) {
            inst->is_pdpt_table_occupied[i] = true;
            return i;
        }
    }

    return 0xdead;
}

uint32_t get_free_pde_table_index(page_table_t* inst) {

    for (uint32_t i = 0; i < TABLE_COUNT; i++) {
        if (!inst->is_pde_table_occupied[i]) {
            inst->is_pde_table_occupied[i] = true;
            return i;
        }
    }

    return 0xdead;
}

uint32_t get_free_pte_table_index(page_table_t* inst) {

    for (uint32_t i = 0; i < TABLE_COUNT; i++) {
        if (!inst->is_pte_table_occupied[i]) {
            inst->is_pte_table_occupied[i] = true;
            return i;
        }
    }

    return 0xdead;
}

bool log_paging_hierarchy(uint64_t va, paging_structs::cr3 target_cr3) {
    auto log_pml4 = [](const char* name, const paging_structs::pml4e_64& entry, int index) {
        if (!entry.present)
            return;

        dbg_log_remapping("%s - Present: %u, Write: %u, Supervisor: %u, Page Frame Number: %u, Execute Disable: %u, Index: %u",
            name, entry.present, entry.write, entry.supervisor, entry.page_frame_number, entry.execute_disable, index);
    };

    auto log_pdpte = [](const char* name, const paging_structs::pdpte_64& entry, int index) {
        if (!entry.present) {
            return;
        }

        dbg_log_remapping("%s - Present: %u, Write: %u, Supervisor: %u, Large Page: %u, Page Frame Number: %u, Execute Disable: %u, Index: %u ",
            name, entry.present, entry.write, entry.supervisor, entry.large_page, entry.page_frame_number, entry.execute_disable, index);
    };

    auto log_pde = [](const char* name, const paging_structs::pde_64& entry, int index) {
        if (!entry.present) {
            return;
        }

        dbg_log_remapping("%s - Present: %u, Write: %u, Supervisor: %u, Large Page: %u, Page Frame Number: %u, Execute Disable: %u, Index: %u",
            name, entry.present, entry.write, entry.supervisor, entry.large_page, entry.page_frame_number, entry.execute_disable, index);
    };

    auto log_pte = [](const char* name, const paging_structs::pte_64& entry, int index) {
        if (!entry.present) {
            return;
        }

        dbg_log_remapping("%s - Present: %u, Write: %u, User/Supervisor: %u, Page Frame Number: %u, Index %u",
            name, entry.present, entry.write, entry.supervisor, entry.page_frame_number, index);
    };

    physmem* instance = physmem::get_physmem_instance();
    uint64_t dummy;

    uint64_t curr = __readcr3();
    __writecr3(instance->get_my_cr3().flags);

    // Extract indices for each level of the page table
    virtual_address vaddr = { va };
    dbg_log_remapping("Logging paging hierachy for va %p in cr3 %p", va, target_cr3.flags);
    dbg_log_remapping("Pml4 idx: %u", vaddr.pml4_idx);
    dbg_log_remapping("Pdpt idx: %u", vaddr.pdpt_idx);
    dbg_log_remapping("Pde idx: %u", vaddr.pd_idx);
    dbg_log_remapping("Pte idx: %u", vaddr.pt_idx);

    paging_structs::pml4e_64* pml4_table = (paging_structs::pml4e_64*)instance->map_outside_physical_addr(target_cr3.address_of_page_directory << 12, &dummy);

    if (!pml4_table) {
        dbg_log_remapping("Failed to get the address of the pml4 table");
        __writecr3(curr);
        return false;
    }

    paging_structs::pml4e_64 pml4_entry = pml4_table[vaddr.pml4_idx];

    log_pml4("PML4E Entry", pml4_entry, vaddr.pml4_idx);

    paging_structs::pdpte_64* pdpt_table = (paging_structs::pdpte_64*)instance->map_outside_physical_addr(pml4_entry.page_frame_number << 12, &dummy);
    if (!pdpt_table) {
        dbg_log_remapping("PDPT table not found");
        __writecr3(curr);
        return false;
    }

    paging_structs::pdpte_64 pdpt_entry = pdpt_table[vaddr.pdpt_idx];

    if (pdpt_entry.large_page) {
        log_pdpte("Large PDPTE Entry", pdpt_table[vaddr.pdpt_idx], vaddr.pdpt_idx);
        __writecr3(curr);
        return true;
    }

    log_pdpte("PDPTE Entry", pdpt_table[vaddr.pdpt_idx], vaddr.pdpt_idx);

    paging_structs::pde_64* pde_table = (paging_structs::pde_64*)instance->map_outside_physical_addr(pdpt_entry.page_frame_number << 12, &dummy);
    if (!pde_table) {
        dbg_log_remapping("PDE table not found");
        __writecr3(curr);
        return false;
    }

    paging_structs::pde_64 pde_entry = pde_table[vaddr.pd_idx];

    if (pde_entry.large_page) {
        log_pde("Large PDE Entry", pde_table[vaddr.pd_idx], vaddr.pd_idx);
        __writecr3(curr);
        return true;
    }

    log_pde("PDE Entry", pde_table[vaddr.pd_idx], vaddr.pd_idx);

    paging_structs::pte_64* pte_table = (paging_structs::pte_64*)instance->map_outside_physical_addr(pde_entry.page_frame_number << 12, &dummy);
    if (!pte_table) {
        dbg_log_remapping("PTE table not found");
        __writecr3(curr);
        return false;
    }

    paging_structs::pte_64 pte_entry = pte_table[vaddr.pt_idx];
    log_pte("PTE Entry", pte_entry, vaddr.pt_idx);

    __writecr3(curr);
    return true;
}

// Checks whether an address has already got a remapping
// (or at least partial remapping) in our cr3
remapped_va_t* is_already_remapped(uint64_t target_address, page_table_t* instance) {
    virtual_address target_va = { target_address };
    remapped_va_t dummy = { 0 };
    remapped_va_t* curr_closest_entry = &dummy;

    for (uint32_t i = 0; i < MAX_REMAPPINGS; i++) {
        remapped_va_t* curr_entry = &instance->remapping_list[i];

        // Sort out all the irrelevant ones
        if (!curr_entry->remapped_va.address)
            continue;

        // Check whether the pml4 index overlaps
        if (curr_entry->remapped_va.pml4_idx != target_va.pml4_idx)
            continue;

        // Check whether the pdpt index overlaps
        if (curr_entry->remapped_va.pdpt_idx != target_va.pdpt_idx) {

            // The curr closest entry is already as good as the entry at the current index
            if (curr_closest_entry->remapped_va.pml4_idx == target_va.pml4_idx)
                continue;

            // Set the curr entry as closest entry
            curr_closest_entry = curr_entry;
            continue;
        }

        // If it points to an entry marked as large page
        // we can return it immediately as there won't be
        // a more fitting entry than this one (oaging hierachry
        // for that va range ends there
        if (curr_entry->pdpte_slot.large_page)
            return curr_entry;

        // Check whether the pde index overlaps
        if (curr_entry->remapped_va.pd_idx != target_va.pd_idx) {

            // The curr closest entry is already as good as the entry at the current index
            if (curr_closest_entry->remapped_va.pml4_idx == target_va.pml4_idx &&
                curr_closest_entry->remapped_va.pdpt_idx == target_va.pdpt_idx)
                continue;

            // Set the curr entry as closest entry
            curr_closest_entry = curr_entry;
            continue;
        }

        if (curr_entry->pde_slot.large_page)
            return curr_entry;

        // Check whether the pte index overlaps
        if (curr_entry->remapped_va.pt_idx != target_va.pt_idx) {

            // The curr closest entry is already as good as the entry at the current index
            if (curr_closest_entry->remapped_va.pml4_idx == target_va.pml4_idx &&
                curr_closest_entry->remapped_va.pdpt_idx == target_va.pdpt_idx &&
                curr_closest_entry->remapped_va.pd_idx == target_va.pd_idx)
                continue;

            // Set the curr entry as closest entry
            curr_closest_entry = curr_entry;
            continue;
        }

        // Everything overlapped, the address resides in the same pte table
        // as another one we mapped, we can reuse everything
        return curr_entry;
    }

    // Check whether we found a fitting entry
    // and if not just return 0 to indicate it not being there
    if (curr_closest_entry == &dummy)
        return 0;

    // Return the closest entry
    return curr_closest_entry;
}

// Creates a new remapping entry that is inserted into a given instance
void create_new_remapping_entry(remapped_va_t new_entry, page_table_t* instance) {
    for (uint32_t i = 0; i < MAX_REMAPPINGS; i++) {
        remapped_va_t* curr_entry = &instance->remapping_list[i];

        // Check whether the current entry is present/occupied
        if (curr_entry->remapped_va.address)
            continue;

        // Copy in the new entry
        crt::memcpy(curr_entry, &new_entry, sizeof(remapped_va_t));
        break;
    }
}

// Gets the max level of already remapped paging hierachy
usable_until get_max_usable_mapping_level(remapped_va_t* remapping_entry, uint64_t target_address) {
    virtual_address target_va = { target_address };

    if (!remapping_entry)
        return non_valid;

    // Check whether the pml4 index overlaps
    if (remapping_entry->remapped_va.pml4_idx != target_va.pml4_idx)
        return non_valid;

    // Check whether the pdpt index overlaps
    if (remapping_entry->remapped_va.pdpt_idx != target_va.pdpt_idx)
        return pdpt_table_valid;

    // Check whether the pde index overlaps
    if (remapping_entry->remapped_va.pd_idx != target_va.pd_idx)
        return pde_table_valid;

    return pte_table_valid;
}

// Remaps the physmem target va points to in our cr3 by force
bool remap_to_target_virtual_address(uint64_t source_va, uint64_t target_va, paging_structs::cr3 outside_cr3) {
    virtual_address target_vaddr = { target_va };
    virtual_address source_vaddr = { source_va };
    physmem* instance = physmem::get_physmem_instance();
    page_table_t* page_tables = instance->get_page_tables();
    uint64_t dummy;

    if (target_vaddr.offset != source_vaddr.offset) {
        dbg_log_remapping("Addresses with different offsets are currently not supported");
        return false;
    }

    // First attach to our cr3 for mappings
    uint64_t curr = __readcr3();
    __writecr3(instance->get_my_cr3().flags);

    // First walk the whole outside paging hierachy and check whether we can remap it
    paging_structs::pml4e_64* pml4_table = (paging_structs::pml4e_64*)instance->map_outside_physical_addr(outside_cr3.address_of_page_directory << 12, &dummy);
    paging_structs::pdpte_64* pdpt_table = (paging_structs::pdpte_64*)instance->map_outside_physical_addr(pml4_table[source_vaddr.pml4_idx].page_frame_number << 12, &dummy);

    if (pdpt_table[source_vaddr.pdpt_idx].large_page) {

        uint32_t free_pdpte_table_index = get_free_pdpt_table_index(page_tables);

        // Assign our tables
        paging_structs::pml4e_64* my_pml4_table = page_tables->pml4_table;
        paging_structs::pdpte_64* my_pdpt_table = &page_tables->pdpt_table[free_pdpte_table_index][0];

        // Get the phys addresses of them
        uint64_t pdpt_phys = instance->get_outside_physical_addr((uint64_t)my_pdpt_table, instance->get_my_cr3());

        // Copy over the base of the outside paging hierachy to use a skeleton
        crt::memcpy(&my_pml4_table[target_vaddr.pml4_idx], &pml4_table[source_vaddr.pml4_idx], sizeof(paging_structs::pml4e_64));
        crt::memcpy(my_pdpt_table, pdpt_table, sizeof(paging_structs::pdpte_64) * 512);

        // Replace where the page tables point to (the pfn; also in the pdpt level we copy the whole entry because the source and target entry might be in the same table)
        my_pml4_table[target_vaddr.pml4_idx].page_frame_number = pdpt_phys >> 12;
        crt::memcpy(&my_pdpt_table[target_vaddr.pdpt_idx], &pdpt_table[source_vaddr.pdpt_idx], sizeof(paging_structs::pdpte_1gb_64));

        // Create a new entry for this mapping
        remapped_va_t new_entry = { 0 };

        new_entry.remapped_va = target_vaddr;
        new_entry.pdpte_slot.large_page = true;
        new_entry.pdpte_slot.slot = free_pdpte_table_index;

        create_new_remapping_entry(new_entry, page_tables);

        __invlpg((void*)target_va);
        __writecr3(curr);

        return true;
    }

    paging_structs::pde_64* pde_table = (paging_structs::pde_64*)instance->map_outside_physical_addr(pdpt_table[source_vaddr.pdpt_idx].page_frame_number << 12, &dummy);

    if (pde_table[source_vaddr.pd_idx].large_page) {

        uint32_t free_pdpte_table_index = get_free_pdpt_table_index(page_tables);
        uint32_t free_pde_table_index = get_free_pde_table_index(page_tables);

        // Assign our tables
        paging_structs::pml4e_64* my_pml4_table = page_tables->pml4_table;
        paging_structs::pdpte_64* my_pdpt_table = &page_tables->pdpt_table[free_pdpte_table_index][0];
        paging_structs::pde_64* my_pde_table = &page_tables->pde_table[free_pde_table_index][0];

        // Get the phys addresses of them
        uint64_t pdpt_phys = instance->get_outside_physical_addr((uint64_t)my_pdpt_table, instance->get_my_cr3());
        uint64_t pde_phys = instance->get_outside_physical_addr((uint64_t)my_pde_table, instance->get_my_cr3());

        // Copy over the base of the outside paging hierachy to use a skeleton
        crt::memcpy(&my_pml4_table[target_vaddr.pml4_idx], &pml4_table[source_vaddr.pml4_idx], sizeof(paging_structs::pml4e_64));
        crt::memcpy(my_pdpt_table, pdpt_table, sizeof(paging_structs::pdpte_64) * 512);
        crt::memcpy(my_pde_table, pde_table, sizeof(paging_structs::pde_64) * 512);

        // Replace where the page tables point to (the pfn; also in the pd level we copy the whole entry because the source and target entry might be in the same table)
        my_pml4_table[target_vaddr.pml4_idx].page_frame_number = pdpt_phys >> 12;
        my_pdpt_table[target_vaddr.pdpt_idx].page_frame_number = pde_phys >> 12;
        my_pde_table[target_vaddr.pd_idx].page_frame_number = 0;
        crt::memcpy(&my_pde_table[target_vaddr.pd_idx], &pde_table[source_vaddr.pd_idx], sizeof(paging_structs::pde_2mb_64));

        // Create a new entry for this mapping
        remapped_va_t new_entry = { 0 };

        new_entry.remapped_va = target_vaddr;

        new_entry.pdpte_slot.large_page = false;
        new_entry.pdpte_slot.slot = free_pdpte_table_index;

        new_entry.pde_slot.large_page = true;
        new_entry.pde_slot.slot = free_pde_table_index;

        create_new_remapping_entry(new_entry, page_tables);

        __invlpg((void*)target_va);
        __writecr3(curr);

        return true;
    }

    paging_structs::pte_64* pte_table = (paging_structs::pte_64*)instance->map_outside_physical_addr(pde_table[source_vaddr.pd_idx].page_frame_number << 12, &dummy);

    // Then get all of the indexes that are necessary
    uint32_t free_pdpte_table_index = get_free_pdpt_table_index(page_tables);
    uint32_t free_pde_table_index = get_free_pde_table_index(page_tables);
    uint32_t free_pte_table_index = get_free_pte_table_index(page_tables);

    // Assign our tables
    paging_structs::pml4e_64* my_pml4_table = page_tables->pml4_table;
    paging_structs::pdpte_64* my_pdpt_table = &page_tables->pdpt_table[free_pdpte_table_index][0];
    paging_structs::pde_64* my_pde_table = &page_tables->pde_table[free_pde_table_index][0];
    paging_structs::pte_64* my_pte_table = &page_tables->pte_table[free_pte_table_index][0];

    // Get the phys addresses of them
    uint64_t pdpt_phys = instance->get_outside_physical_addr((uint64_t)my_pdpt_table, instance->get_my_cr3());
    uint64_t pde_phys = instance->get_outside_physical_addr((uint64_t)my_pde_table, instance->get_my_cr3());
    uint64_t pte_phys = instance->get_outside_physical_addr((uint64_t)my_pte_table, instance->get_my_cr3());

    // Copy over the base of the outside paging hierachy to use a skeleton
    crt::memcpy(&my_pml4_table[target_vaddr.pml4_idx], &pml4_table[source_vaddr.pml4_idx], sizeof(paging_structs::pml4e_64));
    crt::memcpy(my_pdpt_table, pdpt_table, sizeof(paging_structs::pdpte_64) * 512);
    crt::memcpy(my_pde_table, pde_table, sizeof(paging_structs::pde_64) * 512);
    crt::memcpy(my_pte_table, pte_table, sizeof(paging_structs::pte_64) * 512);

    // Replace where the page tables point to (the pfn; also in the pt level we copy the whole entry because the source and target entry might be in the same table)
    my_pml4_table[target_vaddr.pml4_idx].page_frame_number = pdpt_phys >> 12;
    my_pdpt_table[target_vaddr.pdpt_idx].page_frame_number = pde_phys >> 12;
    my_pde_table[target_vaddr.pd_idx].page_frame_number = pte_phys >> 12;
    crt::memcpy(&my_pte_table[target_vaddr.pt_idx], &pte_table[source_vaddr.pt_idx], sizeof(paging_structs::pte_64));

    // Create a new entry for this mapping
    remapped_va_t new_entry = { 0 };

    new_entry.remapped_va = target_vaddr;

    new_entry.pdpte_slot.large_page = false;
    new_entry.pdpte_slot.slot = free_pdpte_table_index;

    new_entry.pde_slot.large_page = false;
    new_entry.pde_slot.slot = free_pde_table_index;

    new_entry.pte_slot = free_pte_table_index;

    create_new_remapping_entry(new_entry, page_tables);

    // Flush tlb for that va and go back to the normal cr3
    __invlpg((void*)target_va);
    __writecr3(curr);

    return true;
}

// Remaps the physmem target va points to in our cr3 by using an old mapping
bool remap_to_target_virtual_address_with_previous_mapping(uint64_t source_va, uint64_t target_va, paging_structs::cr3 outside_cr3, remapped_va_t* remapping_status) {
    virtual_address target_vaddr = { target_va };
    virtual_address source_vaddr = { source_va };
    physmem* instance = physmem::get_physmem_instance();
    page_table_t* page_tables = instance->get_page_tables();
    uint64_t dummy;

    if (target_vaddr.offset != source_vaddr.offset) {
        dbg_log_remapping("Addresses with different offsets are currently not supported");
        return false;
    }

    // First attach to our cr3 for mappings
    uint64_t curr = __readcr3();
    __writecr3(instance->get_my_cr3().flags);

    usable_until max_usable = get_max_usable_mapping_level(remapping_status, target_va);
    if (max_usable == non_valid) {
        dbg_log_remapping("Entry that should already be remapped isn't");
        __writecr3(curr);
        return remap_to_target_virtual_address(source_va, target_va, outside_cr3);
    }

    // First walk the whole outside paging hierachy and check whether we can remap it
    paging_structs::pml4e_64* pml4_table = (paging_structs::pml4e_64*)instance->map_outside_physical_addr(outside_cr3.address_of_page_directory << 12, &dummy);
    paging_structs::pdpte_64* pdpt_table = (paging_structs::pdpte_64*)instance->map_outside_physical_addr(pml4_table[source_vaddr.pml4_idx].page_frame_number << 12, &dummy);

    if (pdpt_table[source_vaddr.pdpt_idx].large_page) {
        switch (max_usable) {
        case pde_table_valid:
        case pdpt_table_valid: {
            paging_structs::pdpte_64* my_pdpt_table = &page_tables->pdpt_table[remapping_status->pdpte_slot.slot][0];

            crt::memcpy(&my_pdpt_table[target_vaddr.pdpt_idx], &pdpt_table[source_vaddr.pdpt_idx], sizeof(paging_structs::pdpte_1gb_64));

            // Create a new entry for this mapping
            remapped_va_t new_entry = { 0 };

            new_entry.remapped_va = target_vaddr;

            new_entry.pdpte_slot.large_page = true;
            new_entry.pdpte_slot.slot = remapping_status->pdpte_slot.slot;

            create_new_remapping_entry(new_entry, page_tables);

            __invlpg((void*)target_va);
            __writecr3(curr);
            return true;
        }
        default: {
            dbg_log_remapping("Wtf happened here??");
            __writecr3(curr);
            return false;
        }
        }
    }

    paging_structs::pde_64* pde_table = (paging_structs::pde_64*)instance->map_outside_physical_addr(pdpt_table[source_vaddr.pdpt_idx].page_frame_number << 12, &dummy);

    if (pde_table[source_vaddr.pd_idx].large_page) {
        switch (max_usable) {
        case pdpt_table_valid: {
            paging_structs::pdpte_64* my_pdpt_table = &page_tables->pdpt_table[remapping_status->pdpte_slot.slot][0];

            uint32_t free_pde_table_index = get_free_pde_table_index(page_tables);
            if (free_pde_table_index == 0xdead) {
                dbg_log_remapping("Failed to get free pde index");
                __writecr3(curr);
                return false;
            }

            // Replace the pde table it points to
            my_pdpt_table[target_vaddr.pdpt_idx].page_frame_number = instance->get_outside_physical_addr((uint64_t)&page_tables->pde_table[free_pde_table_index][0], instance->get_my_cr3()) >> 12;

            paging_structs::pde_64* my_pde_table = &page_tables->pde_table[free_pde_table_index][0];

            // Copy the Pde table
            crt::memcpy(my_pde_table, pde_table, sizeof(paging_structs::pde_64) * 512);

            // Copy the specific entry just in case source and dst are on same pde table
            crt::memcpy(&my_pde_table[target_vaddr.pd_idx], &pde_table[source_vaddr.pd_idx], sizeof(paging_structs::pde_2mb_64));

            // Create a new entry for this mapping
            remapped_va_t new_entry = { 0 };

            new_entry.remapped_va = target_vaddr;

            new_entry.pdpte_slot.large_page = false;
            new_entry.pdpte_slot.slot = remapping_status->pdpte_slot.slot;

            new_entry.pde_slot.large_page = true;
            new_entry.pde_slot.slot = free_pde_table_index;

            create_new_remapping_entry(new_entry, page_tables);

            __invlpg((void*)target_va);
            __writecr3(curr);
            return true;
        }
        case pde_table_valid: {
            paging_structs::pde_64* my_pde_table = &page_tables->pde_table[remapping_status->pde_slot.slot][0];

            // Copy the specific entry just in case source and dst are on same pde table
            crt::memcpy(&my_pde_table[target_vaddr.pd_idx], &pde_table[source_vaddr.pd_idx], sizeof(paging_structs::pde_64));

            // Create a new entry for this mapping
            remapped_va_t new_entry = { 0 };

            new_entry.remapped_va = target_vaddr;

            new_entry.pdpte_slot.large_page = false;
            new_entry.pdpte_slot.slot = remapping_status->pdpte_slot.slot;

            new_entry.pde_slot.large_page = true;
            new_entry.pde_slot.slot = remapping_status->pde_slot.slot;

            create_new_remapping_entry(new_entry, page_tables);

            __invlpg((void*)target_va);
            __writecr3(curr);
            return true;
        }
        default: {
            dbg_log_remapping("Wtf happened here??");
            __writecr3(curr);
            return false;
        }
        }
    }

    paging_structs::pte_64* pte_table = (paging_structs::pte_64*)instance->map_outside_physical_addr(pde_table[source_vaddr.pd_idx].page_frame_number << 12, &dummy);

    switch (max_usable) {
    case pdpt_table_valid: {

        paging_structs::pdpte_64* my_pdpt_table = &page_tables->pdpt_table[remapping_status->pdpte_slot.slot][0];

        uint32_t free_pde_table_index = get_free_pde_table_index(page_tables);
        if (free_pde_table_index == 0xdead) {
            dbg_log_remapping("Failed to get free pde index");
            __writecr3(curr);
            return false;
        }

        // Replace the pde table it points to
        my_pdpt_table[target_vaddr.pdpt_idx].page_frame_number = instance->get_outside_physical_addr((uint64_t)&page_tables->pde_table[free_pde_table_index][0], instance->get_my_cr3()) >> 12;

        paging_structs::pde_64* my_pde_table = &page_tables->pde_table[free_pde_table_index][0];

        // Copy the Pde table
        crt::memcpy(my_pde_table, pde_table, sizeof(paging_structs::pde_64) * 512);
        uint32_t free_pte_table_index = get_free_pte_table_index(page_tables);
        if (free_pte_table_index == 0xdead) {
            dbg_log_remapping("Failed to get free pde index");
            __writecr3(curr);
            return false;
        }

        // Replace the pte table it points to
        my_pde_table[target_vaddr.pd_idx].page_frame_number = instance->get_outside_physical_addr((uint64_t)&page_tables->pte_table[free_pte_table_index][0], instance->get_my_cr3()) >> 12;

        paging_structs::pte_64* my_pte_table = &page_tables->pte_table[free_pte_table_index][0];

        // Copy the Pte table
        crt::memcpy(my_pte_table, pte_table, sizeof(paging_structs::pte_64) * 512);

        // Copy the specific entry just in case source and dst are on same pte table
        crt::memcpy(&my_pte_table[target_vaddr.pt_idx], &pte_table[source_vaddr.pt_idx], sizeof(paging_structs::pte_64));

        // Create a new entry for this mapping
        remapped_va_t new_entry = { 0 };

        new_entry.remapped_va = target_vaddr;

        new_entry.pdpte_slot.large_page = false;
        new_entry.pdpte_slot.slot = remapping_status->pdpte_slot.slot;

        new_entry.pde_slot.large_page = false;
        new_entry.pde_slot.slot = free_pde_table_index;

        new_entry.pte_slot = free_pte_table_index;

        create_new_remapping_entry(new_entry, page_tables);

        __invlpg((void*)target_va);
        __writecr3(curr);
        return true;
    }

    case pde_table_valid: {

        paging_structs::pde_64* my_pde_table = &page_tables->pde_table[remapping_status->pde_slot.slot][0];

        uint32_t free_pte_table_index = get_free_pte_table_index(page_tables);
        if (free_pte_table_index == 0xdead) {
            dbg_log_remapping("Failed to get free pde index");
            __writecr3(curr);
            return false;
        }

        // Replace the pte table it points to
        my_pde_table[target_vaddr.pd_idx].page_frame_number = instance->get_outside_physical_addr((uint64_t)&page_tables->pte_table[free_pte_table_index][0], instance->get_my_cr3()) >> 12;

        paging_structs::pte_64* my_pte_table = &page_tables->pte_table[free_pte_table_index][0];

        // Copy the Pte table
        crt::memcpy(my_pte_table, pte_table, sizeof(paging_structs::pte_64) * 512);

        // Copy the specific entry just in case source and dst are on same pte table
        crt::memcpy(&my_pte_table[target_vaddr.pt_idx], &pte_table[source_vaddr.pt_idx], sizeof(paging_structs::pte_64));

        // Create a new entry for this mapping
        remapped_va_t new_entry = { 0 };

        new_entry.remapped_va = target_vaddr;

        new_entry.pdpte_slot.large_page = false;
        new_entry.pdpte_slot.slot = remapping_status->pdpte_slot.slot;

        new_entry.pde_slot.large_page = false;
        new_entry.pde_slot.slot = remapping_status->pde_slot.slot;

        new_entry.pte_slot = free_pte_table_index;

        create_new_remapping_entry(new_entry, page_tables);

        __invlpg((void*)target_va);
        __writecr3(curr);
        return true;
    }

    case pte_table_valid: {

        // Everything up until to the pte table is already done; We only need to replace a pte entry
        paging_structs::pte_64* my_pte_table = &page_tables->pte_table[remapping_status->pte_slot][0];
        crt::memcpy(&my_pte_table[target_vaddr.pt_idx], &pte_table[source_vaddr.pt_idx], sizeof(paging_structs::pte_64));

        // Create a new entry for this mapping
        remapped_va_t new_entry = { 0 };

        new_entry.remapped_va = target_vaddr;

        new_entry.pdpte_slot.large_page = false;
        new_entry.pdpte_slot.slot = remapping_status->pdpte_slot.slot;

        new_entry.pde_slot.large_page = false;
        new_entry.pde_slot.slot = remapping_status->pde_slot.slot;

        new_entry.pte_slot = remapping_status->pte_slot;

        create_new_remapping_entry(new_entry, page_tables);

        __invlpg((void*)target_va);
        __writecr3(curr);
        return true;
    }
    }

    return false;
};

// Remaps the physmem target va points to in our cr3
bool remap_outside_virtual_address(uint64_t source_va, uint64_t target_va, paging_structs::cr3 outside_cr3) {
    physmem* physmem_instance = physmem::get_physmem_instance();
    remapped_va_t* remapping_status = is_already_remapped(target_va, physmem_instance->get_page_tables());


    if (!remapping_status) {
        // Remap by force
        if (!remap_to_target_virtual_address(source_va, target_va, outside_cr3)) {
            dbg_log_remapping("Failed to remap virtual address");
            return false;
        }
    }
    else {
        // Remap by using an old mapping
        if (!remap_to_target_virtual_address_with_previous_mapping(source_va, target_va, outside_cr3, remapping_status)) {
            dbg_log_remapping("Failed to remap virtual address with a previous mapping");
            return false;
        }
    }

    return true;
}

// Remaps a memory region to itself to ensure proper functionality after the physical memory
// ranges that represent it are removed from the system address space
bool ensure_address_space_mapping(uint64_t base, uint64_t size, paging_structs::cr3 outside_cr3) {
    uint64_t aligned_base = (uint64_t)PAGE_ALIGN(base);
    uint64_t top = base + size;

    for (uint64_t curr_va = aligned_base; curr_va < top; curr_va += PAGE_SIZE) {
        if (!remap_outside_virtual_address(curr_va, curr_va, outside_cr3)) {
            dbg_log_remapping("Failed to ensure mapping for va %p at offset %p", curr_va, curr_va - aligned_base);
            return false;
        }
    }

    return true;
}
