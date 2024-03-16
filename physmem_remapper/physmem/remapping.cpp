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

        uint64_t physical_address = entry.page_frame_number << 12;
        auto virtual_address = get_virtual_address(physical_address);

        dbg_log("%s - Present: %u, Write: %u, Supervisor: %u, Page Frame Number: %u, Execute Disable: %u, Virtual Address: %p, Index: %u",
            name, entry.present, entry.write, entry.supervisor, entry.page_frame_number, entry.execute_disable, virtual_address, index);
    };

    auto log_pdpte = [](const char* name, const paging_structs::pdpte_64& entry, int index) {
        if (!entry.present) {
            return;
        }

        uint64_t physical_address = entry.page_frame_number << 12;
        auto virtual_address = get_virtual_address(physical_address);

        dbg_log("%s - Present: %u, Write: %u, Supervisor: %u, Large Page: %u, Page Frame Number: %u, Execute Disable: %u, Virtual Address: %p, Index: %u ",
            name, entry.present, entry.write, entry.supervisor, entry.large_page, entry.page_frame_number, entry.execute_disable, virtual_address, index);
    };

    auto log_pde = [](const char* name, const paging_structs::pde_64& entry, int index) {
        if (!entry.present) {
            return;
        }

        uint64_t physical_address = entry.page_frame_number << 12;
        auto virtual_address = get_virtual_address(physical_address);

        dbg_log("%s - Present: %u, Write: %u, Supervisor: %u, Large Page: %u, Page Frame Number: %u, Execute Disable: %u, Virtual Address: %p, Index: %u",
            name, entry.present, entry.write, entry.supervisor, entry.large_page, entry.page_frame_number, entry.execute_disable, virtual_address, index);
    };


    auto log_pte = [](const char* name, const paging_structs::pte_64& entry, int index) {
        if (!entry.present) {
            return;
        }

        uint64_t physical_address = entry.page_frame_number << 12;
        auto virtual_address = get_virtual_address(physical_address);

        dbg_log("%s - Present: %u, Write: %u, User/Supervisor: %u, Page Frame Number: %u, Virtual Address: %p, Index %u",
            name, entry.present, entry.write, entry.supervisor, entry.page_frame_number, virtual_address, index);
    };


    // Extract indices for each level of the page table
    virtual_address vaddr = { va };

    dbg_log("Logging paging hierachy for va %p in cr3 %p", va, target_cr3.flags);
    dbg_log("Pml4 idx: %u", vaddr.pml4_idx);
    dbg_log("Pdpt idx: %u", vaddr.pdpt_idx);
    dbg_log("Pde idx: %u", vaddr.pd_idx);
    dbg_log("Pte idx: %u", vaddr.pt_idx);

    paging_structs::pml4e_64* pml4_table = (paging_structs::pml4e_64*)get_virtual_address(target_cr3.address_of_page_directory << 12);

    if (!pml4_table) {
        dbg_log("Failed to get the address of the pml4 table");
        return false;
    }

    // Access and log the PML4 entry
    auto pml4_entry = pml4_table[vaddr.pml4_idx];
    log_pml4("PML4E Entry", pml4_entry, vaddr.pml4_idx);

    // Assuming a function to convert a PFN to a virtual address of the next level table
    auto pdpt_table = reinterpret_cast<paging_structs::pdpte_64*>(get_virtual_address(pml4_entry.page_frame_number << 12));
    if (!pdpt_table) {
        dbg_log("PDPT table not found");
        return false;
    }
    
    //  Access and log the PDPT entry
    auto pdpt_entry = pdpt_table[vaddr.pdpt_idx];
    log_pdpte("PDPTE Entry", pdpt_table[vaddr.pdpt_idx], vaddr.pdpt_idx);

    // Repeat for PDE and PTE if the entries are present and not pointing to a large page
    if (!pdpt_entry.large_page) {
        auto pde_table = reinterpret_cast<paging_structs::pde_64*>(get_virtual_address(pdpt_entry.page_frame_number << 12));
        if (!pde_table) {
            dbg_log("PDE table not found");
            return false;
        }

        auto pde_entry = pde_table[vaddr.pd_idx];
        log_pde("PDE Entry", pde_table[vaddr.pd_idx], vaddr.pd_idx);

        if (!pde_entry.large_page) {
            auto pte_table = reinterpret_cast<paging_structs::pte_64*>(get_virtual_address(pde_entry.page_frame_number << 12));
            if (!pte_table) {
                dbg_log("PTE table not found");
                return false;
            }
            auto pte_entry = pte_table[vaddr.pt_idx];
            log_pte("PTE Entry", pte_entry, vaddr.pt_idx);
        }
    }

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
        if(curr_entry->remapped_va.pdpt_idx != target_va.pdpt_idx) {

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

    // Large page not supported
    if (remapping_entry->pdpte_slot.large_page)
        return non_valid;

    // Check whether the pde index overlaps
    if (remapping_entry->remapped_va.pd_idx != target_va.pd_idx)
        return pde_table_valid;

    // Large page not supported
    if (remapping_entry->pde_slot.large_page)
        return non_valid;

    return pte_table_valid;
}

// Remaps a virtual address to another one in our cr3
bool remap_outside_virtual_address(uint64_t source_va, uint64_t target_va, paging_structs::cr3 outside_cr3) {

    auto remap_to_target_virtual_address = [&](uint64_t source_va, uint64_t target_va, paging_structs::cr3 outside_cr3, page_table_t* instance) {
        virtual_address target_vaddr = { target_va };
        virtual_address outside_vaddr = { source_va };

#ifdef ENABLE_EXPERIMENT_LOGGING
        dbg_log("Starting remap: outside_va: %p, target_va: %p, outside_cr3: %p", source_va, target_va, outside_cr3);
        dbg_log("Target virtual address: pml4_idx: %u, pdpt_idx: %u, pd_idx: %u, pt_idx: %u, offset: %u", target_vaddr.pml4_idx, target_vaddr.pdpt_idx, target_vaddr.pd_idx, target_vaddr.pt_idx, target_vaddr.offset);
        dbg_log("Outside virtual address: pml4_idx: %u, pdpt_idx: %u, pd_idx: %u, pt_idx: %u, offset: %u", outside_vaddr.pml4_idx, outside_vaddr.pdpt_idx, outside_vaddr.pd_idx, outside_vaddr.pt_idx, outside_vaddr.offset);
#endif // ENABLE_EXPERIMENT_LOGGING

        if (target_vaddr.offset != outside_vaddr.offset) {
            dbg_log("Addresses with different offsets are currently not supported");
            return false;
        }

        paging_structs::pml4e_64* outside_pml4e_table = (paging_structs::pml4e_64*)(get_virtual_address((outside_cr3.address_of_page_directory << 12)));
        paging_structs::pml4e_64* my_pml4e_table = instance->pml4_table;

        // Copy the pml4 entry (here only the one entry is enough)
        crt::memcpy(&my_pml4e_table[target_vaddr.pml4_idx], &outside_pml4e_table[outside_vaddr.pml4_idx], sizeof(paging_structs::pml4e_64));
        uint32_t free_pdpte_table_index = get_free_pdpt_table_index(instance);
        if (free_pdpte_table_index == 0xdead) {
            dbg_log("Failed to get free pdpte index");
            return false;
        }

        // Replace the pdpt table it points to 
        my_pml4e_table[target_vaddr.pml4_idx].page_frame_number = get_physical_address(&instance->pdpt_table[free_pdpte_table_index][0]) >> 12;

        paging_structs::pdpte_64* outside_pdpt_table = (paging_structs::pdpte_64*)(get_virtual_address(outside_pml4e_table[outside_vaddr.pml4_idx].page_frame_number << 12));
        paging_structs::pdpte_64* my_pdpt_table = &instance->pdpt_table[free_pdpte_table_index][0];

        // Copy the Pdpte table
        crt::memcpy(my_pdpt_table, outside_pdpt_table, sizeof(paging_structs::pdpte_64) * 512);
        uint32_t free_pde_table_index = get_free_pde_table_index(instance);
        if (free_pde_table_index == 0xdead) {
            dbg_log("Failed to get free pde index");
            return false;
        }

        // Replace the pde table it points to
        my_pdpt_table[target_vaddr.pdpt_idx].page_frame_number = get_physical_address(&instance->pde_table[free_pde_table_index][0]) >> 12;

        paging_structs::pde_64* outside_pde_table = (paging_structs::pde_64*)(get_virtual_address((outside_pdpt_table[outside_vaddr.pdpt_idx].page_frame_number << 12)));
        paging_structs::pde_64* my_pde_table = &instance->pde_table[free_pde_table_index][0];

        // Copy the Pde table
        crt::memcpy(my_pde_table, outside_pde_table, sizeof(paging_structs::pde_64) * 512);
        uint32_t free_pte_table_index = get_free_pte_table_index(instance);
        if (free_pte_table_index == 0xdead) {
            dbg_log("Failed to get free pde index");
            return false;
        }

        // Replace the pte table it points to
        my_pde_table[target_vaddr.pd_idx].page_frame_number = get_physical_address(&instance->pte_table[free_pte_table_index][0]) >> 12;

        paging_structs::pte_64* outside_pte_table = (paging_structs::pte_64*)(get_virtual_address((outside_pde_table[outside_vaddr.pd_idx].page_frame_number << 12)));
        paging_structs::pte_64* my_pte_table = &instance->pte_table[free_pte_table_index][0] ;

        // Copy the Pte table
        crt::memcpy(my_pte_table, outside_pte_table, sizeof(paging_structs::pte_64) * 512);

        // If both the target address and the source address are on the same page
        // we have to specifically copy over from entry a to b otherwise it fails as we just copy the whole
        // pte table
        crt::memcpy(&my_pte_table[target_vaddr.pt_idx], &outside_pte_table[outside_vaddr.pt_idx], sizeof(paging_structs::pte_64));

        // Create a new entry for this mapping
        remapped_va_t new_entry = { 0 };

        new_entry.remapped_va = target_vaddr;

        new_entry.pdpte_slot.large_page = false;
        new_entry.pdpte_slot.slot = free_pdpte_table_index;

        new_entry.pde_slot.large_page = false;
        new_entry.pde_slot.slot = free_pde_table_index;

        new_entry.pte_slot = free_pte_table_index;

        create_new_remapping_entry(new_entry, instance);

        return true;
    };

    auto remap_to_target_virtual_address_with_previous_mapping = [&](uint64_t source_va, uint64_t target_va, paging_structs::cr3 outside_cr3, remapped_va_t* remapping_status, page_table_t* instance) {
        virtual_address target_vaddr = { target_va };
        virtual_address outside_vaddr = { source_va };

#ifdef ENABLE_EXPERIMENT_LOGGING
        dbg_log("Starting remap: outside_va: %p, target_va: %p, outside_cr3: %p", source_va, target_va, outside_cr3);
        dbg_log("Target virtual address: pml4_idx: %u, pdpt_idx: %u, pd_idx: %u, pt_idx: %u, offset: %u", target_vaddr.pml4_idx, target_vaddr.pdpt_idx, target_vaddr.pd_idx, target_vaddr.pt_idx, target_vaddr.offset);
        dbg_log("Outside virtual address: pml4_idx: %u, pdpt_idx: %u, pd_idx: %u, pt_idx: %u, offset: %u", outside_vaddr.pml4_idx, outside_vaddr.pdpt_idx, outside_vaddr.pd_idx, outside_vaddr.pt_idx, outside_vaddr.offset);
#endif // ENABLE_EXPERIMENT_LOGGING


        if (target_vaddr.offset != outside_vaddr.offset) {
            dbg_log("Addresses with different offsets are currently not supported");
            return false;
        }

        // First walk the outside paging directory
        paging_structs::pml4e_64* outside_pml4e_table = (paging_structs::pml4e_64*)(get_virtual_address((outside_cr3.address_of_page_directory << 12)));
        if(!outside_pml4e_table) {
            dbg_log("Address translation 1 failed");
            return false;
        }
        paging_structs::pdpte_64* outside_pdpt_table = (paging_structs::pdpte_64*)(get_virtual_address(outside_pml4e_table[outside_vaddr.pml4_idx].page_frame_number << 12));
        if (!outside_pdpt_table) {
            dbg_log("Address translation 2 failed");
            return false;
        }
        if(outside_pdpt_table[outside_vaddr.pdpt_idx].large_page) {
            dbg_log("No 1gb large pages supported");
            return false;
        }
        paging_structs::pde_64* outside_pde_table = (paging_structs::pde_64*)(get_virtual_address((outside_pdpt_table[outside_vaddr.pdpt_idx].page_frame_number << 12)));
        if (!outside_pde_table) {
            dbg_log("Address translation 3 failed");
            return false;
        }
        if (outside_pde_table[outside_vaddr.pd_idx].large_page) {
            dbg_log("No 2mb large pages supported");
            return false;
        }
        paging_structs::pte_64* outside_pte_table = (paging_structs::pte_64*)(get_virtual_address((outside_pde_table[outside_vaddr.pd_idx].page_frame_number << 12)));
        if(!outside_pte_table) {
            dbg_log("Address translation 4 failed");
            return false;
        }

        usable_until max_usable = get_max_usable_mapping_level(remapping_status, target_va);
        if(max_usable == non_valid) {
            dbg_log("Entry that should already be remapped isn't");
            return remap_to_target_virtual_address(source_va, target_va, outside_cr3, instance);
        }

        switch (max_usable) {
            case pdpt_table_valid: {

                if (remapping_status->pdpte_slot.large_page) {
                    dbg_log("Yikes large page 1gb");
                    return false;
                }

                paging_structs::pdpte_64* my_pdpt_table = &instance->pdpt_table[remapping_status->pdpte_slot.slot][0];

                uint32_t free_pde_table_index = get_free_pde_table_index(instance);
                if (free_pde_table_index == 0xdead) {
                    dbg_log("Failed to get free pde index");
                    return false;
                }

                // Replace the pde table it points to
                my_pdpt_table[target_vaddr.pdpt_idx].page_frame_number = get_physical_address(&instance->pde_table[free_pde_table_index][0]) >> 12;

                paging_structs::pde_64* my_pde_table = &instance->pde_table[free_pde_table_index][0];

                // Copy the Pde table
                crt::memcpy(my_pde_table, outside_pde_table, sizeof(paging_structs::pde_64) * 512);
                uint32_t free_pte_table_index = get_free_pte_table_index(instance);
                if (free_pte_table_index == 0xdead) {
                    dbg_log("Failed to get free pde index");
                    return false;
                }

                // Replace the pte table it points to
                my_pde_table[target_vaddr.pd_idx].page_frame_number = get_physical_address(&instance->pte_table[free_pte_table_index][0]) >> 12;

                paging_structs::pte_64* my_pte_table = &instance->pte_table[free_pte_table_index][0];

                // Copy the Pte table
                crt::memcpy(my_pte_table, outside_pte_table, sizeof(paging_structs::pte_64) * 512);

                // Copy the specific entry just in case source and dst are on same pte table
                crt::memcpy(&my_pte_table[target_vaddr.pt_idx], &outside_pte_table[outside_vaddr.pt_idx], sizeof(paging_structs::pte_64));

                // Create a new entry for this mapping
                remapped_va_t new_entry = { 0 };

                new_entry.remapped_va = target_vaddr;

                new_entry.pdpte_slot.large_page = false;
                new_entry.pdpte_slot.slot = remapping_status->pdpte_slot.slot;

                new_entry.pde_slot.large_page = false;
                new_entry.pde_slot.slot = free_pde_table_index;

                new_entry.pte_slot = free_pte_table_index;

                return true;
            }
            case pde_table_valid: {
                if (remapping_status->pde_slot.large_page) {
                    dbg_log("Yikes large page");
                    return false;
                }
                paging_structs::pde_64* my_pde_table = &instance->pde_table[remapping_status->pde_slot.slot][0];

                uint32_t free_pte_table_index = get_free_pte_table_index(instance);
                if (free_pte_table_index == 0xdead) {
                    dbg_log("Failed to get free pde index");
                    return false;
                }

                // Replace the pte table it points to
                my_pde_table[target_vaddr.pd_idx].page_frame_number = get_physical_address(&instance->pte_table[free_pte_table_index][0]) >> 12;

                paging_structs::pte_64* my_pte_table = &instance->pte_table[free_pte_table_index][0];

                // Copy the Pte table
                crt::memcpy(my_pte_table, outside_pte_table, sizeof(paging_structs::pte_64) * 512);

                // Copy the specific entry just in case source and dst are on same pte table
                crt::memcpy(&my_pte_table[target_vaddr.pt_idx], &outside_pte_table[outside_vaddr.pt_idx], sizeof(paging_structs::pte_64));

                // Create a new entry for this mapping
                remapped_va_t new_entry = { 0 };

                new_entry.remapped_va = target_vaddr;

                new_entry.pdpte_slot.large_page = false;
                new_entry.pdpte_slot.slot = remapping_status->pdpte_slot.slot;

                new_entry.pde_slot.large_page = false;
                new_entry.pde_slot.slot = remapping_status->pde_slot.slot;

                new_entry.pte_slot = free_pte_table_index;

                create_new_remapping_entry(new_entry, instance);
                return true;
            }
            case pte_table_valid: {

                // Everything up until to the pte table is already done; We only need to replace a pte entry
                paging_structs::pte_64* my_pte_table = &instance->pte_table[remapping_status->pte_slot][0];
                crt::memcpy(&my_pte_table[target_vaddr.pt_idx], &outside_pte_table[outside_vaddr.pt_idx], sizeof(paging_structs::pte_64));

                // Create a new entry for this mapping
                remapped_va_t new_entry = { 0 };

                new_entry.remapped_va = target_vaddr;

                new_entry.pdpte_slot.large_page = false;
                new_entry.pdpte_slot.slot = remapping_status->pdpte_slot.slot;

                new_entry.pde_slot.large_page = false;
                new_entry.pde_slot.slot = remapping_status->pde_slot.slot;

                new_entry.pte_slot = remapping_status->pte_slot;

                create_new_remapping_entry(new_entry, instance);
                return true;
            }
        }
      
        return false;
    };


    page_table_t* instance = physmem::get_physmem_instance()->get_page_tables();
    remapped_va_t* remapping_status = is_already_remapped(target_va, instance);

    // If there is no previous remapping in the range of our va,
    // just create a new mapping by force
    if (!remapping_status) {
        // Remap by force
        if (!remap_to_target_virtual_address(source_va, target_va, outside_cr3, instance)) {
            dbg_log("Failed to remap virtual address");
            return false;
        }
    }
    else {
        // Remap by using an old mapping
        if (!remap_to_target_virtual_address_with_previous_mapping(source_va, target_va, outside_cr3, remapping_status, instance)) {
            dbg_log("Failed to remap virtual address with a previous mapping");
            return false;
        }
    }

    return true;
}